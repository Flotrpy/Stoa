"""Team-scoped endpoint, authorization, policy, and audit routes."""

import hashlib
import json
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from stoa_server.audit import record_audit_event
from stoa_server.database import get_session
from stoa_server.job_authorization import JobAuthorizationError, authorize_job
from stoa_server.models import (
    Alert,
    AuditEvent,
    AuthorizationScope,
    Endpoint,
    EndpointMonitoringObservation,
    EndpointState,
    Finding,
    FirewallSimulationObservation,
    Job,
    JobState,
    ModulePolicy,
    PortScanObservation,
    Role,
    RoleName,
    Severity,
    TeamMembership,
    User,
    WebScanObservation,
)
from stoa_server.rbac import Permission, Principal, require_permission
from stoa_server.routers.auth import ensure_roles
from stoa_server.security import hash_password
from stoa_shared.domain import (
    AlertResponse,
    AuditEventPage,
    AuditEventResponse,
    AuthorizationScopeCreate,
    AuthorizationScopeResponse,
    ClientEventCreate,
    EndpointCreate,
    EndpointMonitoringJobConfiguration,
    EndpointMonitoringObservationResponse,
    EndpointMonitoringPolicyConfiguration,
    EndpointMonitoringResultCreate,
    EndpointMonitoringResultResponse,
    EndpointResponse,
    FirewallSimulationJobConfiguration,
    FirewallSimulationObservationResponse,
    FirewallSimulationResultCreate,
    FirewallSimulationResultResponse,
    FirewallSimulatorPolicyConfiguration,
    JobCreate,
    JobResponse,
    MemberCreate,
    MembershipResponse,
    ModulePolicyResponse,
    ModulePolicyUpsert,
    PacketAnalysisPolicyConfiguration,
    PacketAnalysisResultCreate,
    PacketCaptureJobConfiguration,
    PageInfo,
    PortScanJobConfiguration,
    PortScanObservationResponse,
    PortScanPolicyConfiguration,
    PortScanResultCreate,
    PortScanResultResponse,
    UserResponse,
    WebFindingResponse,
    WebScanJobConfiguration,
    WebScanPolicyConfiguration,
    WebScanResultCreate,
    WebScanResultResponse,
)

router = APIRouter(tags=["platform"])


@router.get("/teams/{team_id}/members", response_model=list[MembershipResponse])
def list_members(
    team_id: UUID,
    principal: Annotated[Principal, Depends(require_permission(Permission.VIEW))],
    session: Annotated[Session, Depends(get_session)],
) -> list[MembershipResponse]:
    if team_id != principal.team.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="team not found")
    rows = session.execute(
        select(User, Role.name)
        .join(TeamMembership, TeamMembership.user_id == User.id)
        .join(Role, Role.id == TeamMembership.role_id)
        .where(TeamMembership.team_id == team_id)
        .order_by(User.display_name)
    ).all()
    return [
        MembershipResponse(user=UserResponse.model_validate(user), role=role.value)
        for user, role in rows
    ]


@router.post(
    "/teams/{team_id}/members",
    response_model=MembershipResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_member(
    team_id: UUID,
    payload: MemberCreate,
    principal: Annotated[Principal, Depends(require_permission(Permission.MANAGE_TEAM))],
    session: Annotated[Session, Depends(get_session)],
) -> MembershipResponse:
    if team_id != principal.team.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="team not found")
    try:
        role_name = RoleName(payload.role)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="invalid role"
        ) from error
    if session.scalar(select(User).where(User.email == payload.email)) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="email already exists")
    roles = ensure_roles(session)
    user = User(
        email=payload.email,
        display_name=payload.display_name.strip(),
        password_hash=hash_password(payload.password),
    )
    session.add(user)
    session.flush()
    session.add(TeamMembership(team_id=team_id, user_id=user.id, role_id=roles[role_name].id))
    record_audit_event(
        session,
        team_id=team_id,
        actor_user_id=principal.user.id,
        action="team.member_created",
        resource_type="user",
        resource_id=str(user.id),
        event_data={"role": role_name.value},
    )
    try:
        session.commit()
    except IntegrityError as error:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="member conflict"
        ) from error
    return MembershipResponse(user=UserResponse.model_validate(user), role=role_name.value)


@router.get("/endpoints", response_model=list[EndpointResponse])
def list_endpoints(
    principal: Annotated[Principal, Depends(require_permission(Permission.VIEW))],
    session: Annotated[Session, Depends(get_session)],
) -> list[Endpoint]:
    return list(
        session.scalars(
            select(Endpoint)
            .where(Endpoint.team_id == principal.team.id)
            .order_by(Endpoint.created_at.desc())
        )
    )


@router.post("/endpoints", response_model=EndpointResponse, status_code=status.HTTP_201_CREATED)
def register_endpoint(
    payload: EndpointCreate,
    principal: Annotated[Principal, Depends(require_permission(Permission.MANAGE_ENDPOINTS))],
    session: Annotated[Session, Depends(get_session)],
) -> Endpoint:
    endpoint = Endpoint(
        team_id=principal.team.id,
        name=payload.name.strip(),
        platform=payload.platform,
        state=EndpointState.PENDING,
    )
    session.add(endpoint)
    session.flush()
    record_audit_event(
        session,
        team_id=principal.team.id,
        actor_user_id=principal.user.id,
        action="endpoint.registered",
        resource_type="endpoint",
        resource_id=str(endpoint.id),
    )
    session.commit()
    return endpoint


@router.post("/endpoints/{endpoint_id}/approve", response_model=EndpointResponse)
def approve_endpoint(
    endpoint_id: UUID,
    principal: Annotated[Principal, Depends(require_permission(Permission.MANAGE_ENDPOINTS))],
    session: Annotated[Session, Depends(get_session)],
) -> Endpoint:
    endpoint = session.scalar(
        select(Endpoint).where(Endpoint.id == endpoint_id, Endpoint.team_id == principal.team.id)
    )
    if endpoint is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="endpoint not found")
    endpoint.state = EndpointState.APPROVED
    record_audit_event(
        session,
        team_id=principal.team.id,
        actor_user_id=principal.user.id,
        action="endpoint.approved",
        resource_type="endpoint",
        resource_id=str(endpoint.id),
    )
    session.commit()
    return endpoint


@router.post("/endpoints/{endpoint_id}/revoke", response_model=EndpointResponse)
def revoke_endpoint(
    endpoint_id: UUID,
    principal: Annotated[Principal, Depends(require_permission(Permission.MANAGE_ENDPOINTS))],
    session: Annotated[Session, Depends(get_session)],
) -> Endpoint:
    endpoint = session.scalar(
        select(Endpoint).where(Endpoint.id == endpoint_id, Endpoint.team_id == principal.team.id)
    )
    if endpoint is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="endpoint not found")
    endpoint.state = EndpointState.REVOKED
    endpoint.revoked_at = datetime.now(UTC)
    record_audit_event(
        session,
        team_id=principal.team.id,
        actor_user_id=principal.user.id,
        action="endpoint.revoked",
        resource_type="endpoint",
        resource_id=str(endpoint.id),
    )
    session.commit()
    return endpoint


@router.get("/authorization-scopes", response_model=list[AuthorizationScopeResponse])
def list_scopes(
    principal: Annotated[Principal, Depends(require_permission(Permission.VIEW))],
    session: Annotated[Session, Depends(get_session)],
) -> list[AuthorizationScope]:
    return list(
        session.scalars(
            select(AuthorizationScope)
            .where(AuthorizationScope.team_id == principal.team.id)
            .order_by(AuthorizationScope.created_at.desc())
        )
    )


@router.post(
    "/authorization-scopes",
    response_model=AuthorizationScopeResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_scope(
    payload: AuthorizationScopeCreate,
    principal: Annotated[Principal, Depends(require_permission(Permission.MANAGE_SCOPES))],
    session: Annotated[Session, Depends(get_session)],
) -> AuthorizationScope:
    if payload.valid_from.tzinfo is None or payload.valid_from >= payload.expires_at:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="invalid window"
        )
    maximum = payload.rate_policy.get("max_requests")
    window = payload.rate_policy.get("window_seconds")
    if not isinstance(maximum, int) or not 1 <= maximum <= 10_000:
        raise HTTPException(status_code=422, detail="invalid max_requests")
    if not isinstance(window, int) or not 1 <= window <= 86_400:
        raise HTTPException(status_code=422, detail="invalid window_seconds")
    scope = AuthorizationScope(
        team_id=principal.team.id,
        owner_user_id=principal.user.id,
        name=payload.name.strip(),
        target_pattern=payload.target_pattern.strip(),
        allowed_modules=payload.allowed_modules,
        rate_policy=payload.rate_policy,
        valid_from=payload.valid_from,
        expires_at=payload.expires_at,
    )
    session.add(scope)
    session.flush()
    record_audit_event(
        session,
        team_id=principal.team.id,
        actor_user_id=principal.user.id,
        action="authorization_scope.created",
        resource_type="authorization_scope",
        resource_id=str(scope.id),
        event_data={"target_pattern": scope.target_pattern},
    )
    session.commit()
    return scope


@router.get("/module-policies", response_model=list[ModulePolicyResponse])
def list_policies(
    principal: Annotated[Principal, Depends(require_permission(Permission.VIEW))],
    session: Annotated[Session, Depends(get_session)],
) -> list[ModulePolicy]:
    return list(
        session.scalars(
            select(ModulePolicy)
            .where(ModulePolicy.team_id == principal.team.id)
            .order_by(ModulePolicy.module_id)
        )
    )


@router.put("/module-policies/{module_id}", response_model=ModulePolicyResponse)
def upsert_policy(
    module_id: str,
    payload: ModulePolicyUpsert,
    principal: Annotated[Principal, Depends(require_permission(Permission.CONFIGURE_POLICIES))],
    session: Annotated[Session, Depends(get_session)],
) -> ModulePolicy:
    if not module_id or len(module_id) > 80:
        raise HTTPException(status_code=422, detail="invalid module_id")
    configuration = payload.configuration
    if module_id == "port-scanner":
        configuration = PortScanPolicyConfiguration.model_validate(configuration).model_dump()
    if module_id == "packet-analysis":
        configuration = PacketAnalysisPolicyConfiguration.model_validate(configuration).model_dump()
    if module_id == "web-scanner":
        configuration = WebScanPolicyConfiguration.model_validate(configuration).model_dump()
    if module_id == "firewall-simulator":
        configuration = FirewallSimulatorPolicyConfiguration.model_validate(
            configuration
        ).model_dump()
    if module_id == "endpoint-monitoring":
        configuration = EndpointMonitoringPolicyConfiguration.model_validate(
            configuration
        ).model_dump()
    policy = session.scalar(
        select(ModulePolicy).where(
            ModulePolicy.team_id == principal.team.id, ModulePolicy.module_id == module_id
        )
    )
    if policy is None:
        policy = ModulePolicy(team_id=principal.team.id, module_id=module_id)
        session.add(policy)
    policy.enabled = payload.enabled
    policy.configuration = configuration
    policy.updated_by_user_id = principal.user.id
    session.flush()
    record_audit_event(
        session,
        team_id=principal.team.id,
        actor_user_id=principal.user.id,
        action="module_policy.updated",
        resource_type="module_policy",
        resource_id=str(policy.id),
        event_data={"module_id": module_id, "enabled": policy.enabled},
    )
    session.commit()
    return policy


@router.get("/jobs", response_model=list[JobResponse])
def list_jobs(
    principal: Annotated[Principal, Depends(require_permission(Permission.VIEW))],
    session: Annotated[Session, Depends(get_session)],
) -> list[Job]:
    return list(
        session.scalars(
            select(Job).where(Job.team_id == principal.team.id).order_by(Job.created_at.desc())
        )
    )


@router.post("/jobs", response_model=JobResponse, status_code=status.HTTP_201_CREATED)
def create_job(
    payload: JobCreate,
    principal: Annotated[Principal, Depends(require_permission(Permission.RUN_JOBS))],
    session: Annotated[Session, Depends(get_session)],
) -> Job:
    try:
        authorized = authorize_job(
            session,
            team_id=principal.team.id,
            endpoint_id=payload.executing_endpoint_id,
            scope_id=payload.authorization_scope_id,
            module_id=payload.module_id,
            target=payload.target,
        )
    except JobAuthorizationError as error:
        record_audit_event(
            session,
            team_id=principal.team.id,
            actor_user_id=principal.user.id,
            action="job.rejected",
            resource_type="job",
            resource_id=None,
            event_data={"module_id": payload.module_id, "reason": str(error)},
        )
        session.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(error)) from error

    configuration = dict(payload.configuration)
    if payload.module_id == "port-scanner":
        scan_configuration = PortScanJobConfiguration.model_validate(configuration)
        policy_configuration = authorized.policy.configuration
        maximum_ports = int(policy_configuration.get("max_ports", 1024))
        maximum_concurrency = int(policy_configuration.get("max_concurrency", 64))
        if len(scan_configuration.ports) > maximum_ports:
            raise HTTPException(status_code=403, detail="port count exceeds module policy")
        if scan_configuration.concurrency > maximum_concurrency:
            raise HTTPException(status_code=403, detail="concurrency exceeds module policy")
        if scan_configuration.method == "syn" and not policy_configuration.get("allow_syn", False):
            raise HTTPException(status_code=403, detail="SYN scanning is disabled by policy")
        configuration = scan_configuration.model_dump()
        if not policy_configuration.get("allow_banner_collection", True):
            configuration["collect_banners"] = False
        configuration["effective_minimum_interval_seconds"] = (
            authorized.scope.rate_policy["window_seconds"]
            / authorized.scope.rate_policy["max_requests"]
        )
    if payload.module_id == "packet-analysis":
        capture = PacketCaptureJobConfiguration.model_validate(configuration)
        packet_policy = PacketAnalysisPolicyConfiguration.model_validate(
            authorized.policy.configuration
        )
        if not capture.replay_only and not packet_policy.allow_live_capture:
            raise HTTPException(status_code=403, detail="live capture is disabled by policy")
        if capture.packet_limit > packet_policy.maximum_packets:
            raise HTTPException(status_code=403, detail="packet limit exceeds module policy")
        configuration = capture.model_dump()
        configuration["maximum_file_bytes"] = min(
            capture.maximum_file_bytes, packet_policy.maximum_file_bytes
        )
        configuration["retained_files"] = min(capture.retained_files, packet_policy.retained_files)
    if payload.module_id == "web-scanner":
        scan = WebScanJobConfiguration.model_validate(configuration)
        web_policy = WebScanPolicyConfiguration.model_validate(authorized.policy.configuration)
        if scan.max_depth > web_policy.max_depth:
            raise HTTPException(status_code=403, detail="crawl depth exceeds module policy")
        if scan.max_pages > web_policy.max_pages:
            raise HTTPException(status_code=403, detail="page count exceeds module policy")
        if scan.max_requests_per_second > web_policy.max_requests_per_second:
            raise HTTPException(status_code=403, detail="request rate exceeds module policy")
        if scan.active_checks and not web_policy.allow_active_checks:
            raise HTTPException(status_code=403, detail="active checks are disabled by policy")
        if scan.allow_form_submission and not web_policy.allow_form_submission:
            raise HTTPException(status_code=403, detail="form submission is disabled by policy")
        if scan.import_zap_alerts and not web_policy.allow_zap_import:
            raise HTTPException(status_code=403, detail="ZAP import is disabled by policy")
        configuration = scan.model_dump()
        configuration["effective_minimum_interval_seconds"] = max(
            authorized.scope.rate_policy["window_seconds"]
            / authorized.scope.rate_policy["max_requests"],
            1 / scan.max_requests_per_second,
        )
    if payload.module_id == "firewall-simulator":
        simulation = FirewallSimulationJobConfiguration.model_validate(configuration)
        firewall_policy = FirewallSimulatorPolicyConfiguration.model_validate(
            authorized.policy.configuration
        )
        if len(simulation.rules) > firewall_policy.max_rules:
            raise HTTPException(status_code=403, detail="rule count exceeds module policy")
        if len(simulation.packets) > firewall_policy.max_packets:
            raise HTTPException(status_code=403, detail="packet count exceeds module policy")
        configuration = simulation.model_dump()
    if payload.module_id == "endpoint-monitoring":
        monitoring = EndpointMonitoringJobConfiguration.model_validate(configuration)
        monitoring_policy = EndpointMonitoringPolicyConfiguration.model_validate(
            authorized.policy.configuration
        )
        if monitoring.maximum_file_bytes > monitoring_policy.maximum_file_bytes:
            raise HTTPException(status_code=403, detail="file size exceeds module policy")
        if monitoring.inspect_processes and not monitoring_policy.allow_process_inspection:
            raise HTTPException(status_code=403, detail="process inspection is disabled by policy")
        configuration = monitoring.model_dump()

    job = Job(
        team_id=principal.team.id,
        module_id=payload.module_id,
        requesting_user_id=principal.user.id,
        executing_endpoint_id=authorized.endpoint.id,
        authorization_scope_id=authorized.scope.id,
        asset_id=payload.asset_id,
        target=payload.target.strip(),
        business_justification=payload.business_justification.strip(),
        rate_policy=authorized.scope.rate_policy,
        configuration=configuration,
    )
    session.add(job)
    session.flush()
    record_audit_event(
        session,
        team_id=principal.team.id,
        actor_user_id=principal.user.id,
        action="job.created",
        resource_type="job",
        resource_id=str(job.id),
        event_data={"module_id": job.module_id, "correlation_id": str(job.correlation_id)},
        correlation_id=job.correlation_id,
    )
    session.commit()
    return job


def _port_scan_job(session: Session, principal: Principal, job_id: UUID) -> Job:
    job = session.scalar(select(Job).where(Job.id == job_id, Job.team_id == principal.team.id))
    if job is None or job.module_id != "port-scanner":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="port scan job not found")
    return job


@router.post(
    "/jobs/{job_id}/port-scan-results",
    response_model=PortScanResultResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_port_scan_results(
    job_id: UUID,
    payload: PortScanResultCreate,
    principal: Annotated[Principal, Depends(require_permission(Permission.RUN_JOBS))],
    session: Annotated[Session, Depends(get_session)],
) -> PortScanResultResponse:
    job = _port_scan_job(session, principal, job_id)
    if payload.executing_endpoint_id != job.executing_endpoint_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="endpoint mismatch")
    if job.state not in {JobState.QUEUED, JobState.RUNNING, JobState.CANCELLING}:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="job is already final")
    observations = [
        PortScanObservation(
            team_id=principal.team.id,
            job_id=job.id,
            port=item.port,
            state=item.state,
            service=item.service,
            banner=item.banner,
            latency_ms=item.latency_ms,
        )
        for item in payload.observations
    ]
    session.add_all(observations)
    job.state = JobState.CANCELLED if payload.cancelled else JobState.SUCCEEDED
    record_audit_event(
        session,
        team_id=principal.team.id,
        actor_user_id=principal.user.id,
        action="port_scan.results_recorded",
        resource_type="job",
        resource_id=str(job.id),
        correlation_id=job.correlation_id,
        event_data={
            "observation_count": len(observations),
            "open_count": sum(item.state == "open" for item in observations),
            "cancelled": payload.cancelled,
        },
    )
    try:
        session.commit()
    except IntegrityError as error:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="results already recorded"
        ) from error
    return PortScanResultResponse(
        job=JobResponse.model_validate(job),
        observations=[PortScanObservationResponse.model_validate(item) for item in observations],
    )


@router.get("/jobs/{job_id}/port-scan-results", response_model=PortScanResultResponse)
def get_port_scan_results(
    job_id: UUID,
    principal: Annotated[Principal, Depends(require_permission(Permission.VIEW))],
    session: Annotated[Session, Depends(get_session)],
) -> PortScanResultResponse:
    job = _port_scan_job(session, principal, job_id)
    observations = list(
        session.scalars(
            select(PortScanObservation)
            .where(
                PortScanObservation.job_id == job.id,
                PortScanObservation.team_id == principal.team.id,
            )
            .order_by(PortScanObservation.port)
        )
    )
    return PortScanResultResponse(
        job=JobResponse.model_validate(job),
        observations=[PortScanObservationResponse.model_validate(item) for item in observations],
    )


@router.get("/jobs/{job_id}/port-scan-report")
def get_port_scan_report(
    job_id: UUID,
    principal: Annotated[Principal, Depends(require_permission(Permission.VIEW))],
    session: Annotated[Session, Depends(get_session)],
    format: Annotated[str, Query(pattern=r"^(json|text)$")] = "json",
) -> Response:
    result = get_port_scan_results(job_id, principal, session)
    if format == "json":
        return Response(content=result.model_dump_json(indent=2), media_type="application/json")
    lines = [
        f"Stoá port scan report: {result.job.target}",
        f"Job: {result.job.id}",
        f"State: {result.job.state}",
        "",
        "PORT     STATE        SERVICE             BANNER",
    ]
    for item in result.observations:
        lines.append(
            f"{item.port:<8} {item.state:<12} {(item.service or '-'):<19} {item.banner or '-'}"
        )
    return Response(content="\n".join(lines) + "\n", media_type="text/plain")


def _web_scan_job(session: Session, principal: Principal, job_id: UUID) -> Job:
    job = session.scalar(select(Job).where(Job.id == job_id, Job.team_id == principal.team.id))
    if job is None or job.module_id != "web-scanner":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="web scan job not found")
    return job


@router.post(
    "/jobs/{job_id}/web-scan-results",
    response_model=WebScanResultResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_web_scan_results(
    job_id: UUID,
    payload: WebScanResultCreate,
    principal: Annotated[Principal, Depends(require_permission(Permission.RUN_JOBS))],
    session: Annotated[Session, Depends(get_session)],
) -> WebScanResultResponse:
    job = _web_scan_job(session, principal, job_id)
    if payload.executing_endpoint_id != job.executing_endpoint_id:
        raise HTTPException(status_code=403, detail="endpoint mismatch")
    if job.state not in {JobState.QUEUED, JobState.RUNNING, JobState.CANCELLING}:
        raise HTTPException(status_code=409, detail="job is already final")
    observations = [
        WebScanObservation(
            team_id=principal.team.id,
            job_id=job.id,
            rule_id=item.rule_id,
            category=item.category,
            title=item.title,
            severity=item.severity,
            confidence=item.confidence,
            url=item.url,
            evidence=item.evidence,
            remediation=item.remediation,
        )
        for item in payload.findings
    ]
    session.add_all(observations)
    alerts_created = 0
    for item in payload.findings:
        evidence = json.dumps(item.evidence, sort_keys=True, separators=(",", ":"))
        finding = Finding(
            team_id=principal.team.id,
            job_id=job.id,
            title=item.title,
            summary=f"{item.url} Evidence: {evidence}",
            severity=Severity(item.severity),
            confidence=item.confidence,
            remediation=item.remediation,
        )
        session.add(finding)
        session.flush()
        deduplication_key = hashlib.sha256(
            f"{item.rule_id}|{item.url}|{evidence}".encode()
        ).hexdigest()
        existing = session.scalar(
            select(Alert).where(
                Alert.team_id == principal.team.id,
                Alert.deduplication_key == deduplication_key,
            )
        )
        if existing is None:
            session.add(
                Alert(
                    team_id=principal.team.id,
                    finding_id=finding.id,
                    title=item.title,
                    severity=Severity(item.severity),
                    confidence=item.confidence,
                    deduplication_key=deduplication_key,
                )
            )
            alerts_created += 1
    job.state = JobState.CANCELLED if payload.cancelled else JobState.SUCCEEDED
    record_audit_event(
        session,
        team_id=principal.team.id,
        actor_user_id=principal.user.id,
        action="web_scan.results_recorded",
        resource_type="job",
        resource_id=str(job.id),
        correlation_id=job.correlation_id,
        event_data={
            "page_count": payload.page_count,
            "finding_count": len(payload.findings),
            "alerts_created": alerts_created,
            "cancelled": payload.cancelled,
        },
    )
    session.commit()
    return WebScanResultResponse(
        job=JobResponse.model_validate(job),
        findings=[WebFindingResponse.model_validate(item) for item in observations],
    )


@router.get("/jobs/{job_id}/web-scan-results", response_model=WebScanResultResponse)
def get_web_scan_results(
    job_id: UUID,
    principal: Annotated[Principal, Depends(require_permission(Permission.VIEW))],
    session: Annotated[Session, Depends(get_session)],
) -> WebScanResultResponse:
    job = _web_scan_job(session, principal, job_id)
    observations = list(
        session.scalars(
            select(WebScanObservation)
            .where(
                WebScanObservation.job_id == job.id,
                WebScanObservation.team_id == principal.team.id,
            )
            .order_by(WebScanObservation.severity.desc(), WebScanObservation.created_at)
        )
    )
    return WebScanResultResponse(
        job=JobResponse.model_validate(job),
        findings=[WebFindingResponse.model_validate(item) for item in observations],
    )


@router.get("/jobs/{job_id}/web-scan-report")
def get_web_scan_report(
    job_id: UUID,
    principal: Annotated[Principal, Depends(require_permission(Permission.VIEW))],
    session: Annotated[Session, Depends(get_session)],
    format: Annotated[str, Query(pattern=r"^(json|text)$")] = "json",
) -> Response:
    result = get_web_scan_results(job_id, principal, session)
    if format == "json":
        return Response(content=result.model_dump_json(indent=2), media_type="application/json")
    lines = [
        f"Stoá web scan report: {result.job.target}",
        f"Job: {result.job.id}",
        f"State: {result.job.state}",
        "",
        "SEVERITY  CONFIDENCE  RULE          URL",
    ]
    for item in result.findings:
        lines.append(f"{item.severity:<9} {item.confidence:<11.2f} {item.rule_id:<13} {item.url}")
        lines.append(f"  {item.title}")
        lines.append(f"  Remediation: {item.remediation}")
    return Response(content="\n".join(lines) + "\n", media_type="text/plain")


def _firewall_job(session: Session, principal: Principal, job_id: UUID) -> Job:
    job = session.scalar(select(Job).where(Job.id == job_id, Job.team_id == principal.team.id))
    if job is None or job.module_id != "firewall-simulator":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="firewall simulation job not found"
        )
    return job


@router.post(
    "/jobs/{job_id}/firewall-simulation-results",
    response_model=FirewallSimulationResultResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_firewall_simulation_results(
    job_id: UUID,
    payload: FirewallSimulationResultCreate,
    principal: Annotated[Principal, Depends(require_permission(Permission.RUN_JOBS))],
    session: Annotated[Session, Depends(get_session)],
) -> FirewallSimulationResultResponse:
    job = _firewall_job(session, principal, job_id)
    if payload.executing_endpoint_id != job.executing_endpoint_id:
        raise HTTPException(status_code=403, detail="endpoint mismatch")
    if job.state not in {JobState.QUEUED, JobState.RUNNING, JobState.CANCELLING}:
        raise HTTPException(status_code=409, detail="job is already final")
    observations = [
        FirewallSimulationObservation(
            team_id=principal.team.id,
            job_id=job.id,
            packet=item.packet.model_dump(),
            action=item.action,
            matched_rule=item.matched_rule,
            explanation=item.explanation,
        )
        for item in payload.observations
    ]
    session.add_all(observations)
    job.state = JobState.CANCELLED if payload.cancelled else JobState.SUCCEEDED
    record_audit_event(
        session,
        team_id=principal.team.id,
        actor_user_id=principal.user.id,
        action="firewall_simulation.results_recorded",
        resource_type="job",
        resource_id=str(job.id),
        correlation_id=job.correlation_id,
        event_data={
            "observation_count": len(observations),
            "shadowed_rules": len(payload.analysis.shadowed_rules),
            "conflicting_rules": len(payload.analysis.conflicting_rules),
            "cancelled": payload.cancelled,
        },
    )
    session.commit()
    return FirewallSimulationResultResponse(
        job=JobResponse.model_validate(job),
        analysis=payload.analysis,
        observations=[
            FirewallSimulationObservationResponse.model_validate(item) for item in observations
        ],
    )


@router.get(
    "/jobs/{job_id}/firewall-simulation-results",
    response_model=FirewallSimulationResultResponse,
)
def get_firewall_simulation_results(
    job_id: UUID,
    principal: Annotated[Principal, Depends(require_permission(Permission.VIEW))],
    session: Annotated[Session, Depends(get_session)],
) -> FirewallSimulationResultResponse:
    job = _firewall_job(session, principal, job_id)
    observations = list(
        session.scalars(
            select(FirewallSimulationObservation)
            .where(
                FirewallSimulationObservation.job_id == job.id,
                FirewallSimulationObservation.team_id == principal.team.id,
            )
            .order_by(FirewallSimulationObservation.created_at)
        )
    )
    return FirewallSimulationResultResponse(
        job=JobResponse.model_validate(job),
        observations=[
            FirewallSimulationObservationResponse.model_validate(item) for item in observations
        ],
    )


@router.get("/jobs/{job_id}/firewall-simulation-report")
def get_firewall_simulation_report(
    job_id: UUID,
    principal: Annotated[Principal, Depends(require_permission(Permission.VIEW))],
    session: Annotated[Session, Depends(get_session)],
    format: Annotated[str, Query(pattern=r"^(json|text)$")] = "json",
) -> Response:
    result = get_firewall_simulation_results(job_id, principal, session)
    if format == "json":
        return Response(content=result.model_dump_json(indent=2), media_type="application/json")
    lines = [
        f"Stoá firewall simulation report: {result.job.target}",
        f"Job: {result.job.id}",
        f"State: {result.job.state}",
        "",
        "ACTION   MATCHED RULE                 PACKET",
    ]
    for item in result.observations:
        packet = item.packet
        lines.append(
            f"{item.action:<8} {(item.matched_rule or 'default'):<28} "
            f"{packet.protocol} {packet.source}:{packet.source_port or '-'} -> "
            f"{packet.destination}:{packet.destination_port or '-'}"
        )
        lines.append(f"  {item.explanation}")
    return Response(content="\n".join(lines) + "\n", media_type="text/plain")


def _endpoint_monitoring_job(session: Session, principal: Principal, job_id: UUID) -> Job:
    job = session.scalar(select(Job).where(Job.id == job_id, Job.team_id == principal.team.id))
    if job is None or job.module_id != "endpoint-monitoring":
        raise HTTPException(status_code=404, detail="endpoint monitoring job not found")
    return job


@router.post(
    "/jobs/{job_id}/endpoint-monitoring-results",
    response_model=EndpointMonitoringResultResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_endpoint_monitoring_results(
    job_id: UUID,
    payload: EndpointMonitoringResultCreate,
    principal: Annotated[Principal, Depends(require_permission(Permission.RUN_JOBS))],
    session: Annotated[Session, Depends(get_session)],
) -> EndpointMonitoringResultResponse:
    job = _endpoint_monitoring_job(session, principal, job_id)
    if payload.executing_endpoint_id != job.executing_endpoint_id:
        raise HTTPException(status_code=403, detail="endpoint mismatch")
    if job.state not in {JobState.QUEUED, JobState.RUNNING, JobState.CANCELLING}:
        raise HTTPException(status_code=409, detail="job is already final")
    observations = [
        EndpointMonitoringObservation(
            team_id=principal.team.id,
            job_id=job.id,
            baseline_id=payload.baseline_id,
            **item.model_dump(),
        )
        for item in payload.observations
    ]
    session.add_all(observations)
    alerts_created = 0
    for item in payload.observations:
        if item.severity not in {"medium", "high"}:
            continue
        finding = Finding(
            team_id=principal.team.id,
            job_id=job.id,
            title=item.title,
            summary=f"{item.subject}: {item.explanation}",
            severity=Severity(item.severity),
            confidence=item.confidence,
            remediation=(
                "Validate the process or file change and renew the baseline only if approved."
            ),
        )
        session.add(finding)
        session.flush()
        deduplication_key = hashlib.sha256(
            f"{item.rule_id}|{job.executing_endpoint_id}|{item.subject}".encode()
        ).hexdigest()
        if (
            session.scalar(
                select(Alert).where(
                    Alert.team_id == principal.team.id,
                    Alert.deduplication_key == deduplication_key,
                )
            )
            is None
        ):
            session.add(
                Alert(
                    team_id=principal.team.id,
                    finding_id=finding.id,
                    title=item.title,
                    severity=Severity(item.severity),
                    confidence=item.confidence,
                    deduplication_key=deduplication_key,
                )
            )
            alerts_created += 1
    job.state = JobState.CANCELLED if payload.cancelled else JobState.SUCCEEDED
    record_audit_event(
        session,
        team_id=principal.team.id,
        actor_user_id=principal.user.id,
        action="endpoint_monitoring.results_recorded",
        resource_type="job",
        resource_id=str(job.id),
        correlation_id=job.correlation_id,
        event_data={
            "baseline_id": payload.baseline_id,
            "observation_count": len(observations),
            "alerts_created": alerts_created,
            "cancelled": payload.cancelled,
        },
    )
    session.commit()
    return EndpointMonitoringResultResponse(
        job=JobResponse.model_validate(job),
        baseline_id=payload.baseline_id,
        observations=[
            EndpointMonitoringObservationResponse.model_validate(item) for item in observations
        ],
    )


@router.get(
    "/jobs/{job_id}/endpoint-monitoring-results",
    response_model=EndpointMonitoringResultResponse,
)
def get_endpoint_monitoring_results(
    job_id: UUID,
    principal: Annotated[Principal, Depends(require_permission(Permission.VIEW))],
    session: Annotated[Session, Depends(get_session)],
) -> EndpointMonitoringResultResponse:
    job = _endpoint_monitoring_job(session, principal, job_id)
    observations = list(
        session.scalars(
            select(EndpointMonitoringObservation)
            .where(
                EndpointMonitoringObservation.job_id == job.id,
                EndpointMonitoringObservation.team_id == principal.team.id,
            )
            .order_by(EndpointMonitoringObservation.created_at)
        )
    )
    return EndpointMonitoringResultResponse(
        job=JobResponse.model_validate(job),
        baseline_id=observations[0].baseline_id if observations else None,
        observations=[
            EndpointMonitoringObservationResponse.model_validate(item) for item in observations
        ],
    )


@router.get("/jobs/{job_id}/endpoint-monitoring-report")
def get_endpoint_monitoring_report(
    job_id: UUID,
    principal: Annotated[Principal, Depends(require_permission(Permission.VIEW))],
    session: Annotated[Session, Depends(get_session)],
    format: Annotated[str, Query(pattern=r"^(json|text)$")] = "json",
) -> Response:
    result = get_endpoint_monitoring_results(job_id, principal, session)
    if format == "json":
        return Response(content=result.model_dump_json(indent=2), media_type="application/json")
    lines = [
        f"Stoá endpoint monitoring report: {result.job.target}",
        f"Baseline: {result.baseline_id or 'not recorded'}",
        "",
    ]
    for item in result.observations:
        lines.append(f"{item.severity.upper():<7} {item.rule_id:<24} {item.subject}")
        lines.append(f"  {item.explanation}")
    return Response(content="\n".join(lines) + "\n", media_type="text/plain")


@router.post("/jobs/{job_id}/packet-analysis-results", status_code=status.HTTP_201_CREATED)
def create_packet_analysis_results(
    job_id: UUID,
    payload: PacketAnalysisResultCreate,
    principal: Annotated[Principal, Depends(require_permission(Permission.RUN_JOBS))],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, int | str]:
    job = session.scalar(
        select(Job).where(
            Job.id == job_id,
            Job.team_id == principal.team.id,
            Job.module_id == "packet-analysis",
        )
    )
    if job is None:
        raise HTTPException(status_code=404, detail="packet analysis job not found")
    if payload.executing_endpoint_id != job.executing_endpoint_id:
        raise HTTPException(status_code=403, detail="endpoint mismatch")
    if job.state not in {JobState.QUEUED, JobState.RUNNING, JobState.CANCELLING}:
        raise HTTPException(status_code=409, detail="job is already final")

    alerts_created = 0
    for indicator in payload.indicators:
        evidence = json.dumps(indicator.evidence, sort_keys=True, separators=(",", ":"))
        finding = Finding(
            team_id=principal.team.id,
            job_id=job.id,
            title=indicator.title,
            summary=f"{indicator.explanation} Evidence: {evidence}",
            severity=Severity(indicator.severity),
            confidence=indicator.confidence,
            remediation=(
                "Review the affected systems and corroborate with endpoint and network logs."
            ),
        )
        session.add(finding)
        session.flush()
        deduplication_key = hashlib.sha256(
            f"{indicator.rule_id}|{indicator.source}|{indicator.destination}".encode()
        ).hexdigest()
        existing = session.scalar(
            select(Alert).where(
                Alert.team_id == principal.team.id,
                Alert.deduplication_key == deduplication_key,
            )
        )
        if existing is None:
            session.add(
                Alert(
                    team_id=principal.team.id,
                    finding_id=finding.id,
                    title=indicator.title,
                    severity=Severity(indicator.severity),
                    confidence=indicator.confidence,
                    deduplication_key=deduplication_key,
                )
            )
            alerts_created += 1
    job.state = JobState.CANCELLED if payload.cancelled else JobState.SUCCEEDED
    record_audit_event(
        session,
        team_id=principal.team.id,
        actor_user_id=principal.user.id,
        action="packet_analysis.results_recorded",
        resource_type="job",
        resource_id=str(job.id),
        correlation_id=job.correlation_id,
        event_data={
            "packet_count": payload.packet_count,
            "byte_count": payload.byte_count,
            "protocols": payload.protocols,
            "indicator_count": len(payload.indicators),
            "cancelled": payload.cancelled,
        },
    )
    session.commit()
    return {
        "job_id": str(job.id),
        "state": job.state.value,
        "alerts_created": alerts_created,
    }


@router.get("/alerts", response_model=list[AlertResponse])
def list_alerts(
    principal: Annotated[Principal, Depends(require_permission(Permission.VIEW))],
    session: Annotated[Session, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[Alert]:
    return list(
        session.scalars(
            select(Alert)
            .where(Alert.team_id == principal.team.id)
            .order_by(Alert.created_at.desc())
            .limit(limit)
        )
    )


@router.get("/audit-events", response_model=AuditEventPage)
def list_audit_events(
    principal: Annotated[Principal, Depends(require_permission(Permission.VIEW_AUDIT))],
    session: Annotated[Session, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditEventPage:
    events = list(
        session.scalars(
            select(AuditEvent)
            .where(AuditEvent.team_id == principal.team.id)
            .order_by(AuditEvent.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
    )
    return AuditEventPage(
        items=[AuditEventResponse.model_validate(event) for event in events],
        page=PageInfo(limit=limit, offset=offset, returned=len(events)),
    )


@router.post("/client-events", status_code=status.HTTP_202_ACCEPTED)
def accept_client_event(
    payload: ClientEventCreate,
    principal: Annotated[Principal, Depends(require_permission(Permission.VIEW))],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, bool]:
    """Accept bounded operational metadata queued by disconnected desktops."""

    record_audit_event(
        session,
        team_id=principal.team.id,
        actor_user_id=principal.user.id,
        action=f"client.{payload.event_type}",
        resource_type="desktop_event",
        resource_id=None,
        event_data=payload.payload,
    )
    session.commit()
    return {"accepted": True}
