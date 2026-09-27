"""Team-scoped endpoint, authorization, policy, and audit routes."""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from stoa_server.audit import record_audit_event
from stoa_server.database import get_session
from stoa_server.job_authorization import JobAuthorizationError, authorize_job
from stoa_server.models import (
    AuditEvent,
    AuthorizationScope,
    Endpoint,
    EndpointState,
    Job,
    ModulePolicy,
    Role,
    RoleName,
    TeamMembership,
    User,
)
from stoa_server.rbac import Permission, Principal, require_permission
from stoa_server.routers.auth import ensure_roles
from stoa_server.security import hash_password
from stoa_shared.domain import (
    AuditEventPage,
    AuditEventResponse,
    AuthorizationScopeCreate,
    AuthorizationScopeResponse,
    ClientEventCreate,
    EndpointCreate,
    EndpointResponse,
    JobCreate,
    JobResponse,
    MemberCreate,
    MembershipResponse,
    ModulePolicyResponse,
    ModulePolicyUpsert,
    PageInfo,
    UserResponse,
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
    policy = session.scalar(
        select(ModulePolicy).where(
            ModulePolicy.team_id == principal.team.id, ModulePolicy.module_id == module_id
        )
    )
    if policy is None:
        policy = ModulePolicy(team_id=principal.team.id, module_id=module_id)
        session.add(policy)
    policy.enabled = payload.enabled
    policy.configuration = payload.configuration
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
        configuration=payload.configuration,
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
