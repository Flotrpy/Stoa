"""Versioned API schemas for identity and central metadata."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)


def normalize_email(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) > 320 or "@" not in normalized or normalized.startswith("@"):
        raise ValueError("a valid email address is required")
    return normalized


class BootstrapRequest(ApiModel):
    team_name: str = Field(min_length=2, max_length=120)
    team_slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,78}[a-z0-9]$")
    email: str
    display_name: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=12, max_length=256)

    _email = field_validator("email")(normalize_email)


class LoginRequest(ApiModel):
    email: str
    password: str = Field(min_length=1, max_length=256)
    team_id: UUID | None = None

    _email = field_validator("email")(normalize_email)


class TokenResponse(ApiModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token type, not a credential
    expires_in: int


class TeamResponse(ApiModel):
    id: UUID
    name: str
    slug: str
    created_at: datetime


class UserResponse(ApiModel):
    id: UUID
    email: str
    display_name: str
    is_active: bool
    created_at: datetime


class PrincipalResponse(ApiModel):
    user: UserResponse
    team: TeamResponse
    role: str


class MemberCreate(ApiModel):
    email: str
    display_name: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=12, max_length=256)
    role: str

    _email = field_validator("email")(normalize_email)


class MembershipResponse(ApiModel):
    user: UserResponse
    role: str


class EndpointCreate(ApiModel):
    name: str = Field(min_length=1, max_length=160)
    platform: str = Field(pattern=r"^(windows|linux)$")


class EndpointResponse(ApiModel):
    id: UUID
    team_id: UUID
    name: str
    platform: str
    state: str
    last_seen_at: datetime | None
    created_at: datetime


class AuthorizationScopeCreate(ApiModel):
    name: str = Field(min_length=2, max_length=160)
    target_pattern: str = Field(min_length=1, max_length=512)
    allowed_modules: list[str] = Field(min_length=1, max_length=20)
    rate_policy: dict[str, Any]
    valid_from: datetime
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def expiration_has_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("expires_at must include a timezone")
        return value


class AuthorizationScopeResponse(ApiModel):
    id: UUID
    team_id: UUID
    owner_user_id: UUID
    name: str
    target_pattern: str
    allowed_modules: list[str]
    rate_policy: dict[str, Any]
    valid_from: datetime
    expires_at: datetime
    is_active: bool


class ModulePolicyUpsert(ApiModel):
    enabled: bool
    configuration: dict[str, Any] = Field(default_factory=dict)


class PortScanPolicyConfiguration(ApiModel):
    max_ports: int = Field(default=1024, ge=1, le=1024)
    max_concurrency: int = Field(default=64, ge=1, le=256)
    allow_banner_collection: bool = True
    allow_syn: bool = False


class PacketAnalysisPolicyConfiguration(ApiModel):
    maximum_packets: int = Field(default=100_000, ge=1, le=1_000_000)
    maximum_file_bytes: int = Field(default=50_000_000, ge=1_000, le=2_000_000_000)
    retained_files: int = Field(default=5, ge=1, le=100)
    allow_live_capture: bool = True


class WebScanPolicyConfiguration(ApiModel):
    max_depth: int = Field(default=3, ge=0, le=5)
    max_pages: int = Field(default=100, ge=1, le=500)
    max_requests_per_second: int = Field(default=10, ge=1, le=50)
    allow_active_checks: bool = False
    allow_form_submission: bool = False
    allow_zap_import: bool = False


class FirewallSimulatorPolicyConfiguration(ApiModel):
    max_rules: int = Field(default=250, ge=1, le=1000)
    max_packets: int = Field(default=500, ge=1, le=5000)


class EndpointMonitoringPolicyConfiguration(ApiModel):
    max_files: int = Field(default=50_000, ge=1, le=500_000)
    maximum_file_bytes: int = Field(default=100_000_000, ge=1_000, le=2_000_000_000)
    allow_process_inspection: bool = True


class ModulePolicyResponse(ApiModel):
    id: UUID
    team_id: UUID
    module_id: str
    enabled: bool
    configuration: dict[str, Any]
    updated_by_user_id: UUID
    updated_at: datetime


class JobCreate(ApiModel):
    module_id: str = Field(min_length=1, max_length=80)
    executing_endpoint_id: UUID
    authorization_scope_id: UUID
    asset_id: UUID | None = None
    target: str = Field(min_length=1, max_length=512)
    business_justification: str = Field(min_length=10, max_length=2000)
    configuration: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_module_configuration(self) -> "JobCreate":
        if self.module_id == "port-scanner":
            PortScanJobConfiguration.model_validate(self.configuration)
        if self.module_id == "packet-analysis":
            PacketCaptureJobConfiguration.model_validate(self.configuration)
        if self.module_id == "web-scanner":
            WebScanJobConfiguration.model_validate(self.configuration)
        if self.module_id == "firewall-simulator":
            FirewallSimulationJobConfiguration.model_validate(self.configuration)
        if self.module_id == "endpoint-monitoring":
            EndpointMonitoringJobConfiguration.model_validate(self.configuration)
        return self


class JobResponse(ApiModel):
    id: UUID
    team_id: UUID
    module_id: str
    requesting_user_id: UUID
    executing_endpoint_id: UUID
    authorization_scope_id: UUID
    asset_id: UUID | None
    target: str
    business_justification: str
    rate_policy: dict[str, Any]
    configuration: dict[str, Any]
    state: str
    correlation_id: UUID
    created_at: datetime


class PortScanJobConfiguration(ApiModel):
    ports: list[int] = Field(min_length=1, max_length=1024)
    method: str = Field(default="tcp-connect", pattern=r"^(tcp-connect|syn)$")
    timeout_seconds: float = Field(default=1.0, ge=0.05, le=10)
    concurrency: int = Field(default=64, ge=1, le=256)
    max_attempts_per_second: int = Field(default=100, ge=1, le=500)
    collect_banners: bool = True

    @field_validator("ports")
    @classmethod
    def ports_are_unique_sorted(cls, value: list[int]) -> list[int]:
        if any(port < 1 or port > 65535 for port in value):
            raise ValueError("ports must be between 1 and 65535")
        if value != sorted(set(value)):
            raise ValueError("ports must be unique and sorted")
        return value


class PortObservationCreate(ApiModel):
    port: int = Field(ge=1, le=65535)
    state: str = Field(pattern=r"^(open|closed|filtered|unreachable)$")
    service: str | None = Field(default=None, max_length=80)
    banner: str | None = Field(default=None, max_length=256)
    latency_ms: float | None = Field(default=None, ge=0, le=600_000)

    @field_validator("banner")
    @classmethod
    def banner_is_printable(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = "".join(character if character.isprintable() else " " for character in value)
        return " ".join(cleaned.split()) or None


class PortScanResultCreate(ApiModel):
    executing_endpoint_id: UUID
    observations: list[PortObservationCreate] = Field(max_length=1024)
    cancelled: bool = False

    @model_validator(mode="after")
    def completed_result_is_not_empty(self) -> "PortScanResultCreate":
        if not self.cancelled and not self.observations:
            raise ValueError("a completed scan requires observations")
        return self

    @field_validator("observations")
    @classmethod
    def observation_ports_are_unique(
        cls, value: list[PortObservationCreate]
    ) -> list[PortObservationCreate]:
        ports = [item.port for item in value]
        if len(ports) != len(set(ports)):
            raise ValueError("observation ports must be unique")
        return value


class PortScanObservationResponse(PortObservationCreate):
    id: UUID
    job_id: UUID
    created_at: datetime


class PortScanResultResponse(ApiModel):
    job: JobResponse
    observations: list[PortScanObservationResponse]


class PacketCaptureJobConfiguration(ApiModel):
    interface: str = Field(min_length=1, max_length=512)
    protocols: list[str] = Field(min_length=1, max_length=8)
    packet_limit: int = Field(default=100_000, ge=1, le=1_000_000)
    maximum_file_bytes: int = Field(default=50_000_000, ge=1_000, le=2_000_000_000)
    retained_files: int = Field(default=5, ge=1, le=100)
    replay_only: bool = False

    @field_validator("protocols")
    @classmethod
    def protocols_are_supported(cls, value: list[str]) -> list[str]:
        supported = {"tcp", "udp", "icmp", "arp", "dns", "http", "tls", "other"}
        if len(value) != len(set(value)) or not set(value) <= supported:
            raise ValueError("protocols must be unique supported values")
        return value


class PacketIndicatorCreate(ApiModel):
    rule_id: str = Field(pattern=r"^STOA-NET-[0-9]{3}$")
    title: str = Field(min_length=1, max_length=240)
    severity: str = Field(pattern=r"^(info|low|medium|high)$")
    confidence: float = Field(ge=0, le=1)
    explanation: str = Field(min_length=1, max_length=2000)
    source: str | None = Field(default=None, max_length=253)
    destination: str | None = Field(default=None, max_length=253)
    evidence: dict[str, str | int | float] = Field(default_factory=dict)

    @field_validator("evidence")
    @classmethod
    def evidence_is_bounded(
        cls, value: dict[str, str | int | float]
    ) -> dict[str, str | int | float]:
        forbidden = {"payload", "packet_payload", "token", "secret", "password", "hash"}
        if (
            len(value) > 20
            or any(key.casefold() in forbidden for key in value)
            or any(len(str(item)) > 512 for item in value.values())
        ):
            raise ValueError("indicator evidence is too large")
        return value


class PacketAnalysisResultCreate(ApiModel):
    executing_endpoint_id: UUID
    packet_count: int = Field(ge=0, le=1_000_000)
    byte_count: int = Field(ge=0, le=100_000_000_000)
    protocols: dict[str, int]
    indicators: list[PacketIndicatorCreate] = Field(max_length=10_000)
    cancelled: bool = False

    @field_validator("protocols")
    @classmethod
    def protocol_counts_are_bounded(cls, value: dict[str, int]) -> dict[str, int]:
        supported = {"tcp", "udp", "icmp", "arp", "dns", "http", "tls", "other"}
        if not set(value) <= supported or any(count < 0 for count in value.values()):
            raise ValueError("protocol counts contain unsupported values")
        return value


class WebScanJobConfiguration(ApiModel):
    max_depth: int = Field(default=2, ge=0, le=5)
    max_pages: int = Field(default=25, ge=1, le=500)
    max_requests_per_second: int = Field(default=5, ge=1, le=50)
    timeout_seconds: float = Field(default=5.0, ge=0.1, le=15)
    active_checks: bool = False
    allow_form_submission: bool = False
    import_zap_alerts: bool = False


class WebFindingCreate(ApiModel):
    rule_id: str = Field(pattern=r"^STOA-WEB-(?:[0-9]{3}|ZAP)$")
    title: str = Field(min_length=1, max_length=240)
    category: str = Field(default="web", min_length=1, max_length=80)
    severity: str = Field(pattern=r"^(info|low|medium|high)$")
    confidence: float = Field(ge=0, le=1)
    url: str = Field(min_length=1, max_length=512)
    evidence: dict[str, str | int | float] = Field(default_factory=dict)
    remediation: str = Field(min_length=1, max_length=2000)

    @field_validator("evidence")
    @classmethod
    def evidence_is_bounded(
        cls, value: dict[str, str | int | float]
    ) -> dict[str, str | int | float]:
        forbidden = {"payload", "body", "cookie", "token", "secret", "password", "hash"}
        if (
            len(value) > 20
            or any(key.casefold() in forbidden for key in value)
            or any(len(str(item)) > 512 for item in value.values())
        ):
            raise ValueError("web evidence is too large or sensitive")
        return value


class WebScanResultCreate(ApiModel):
    executing_endpoint_id: UUID
    page_count: int = Field(ge=0, le=500)
    findings: list[WebFindingCreate] = Field(max_length=10_000)
    cancelled: bool = False


class WebFindingResponse(WebFindingCreate):
    id: UUID
    job_id: UUID
    created_at: datetime


class WebScanResultResponse(ApiModel):
    job: JobResponse
    findings: list[WebFindingResponse]


class FirewallPortRangeModel(ApiModel):
    start: int = Field(ge=1, le=65535)
    end: int = Field(ge=1, le=65535)

    @model_validator(mode="after")
    def range_is_ordered(self) -> "FirewallPortRangeModel":
        if self.start > self.end:
            raise ValueError("port range must be ordered")
        return self


class FirewallRuleModel(ApiModel):
    order: int = Field(ge=1, le=10_000)
    name: str = Field(min_length=1, max_length=160)
    direction: str = Field(pattern=r"^(inbound|outbound)$")
    action: str = Field(pattern=r"^(allow|block)$")
    protocol: str = Field(default="any", pattern=r"^(tcp|udp|icmp|any)$")
    source: str = Field(default="0.0.0.0/0", min_length=1, max_length=64)
    destination: str = Field(default="0.0.0.0/0", min_length=1, max_length=64)
    source_ports: list[FirewallPortRangeModel] = Field(default_factory=list, max_length=50)
    destination_ports: list[FirewallPortRangeModel] = Field(default_factory=list, max_length=50)
    enabled: bool = True


class FirewallPacketModel(ApiModel):
    direction: str = Field(pattern=r"^(inbound|outbound)$")
    protocol: str = Field(pattern=r"^(tcp|udp|icmp)$")
    source: str = Field(min_length=1, max_length=64)
    destination: str = Field(min_length=1, max_length=64)
    source_port: int | None = Field(default=None, ge=1, le=65535)
    destination_port: int | None = Field(default=None, ge=1, le=65535)


class FirewallSimulationJobConfiguration(ApiModel):
    default_action: str = Field(default="block", pattern=r"^(allow|block)$")
    rules: list[FirewallRuleModel] = Field(min_length=1, max_length=1000)
    packets: list[FirewallPacketModel] = Field(default_factory=list, max_length=5000)
    generate_test_packets: bool = True


class FirewallPolicyAnalysisModel(ApiModel):
    shadowed_rules: list[dict[str, str | int]]
    conflicting_rules: list[dict[str, str | int]]


class FirewallSimulationObservationCreate(ApiModel):
    packet: FirewallPacketModel
    action: str = Field(pattern=r"^(allow|block)$")
    matched_rule: str | None = Field(default=None, max_length=160)
    explanation: str = Field(min_length=1, max_length=2000)


class FirewallSimulationResultCreate(ApiModel):
    executing_endpoint_id: UUID
    analysis: FirewallPolicyAnalysisModel
    observations: list[FirewallSimulationObservationCreate] = Field(max_length=5000)
    cancelled: bool = False


class FirewallSimulationObservationResponse(FirewallSimulationObservationCreate):
    id: UUID
    job_id: UUID
    created_at: datetime


class FirewallSimulationResultResponse(ApiModel):
    job: JobResponse
    analysis: FirewallPolicyAnalysisModel | None = None
    observations: list[FirewallSimulationObservationResponse]


class EndpointMonitoringJobConfiguration(ApiModel):
    root: str = Field(min_length=1, max_length=1024)
    recursive: bool = True
    include: list[str] = Field(default_factory=lambda: ["*"], min_length=1, max_length=50)
    exclude: list[str] = Field(default_factory=list, max_length=100)
    maximum_file_bytes: int = Field(default=100_000_000, ge=1_000, le=2_000_000_000)
    inspect_processes: bool = True


class EndpointMonitoringObservationCreate(ApiModel):
    observation_type: str = Field(pattern=r"^(integrity|process-indicator)$")
    rule_id: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=240)
    severity: str = Field(pattern=r"^(info|low|medium|high)$")
    confidence: float = Field(ge=0, le=1)
    subject: str = Field(min_length=1, max_length=1024)
    explanation: str = Field(min_length=1, max_length=2000)
    evidence: dict[str, str | int | float] = Field(default_factory=dict)
    chain_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    @field_validator("evidence")
    @classmethod
    def endpoint_evidence_is_bounded(
        cls, value: dict[str, str | int | float]
    ) -> dict[str, str | int | float]:
        forbidden = {"keystrokes", "content", "password", "token", "secret"}
        if len(value) > 20 or any(key.casefold() in forbidden for key in value):
            raise ValueError("endpoint evidence is too large or sensitive")
        return value


class EndpointMonitoringResultCreate(ApiModel):
    executing_endpoint_id: UUID
    baseline_id: str = Field(min_length=1, max_length=128)
    observations: list[EndpointMonitoringObservationCreate] = Field(max_length=10_000)
    cancelled: bool = False


class EndpointMonitoringObservationResponse(EndpointMonitoringObservationCreate):
    id: UUID
    job_id: UUID
    created_at: datetime


class EndpointMonitoringResultResponse(ApiModel):
    job: JobResponse
    baseline_id: str | None = None
    observations: list[EndpointMonitoringObservationResponse]


class AlertResponse(ApiModel):
    id: UUID
    finding_id: UUID | None
    title: str
    severity: str
    confidence: float
    state: str
    deduplication_key: str
    created_at: datetime


class ClientEventCreate(ApiModel):
    event_type: str = Field(pattern=r"^(endpoint\.status|job\.progress|desktop\.diagnostic)$")
    payload: dict[str, str | int | float | bool | None]

    @field_validator("payload")
    @classmethod
    def payload_is_safe_metadata(
        cls, value: dict[str, str | int | float | bool | None]
    ) -> dict[str, str | int | float | bool | None]:
        forbidden = {"password", "token", "secret", "hash", "payload", "ciphertext"}
        if len(value) > 30 or any(key.casefold() in forbidden for key in value):
            raise ValueError("payload must contain bounded non-sensitive metadata")
        return value


class ChatDeviceCreate(ApiModel):
    name: str = Field(min_length=1, max_length=160)
    identity_public_key: str = Field(min_length=40, max_length=2000)


class ChatDeviceResponse(ApiModel):
    id: UUID
    user_id: UUID
    name: str
    identity_public_key: str
    verified_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class EncryptedEnvelopeCreate(ApiModel):
    sender_device_id: UUID
    recipient_device_id: UUID
    message_id: UUID
    ciphertext: str = Field(min_length=1, max_length=100_000)
    nonce: str = Field(min_length=16, max_length=128)
    protocol_version: str = Field(pattern=r"^stoa-chat-v1$")


class EncryptedEnvelopeResponse(EncryptedEnvelopeCreate):
    id: UUID
    created_at: datetime
    delivered_at: datetime | None


class AuditEventResponse(ApiModel):
    id: UUID
    actor_user_id: UUID | None
    action: str
    resource_type: str
    resource_id: str | None
    correlation_id: UUID
    event_data: dict[str, Any]
    previous_hash: str | None
    event_hash: str
    created_at: datetime


class PageInfo(ApiModel):
    limit: int
    offset: int
    returned: int


class AuditEventPage(ApiModel):
    items: list[AuditEventResponse]
    page: PageInfo
