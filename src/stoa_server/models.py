"""Central metadata entities for identity, authorization, jobs, and audit."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from stoa_server.database import Base


def utc_now() -> datetime:
    return datetime.now(UTC)


class RoleName(StrEnum):
    ADMINISTRATOR = "administrator"
    ANALYST = "analyst"
    VIEWER = "viewer"


class EndpointState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REVOKED = "revoked"


class RecordState(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class JobState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    FAILED = "failed"
    SUCCEEDED = "succeeded"


class IdentityMixin:
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )


class Team(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "teams"

    name: Mapped[str] = mapped_column(String(120))
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)


class User(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(String(512))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class Role(IdentityMixin, Base):
    __tablename__ = "roles"

    name: Mapped[RoleName] = mapped_column(Enum(RoleName), unique=True)


class TeamMembership(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "team_memberships"
    __table_args__ = (Index("uq_membership_team_user", "team_id", "user_id", unique=True),)

    team_id: Mapped[UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"))
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    role_id: Mapped[UUID] = mapped_column(ForeignKey("roles.id"))


class Endpoint(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "endpoints"
    __table_args__ = (Index("ix_endpoint_team_state", "team_id", "state"),)

    team_id: Mapped[UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(160))
    platform: Mapped[str] = mapped_column(String(32))
    state: Mapped[EndpointState] = mapped_column(Enum(EndpointState), default=EndpointState.PENDING)
    enrollment_secret_hash: Mapped[str | None] = mapped_column(String(512), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Asset(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "assets"

    team_id: Mapped[UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"))
    endpoint_id: Mapped[UUID | None] = mapped_column(ForeignKey("endpoints.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(48))
    name: Mapped[str] = mapped_column(String(160))
    locator: Mapped[str] = mapped_column(String(512))


class AuthorizationScope(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "authorization_scopes"

    team_id: Mapped[UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"))
    owner_user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String(160))
    target_pattern: Mapped[str] = mapped_column(String(512))
    allowed_modules: Mapped[list[str]] = mapped_column(JSON, default=list)
    rate_policy: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class ModulePolicy(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "module_policies"
    __table_args__ = (Index("uq_policy_team_module", "team_id", "module_id", unique=True),)

    team_id: Mapped[UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"))
    module_id: Mapped[str] = mapped_column(String(80))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_by_user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"))


class Job(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "jobs"

    team_id: Mapped[UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"))
    module_id: Mapped[str] = mapped_column(String(80))
    requesting_user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    executing_endpoint_id: Mapped[UUID] = mapped_column(ForeignKey("endpoints.id"))
    authorization_scope_id: Mapped[UUID] = mapped_column(ForeignKey("authorization_scopes.id"))
    asset_id: Mapped[UUID | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    target: Mapped[str] = mapped_column(String(512))
    business_justification: Mapped[str] = mapped_column(Text)
    rate_policy: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    state: Mapped[JobState] = mapped_column(Enum(JobState), default=JobState.QUEUED)
    correlation_id: Mapped[UUID] = mapped_column(Uuid, unique=True, default=uuid4)


class JobProgress(IdentityMixin, Base):
    __tablename__ = "job_progress"

    job_id: Mapped[UUID] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"))
    percent: Mapped[float] = mapped_column(Float)
    message: Mapped[str] = mapped_column(String(500))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class PortScanObservation(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "port_scan_observations"
    __table_args__ = (Index("uq_port_scan_job_port", "job_id", "port", unique=True),)

    team_id: Mapped[UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"))
    job_id: Mapped[UUID] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"))
    port: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(24))
    service: Mapped[str | None] = mapped_column(String(80), nullable=True)
    banner: Mapped[str | None] = mapped_column(String(256), nullable=True)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)


class WebScanObservation(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "web_scan_observations"

    team_id: Mapped[UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"))
    job_id: Mapped[UUID] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"))
    rule_id: Mapped[str] = mapped_column(String(32))
    category: Mapped[str] = mapped_column(String(80))
    title: Mapped[str] = mapped_column(String(240))
    severity: Mapped[str] = mapped_column(String(24))
    confidence: Mapped[float] = mapped_column(Float)
    url: Mapped[str] = mapped_column(String(512))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    remediation: Mapped[str] = mapped_column(Text)


class Finding(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "findings"

    team_id: Mapped[UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"))
    job_id: Mapped[UUID] = mapped_column(ForeignKey("jobs.id"))
    title: Mapped[str] = mapped_column(String(240))
    summary: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    confidence: Mapped[float] = mapped_column(Float)
    remediation: Mapped[str] = mapped_column(Text)
    state: Mapped[RecordState] = mapped_column(Enum(RecordState), default=RecordState.OPEN)


class Alert(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "alerts"

    team_id: Mapped[UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"))
    finding_id: Mapped[UUID | None] = mapped_column(ForeignKey("findings.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(240))
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    confidence: Mapped[float] = mapped_column(Float)
    state: Mapped[RecordState] = mapped_column(Enum(RecordState), default=RecordState.OPEN)
    deduplication_key: Mapped[str] = mapped_column(String(256), index=True)


class EvidenceReference(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "evidence_references"

    team_id: Mapped[UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"))
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    storage_class: Mapped[str] = mapped_column(String(32), default="local")
    opaque_locator: Mapped[str] = mapped_column(String(512))
    sha256: Mapped[str] = mapped_column(String(64))
    redacted_summary: Mapped[str] = mapped_column(Text)


class Report(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "reports"

    team_id: Mapped[UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"))
    created_by_user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    title: Mapped[str] = mapped_column(String(240))
    format: Mapped[str] = mapped_column(String(24))
    storage_locator: Mapped[str | None] = mapped_column(String(512), nullable=True)


class AuditEvent(IdentityMixin, Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_team_created", "team_id", "created_at"),)

    team_id: Mapped[UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"))
    actor_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(160))
    resource_type: Mapped[str] = mapped_column(String(80))
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    correlation_id: Mapped[UUID] = mapped_column(Uuid, default=uuid4, index=True)
    event_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    previous_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ChatDevice(IdentityMixin, TimestampMixin, Base):
    __tablename__ = "chat_devices"

    team_id: Mapped[UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"))
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(160))
    identity_public_key: Mapped[str] = mapped_column(Text)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EncryptedEnvelope(IdentityMixin, Base):
    __tablename__ = "encrypted_envelopes"

    team_id: Mapped[UUID] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"))
    sender_device_id: Mapped[UUID] = mapped_column(ForeignKey("chat_devices.id"))
    recipient_device_id: Mapped[UUID] = mapped_column(ForeignKey("chat_devices.id"))
    message_id: Mapped[UUID] = mapped_column(Uuid, unique=True)
    ciphertext: Mapped[str] = mapped_column(Text)
    nonce: Mapped[str] = mapped_column(String(128))
    protocol_version: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
