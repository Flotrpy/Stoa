"""Versioned API schemas for identity and central metadata."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


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
