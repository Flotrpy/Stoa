"""Fail-closed authorization checks for every active security job."""

from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from stoa_server.models import AuthorizationScope, Endpoint, EndpointState, ModulePolicy


class JobAuthorizationError(ValueError):
    """A user-safe reason an active job was rejected."""


@dataclass(frozen=True, slots=True)
class AuthorizedJobContext:
    endpoint: Endpoint
    scope: AuthorizationScope
    policy: ModulePolicy


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def target_matches_scope(target: str, pattern: str) -> bool:
    """Match exact hosts, IP networks, or exact-origin URL prefixes without wildcards."""

    normalized_target = target.strip()
    normalized_pattern = pattern.strip()
    try:
        network = ip_network(normalized_pattern, strict=False)
        candidate = urlsplit(normalized_target).hostname or normalized_target
        return ip_address(candidate) in network
    except ValueError:
        pass

    pattern_url = urlsplit(normalized_pattern)
    target_url = urlsplit(normalized_target)
    if pattern_url.scheme and pattern_url.hostname:
        return (
            pattern_url.scheme.lower() == target_url.scheme.lower()
            and pattern_url.hostname.lower() == (target_url.hostname or "").lower()
            and pattern_url.port == target_url.port
            and (target_url.path or "/").startswith(pattern_url.path or "/")
        )
    return normalized_target.casefold() == normalized_pattern.casefold()


def authorize_job(
    session: Session,
    *,
    team_id: UUID,
    endpoint_id: UUID,
    scope_id: UUID,
    module_id: str,
    target: str,
    now: datetime | None = None,
) -> AuthorizedJobContext:
    """Validate endpoint, scope, target, module, window, rate policy, and module policy."""

    endpoint = session.scalar(
        select(Endpoint).where(Endpoint.id == endpoint_id, Endpoint.team_id == team_id)
    )
    if endpoint is None or endpoint.state != EndpointState.APPROVED:
        raise JobAuthorizationError("executing endpoint is not approved")

    scope = session.scalar(
        select(AuthorizationScope).where(
            AuthorizationScope.id == scope_id, AuthorizationScope.team_id == team_id
        )
    )
    current = _as_utc(now or datetime.now(UTC))
    if scope is None or not scope.is_active:
        raise JobAuthorizationError("authorization scope is unavailable")
    if not _as_utc(scope.valid_from) <= current < _as_utc(scope.expires_at):
        raise JobAuthorizationError("authorization scope is not current")
    if module_id not in scope.allowed_modules:
        raise JobAuthorizationError("module is outside authorization scope")
    if not target_matches_scope(target, scope.target_pattern):
        raise JobAuthorizationError("target is outside authorization scope")

    maximum = scope.rate_policy.get("max_requests")
    window = scope.rate_policy.get("window_seconds")
    if not isinstance(maximum, int) or not 1 <= maximum <= 10_000:
        raise JobAuthorizationError("authorization rate policy is invalid")
    if not isinstance(window, int) or not 1 <= window <= 86_400:
        raise JobAuthorizationError("authorization rate policy is invalid")

    policy = session.scalar(
        select(ModulePolicy).where(
            ModulePolicy.team_id == team_id,
            ModulePolicy.module_id == module_id,
            ModulePolicy.enabled.is_(True),
        )
    )
    if policy is None:
        raise JobAuthorizationError("module policy is not enabled")
    return AuthorizedJobContext(endpoint=endpoint, scope=scope, policy=policy)
