"""Server-side role and permission enforcement."""

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from stoa_server.database import get_session
from stoa_server.models import Role, RoleName, Team, TeamMembership, User
from stoa_server.security import TokenValidationError, decode_access_token
from stoa_shared.settings import Settings, get_settings


class Permission(StrEnum):
    MANAGE_TEAM = "manage_team"
    MANAGE_ENDPOINTS = "manage_endpoints"
    MANAGE_SCOPES = "manage_scopes"
    CONFIGURE_POLICIES = "configure_policies"
    VIEW_AUDIT = "view_audit"
    RUN_JOBS = "run_jobs"
    INVESTIGATE = "investigate"
    GENERATE_REPORTS = "generate_reports"
    USE_CHAT = "use_chat"
    VIEW = "view"


ROLE_PERMISSIONS: dict[RoleName, frozenset[Permission]] = {
    RoleName.ADMINISTRATOR: frozenset(Permission),
    RoleName.ANALYST: frozenset(
        {
            Permission.RUN_JOBS,
            Permission.INVESTIGATE,
            Permission.GENERATE_REPORTS,
            Permission.USE_CHAT,
            Permission.VIEW,
        }
    ),
    RoleName.VIEWER: frozenset({Permission.VIEW}),
}


@dataclass(frozen=True, slots=True)
class Principal:
    user: User
    team: Team
    role: RoleName


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


def get_current_principal(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Principal:
    """Load current membership on every request so revocations take effect immediately."""

    try:
        user_id, team_id = decode_access_token(token, settings)
    except TokenValidationError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error

    row = session.execute(
        select(User, Team, Role.name)
        .join(TeamMembership, TeamMembership.user_id == User.id)
        .join(Team, Team.id == TeamMembership.team_id)
        .join(Role, Role.id == TeamMembership.role_id)
        .where(User.id == user_id, Team.id == team_id, User.is_active.is_(True))
    ).one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="membership unavailable"
        )
    user, team, role = row
    return Principal(user=user, team=team, role=role)


def require_permission(permission: Permission) -> Callable[[Principal], Principal]:
    """Build a dependency that enforces one permission on the server."""

    def dependency(
        principal: Annotated[Principal, Depends(get_current_principal)],
    ) -> Principal:
        if permission not in ROLE_PERMISSIONS[principal.role]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="permission denied")
        return principal

    return dependency
