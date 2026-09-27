"""Bootstrap, authentication, and current-principal routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from stoa_server.audit import record_audit_event
from stoa_server.database import get_session
from stoa_server.models import Role, RoleName, Team, TeamMembership, User
from stoa_server.rbac import Principal, get_current_principal
from stoa_server.security import create_access_token, hash_password, verify_password
from stoa_shared.domain import (
    BootstrapRequest,
    LoginRequest,
    PrincipalResponse,
    TeamResponse,
    TokenResponse,
    UserResponse,
)
from stoa_shared.settings import Settings, get_settings

router = APIRouter(prefix="/auth", tags=["identity"])


def ensure_roles(session: Session) -> dict[RoleName, Role]:
    """Create the fixed role catalog exactly once."""

    existing = {role.name: role for role in session.scalars(select(Role)).all()}
    for name in RoleName:
        if name not in existing:
            role = Role(name=name)
            session.add(role)
            existing[name] = role
    session.flush()
    return existing


@router.post("/bootstrap", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def bootstrap(
    payload: BootstrapRequest,
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TokenResponse:
    """Create the first team and administrator on an empty deployment."""

    if session.scalar(select(func.count()).select_from(User)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="bootstrap is closed")
    roles = ensure_roles(session)
    team = Team(name=payload.team_name.strip(), slug=payload.team_slug)
    user = User(
        email=payload.email,
        display_name=payload.display_name.strip(),
        password_hash=hash_password(payload.password),
    )
    session.add_all([team, user])
    session.flush()
    session.add(
        TeamMembership(
            team_id=team.id,
            user_id=user.id,
            role_id=roles[RoleName.ADMINISTRATOR].id,
        )
    )
    record_audit_event(
        session,
        team_id=team.id,
        actor_user_id=user.id,
        action="deployment.bootstrapped",
        resource_type="team",
        resource_id=str(team.id),
        event_data={"team_slug": team.slug},
    )
    try:
        session.commit()
    except IntegrityError as error:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="bootstrap conflict"
        ) from error
    token, expires_in = create_access_token(user.id, team.id, settings)
    return TokenResponse(access_token=token, expires_in=expires_in)


@router.post("/token", response_model=TokenResponse)
def issue_token(
    payload: LoginRequest,
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TokenResponse:
    """Authenticate credentials and bind the token to one current team membership."""

    user = session.scalar(select(User).where(User.email == payload.email))
    if (
        user is None
        or not user.is_active
        or not verify_password(payload.password, user.password_hash)
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
    memberships = session.execute(
        select(TeamMembership.team_id).where(TeamMembership.user_id == user.id)
    ).scalars()
    team_ids = list(memberships)
    selected_team = payload.team_id or (team_ids[0] if len(team_ids) == 1 else None)
    if selected_team is None or selected_team not in team_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="a valid team_id is required",
        )
    token, expires_in = create_access_token(user.id, selected_team, settings)
    return TokenResponse(access_token=token, expires_in=expires_in)


@router.get("/me", response_model=PrincipalResponse)
def current_user(
    principal: Annotated[Principal, Depends(get_current_principal)],
) -> PrincipalResponse:
    return PrincipalResponse(
        user=UserResponse.model_validate(principal.user),
        team=TeamResponse.model_validate(principal.team),
        role=principal.role.value,
    )
