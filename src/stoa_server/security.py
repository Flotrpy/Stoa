"""Password hashing and short-lived signed access tokens."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import jwt
from jwt import InvalidTokenError
from pwdlib import PasswordHash

from stoa_shared.settings import Settings

_password_hash = PasswordHash.recommended()
_issuer = "stoa-api"
_algorithm = "HS256"


class TokenValidationError(ValueError):
    """Raised when an access token is absent, malformed, or expired."""


def hash_password(password: str) -> str:
    """Hash a password using pwdlib's maintained Argon2 recommendation."""

    return _password_hash.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password without exposing hash details to callers."""

    return _password_hash.verify(password, password_hash)


def create_access_token(user_id: UUID, team_id: UUID, settings: Settings) -> tuple[str, int]:
    """Create a scoped access token and return its lifetime in seconds."""

    now = datetime.now(UTC)
    lifetime = timedelta(minutes=settings.access_token_minutes)
    token = jwt.encode(
        {
            "sub": str(user_id),
            "team": str(team_id),
            "type": "access",
            "iss": _issuer,
            "iat": now,
            "exp": now + lifetime,
        },
        settings.auth_secret.get_secret_value(),
        algorithm=_algorithm,
    )
    return token, int(lifetime.total_seconds())


def decode_access_token(token: str, settings: Settings) -> tuple[UUID, UUID]:
    """Validate a token and return its user and team identifiers."""

    try:
        payload = jwt.decode(
            token,
            settings.auth_secret.get_secret_value(),
            algorithms=[_algorithm],
            issuer=_issuer,
            options={"require": ["sub", "team", "type", "exp", "iat", "iss"]},
        )
        if payload["type"] != "access":
            raise TokenValidationError("invalid token type")
        return UUID(payload["sub"]), UUID(payload["team"])
    except (InvalidTokenError, KeyError, TypeError, ValueError) as error:
        raise TokenValidationError("invalid or expired access token") from error
