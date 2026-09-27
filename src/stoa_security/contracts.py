"""Authorization gate shared by future active security modules."""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    """Required authorization metadata for any active module operation."""

    scope_id: UUID
    requesting_user_id: UUID
    executing_endpoint_id: UUID
    target: str
    valid_from: datetime
    expires_at: datetime
    business_justification: str
    correlation_id: UUID

    def is_current(self, now: datetime) -> bool:
        """Return whether the authorization window includes ``now``."""

        return self.valid_from <= now < self.expires_at
