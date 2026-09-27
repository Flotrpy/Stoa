from datetime import UTC, datetime, timedelta
from uuid import uuid4

from stoa_security.contracts import AuthorizationContext


def test_authorization_window_is_start_inclusive_and_end_exclusive() -> None:
    now = datetime.now(UTC)
    context = AuthorizationContext(
        scope_id=uuid4(),
        requesting_user_id=uuid4(),
        executing_endpoint_id=uuid4(),
        target="127.0.0.1",
        valid_from=now,
        expires_at=now + timedelta(minutes=5),
        business_justification="Local fixture verification",
        correlation_id=uuid4(),
    )

    assert context.is_current(now)
    assert context.is_current(now + timedelta(minutes=4))
    assert not context.is_current(now + timedelta(minutes=5))
