"""Append-oriented, hash-chained audit recording."""

import hashlib
import json
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from stoa_server.models import AuditEvent, utc_now


def record_audit_event(
    session: Session,
    *,
    team_id: UUID,
    actor_user_id: UUID | None,
    action: str,
    resource_type: str,
    resource_id: str | None,
    event_data: dict[str, Any] | None = None,
    correlation_id: UUID | None = None,
) -> AuditEvent:
    """Append an event whose digest links to the previous team event."""

    previous = session.scalar(
        select(AuditEvent)
        .where(AuditEvent.team_id == team_id)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(1)
    )
    event = AuditEvent(
        team_id=team_id,
        actor_user_id=actor_user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        correlation_id=correlation_id or uuid4(),
        event_data=event_data or {},
        previous_hash=previous.event_hash if previous else None,
        event_hash="",
        created_at=utc_now(),
    )
    canonical = json.dumps(
        {
            "team_id": str(team_id),
            "actor_user_id": str(actor_user_id) if actor_user_id else None,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "correlation_id": str(event.correlation_id),
            "event_data": event.event_data,
            "previous_hash": event.previous_hash,
            "created_at": event.created_at.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    event.event_hash = hashlib.sha256(canonical.encode()).hexdigest()
    session.add(event)
    return event
