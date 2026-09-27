"""Durable queue for non-sensitive events created during disconnection."""

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from platformdirs import user_data_path

_FORBIDDEN_KEYS = {
    "password",
    "token",
    "secret",
    "private_key",
    "hash",
    "wordlist",
    "pcap",
    "packet_payload",
    "ciphertext",
}


@dataclass(frozen=True, slots=True)
class QueuedEvent:
    id: UUID
    event_type: str
    payload: dict[str, Any]
    created_at: datetime
    attempts: int


class OfflineQueue:
    """SQLite queue that rejects sensitive evidence by field name."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or user_data_path("Stoa", "Flotrpy") / "offline-queue.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS queued_events (
                    id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0
                )
                """
            )

    def enqueue(self, event_type: str, payload: dict[str, Any]) -> QueuedEvent:
        self._validate_payload(payload)
        event = QueuedEvent(
            id=uuid4(),
            event_type=event_type,
            payload=payload,
            created_at=datetime.now(UTC),
            attempts=0,
        )
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO queued_events VALUES (?, ?, ?, ?, ?)",
                (
                    str(event.id),
                    event.event_type,
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                    event.created_at.isoformat(),
                    event.attempts,
                ),
            )
        return event

    def pending(self, limit: int = 100) -> list[QueuedEvent]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id, event_type, payload, created_at, attempts "
                "FROM queued_events ORDER BY created_at LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            QueuedEvent(
                id=UUID(row[0]),
                event_type=row[1],
                payload=json.loads(row[2]),
                created_at=datetime.fromisoformat(row[3]),
                attempts=row[4],
            )
            for row in rows
        ]

    def acknowledge(self, event_id: UUID) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM queued_events WHERE id = ?", (str(event_id),))

    def record_attempt(self, event_id: UUID) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE queued_events SET attempts = attempts + 1 WHERE id = ?",
                (str(event_id),),
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    @classmethod
    def _validate_payload(cls, value: object, path: str = "payload") -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if key.casefold() in _FORBIDDEN_KEYS:
                    raise ValueError(
                        f"sensitive field is not allowed in offline queue: {path}.{key}"
                    )
                cls._validate_payload(nested, f"{path}.{key}")
        elif isinstance(value, list):
            for index, nested in enumerate(value):
                cls._validate_payload(nested, f"{path}[{index}]")
