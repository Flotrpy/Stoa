"""Synchronize safe offline metadata after connectivity returns."""

from typing import Any, Protocol

from stoa_desktop.api_client import ApiClientError
from stoa_desktop.offline_queue import OfflineQueue


class EventClient(Protocol):
    def post(self, path: str, payload: dict[str, Any]) -> Any: ...


class OfflineSynchronizer:
    def __init__(self, client: EventClient, queue: OfflineQueue) -> None:
        self.client = client
        self.queue = queue

    def flush(self, limit: int = 100) -> int:
        synchronized = 0
        for event in self.queue.pending(limit):
            try:
                self.client.post(
                    "/api/v1/client-events",
                    {"event_type": event.event_type, "payload": event.payload},
                )
            except ApiClientError:
                self.queue.record_attempt(event.id)
                break
            self.queue.acknowledge(event.id)
            synchronized += 1
        return synchronized
