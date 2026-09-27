"""Endpoint enrollment through the central authorization plane."""

import platform
import socket
from dataclasses import replace
from typing import Any, Protocol
from uuid import UUID

from stoa_desktop.config import ConfigStore, DesktopSettings


class EnrollmentClient(Protocol):
    def post(self, path: str, payload: dict[str, Any]) -> Any: ...

    def get(self, path: str) -> Any: ...


class EnrollmentService:
    """Register this device and persist only its non-secret identifiers."""

    def __init__(self, client: EnrollmentClient, config_store: ConfigStore) -> None:
        self.client = client
        self.config_store = config_store

    def enroll(self, settings: DesktopSettings, name: str | None = None) -> DesktopSettings:
        system = platform.system().casefold()
        if system not in {"windows", "linux"}:
            raise ValueError("endpoint enrollment supports Windows and Linux")
        payload = self.client.post(
            "/api/v1/endpoints",
            {"name": (name or socket.gethostname()).strip(), "platform": system},
        )
        principal = self.client.get("/api/v1/auth/me")
        updated = replace(
            settings,
            endpoint_id=UUID(str(payload["id"])),
            team_id=UUID(str(principal["team"]["id"])),
        )
        self.config_store.save(updated)
        return updated
