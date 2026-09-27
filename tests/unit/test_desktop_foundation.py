import asyncio
import json
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest

from stoa_desktop.api_client import ApiClient, ApiClientError, Connectivity
from stoa_desktop.config import ConfigStore, DesktopSettings
from stoa_desktop.enrollment import EnrollmentService
from stoa_desktop.offline_queue import OfflineQueue
from stoa_desktop.realtime import RealtimeClient
from stoa_desktop.secrets import SecureTokenStore
from stoa_desktop.sync import OfflineSynchronizer


class MemoryCredentials:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


def test_config_round_trip_is_non_secret_and_atomic(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    store = ConfigStore(path)
    endpoint_id = uuid4()
    team_id = uuid4()
    settings = DesktopSettings(
        api_url="https://stoa.example.test", theme="dark", endpoint_id=endpoint_id, team_id=team_id
    )

    store.save(settings)

    assert store.load() == settings
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["endpoint_id"] == str(endpoint_id)
    assert "token" not in payload


@pytest.mark.parametrize(
    ("api_url", "theme"),
    [("ftp://example.test", "light"), ("https://example.test", "system")],
)
def test_config_rejects_unsupported_values(api_url: str, theme: str) -> None:
    with pytest.raises(ValueError):
        DesktopSettings(api_url=api_url, theme=theme)


def test_secure_token_store_uses_supplied_vault() -> None:
    backend = MemoryCredentials()
    store = SecureTokenStore(backend)

    assert store.get() is None
    store.set("opaque-access-token")
    assert store.get() == "opaque-access-token"
    store.clear()
    assert store.get() is None
    with pytest.raises(ValueError):
        store.set("")


def test_offline_queue_orders_events_and_rejects_sensitive_data(tmp_path: Path) -> None:
    queue = OfflineQueue(tmp_path / "events.db")
    first = queue.enqueue("endpoint.status", {"endpoint_id": str(uuid4()), "state": "ready"})
    second = queue.enqueue("job.progress", {"job_id": str(uuid4()), "percent": 20})

    assert [event.id for event in queue.pending()] == [first.id, second.id]
    queue.record_attempt(first.id)
    assert queue.pending()[0].attempts == 1
    queue.acknowledge(first.id)
    assert [event.id for event in queue.pending()] == [second.id]
    with pytest.raises(ValueError, match="sensitive field"):
        queue.enqueue("unsafe", {"nested": [{"token": "must-not-persist"}]})
    with pytest.raises(ValueError, match="between"):
        queue.pending(0)


def test_api_client_connects_authenticates_and_maps_errors() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/health":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/api/v1/auth/token":
            return httpx.Response(200, json={"access_token": "opaque"})
        if request.url.path == "/api/v1/auth/me":
            assert request.headers["authorization"] == "Bearer opaque"
            return httpx.Response(200, json={"role": "administrator"})
        return httpx.Response(404)

    client = ApiClient("https://stoa.example.test", transport=httpx.MockTransport(handler))
    assert client.health() is Connectivity.AUTH_REQUIRED
    assert client.login("admin@example.test", "password") == "opaque"
    assert client.health() is Connectivity.CONNECTED
    assert client.get("/api/v1/auth/me") == {"role": "administrator"}


def test_api_client_reports_authentication_failure() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(401, request=request))
    client = ApiClient("https://stoa.example.test", transport=transport)

    with pytest.raises(ApiClientError, match="sign in failed"):
        client.login("admin@example.test", "wrong")
    with pytest.raises(ApiClientError, match="authentication required"):
        client.get("/api/v1/auth/me")


class EnrollmentClient:
    def __init__(self, endpoint_id: UUID, team_id: UUID) -> None:
        self.endpoint_id = endpoint_id
        self.team_id = team_id
        self.payload: dict[str, Any] | None = None

    def post(self, path: str, payload: dict[str, Any]) -> dict[str, str]:
        assert path == "/api/v1/endpoints"
        self.payload = payload
        return {"id": str(self.endpoint_id)}

    def get(self, path: str) -> dict[str, dict[str, str]]:
        assert path == "/api/v1/auth/me"
        return {"team": {"id": str(self.team_id)}}


def test_enrollment_persists_public_identifiers(tmp_path: Path) -> None:
    endpoint_id = uuid4()
    team_id = uuid4()
    client = EnrollmentClient(endpoint_id, team_id)
    store = ConfigStore(tmp_path / "settings.json")
    service = EnrollmentService(client, store)

    settings = service.enroll(DesktopSettings(), name="lab-workstation")

    assert settings.endpoint_id == endpoint_id
    assert settings.team_id == team_id
    assert client.payload is not None
    assert client.payload["name"] == "lab-workstation"
    assert store.load() == settings


def test_realtime_client_builds_transport_url_and_stops() -> None:
    secure = RealtimeClient("https://stoa.example.test/", "opaque")
    local = RealtimeClient("http://127.0.0.1:8787", "opaque")

    assert secure.url == "wss://stoa.example.test/api/v1/events/ws"
    assert local.url == "ws://127.0.0.1:8787/api/v1/events/ws"
    secure.stop()
    assert asyncio.run(secure._stop.wait()) is True


class SyncClient:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.payloads: list[dict[str, Any]] = []

    def post(self, path: str, payload: dict[str, Any]) -> dict[str, bool]:
        assert path == "/api/v1/client-events"
        if self.fail:
            raise ApiClientError("offline")
        self.payloads.append(payload)
        return {"accepted": True}


def test_offline_synchronizer_acknowledges_only_accepted_events(tmp_path: Path) -> None:
    queue = OfflineQueue(tmp_path / "sync.db")
    queue.enqueue("endpoint.status", {"state": "ready"})
    client = SyncClient()

    assert OfflineSynchronizer(client, queue).flush() == 1
    assert queue.pending() == []
    assert client.payloads[0]["event_type"] == "endpoint.status"

    event = queue.enqueue("desktop.diagnostic", {"state": "offline"})
    assert OfflineSynchronizer(SyncClient(fail=True), queue).flush() == 0
    assert queue.pending()[0].id == event.id
    assert queue.pending()[0].attempts == 1
