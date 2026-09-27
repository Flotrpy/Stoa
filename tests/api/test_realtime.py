import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect


def test_realtime_stream_requires_authentication(client: TestClient) -> None:
    with (
        pytest.raises(WebSocketDisconnect) as error,
        client.websocket_connect("/api/v1/events/ws"),
    ):
        pass
    assert error.value.code == 1008


def test_realtime_stream_is_team_bound(client: TestClient, admin_token: str) -> None:
    with client.websocket_connect(
        "/api/v1/events/ws", headers={"Authorization": f"Bearer {admin_token}"}
    ) as websocket:
        ready = websocket.receive_json()
        assert ready["type"] == "session.ready"
        assert ready["team_id"]
        assert ready["user_id"]
        websocket.send_json({"type": "ping"})
        assert websocket.receive_json() == {"type": "pong"}
