from fastapi.testclient import TestClient

from stoa_server.app import create_app


def test_health_contract() -> None:
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["service"] == "stoa-api"
    assert payload["version"] == "0.1.0"
    assert payload["timestamp"].endswith("Z")


def test_readiness_contract() -> None:
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "checks": {"application": "ready"}}


def test_unversioned_health_route_does_not_exist() -> None:
    with TestClient(create_app()) as client:
        response = client.get("/health")

    assert response.status_code == 404
