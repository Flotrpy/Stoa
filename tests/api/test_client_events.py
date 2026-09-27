from fastapi.testclient import TestClient


def test_client_event_is_accepted_as_audit_metadata(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    response = client.post(
        "/api/v1/client-events",
        headers=admin_headers,
        json={"event_type": "endpoint.status", "payload": {"state": "ready"}},
    )

    assert response.status_code == 202
    assert response.json() == {"accepted": True}
    audit = client.get("/api/v1/audit-events", headers=admin_headers)
    assert audit.json()["items"][0]["action"] == "client.endpoint.status"


def test_client_event_rejects_sensitive_or_unknown_payloads(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    sensitive = client.post(
        "/api/v1/client-events",
        headers=admin_headers,
        json={"event_type": "desktop.diagnostic", "payload": {"token": "not-allowed"}},
    )
    unknown = client.post(
        "/api/v1/client-events",
        headers=admin_headers,
        json={"event_type": "arbitrary.event", "payload": {"state": "ready"}},
    )

    assert sensitive.status_code == 422
    assert unknown.status_code == 422
