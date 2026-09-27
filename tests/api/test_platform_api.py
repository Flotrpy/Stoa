from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient


def test_scope_requires_bounded_rate_policy(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    now = datetime.now(UTC)
    base = {
        "name": "Local lab",
        "target_pattern": "127.0.0.0/8",
        "allowed_modules": ["port-scanner"],
        "valid_from": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
    }
    invalid = client.post(
        "/api/v1/authorization-scopes",
        headers=admin_headers,
        json={**base, "rate_policy": {"max_requests": 0, "window_seconds": 60}},
    )
    valid = client.post(
        "/api/v1/authorization-scopes",
        headers=admin_headers,
        json={**base, "rate_policy": {"max_requests": 100, "window_seconds": 60}},
    )

    assert invalid.status_code == 422
    assert valid.status_code == 201
    assert valid.json()["target_pattern"] == "127.0.0.0/8"


def test_policy_upsert_is_audited(client: TestClient, admin_headers: dict[str, str]) -> None:
    policy = client.put(
        "/api/v1/module-policies/port-scanner",
        headers=admin_headers,
        json={"enabled": True, "configuration": {"max_concurrency": 20}},
    )
    audit = client.get("/api/v1/audit-events?limit=100", headers=admin_headers)

    assert policy.status_code == 200
    assert policy.json()["enabled"] is True
    assert audit.status_code == 200
    actions = [item["action"] for item in audit.json()["items"]]
    assert "module_policy.updated" in actions
    assert all(len(item["event_hash"]) == 64 for item in audit.json()["items"])


def test_audit_endpoint_is_admin_only(client: TestClient, admin_headers: dict[str, str]) -> None:
    me = client.get("/api/v1/auth/me", headers=admin_headers).json()
    client.post(
        f"/api/v1/teams/{me['team']['id']}/members",
        headers=admin_headers,
        json={
            "email": "analyst@example.test",
            "display_name": "Analyst",
            "password": "analyst password long enough",
            "role": "analyst",
        },
    )
    login = client.post(
        "/api/v1/auth/token",
        json={
            "email": "analyst@example.test",
            "password": "analyst password long enough",
        },
    )
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    assert client.get("/api/v1/audit-events", headers=headers).status_code == 403
