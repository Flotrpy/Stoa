from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient


def prepare_authorized_job(client: TestClient, headers: dict[str, str]) -> tuple[str, str]:
    endpoint = client.post(
        "/api/v1/endpoints",
        headers=headers,
        json={"name": "lab-runner", "platform": "linux"},
    ).json()
    client.post(f"/api/v1/endpoints/{endpoint['id']}/approve", headers=headers)
    now = datetime.now(UTC)
    scope = client.post(
        "/api/v1/authorization-scopes",
        headers=headers,
        json={
            "name": "Loopback only",
            "target_pattern": "127.0.0.0/8",
            "allowed_modules": ["port-scanner"],
            "rate_policy": {"max_requests": 100, "window_seconds": 60},
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
        },
    ).json()
    client.put(
        "/api/v1/module-policies/port-scanner",
        headers=headers,
        json={"enabled": True, "configuration": {}},
    )
    return endpoint["id"], scope["id"]


def test_job_requires_target_within_current_scope(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    endpoint_id, scope_id = prepare_authorized_job(client, admin_headers)
    base = {
        "module_id": "port-scanner",
        "executing_endpoint_id": endpoint_id,
        "authorization_scope_id": scope_id,
        "business_justification": "Validate the local lab service inventory",
        "configuration": {"ports": [443]},
    }
    rejected = client.post(
        "/api/v1/jobs",
        headers=admin_headers,
        json={**base, "target": "8.8.8.8"},
    )
    accepted = client.post(
        "/api/v1/jobs",
        headers=admin_headers,
        json={**base, "target": "127.0.0.1"},
    )

    assert rejected.status_code == 403
    assert rejected.json()["detail"] == "target is outside authorization scope"
    assert accepted.status_code == 201
    assert accepted.json()["rate_policy"] == {"max_requests": 100, "window_seconds": 60}
    assert accepted.json()["state"] == "queued"


def test_disabled_policy_rejects_job(client: TestClient, admin_headers: dict[str, str]) -> None:
    endpoint_id, scope_id = prepare_authorized_job(client, admin_headers)
    client.put(
        "/api/v1/module-policies/port-scanner",
        headers=admin_headers,
        json={"enabled": False, "configuration": {}},
    )
    response = client.post(
        "/api/v1/jobs",
        headers=admin_headers,
        json={
            "module_id": "port-scanner",
            "executing_endpoint_id": endpoint_id,
            "authorization_scope_id": scope_id,
            "target": "127.0.0.1",
            "business_justification": "Validate the local lab service inventory",
            "configuration": {},
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "module policy is not enabled"
