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
            "configuration": {"ports": [443]},
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "module policy is not enabled"


def test_port_scan_results_are_endpoint_bound_and_reportable(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    endpoint_id, scope_id = prepare_authorized_job(client, admin_headers)
    job = client.post(
        "/api/v1/jobs",
        headers=admin_headers,
        json={
            "module_id": "port-scanner",
            "executing_endpoint_id": endpoint_id,
            "authorization_scope_id": scope_id,
            "target": "127.0.0.1",
            "business_justification": "Validate the local lab service inventory",
            "configuration": {
                "ports": [22, 443],
                "method": "tcp-connect",
                "timeout_seconds": 1,
                "concurrency": 2,
                "max_attempts_per_second": 10,
                "collect_banners": True,
            },
        },
    ).json()
    mismatch = client.post(
        f"/api/v1/jobs/{job['id']}/port-scan-results",
        headers=admin_headers,
        json={
            "executing_endpoint_id": "00000000-0000-0000-0000-000000000001",
            "observations": [{"port": 22, "state": "open"}],
        },
    )
    accepted = client.post(
        f"/api/v1/jobs/{job['id']}/port-scan-results",
        headers=admin_headers,
        json={
            "executing_endpoint_id": endpoint_id,
            "observations": [
                {
                    "port": 22,
                    "state": "open",
                    "service": "ssh",
                    "banner": "SSH-2.0-Safe-Fixture\n",
                    "latency_ms": 1.2,
                },
                {"port": 443, "state": "closed", "service": "https"},
            ],
        },
    )
    text_report = client.get(
        f"/api/v1/jobs/{job['id']}/port-scan-report?format=text", headers=admin_headers
    )
    json_report = client.get(
        f"/api/v1/jobs/{job['id']}/port-scan-report?format=json", headers=admin_headers
    )

    assert mismatch.status_code == 403
    assert accepted.status_code == 201
    assert accepted.json()["job"]["state"] == "succeeded"
    assert accepted.json()["observations"][0]["banner"] == "SSH-2.0-Safe-Fixture"
    assert text_report.status_code == 200
    assert "ssh" in text_report.text
    assert json_report.status_code == 200
    assert len(json_report.json()["observations"]) == 2


def test_port_scan_policy_controls_privileged_method_and_concurrency(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    endpoint_id, scope_id = prepare_authorized_job(client, admin_headers)
    base = {
        "module_id": "port-scanner",
        "executing_endpoint_id": endpoint_id,
        "authorization_scope_id": scope_id,
        "target": "127.0.0.1",
        "business_justification": "Validate the local lab service inventory",
    }
    syn_rejected = client.post(
        "/api/v1/jobs",
        headers=admin_headers,
        json={**base, "configuration": {"ports": [443], "method": "syn"}},
    )
    concurrency_rejected = client.post(
        "/api/v1/jobs",
        headers=admin_headers,
        json={**base, "configuration": {"ports": [443], "concurrency": 65}},
    )
    client.put(
        "/api/v1/module-policies/port-scanner",
        headers=admin_headers,
        json={
            "enabled": True,
            "configuration": {
                "max_ports": 10,
                "max_concurrency": 100,
                "allow_banner_collection": False,
                "allow_syn": True,
            },
        },
    )
    accepted = client.post(
        "/api/v1/jobs",
        headers=admin_headers,
        json={
            **base,
            "configuration": {
                "ports": [443],
                "method": "syn",
                "concurrency": 65,
                "collect_banners": True,
            },
        },
    )

    assert syn_rejected.status_code == 403
    assert concurrency_rejected.status_code == 403
    assert accepted.status_code == 201
    assert accepted.json()["configuration"]["collect_banners"] is False
    assert accepted.json()["configuration"]["effective_minimum_interval_seconds"] == 0.6
