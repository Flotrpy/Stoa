from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient


def prepare_authorized_job(
    client: TestClient, headers: dict[str, str], module_id: str = "port-scanner"
) -> tuple[str, str]:
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
            "allowed_modules": [module_id],
            "rate_policy": {"max_requests": 100, "window_seconds": 60},
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
        },
    ).json()
    client.put(
        f"/api/v1/module-policies/{module_id}",
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


def test_packet_analysis_results_create_deduplicated_metadata_alerts(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    endpoint_id, scope_id = prepare_authorized_job(
        client, admin_headers, module_id="packet-analysis"
    )
    job = client.post(
        "/api/v1/jobs",
        headers=admin_headers,
        json={
            "module_id": "packet-analysis",
            "executing_endpoint_id": endpoint_id,
            "authorization_scope_id": scope_id,
            "target": "127.0.0.1",
            "business_justification": "Inspect authorized local lab packet metadata",
            "configuration": {
                "interface": "loopback-fixture",
                "protocols": ["tcp", "dns"],
                "packet_limit": 100,
                "replay_only": True,
            },
        },
    )
    assert job.status_code == 201
    result = client.post(
        f"/api/v1/jobs/{job.json()['id']}/packet-analysis-results",
        headers=admin_headers,
        json={
            "executing_endpoint_id": endpoint_id,
            "packet_count": 12,
            "byte_count": 840,
            "protocols": {"tcp": 10, "dns": 2},
            "indicators": [
                {
                    "rule_id": "STOA-NET-001",
                    "title": "Rapid connection attempts across multiple ports",
                    "severity": "medium",
                    "confidence": 0.85,
                    "explanation": "Administrative discovery can produce the same pattern.",
                    "source": "192.0.2.10",
                    "destination": "192.0.2.20",
                    "evidence": {"unique_ports": 20, "window_seconds": 10},
                }
            ],
        },
    )
    alerts = client.get("/api/v1/alerts", headers=admin_headers)

    assert result.status_code == 201
    assert result.json()["alerts_created"] == 1
    assert alerts.status_code == 200
    assert alerts.json()[0]["severity"] == "medium"
    assert "payload" not in str(alerts.json()).casefold()


def test_web_scan_policy_results_and_reports(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    endpoint_id, scope_id = prepare_authorized_job(client, admin_headers, module_id="web-scanner")
    base = {
        "module_id": "web-scanner",
        "executing_endpoint_id": endpoint_id,
        "authorization_scope_id": scope_id,
        "target": "127.0.0.1",
        "business_justification": "Inspect authorized local lab web metadata",
    }
    active_rejected = client.post(
        "/api/v1/jobs",
        headers=admin_headers,
        json={**base, "configuration": {"active_checks": True}},
    )
    client.put(
        "/api/v1/module-policies/web-scanner",
        headers=admin_headers,
        json={
            "enabled": True,
            "configuration": {
                "max_depth": 2,
                "max_pages": 20,
                "max_requests_per_second": 5,
                "allow_active_checks": True,
                "allow_form_submission": True,
                "allow_zap_import": False,
            },
        },
    )
    job = client.post(
        "/api/v1/jobs",
        headers=admin_headers,
        json={
            **base,
            "configuration": {
                "max_depth": 1,
                "max_pages": 5,
                "active_checks": True,
                "allow_form_submission": True,
            },
        },
    )
    assert active_rejected.status_code == 403
    assert job.status_code == 201
    result = client.post(
        f"/api/v1/jobs/{job.json()['id']}/web-scan-results",
        headers=admin_headers,
        json={
            "executing_endpoint_id": endpoint_id,
            "page_count": 2,
            "findings": [
                {
                    "rule_id": "STOA-WEB-005",
                    "title": "Reflected input marker in response body",
                    "category": "web",
                    "severity": "medium",
                    "confidence": 0.75,
                    "url": "http://127.0.0.1/search?q=REDACTED",
                    "evidence": {"parameter": "q", "marker": "stoa-canary-6b7b4f"},
                    "remediation": "Encode untrusted input in the response context.",
                }
            ],
        },
    )
    text_report = client.get(
        f"/api/v1/jobs/{job.json()['id']}/web-scan-report?format=text",
        headers=admin_headers,
    )
    alerts = client.get("/api/v1/alerts", headers=admin_headers)

    assert result.status_code == 201
    assert result.json()["job"]["state"] == "succeeded"
    assert result.json()["findings"][0]["url"].endswith("q=REDACTED")
    assert text_report.status_code == 200
    assert "STOA-WEB-005" in text_report.text
    assert alerts.json()[0]["title"] == "Reflected input marker in response body"
    assert "secret" not in str(result.json()).casefold()


def test_firewall_simulation_policy_results_and_report(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    endpoint_id, scope_id = prepare_authorized_job(
        client, admin_headers, module_id="firewall-simulator"
    )
    base = {
        "module_id": "firewall-simulator",
        "executing_endpoint_id": endpoint_id,
        "authorization_scope_id": scope_id,
        "target": "127.0.0.1",
        "business_justification": "Review proposed firewall policy behavior",
    }
    rules = [
        {
            "order": 1,
            "name": "Allow HTTPS",
            "direction": "outbound",
            "action": "allow",
            "protocol": "tcp",
            "source": "192.0.2.0/24",
            "destination": "198.51.100.10/32",
            "destination_ports": [{"start": 443, "end": 443}],
        }
    ]
    client.put(
        "/api/v1/module-policies/firewall-simulator",
        headers=admin_headers,
        json={"enabled": True, "configuration": {"max_rules": 1, "max_packets": 1}},
    )
    too_many_packets = client.post(
        "/api/v1/jobs",
        headers=admin_headers,
        json={
            **base,
            "configuration": {
                "default_action": "block",
                "rules": rules,
                "packets": [
                    {
                        "direction": "outbound",
                        "protocol": "tcp",
                        "source": "192.0.2.15",
                        "destination": "198.51.100.10",
                        "source_port": 50000,
                        "destination_port": 443,
                    },
                    {
                        "direction": "outbound",
                        "protocol": "tcp",
                        "source": "192.0.2.15",
                        "destination": "198.51.100.20",
                        "source_port": 50000,
                        "destination_port": 443,
                    },
                ],
            },
        },
    )
    job = client.post(
        "/api/v1/jobs",
        headers=admin_headers,
        json={
            **base,
            "configuration": {
                "default_action": "block",
                "rules": rules,
                "packets": [
                    {
                        "direction": "outbound",
                        "protocol": "tcp",
                        "source": "192.0.2.15",
                        "destination": "198.51.100.10",
                        "source_port": 50000,
                        "destination_port": 443,
                    }
                ],
            },
        },
    )
    result = client.post(
        f"/api/v1/jobs/{job.json()['id']}/firewall-simulation-results",
        headers=admin_headers,
        json={
            "executing_endpoint_id": endpoint_id,
            "analysis": {"shadowed_rules": [], "conflicting_rules": []},
            "observations": [
                {
                    "packet": {
                        "direction": "outbound",
                        "protocol": "tcp",
                        "source": "192.0.2.15",
                        "destination": "198.51.100.10",
                        "source_port": 50000,
                        "destination_port": 443,
                    },
                    "action": "allow",
                    "matched_rule": "Allow HTTPS",
                    "explanation": "Rule 1 is the first match and allows the packet.",
                }
            ],
        },
    )
    text_report = client.get(
        f"/api/v1/jobs/{job.json()['id']}/firewall-simulation-report?format=text",
        headers=admin_headers,
    )

    assert too_many_packets.status_code == 403
    assert job.status_code == 201
    assert result.status_code == 201
    assert result.json()["observations"][0]["action"] == "allow"
    assert text_report.status_code == 200
    assert "Allow HTTPS" in text_report.text
