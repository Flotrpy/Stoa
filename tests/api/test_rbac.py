from fastapi.testclient import TestClient


def create_viewer(client: TestClient, headers: dict[str, str]) -> None:
    me = client.get("/api/v1/auth/me", headers=headers).json()
    response = client.post(
        f"/api/v1/teams/{me['team']['id']}/members",
        headers=headers,
        json={
            "email": "viewer@example.test",
            "display_name": "Read Only",
            "password": "another correct horse battery",
            "role": "viewer",
        },
    )
    assert response.status_code == 201


def test_viewer_can_read_but_cannot_register_endpoint(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    create_viewer(client, admin_headers)
    login = client.post(
        "/api/v1/auth/token",
        json={
            "email": "viewer@example.test",
            "password": "another correct horse battery",
        },
    )
    viewer_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    assert client.get("/api/v1/endpoints", headers=viewer_headers).status_code == 200
    denied = client.post(
        "/api/v1/endpoints",
        headers=viewer_headers,
        json={"name": "viewer-laptop", "platform": "windows"},
    )
    assert denied.status_code == 403


def test_admin_registers_approves_and_revokes_endpoint(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    created = client.post(
        "/api/v1/endpoints",
        headers=admin_headers,
        json={"name": "lab-workstation", "platform": "linux"},
    )
    assert created.status_code == 201
    assert created.json()["state"] == "pending"
    endpoint_id = created.json()["id"]

    approved = client.post(f"/api/v1/endpoints/{endpoint_id}/approve", headers=admin_headers)
    assert approved.status_code == 200
    assert approved.json()["state"] == "approved"

    revoked = client.post(f"/api/v1/endpoints/{endpoint_id}/revoke", headers=admin_headers)
    assert revoked.status_code == 200
    assert revoked.json()["state"] == "revoked"
    assert revoked.json()["last_seen_at"] is None
