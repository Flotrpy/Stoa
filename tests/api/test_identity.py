from fastapi.testclient import TestClient


def test_bootstrap_is_single_use_and_token_loads_current_principal(client: TestClient) -> None:
    payload = {
        "team_name": "Example Security",
        "team_slug": "example-security",
        "email": "admin@example.test",
        "display_name": "Test Administrator",
        "password": "correct horse battery staple",
    }
    first = client.post("/api/v1/auth/bootstrap", json=payload)
    second = client.post("/api/v1/auth/bootstrap", json=payload)

    assert first.status_code == 201
    assert second.status_code == 409
    token = first.json()["access_token"]
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["user"]["email"] == "admin@example.test"
    assert me.json()["role"] == "administrator"


def test_login_rejects_wrong_password(client: TestClient, admin_token: str) -> None:
    del admin_token
    response = client.post(
        "/api/v1/auth/token",
        json={"email": "admin@example.test", "password": "incorrect password"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid credentials"


def test_login_issues_new_team_scoped_token(client: TestClient, admin_token: str) -> None:
    del admin_token
    response = client.post(
        "/api/v1/auth/token",
        json={
            "email": "admin@example.test",
            "password": "correct horse battery staple",
        },
    )

    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"  # noqa: S105
    assert response.json()["expires_in"] == 1800


def test_invalid_token_does_not_disclose_validation_detail(client: TestClient) -> None:
    response = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer definitely-invalid"})

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid authentication credentials"
