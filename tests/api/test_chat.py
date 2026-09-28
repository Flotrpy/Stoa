from uuid import uuid4

from fastapi.testclient import TestClient


def _device(client: TestClient, headers: dict[str, str], name: str) -> dict[str, object]:
    response = client.post(
        "/api/v1/chat/devices",
        headers=headers,
        json={"name": name, "identity_public_key": "public-bundle-" + "a" * 64},
    )
    assert response.status_code == 201
    return response.json()


def test_ciphertext_only_offline_relay_and_replay_rejection(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    sender = _device(client, admin_headers, "sender")
    recipient = _device(client, admin_headers, "recipient")
    message_id = str(uuid4())
    payload = {
        "sender_device_id": sender["id"],
        "recipient_device_id": recipient["id"],
        "message_id": message_id,
        "ciphertext": "opaque-encrypted-payload",
        "nonce": "opaque-nonce-value",
        "protocol_version": "stoa-chat-v1",
    }
    sent = client.post("/api/v1/chat/envelopes", headers=admin_headers, json=payload)
    duplicate = client.post("/api/v1/chat/envelopes", headers=admin_headers, json=payload)
    received = client.get(f"/api/v1/chat/envelopes/{recipient['id']}", headers=admin_headers)
    assert sent.status_code == 201
    assert duplicate.status_code == 409
    assert received.json()[0]["ciphertext"] == "opaque-encrypted-payload"
    assert "plaintext" not in received.json()[0]
    assert (
        client.get(f"/api/v1/chat/envelopes/{recipient['id']}", headers=admin_headers).json() == []
    )


def test_device_verification_and_owner_revocation(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    device = _device(client, admin_headers, "workstation")
    verified = client.post(f"/api/v1/chat/devices/{device['id']}/verify", headers=admin_headers)
    revoked = client.post(f"/api/v1/chat/devices/{device['id']}/revoke", headers=admin_headers)
    assert verified.json()["verified_at"] is not None
    assert revoked.json()["revoked_at"] is not None
