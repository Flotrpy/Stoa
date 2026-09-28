"""Device-local encrypted chat orchestration."""

import base64
import json
import secrets
from dataclasses import asdict
from typing import Any, cast
from uuid import UUID

from stoa_desktop.session import DesktopSession
from stoa_security.secure_chat import (
    DeviceKeys,
    DevicePublicBundle,
    EncryptedChatEnvelope,
    ReplayProtector,
    decrypt_message,
    encrypt_message,
    envelope_to_dict,
)


class ChatService:
    def __init__(self, session: DesktopSession) -> None:
        self.session = session
        self.keys = self._load_keys()
        self.counter = 0
        self.replay = ReplayProtector()

    def register(self, name: str) -> dict[str, Any]:
        self.keys = DeviceKeys.generate()
        password = secrets.token_bytes(32)
        encrypted = self.keys.export_encrypted(password)
        self.session.token_store.set(
            json.dumps(
                {
                    "password": base64.urlsafe_b64encode(password).decode(),
                    "bundle": base64.urlsafe_b64encode(encrypted).decode(),
                }
            ),
            profile="chat-device-keys",
        )
        bundle = self.keys.public_bundle()
        return cast(
            dict[str, Any],
            self.session.client.post(
                "/api/v1/chat/devices",
                {
                    "device_id": str(bundle.device_id),
                    "name": name,
                    "identity_public_key": json.dumps(asdict(bundle), default=str),
                },
            ),
        )

    def devices(self) -> list[dict[str, Any]]:
        return cast(list[dict[str, Any]], self.session.client.get("/api/v1/chat/devices"))

    def verify(self, device_id: str) -> None:
        self.session.client.post(f"/api/v1/chat/devices/{device_id}/verify", {})

    def send(self, recipient_record: dict[str, Any], plaintext: str) -> None:
        if self.keys is None:
            raise RuntimeError("register this device before sending messages")
        bundle_data = json.loads(recipient_record["identity_public_key"])
        recipient = DevicePublicBundle(
            UUID(bundle_data["device_id"]),
            bundle_data["agreement_key"],
            bundle_data["signing_key"],
        )
        self.counter += 1
        envelope = encrypt_message(self.keys, recipient, plaintext, counter=self.counter)
        encoded = json.dumps(envelope_to_dict(envelope), separators=(",", ":"))
        self.session.client.post(
            "/api/v1/chat/envelopes",
            {
                "sender_device_id": str(envelope.sender_device_id),
                "recipient_device_id": str(envelope.recipient_device_id),
                "message_id": str(envelope.message_id),
                "ciphertext": encoded,
                "nonce": envelope.nonce,
                "protocol_version": envelope.protocol_version,
            },
        )

    def receive(self) -> list[str]:
        if self.keys is None:
            return []
        devices = {UUID(item["id"]): item for item in self.devices()}
        rows = cast(
            list[dict[str, Any]],
            self.session.client.get(f"/api/v1/chat/envelopes/{self.keys.device_id}"),
        )
        messages: list[str] = []
        for row in rows:
            data = json.loads(row["ciphertext"])
            envelope = EncryptedChatEnvelope(
                message_id=UUID(data["message_id"]),
                sender_device_id=UUID(data["sender_device_id"]),
                recipient_device_id=UUID(data["recipient_device_id"]),
                counter=int(data["counter"]),
                ephemeral_key=data["ephemeral_key"],
                nonce=data["nonce"],
                ciphertext=data["ciphertext"],
                signature=data["signature"],
                protocol_version=data["protocol_version"],
            )
            sender_data = json.loads(devices[envelope.sender_device_id]["identity_public_key"])
            sender = DevicePublicBundle(
                UUID(sender_data["device_id"]),
                sender_data["agreement_key"],
                sender_data["signing_key"],
            )
            messages.append(decrypt_message(self.keys, sender, envelope, self.replay))
        return messages

    def _load_keys(self) -> DeviceKeys | None:
        stored = self.session.token_store.get(profile="chat-device-keys")
        if stored is None:
            return None
        try:
            payload = json.loads(stored)
            return DeviceKeys.import_encrypted(
                base64.urlsafe_b64decode(payload["bundle"]),
                base64.urlsafe_b64decode(payload["password"]),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None
