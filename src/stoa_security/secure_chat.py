"""Device-controlled authenticated encryption for Stoá chat.

Protocol v1 uses X25519 ephemeral-static key agreement, HKDF-SHA256, AES-256-GCM,
and Ed25519 signatures. The server only relays serialized encrypted envelopes.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import asdict, dataclass
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL_VERSION = "stoa-chat-v1"


@dataclass(frozen=True, slots=True)
class DevicePublicBundle:
    device_id: UUID
    agreement_key: str
    signing_key: str


@dataclass(frozen=True, slots=True)
class EncryptedChatEnvelope:
    message_id: UUID
    sender_device_id: UUID
    recipient_device_id: UUID
    counter: int
    ephemeral_key: str
    nonce: str
    ciphertext: str
    signature: str
    protocol_version: str = PROTOCOL_VERSION


@dataclass(slots=True)
class DeviceKeys:
    device_id: UUID
    agreement: x25519.X25519PrivateKey
    signing: ed25519.Ed25519PrivateKey

    @classmethod
    def generate(cls, device_id: UUID | None = None) -> DeviceKeys:
        return cls(
            device_id or uuid4(),
            x25519.X25519PrivateKey.generate(),
            ed25519.Ed25519PrivateKey.generate(),
        )

    def public_bundle(self) -> DevicePublicBundle:
        return DevicePublicBundle(
            self.device_id,
            _b64(
                self.agreement.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
            ),
            _b64(
                self.signing.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
            ),
        )

    def export_encrypted(self, password: bytes) -> bytes:
        if len(password) < 12:
            raise ValueError("device-key password must contain at least 12 bytes")
        payload = {
            "device_id": str(self.device_id),
            "agreement": _b64(
                self.agreement.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.BestAvailableEncryption(password),
                )
            ),
            "signing": _b64(
                self.signing.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.BestAvailableEncryption(password),
                )
            ),
        }
        return json.dumps(payload, separators=(",", ":")).encode()

    @classmethod
    def import_encrypted(cls, payload: bytes, password: bytes) -> DeviceKeys:
        data = json.loads(payload)
        agreement = serialization.load_pem_private_key(_unb64(data["agreement"]), password)
        signing = serialization.load_pem_private_key(_unb64(data["signing"]), password)
        if not isinstance(agreement, x25519.X25519PrivateKey) or not isinstance(
            signing, ed25519.Ed25519PrivateKey
        ):
            raise ValueError("encrypted device bundle contains unexpected key types")
        return cls(UUID(data["device_id"]), agreement, signing)


class ReplayProtector:
    def __init__(self) -> None:
        self._message_ids: set[UUID] = set()
        self._counters: dict[UUID, int] = {}

    def accept(self, envelope: EncryptedChatEnvelope) -> None:
        prior = self._counters.get(envelope.sender_device_id, 0)
        if envelope.message_id in self._message_ids or envelope.counter <= prior:
            raise ValueError("replayed or out-of-order chat envelope")
        self._message_ids.add(envelope.message_id)
        self._counters[envelope.sender_device_id] = envelope.counter


def encrypt_message(
    sender: DeviceKeys,
    recipient: DevicePublicBundle,
    plaintext: str,
    *,
    counter: int,
) -> EncryptedChatEnvelope:
    if not plaintext or len(plaintext.encode()) > 64_000 or counter < 1:
        raise ValueError("message or counter is outside protocol limits")
    ephemeral = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    shared = ephemeral.exchange(
        x25519.X25519PublicKey.from_public_bytes(_unb64(recipient.agreement_key))
    )
    message_id = uuid4()
    aad = _aad(message_id, sender.device_id, recipient.device_id, counter, ephemeral_public)
    key = _derive_key(shared, aad)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode(), aad)
    signature = sender.signing.sign(aad + nonce + ciphertext)
    return EncryptedChatEnvelope(
        message_id,
        sender.device_id,
        recipient.device_id,
        counter,
        _b64(ephemeral_public),
        _b64(nonce),
        _b64(ciphertext),
        _b64(signature),
    )


def decrypt_message(
    recipient: DeviceKeys,
    sender: DevicePublicBundle,
    envelope: EncryptedChatEnvelope,
    replay: ReplayProtector,
) -> str:
    if (
        envelope.protocol_version != PROTOCOL_VERSION
        or envelope.recipient_device_id != recipient.device_id
    ):
        raise ValueError("unsupported protocol or wrong recipient")
    ephemeral = _unb64(envelope.ephemeral_key)
    nonce = _unb64(envelope.nonce)
    ciphertext = _unb64(envelope.ciphertext)
    aad = _aad(
        envelope.message_id,
        envelope.sender_device_id,
        envelope.recipient_device_id,
        envelope.counter,
        ephemeral,
    )
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(_unb64(sender.signing_key)).verify(
            _unb64(envelope.signature), aad + nonce + ciphertext
        )
    except InvalidSignature as error:
        raise ValueError("chat envelope signature is invalid") from error
    shared = recipient.agreement.exchange(x25519.X25519PublicKey.from_public_bytes(ephemeral))
    plaintext = AESGCM(_derive_key(shared, aad)).decrypt(nonce, ciphertext, aad)
    replay.accept(envelope)
    return plaintext.decode()


def envelope_to_dict(envelope: EncryptedChatEnvelope) -> dict[str, str | int]:
    return {
        key: str(value) if isinstance(value, UUID) else value
        for key, value in asdict(envelope).items()
    }


def _derive_key(shared: bytes, aad: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=aad).derive(shared)


def _aad(message_id: UUID, sender: UUID, recipient: UUID, counter: int, ephemeral: bytes) -> bytes:
    return b"|".join(
        (
            PROTOCOL_VERSION.encode(),
            message_id.bytes,
            sender.bytes,
            recipient.bytes,
            str(counter).encode(),
            ephemeral,
        )
    )


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode()


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode())
