from dataclasses import replace

import pytest

from stoa_security.secure_chat import (
    DeviceKeys,
    ReplayProtector,
    decrypt_message,
    encrypt_message,
)


def test_authenticated_encryption_round_trip_and_replay_rejection() -> None:
    alice, bob = DeviceKeys.generate(), DeviceKeys.generate()
    envelope = encrypt_message(alice, bob.public_bundle(), "confidential", counter=1)
    replay = ReplayProtector()
    assert decrypt_message(bob, alice.public_bundle(), envelope, replay) == "confidential"
    with pytest.raises(ValueError, match="replayed"):
        decrypt_message(bob, alice.public_bundle(), envelope, replay)


def test_tamper_wrong_recipient_and_rotation_fail_closed() -> None:
    alice, bob, mallory = DeviceKeys.generate(), DeviceKeys.generate(), DeviceKeys.generate()
    envelope = encrypt_message(alice, bob.public_bundle(), "hello", counter=2)
    with pytest.raises(ValueError, match="wrong recipient"):
        decrypt_message(mallory, alice.public_bundle(), envelope, ReplayProtector())
    with pytest.raises(ValueError):
        decrypt_message(
            bob,
            alice.public_bundle(),
            replace(envelope, ciphertext=envelope.ciphertext[:-2] + "AA"),
            ReplayProtector(),
        )
    rotated = DeviceKeys.generate(alice.device_id)
    with pytest.raises(ValueError, match="signature"):
        decrypt_message(bob, rotated.public_bundle(), envelope, ReplayProtector())


def test_private_key_export_requires_password_and_is_encrypted() -> None:
    keys = DeviceKeys.generate()
    with pytest.raises(ValueError, match="at least 12"):
        keys.export_encrypted(b"short")
    exported = keys.export_encrypted(b"correct horse battery staple")
    assert b"agreement" in exported
    assert keys.public_bundle().agreement_key.encode() not in exported
    restored = DeviceKeys.import_encrypted(exported, b"correct horse battery staple")
    assert restored.public_bundle() == keys.public_bundle()
