# Secure chat protocol

Stoá Chat v1 uses maintained primitives from Python Cryptographic Authority's `cryptography`
package: X25519 ephemeral-static key agreement, HKDF-SHA256 key derivation, AES-256-GCM
authenticated encryption, and Ed25519 sender signatures. Every envelope binds the protocol,
message ID, sender and recipient device IDs, monotonic counter, and ephemeral public key as
authenticated data. Nonces are 96 random bits and a fresh content key is derived per message.

Private agreement and signing keys are generated on the endpoint. Exported key bundles encrypt
each PKCS#8 private key with `BestAvailableEncryption`; the server receives only public bundles.
Device verification, revocation, replacement/rotation, message-ID uniqueness, counter replay
protection, tamper rejection, and ciphertext-only offline relay are explicit protocol operations.

The relay cannot decrypt messages. Decrypted content and private keys are absent from server
schemas, logs, telemetry, audit records, and backups. Revocation prevents new envelopes but cannot
retroactively revoke ciphertext already delivered to a device.

This implementation must receive an independent professional cryptographic review before any
production-security claim. It deliberately does not claim Signal-protocol forward secrecy across
an ongoing session, post-compromise security, or metadata anonymity.
