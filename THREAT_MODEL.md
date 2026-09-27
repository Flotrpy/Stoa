# Threat model

## Scope and assets

This initial model covers the desktop agent, central API, workers, database, local evidence stores, endpoint enrollment material, authorization scopes, audit events, reports, and future encrypted chat. Highest-value assets are credentials and tokens, device identity keys, authorization policy, tamper-evident audit history, local packet/filesystem/password evidence, and message plaintext.

## Trust boundaries

1. User ↔ desktop UI.
2. Unprivileged desktop process ↔ narrowly scoped privileged helper.
3. Desktop/worker ↔ central API over authenticated TLS.
4. API ↔ PostgreSQL and queues.
5. Local evidence store ↔ export destination.
6. Chat device ↔ ciphertext-only relay ↔ other verified device.
7. Security module ↔ explicitly authorized target or safe fixture.

## Principal threats and controls

| Threat | Initial control | Owning PRs |
| --- | --- | --- |
| Unauthorized scanning or scope expansion | Server-side RBAC, current allowlist match, endpoint approval, module policy, target validation, rate caps, correlation ID | 2, 4–9 |
| Privilege escalation through the agent | Default unprivileged process; narrowly scoped helper; permission explanation and denial states | 3, 5, 8, 10 |
| Sensitive evidence exfiltration | Local-by-default classification, explicit export, redaction, schema separation, egress tests | 2–10 |
| Credential or token leakage | Secret stores, structured redacted logging, commit scanning, short-lived credentials | 1–3, 10 |
| Audit deletion or forgery | Append-oriented records, integrity chaining/signing, restricted retention actions, backups | 2, 10 |
| Malicious or malformed input | Pydantic schemas, bounded parsers, size/time limits, fuzz/malformed-input tests | 2–10 |
| Job replay or confused deputy | Nonce/idempotency, current authorization re-check, endpoint binding, correlation IDs | 2–10 |
| Chat interception, replay, device compromise | Established authenticated protocol, device verification, AEAD, replay windows, rotation, revocation | 10 |
| Supply-chain compromise | Pinned dependencies, audit/SBOM, protected CI, signed artifacts, checksums | 1, 10 |
| Availability exhaustion | Concurrency/rate/size limits, cancellation, timeouts, rolling retention; no DoS features | 2–10 |

## Safety invariants

- No active job runs without a server-validated authorization record that is current and target-matching.
- Raw packet payloads, password material, private keys, decrypted chat, and sensitive local evidence do not synchronize by default.
- Stoá never claims a heuristic finding proves malware or guarantees a vulnerability.
- No module includes stealth, evasion, exploit delivery, persistence, credential theft, destructive testing, or denial-of-service behavior.
- A failure to validate authorization, input, permission, or policy fails closed and creates a redacted audit event.

## Open analysis

PR 2 will add data-flow diagrams and STRIDE analysis for identity and job coordination. Each module PR adds abuse cases and parser-specific risks. PR 10 requires an independent cryptographic review before production claims.
