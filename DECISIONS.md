# Architecture decision log

## ADR-001 — Python monorepo with installable package boundaries

Status: accepted · 2026-09-27

Stoá uses one Python distribution containing separately importable desktop, server, worker, shared, security, and platform-adapter packages. This keeps contracts consistent while preserving boundaries that can later become independently deployed artifacts.

## ADR-002 — npm is orchestration only

Status: accepted · 2026-09-27

Root npm scripts call checked-in Node orchestration and platform setup scripts. Application logic remains Python. The wrapper validates tool versions, owns `.venv`, and prevents users from needing manual pip commands.

## ADR-003 — Active modules require authorization context

Status: accepted · 2026-09-27

Every future active module accepts a validated authorization context originating from the server. The UI cannot be an authorization boundary. No scanner implementation will precede the persistent identity, scope, policy, and audit system in PR 2.

## ADR-004 — Sensitive evidence remains local by default

Status: accepted · 2026-09-27

Raw captures, packet payloads, password material, filesystem evidence, sensitive web evidence, chat private keys, and plaintext chat never enter general central persistence. Central records use redacted findings and explicit evidence references.

## ADR-005 — Deliberate native desktop visual system

Status: accepted · 2026-09-27

Stoá uses a restrained operations-console aesthetic with dense, readable surfaces, minimal decoration, and exactly two user-selectable themes. Feature UI research will occur after backend contracts are stable so visual work reflects real workflows rather than decorative mockups.

## ADR-006 — Short-lived team-scoped tokens with live membership checks

Status: accepted · 2026-09-27

Access tokens identify a user and one team but do not carry authoritative permissions. Each request reloads active membership and role from PostgreSQL. This adds one indexed lookup while ensuring user deactivation, membership removal, and role changes apply immediately.

## ADR-007 — Explicit target matching without wildcards

Status: accepted · 2026-09-27

Authorization scopes initially match exact hosts, IP networks, or exact-origin URL path prefixes. General wildcard and regular-expression matching are excluded because ambiguous patterns make authorization review and boundary testing unreliable.

## ADR-008 — Hash-chained append-oriented audit events

Status: accepted · 2026-09-27

Each team audit event stores a SHA-256 digest covering its canonical fields and the previous event digest. This detects offline mutation or deletion when a trusted checkpoint exists. It does not replace database access controls, backups, or future external checkpointing.

## ADR-009 — OS vault credentials and non-sensitive offline queue

Status: accepted · 2026-09-27

The desktop stores access tokens through the operating-system credential vault and keeps non-secret preferences in an atomically replaced JSON file. Disconnected operational metadata uses a local SQLite queue with field-name rejection, a small server event allowlist, bounded flat payloads, and stop-on-first-failure retry behavior. Passwords, tokens, hashes, packet data, private keys, ciphertext, and raw evidence are never valid queue content.

## ADR-010 — Connect scanning by default; SYN requires explicit policy and privilege

Status: accepted · 2026-09-27

The port scanner defaults to ordinary TCP connections from the endpoint's real address. SYN scanning is isolated in a privileged Scapy adapter and requires both central `allow_syn` policy and an explicit local privilege confirmation. The adapter sends a reset after an open response and exposes no source spoofing, timing evasion, fragmentation, decoys, or stealth controls. Hostnames resolve once to one pinned IPv4 address for a scan.

## ADR-011 — PCAP remains local; central IDS data is metadata-only

Status: accepted · 2026-09-27

Live and replayed packet bytes are processed on the endpoint and retained only in a rotating per-user PCAP store. Central results contain bounded counts and explainable indicators, never raw frames or payloads. Live capture is constrained to addresses inside the reviewed network scope before a packet is written locally. PCAP export is an explicit file action.
