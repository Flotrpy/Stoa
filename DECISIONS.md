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
