# Stoá delivery plan

The specification is delivered through exactly ten independently reviewable pull requests. Later work may refine acceptance details, but it may not silently remove requirements or weaken safety boundaries.

| PR | Delivery | Requirement groups | Acceptance evidence |
| --- | --- | --- | --- |
| 1 | Foundation | Monorepo, npm interface, pinned Python environment, desktop/API shells, CI, Compose, architecture, security planning, ledger | Clean Windows and Linux setup; API health tests; desktop smoke test; lint, types, tests, security and package build pass |
| 2 | Identity and shared platform | All shared entities, PostgreSQL/Alembic, authentication, teams, roles, RBAC, endpoints, scopes, policies, audit, API versioning | Migration upgrade/downgrade tests; permission matrix; rejected out-of-scope requests; audit integrity tests |
| 3 | Desktop foundation | Navigation, onboarding, enrollment, secure storage, clients, background execution, offline queue, connectivity, settings, themes | UI workflow tests; offline/reconnection tests; local/central labels; crash recovery exercise |
| 4 | Port scanner | Authorized TCP connect/SYN scanning, service discovery, cancellation, limits, reports, fixtures | Lab-only open/closed-port tests; authorization/rate tests; cancellation; JSON/text report snapshots |
| 5 | Packet analysis and IDS | Capture, protocol metadata, PCAP rotation/replay/export, IDS patterns and timelines | Deterministic PCAP fixtures; Wireshark-readable export; retention; alert suppression/dedup tests |
| 6 | Web security scanner | Same-origin crawl, passive checks, bounded probes, evidence redaction, ZAP adapter | Safe local vulnerable service; allowlist boundaries; rate limits; no form submission; report tests |
| 7 | Firewall simulator | Rule model, validation, matching, conflicts, replay, explanation, import/export | First-match test matrix; shadow/conflict detection; deterministic replay; proof no host firewall mutation |
| 8 | Endpoint monitoring | FIM plus Windows/Linux keylogger-indicator adapters | File lifecycle fixtures; baseline/tamper tests; benign/suspicious process fixtures; confidence explanations |
| 9 | Risk-analysis tools | Phishing pipeline and constrained offline password lab | Model provenance/metrics; held-out evaluation; strict local-only tests; limits/cancellation; no online target support |
| 10 | Secure chat and release hardening | Device-key E2EE subsystem, packaging, installers, backup/restore, upgrade/rollback, SBOM, operational docs | Cryptographic protocol vectors; tamper/replay/revocation/rotation; clean installs; signed release evidence; restore drill |

## Cross-cutting acceptance map

- Authorization, safety prohibitions, audit correlation, validation, and redaction are enforced by shared server policies beginning in PR 2 and regression-tested in every active-module PR.
- Central-versus-local data classification is encoded in schemas and storage adapters in PR 2, surfaced by the desktop in PR 3, and tested for every sensitive module in PRs 4–10.
- Search, filtering, sorting, pagination, loading, empty, error, offline, permission-denied, progress, cancellation, notifications, exports, and keyboard access are introduced with their owning workflow and covered by UI/API tests.
- Windows and Linux behavior is covered continuously in CI; privilege-requiring capture tests use explicit opt-in runners and never silently elevate.
- Installation, upgrade, repair, backup, restore, rollback, uninstall, checksums, release notes, and SBOM reach verified production form in PR 10.

## PR 1 task breakdown

1. Capture the authoritative specification, decision record, delivery map, status, threat model, and development ledger.
2. Establish repository metadata, pinned tool versions, local-only Git identity, and contribution conventions.
3. Create package boundaries for desktop, API, workers, shared models, security modules, and platform adapters.
4. Add a versioned FastAPI application with liveness and readiness routes.
5. Add the PySide6 desktop shell with accessible navigation and deliberate light/dark themes.
6. Provide the complete npm command interface and cross-platform environment bootstrap.
7. Add PostgreSQL Compose and a production-shaped API container.
8. Add unit/API/smoke tests, safe fixtures, lint, formatting, type, dependency, static-security, secret, and package gates.
9. Add Windows/Linux CI and PR review templates.
10. Verify from a clean environment, review the diff, scan for secrets, update the ledger, and open PR 1.

## Proposed meaningful PR 1 commits

1. `docs: capture product specification and delivery map`
2. `chore: establish repository policy and pinned runtimes`
3. `feat(shared): add versioned foundation contracts and settings`
4. `feat(api): add versioned health and readiness service`
5. `feat(desktop): add accessible application shell and themes`
6. `feat(workers): establish cancellable job boundaries`
7. `feat(security): establish authorization context boundary`
8. `build: add cross-platform npm command interface`
9. `build: add reproducible Python environment bootstrap`
10. `build: add PostgreSQL and API container foundation`
11. `test: add foundation unit API and desktop smoke coverage`
12. `ci: enforce Windows and Linux quality gates`
13. `docs: add architecture security and contributor guidance`
14. `docs: record verified PR 1 evidence and residual risks`

## PR 1 acceptance criteria

- A new developer on supported Windows or Linux can run `npm install` and `npm run setup` without manual pip commands.
- `npm run dev:server` serves versioned health and readiness endpoints.
- `npm run dev:desktop` opens the desktop shell without administrator/root privileges.
- Every required root npm command exists and fails with an actionable message when a prerequisite is missing.
- `npm run build` runs formatting, linting, typing, tests, static security, dependency auditing, secret scanning, and package validation before succeeding.
- PostgreSQL can be started through Docker Compose when Docker is installed; its absence is reported clearly.
- CI runs the same quality gate on Windows and Linux.
- No security module is falsely represented as implemented.
- The authoritative specification and requirement-to-PR map are version controlled.
- GitHub repository ownership, branch prefix, local identity, and PR evidence conform to the specification.
