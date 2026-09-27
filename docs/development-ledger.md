# Development ledger

This ledger records meaningful commits only. Hashes and PR numbers are filled after commits and pull-request creation; test evidence must reflect actual execution.

| # | Commit | Subject | PR | Requirement | Tests | Result | Remaining work |
| ---: | --- | --- | --- | --- | --- | --- | --- |
| 1 | `b29def3` | docs: capture product specification and delivery map | 1 | Specification, plan, status, risks, acceptance | Document review | Pass | Foundation implementation |
| 2 | `c26f96a` | docs: define architecture security and contribution policy | 1 | Architecture, threat model, contribution and security policy | Document review | Pass | Module-specific threat models |
| 3 | `c6d2bcd` | chore: establish repository policy and pinned runtimes | 1 | Repository metadata, supported runtimes, environment template | Setup review | Pass | Release policy in PR 10 |
| 4 | `9463e5a` | build: establish Python monorepo package boundaries | 1 | Python package layout and dependency pins | Build gate | Pass | Domain packages in PR 2+ |
| 5 | `fec971b` | feat(shared): add versioned contracts and settings | 1 | Shared schemas and validated settings foundation | Unit tests, mypy | Pass | Full shared entities in PR 2 |
| 6 | `9bd0fcf` | feat(api): add versioned health and readiness service | 1 | Initial server shell, API versioning, health checks | API tests | Pass | Persistence and auth in PR 2 |
| 7 | `bce5311` | feat(desktop): add accessible application shell and themes | 1 | Desktop shell, navigation, light/dark theme | Offscreen smoke test | Pass | Functional screens in PR 3+ |
| 8 | `b6bb733` | feat(core): add job authorization and platform boundaries | 1 | Workers, authorization context, platform adapters | Unit tests, mypy | Pass | Enforcement and adapters in PR 2+ |
| 9 | `a79ee60` | build: add cross-platform npm command interface | 1 | Required npm commands, setup, build/security/package gates | Windows local build; Windows/Linux CI | Pass | Later platform workflows |
| 10 | `1a34535` | build: add PostgreSQL and API container foundation | 1 | Compose and container foundation | Hosted Compose validation | Pass | Runtime integration in PR 2 |
| 11 | `20df0ac` | test: add foundation API unit and desktop smoke coverage | 1 | Unit, API, desktop smoke, safe-fixture policy | 13 tests, 83.19% coverage | Pass | Integration suites in PR 2+ |
| 12 | `b88ce09` | ci: enforce Windows Linux and Compose quality gates | 1 | Windows/Linux and Compose CI | Hosted workflow run | Pass | Future platform matrix expansion |
| 13 | `9ddda13` | docs: record verified PR 1 evidence and residual risks | 1 | Ledger and delivery status | Full local and hosted build | Pass | PR review |
| 14 | `6a23bc5` | build: add pinned identity and persistence dependencies | 2 | SQLAlchemy, Alembic, PostgreSQL, Argon2, JWT | Setup and dependency audit | Pass | Hosted audit |
| 15 | `50d97b6` | feat(shared): define identity platform and job schemas | 2 | Versioned identity, platform, policy, audit, and job schemas | Ruff, mypy, API tests | Pass | Later module schemas |
| 16 | `5766a87` | feat(database): add central metadata entity model | 2 | All required shared central entities | ORM table creation, mypy | Pass | Production migration validation |
| 17 | `71bd54a` | feat(database): add reversible initial Alembic migration | 2 | Database migrations | SQLite upgrade/downgrade/upgrade | Pass | PostgreSQL hosted cycle |
| 18 | `a6c03ca` | feat(auth): add Argon2 passwords and scoped access tokens | 2 | Authentication and secure password storage | Authentication API tests | Pass | Rotation and rate limiting |
| 19 | `719bf8f` | feat(auth): enforce live role based permissions | 2 | Administrator, analyst, viewer RBAC | Permission boundary tests | Pass | Per-module policy tests |
| 20 | `2bacbb8` | feat(audit): add hash chained audit recording | 2 | Tamper-evident audit foundation | Audit API and digest tests | Pass | External checkpoints |
| 21 | `e47c7ed` | feat(api): add bootstrap login and principal routes | 2 | First-run identity and team-scoped login | Bootstrap/login/error tests | Pass | Desktop onboarding in PR 3 |
| 22 | `5781605` | feat(jobs): add fail closed authorization gate | 2 | Endpoint, scope, target, module, rate and policy checks | Authorization boundary tests | Pass | Module execution in PR 4+ |
| 23 | `b2a3ce7` | feat(api): add team scoped platform and job routes | 2 | Members, endpoints, scopes, policies, jobs, audit APIs | API and team/RBAC tests | Pass | Findings/report APIs in owning PRs |
| 24 | `9cfc86c` | test: cover identity RBAC authorization and migrations | 2 | API, migration, permission and boundary quality | 27 tests, 89.97% coverage | Pass | Hosted platform matrix |
| 25 | `7f789ac` | ci: verify PostgreSQL migration lifecycle | 2 | PostgreSQL migration quality gate | Workflow review | Pass, pending hosted run | Hosted result |
| 26 | `ad0aa6d` | docs: document identity authorization and residual risk | 2 | Identity design, STRIDE, decisions and status | Document review | Pass | PR review |
| 27 | `c0701dd` | build: add desktop persistence and realtime dependencies | 3 | OS credential vault, platform paths, WebSocket transport | Setup, dependency resolution | Pass | Hosted dependency audit |
| 28 | `2cf51fa` | feat(desktop): add secure local session foundation | 3 | API client, atomic settings, OS vault, enrollment, background work, offline queue | Ruff, strict mypy, unit tests | Pass | Token refresh in PR 10 |
| 29 | `6266860` | feat(realtime): add authenticated reconnectable event channel | 3 | Team-bound WebSocket server and reconnecting client | API and unit tests | Pass | Event fan-out with module delivery |
| 30 | `11d717e` | feat(sync): add bounded offline metadata synchronization | 3 | Allowlisted metadata retry and central audit acceptance | API and unit tests | Pass | Retention limits in PR 10 |
| 31 | `64277b4` | feat(desktop): add onboarding enrollment and settings workflows | 3 | First-run connection, endpoint enrollment, connectivity UI, settings, themes | Offscreen smoke, strict mypy | Pass | Module screens in PRs 4–10 |
| 32 | `f0c0ae8` | test(desktop): cover storage transport enrollment and sync | 3 | Desktop persistence, API, realtime, enrollment, sync boundaries | 41 tests, 81.62% coverage | Pass | Hosted Windows/Linux matrix |
| 33 | `fb2c0f1` | feat(desktop): flush safe metadata after reconnect | 3 | Ordered replay after restored connectivity | Local and hosted Windows/Linux build | Pass | PR review |
| 34 | `aa9ef50` | build: add pinned Scapy support for authorized SYN scans | 4 | Optional privileged SYN transport | Setup and dependency resolution | Pass | Hosted dependency audit |
| 35 | `4a12ec3` | feat(scanner): implement bounded authorized port scanning | 4 | TCP connect, SYN adapter, ports, IPv4, banners, cancellation, rate and reports | Unit tests, Ruff, strict mypy | Pass | Platform packet validation |
| 36 | `3fab6cb` | feat(api): persist scanner results and enforce module policy | 4 | Policy caps, migration, endpoint-bound observations, JSON/text report APIs | API and migration tests | Pass | Hosted PostgreSQL cycle |
| 37 | `5195149` | feat(desktop): add authorized port scanner workflow | 4 | Scope selection, progress, cancellation, results, report export | Offscreen smoke, strict mypy | Pass | Hosted Windows/Linux matrix |
| 38 | `8c909ca` | test(scanner): cover safe fixtures policy results and reports | 4 | Loopback scan fixture, authorization failures, policy gates, reports | 49 tests, 78.16% coverage | Pass | Local and hosted build green; PR review |
