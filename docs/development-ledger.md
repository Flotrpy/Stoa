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
