# Contributing to Stoá

Work from a `codex/` branch and keep each commit coherent, reviewable, and in a valid state. Use Conventional Commit subjects. Do not split changes solely to increase the commit count.

Before opening a pull request:

1. Run `npm run build`.
2. Review the full diff and generated artifacts.
3. Confirm `npm run security` passes and no sensitive fixture was added.
4. Update `STATUS.md`, `DECISIONS.md` when relevant, and `docs/development-ledger.md`.
5. Complete every applicable section of the pull-request template, including rollback and security impact.

Tests must use loopback, private lab networks, and checked-in deterministic fixtures. Public systems are never test targets without explicit, documented authorization.
