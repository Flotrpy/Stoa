# Stoá

Stoá is a safety-first, unified security workspace for authorized IT and security teams. This repository is a Python monorepo containing a PySide6 desktop client, a FastAPI control plane, shared domain packages, background workers, platform adapters, safe lab fixtures, packaging, and documentation.

> [!IMPORTANT]
> Stoá is built for defensive use on assets covered by explicit authorization. It does not include exploit delivery, stealth scanning, credential theft, persistence, denial-of-service behavior, or unauthorized remote execution.

## Current delivery stage

PR 1 establishes the runnable foundation. Security modules are intentionally not presented as implemented yet. See `STATUS.md` and `PLAN.md` for the delivery sequence.

## Quick start

Requirements: Node.js 24, npm 11, and Python 3.12. Docker Desktop is required only for the PostgreSQL development service.

```powershell
npm install
npm run setup
npm run dev
```

The setup command creates `.venv` and installs pinned dependencies. On Windows, `npm run dev` launches both the API and desktop app; use `npm run dev:server` or `npm run dev:desktop` to run one process.

## Commands

| Command | Purpose |
| --- | --- |
| `npm run setup` | Validate prerequisites, create `.venv`, and install pinned dependencies |
| `npm run dev` | Start the local API and desktop application |
| `npm run build` | Run tests, lint, type checks, security checks, and packaging validation |
| `npm run install-app` | Build and install the desktop package into the active user profile |
| `npm start` | Start the installed desktop application |
| `npm test` | Run the test suite |
| `npm run lint` | Run Ruff formatting and lint checks |
| `npm run typecheck` | Run mypy |
| `npm run security` | Run Bandit, dependency audit, and secret checks |
| `npm run server:up` | Start PostgreSQL through Docker Compose |
| `npm run server:down` | Stop the local Docker Compose stack |

Full development instructions live in `docs/development.md`.
