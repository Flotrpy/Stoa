# Development setup

## Supported hosts

- Windows 11 with PowerShell 5.1 or newer
- Current Linux distributions with Bash
- Python 3.12.x
- Node.js 24.x and npm 11.x
- Docker with Compose for the local PostgreSQL service

## Bootstrap

From the repository root:

```text
npm install
npm run setup
```

Setup validates the Python minor version, creates `.venv`, installs the pinned files in `requirements/`, and installs the repository as an editable package. It does not require administrator/root privileges.

Copy `.env.example` to `.env` only when overriding defaults. Never place production secrets in this repository.

## Run

Start PostgreSQL after installing Docker:

```text
npm run server:up
```

For PR 1 the API does not yet depend on PostgreSQL, allowing health checks before identity persistence lands. Run the API and desktop together with `npm run dev`, or separately with `npm run dev:server` and `npm run dev:desktop`.

API documentation is at `http://127.0.0.1:8787/api/docs`; liveness is at `/api/v1/health`.

## Quality and packaging

`npm run build` is the authoritative local gate. It stops at the first failure and runs formatting/lint, strict typing, tests/coverage, Bandit, dependency audit, secret scanning, wheel/sdist creation, and artifact validation.

Docker is currently a missing prerequisite on the initial Windows workstation. Use CI or a Docker-enabled host to validate `docker compose config`, service health, and shutdown until it is installed.
