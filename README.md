# NexOps AI — Autonomous CloudOps and SRE Platform

A local-first CloudOps/SRE portfolio platform: FastAPI backend, React/TypeScript dashboard, PostgreSQL (SQLite for tests),
Prometheus + Grafana monitoring, deterministic incident detection, evidence-based diagnosis, and **simulated** controlled
recovery for disposable demo services.

<img width="1440" height="700" alt="01-login" src="https://github.com/user-attachments/assets/1c5058c0-7d4a-40e4-a045-086b1780834d" />

> **Honesty notes.** Recovery is **simulated**: nothing real is restarted, rolled back or executed. Deployment history is
> *recorded* (or sample data), never performed by NexOps. Diagnosis is deterministic rules, not an AI model. See
> [docs/BUILD_STATUS.md](docs/BUILD_STATUS.md) for exactly what was and was not verified.

## Features
- Auth with Argon2 password hashing, JWT access tokens, roles `viewer` < `operator` < `admin`, server-side authorization.
- Service registry, metric ingestion, deployment history, structured JSON logs, `/metrics` for Prometheus.
- Detection rules: brute-force logins, service down, high error rate, high latency, suspicious access, privilege changes —
  with evidence correlated to service status, metrics, deployments and logs.
- Diagnosis that separates **observed facts** from **hypotheses** (confidence capped at "medium").
- Recovery: allowlist, demo-only services, approval by a different admin, typed confirmation, simulated post-action
  verification, full audit trail (denied attempts included).
- Dashboard: overview, services + charts, deployments, incidents (filters/search), incident evidence + diagnosis,
  recovery approvals, audit history.

## Layout
```
backend/      FastAPI app (app/), Alembic migrations, pytest suite (tests/)
frontend/     React + TypeScript + Vite dashboard, Vitest tests
monitoring/   Prometheus config + alert rules, Grafana provisioning + dashboard
deployment/   docker-compose.yml (PostgreSQL, Prometheus, Grafana)
scripts/      Windows PowerShell scripts, env generator, end-to-end demo script
docs/         Architecture, API, security/threat model, demo walkthrough, build status
```

<img width="1440" height="900" alt="02-dashboard" src="https://github.com/user-attachments/assets/66ee5ee5-0334-48e8-873d-45833b5b9d17" />


## Quick start on Windows 11 (no Docker, SQLite)
Prerequisites: Python 3.11+, Node.js 20+ (22 tested), Git. In PowerShell from the project root:

```powershell
Set-ExecutionPolicy -Scope Process Bypass      # allows the scripts for this window only
.\scripts\setup.ps1                            # venv, dependencies, generates .env with random secrets
cd backend
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m app.cli create-user --email admin@example.com --role admin       # prompts for password
.\.venv\Scripts\python.exe -m app.cli create-user --email operator@example.com --role operator
.\.venv\Scripts\python.exe -m app.cli seed-demo --reset --detect   # synthetic data + incidents
cd ..
.\scripts\start-backend.ps1                    # http://127.0.0.1:8000/docs
.\scripts\start-frontend.ps1                   # second terminal -> http://localhost:5173
```
There is **no default admin**; you create users with the CLI (passwords are prompted, 12+ characters).
Follow [docs/DEMO.md](docs/DEMO.md) for the walkthrough.

## Optional: PostgreSQL, Prometheus, Grafana (Docker Desktop)
```powershell
cd deployment
docker compose --env-file ..\.env up -d
```
Then set `NEXOPS_DATABASE_URL=postgresql+psycopg://<POSTGRES_USER>:<POSTGRES_PASSWORD>@localhost:5432/nexops` in `.env`,
re-run the migration, and open Prometheus (http://localhost:9090) and Grafana (http://localhost:3000, credentials from `.env`;
dashboard *NexOps → NexOps Overview*). The compose stack is **not verified** in the build environment (see BUILD_STATUS).

## Running the tests (no Docker needed)
```powershell
.\scripts\test-all.ps1                         # lint, backend tests (SQLite), frontend typecheck/tests/build
```
or manually: `cd backend; .\.venv\Scripts\python.exe -m pytest -q` and `cd frontend; npm test`.
To run the backend suite against PostgreSQL: set `TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/dbname`
(the test database is dropped and recreated per test — use a throwaway database).

<img width="390" height="1244" alt="16-mobile-dashboard" src="https://github.com/user-attachments/assets/535bc740-b260-4c84-83ff-58116cbd6823" />

## Environment variables
See [.env.example](.env.example). Key ones (prefix `NEXOPS_`): `SECRET_KEY` (required, ≥32 chars, placeholder rejected),
`DATABASE_URL`, `ACCESS_TOKEN_MINUTES`, `CORS_ORIGINS` (JSON list), `RECOVERY_MODE` (only `simulated`),
`ALLOW_SELF_APPROVAL` (demo only, default false), detection thresholds (`BRUTE_FORCE_THRESHOLD`, `ERROR_RATE_THRESHOLD`, …,
see `backend/app/core/config.py`).

## Troubleshooting
| Symptom | Fix |
|---|---|
| `ValidationError ... secret_key` at start | Run `python scripts/generate_env.py` or set `NEXOPS_SECRET_KEY` (≥32 random chars). |
| Scripts blocked in PowerShell | `Set-ExecutionPolicy -Scope Process Bypass`. |
| `Database not ready` / connection refused | Wrong `NEXOPS_DATABASE_URL`, or Docker stack not up. SQLite default needs nothing. |
| No security incidents after "Run detection" | Security rules look back 10 minutes. Re-seed with `seed-demo --reset --detect` and run detection right away. |
| Dashboard shows "Cannot reach the API" | Start the backend on port 8000 (the Vite dev server proxies `/api`). |
| Prometheus target down | Backend must listen on port 8000 on the host; on Linux Docker use the compose `extra_hosts` entry. |
| `alembic` cannot find a module | Run it from the `backend/` folder. |

## Documentation
[Architecture](docs/ARCHITECTURE.md) · [API](docs/API.md) · [Security & threat model](docs/SECURITY.md) ·
[Observability](docs/OBSERVABILITY.md) · [Demo walkthrough](docs/DEMO.md) · [Build status & checklist](docs/BUILD_STATUS.md)

MIT licensed.
