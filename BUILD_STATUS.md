# Build status

**State: complete MVP, all planned milestones implemented.** Nothing below is labelled complete unless it was run.
Build environment: Linux (Ubuntu 24), Python 3.12.3, Node 22.22.2, PostgreSQL 16.15 installed natively.
**Not available in the build environment:** Windows, PowerShell, Docker, a web browser.

## Exact results (run during the build)
| Check | Result |
|---|---|
| `ruff check` / `ruff format --check` (backend) | pass / 43 files formatted |
| Backend `pytest` on SQLite | **74 passed**, 0 failed, 0 skipped (96% line coverage of `app/`) |
| Backend `pytest` on **PostgreSQL 16.15** (`TEST_DATABASE_URL`) | **74 passed**, 0 failed, 0 skipped |
| Alembic `upgrade head`, `check` (models == migration), `downgrade base`, re-upgrade on PostgreSQL | pass |
| Alembic `upgrade head` + `check` on SQLite | pass (inside the test suite) |
| Frontend `tsc --noEmit` | pass |
| Frontend `vitest run` | **17 passed**, 0 failed |
| Frontend `npm run build` (Vite production build) | pass (≈290 kB JS, 91 kB gzip) |
| Live end-to-end (`scripts/e2e_demo.py`): real uvicorn + PostgreSQL 16, CLI-created users, CLI seed | **16/16 steps passed** |
| Server log scan after e2e: admin password / "Bearer" occurrences | 0 / 0 |
| YAML/JSON syntax: Prometheus, alerts, Grafana provisioning + dashboard, compose, CI workflow | parse OK |

Test areas: authentication & token attacks, role enforcement, service/metric/deployment validation, each detection rule
(boundaries, windows, dedupe, correlation), diagnosis honesty (facts vs hypotheses, confidence cap, no invented evidence),
recovery safety (allowlist, demo-only, approval, self-approval, confirmation, expiry, ownership, no process/network imports),
metrics/logging/redaction/error format, CLI, migrations, seed → expected incident set.

## Feature checklist
Legend: **I** implemented · **T** automated tests ran and passed · **S** simulated · **U** unverified (not run here)

| Feature | I | T | S | U | Notes |
|---|:-:|:-:|:-:|:-:|---|
| FastAPI `/api/v1`, error format, health/ready | ✔ | ✔ | | | |
| SQLAlchemy 2 + Alembic, PostgreSQL | ✔ | ✔ | | | PostgreSQL 16.15 native, not Docker |
| Registration, login, JWT, RBAC | ✔ | ✔ | | | no rate limiting / revocation |
| Service registry, metrics, deployment records | ✔ | ✔ | | | deployments are *recorded*, never performed |
| Sample data seed | ✔ | ✔ | ✔ | | synthetic, labelled `sample` |
| Six detection rules + correlation | ✔ | ✔ | | | on-demand, no scheduler |
| Incident search/filter/pagination | ✔ | ✔ | | | |
| Deterministic diagnosis | ✔ | ✔ | | | no external AI exists (none required) |
| Recovery: allowlist/approval/confirmation/verification/audit | ✔ | ✔ | ✔ | | **simulated only**; no real execution code |
| Prometheus metrics endpoint, JSON logs | ✔ | ✔ | | | |
| Prometheus config, alert rules, Grafana dashboard | ✔ | | | ✔ | syntax-checked; queries never run against Prometheus |
| Docker Compose stack | ✔ | | | ✔ | never started (no Docker) |
| React dashboard (all screens) | ✔ | ✔ | | ✔ | logic tested in jsdom; **never viewed in a browser**, responsive layout unchecked |
| Vite dev proxy to backend | ✔ | | | ✔ | server-side verified by e2e; browser path not exercised |
| Windows PowerShell scripts | ✔ | | | ✔ | not run on Windows/PowerShell |
| GitHub Actions CI | ✔ | | | ✔ | YAML parses; never executed on GitHub |
| Dependency vulnerability audit | | | | ✔ | not performed |
| User-management UI | | | | | not built (role changes via API/CLI) |
| External AI integration | | | | | intentionally not implemented |

## Known issues / caveats
- Dependencies resolved to the newest releases at build time (e.g. SQLAlchemy 2.1, Starlette 1.x, React 19, Vite 7).
  A Starlette deprecation warning about `httpx` in `TestClient` appears in test output; harmless.
- `docs/SECURITY.md` lists security limitations (no rate limiting, unauthenticated `/metrics`, sessionStorage token, …).
- The first failed attempt to install PostgreSQL in the background was interrupted; it was repaired and re-run — no effect on the project.

## Next tasks (suggested)
1. Run `scripts\setup.ps1` on Windows and fix any PowerShell-specific issues.
2. Start the Docker stack and confirm Prometheus scrapes the backend and the Grafana dashboard renders.
3. Open the dashboard in a browser; check the responsive layout and the demo walkthrough.
4. Add a scheduler for detection, rate limiting/lockout, and a user-management screen.
