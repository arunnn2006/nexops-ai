# Reproducible demo walkthrough

Uses synthetic data. Replace passwords with your own; they are prompted, never stored in files.

## 1. Prepare (from `backend/`)
```powershell
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m app.cli create-user --email admin@example.com --role admin
.\.venv\Scripts\python.exe -m app.cli create-user --email operator@example.com --role operator
.\.venv\Scripts\python.exe -m app.cli seed-demo --reset --detect
```
Seeding creates 5 services (one non-demo `legacy-billing`, one demo service with recovery disabled), sample deployments, 3 hours
of metric samples, and sample security events relative to *now*. `--detect` runs detection immediately and creates six incidents.
(Security rules use a 10-minute window; if you wait longer, re-run with `--reset --detect`.)

## 2. Walk through in the dashboard (http://localhost:5173)
1. Sign in as **operator**. *Dashboard* shows service status counts, open incidents by severity, recent deployments.
2. *Services* → click `checkout-api`: latency and error-rate charts show the spike (sample data).
3. *Incidents* → filter severity `critical`; search `checkout`. Open **High error rate: checkout-api**:
   evidence shows the service status, metrics, deployment **2.4.1** recorded 10 minutes before onset, and application errors.
   The diagnosis lists *observed facts* separately from *hypotheses (not confirmed)* with capped confidence.
4. Open **Service unavailable: inventory-service**: evidence says *no deployment recorded* in the lookback window and shows
   "connection refused" errors; the hypothesis cites logs, not a deployment.
5. Open the **brute-force** incident: failed logins from one documentation-range IP followed by a success → critical.
6. On the inventory outage choose `restart_service` → *Submit request* (simulated).
7. *Sign out*, sign in as **admin** → *Recovery*: Approve the request (the requester cannot approve their own).
8. Sign in as **operator** again → *Recovery*: type the displayed phrase (`restart_service inventory-service`) → *Execute (simulated)*.
   The result shows `simulated: true` and a passed verification; the service becomes `healthy`.
9. As **admin** → *Audit*: see request, approval and execution, plus any `denied` attempts.

## 3. Scripted version
With the server running and both users created, export their emails/passwords as `E2E_ADMIN_EMAIL`, `E2E_ADMIN_PASSWORD`,
`E2E_OPERATOR_EMAIL`, `E2E_OPERATOR_PASSWORD` and run `python scripts/e2e_demo.py` (16 checks, exits non-zero on failure).

## Safety checks you can show
- `POST /recovery/requests` with `"action": "rm -rf /"` → 422, audited as denied.
- Execute before approval → 409. Execute with a wrong phrase → 422. Request recovery on `legacy-billing` → 403.
