# API

Base path `/api/v1`. Interactive docs: `http://127.0.0.1:8000/docs` (OpenAPI JSON at `/api/v1/openapi.json`).
Authenticate with `Authorization: Bearer <token>` from `POST /auth/login`. Errors share one shape:
`{"error": {"code": "...", "message": "...", "details": [...]}}`.

| Method & path | Min role | Notes |
|---|---|---|
| `POST /auth/register` | public | Always creates a `viewer`; password ≥ 12 chars |
| `POST /auth/login` | public | Generic 401 on failure; failures are recorded as security events |
| `GET /auth/me` | viewer | |
| `GET /users`, `PATCH /users/{id}/role` | admin | Role changes are audited and emitted as security events; last admin protected |
| `GET /services`, `GET /services/{id}`, `GET /services/{id}/metrics` | viewer | |
| `POST /services` | admin | `recovery_allowed` requires `is_demo`; secret-looking metadata keys rejected |
| `POST /services/{id}/metrics` | operator | Ingest a health/latency/error sample |
| `GET /deployments`, `POST /services/{id}/deployments` | viewer / operator | POST *records* a deployment; it does not deploy |
| `GET /incidents` | viewer | Filters: `status, severity, rule, service_id, q, limit, offset` |
| `GET /incidents/{id}` | viewer | Includes evidence and latest diagnosis |
| `POST /incidents/detect` | operator | Runs all rules, returns newly created incidents |
| `PATCH /incidents/{id}/status` | operator | `open / investigating / resolved` |
| `POST /incidents/{id}/diagnose`, `GET /incidents/{id}/diagnosis` | operator / viewer | |
| `GET/POST /security-events` | operator | Ingest access/app-log lines; `detail` is redacted and size-limited |
| `GET /recovery/actions` | viewer | The allowlist and its simulated effects |
| `GET/POST /recovery/requests` | viewer / operator | Allowlist + demo-service checks |
| `POST /recovery/requests/{id}/approve` \| `reject` | admin | Requester cannot self-approve unless `ALLOW_SELF_APPROVAL=true` |
| `POST /recovery/requests/{id}/execute` | operator (requester) / admin | Body `{"confirm": true, "confirmation_phrase": "<action> <service-name>"}`; approval expires after 30 min |
| `GET /audit` | admin | Filters `action` (prefix), `outcome` |
| `GET /dashboard/summary` | viewer | |
| `GET /health`, `GET /ready` | public | Liveness / DB readiness |
| `GET /metrics` (root path) | public | Prometheus exposition |

Recovery request lifecycle: `pending → approved → executed | failed | verification_failed`, or `rejected | expired`.
