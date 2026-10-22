# Observability

- **Logs**: JSON lines on stdout (`ts, level, logger, message, request_id, method, path, status, duration_ms, client`).
  Secret-looking fields are redacted. A request ID is returned in the `X-Request-ID` header.
- **Metrics** at `GET /metrics`:
  `nexops_http_requests_total{method,path,status}`, `nexops_http_request_duration_seconds` (histogram),
  `nexops_login_attempts_total{outcome}`, `nexops_recovery_events_total{event}`, and database-backed gauges
  `nexops_service_status{service,status}`, `nexops_service_latest_latency_ms`, `nexops_service_latest_error_rate`,
  `nexops_open_incidents{severity}`. Path labels use templates (`/api/v1/incidents/{incident_id}`) to keep cardinality low.
- **Prometheus**: `monitoring/prometheus.yml` scrapes `host.docker.internal:8000`; alert rules in `monitoring/alerts.yml`
  (backend down, service down, 5xx ratio, critical incidents open).
- **Grafana**: provisioned datasource and the dashboard `NexOps Overview` (request rate, p95 latency, 5xx, logins, services
  down, critical incidents, per-service latency/error rate, incidents by severity).
- Seeded sample metrics live in the **database** and are shown by the dashboard and the `nexops_service_*` gauges; the HTTP
  panels fill only as you use the API.

Status: configuration files are syntax-validated; the Docker stack itself was not run (see BUILD_STATUS).
