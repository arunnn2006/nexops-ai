import json
import logging

from app.core.logging import JsonFormatter, log_event
from app.services.seed import seed_demo


def test_health_and_ready(client):
    assert client.get("/api/v1/health").json() == {"status": "ok"}
    assert client.get("/api/v1/ready").json() == {"status": "ready"}


def test_metrics_endpoint_exposes_http_and_domain_metrics(client, db, operator_h):
    seed_demo(db)
    client.post("/api/v1/incidents/detect", headers=operator_h)
    client.get("/api/v1/services", headers=operator_h)
    text = client.get("/metrics").text
    assert 'nexops_http_requests_total{method="GET",path="/api/v1/services",status="200"}' in text
    assert "nexops_http_request_duration_seconds_bucket" in text
    assert 'nexops_service_status{service="inventory-service",status="down"} 1.0' in text
    assert 'nexops_open_incidents{severity="critical"} 2.0' in text
    assert 'nexops_login_attempts_total{outcome="success"}' in text
    assert "/api/v1/incidents/{incident_id}" not in text or "unmatched" not in text


def test_request_id_header_and_error_format(client):
    r = client.get("/api/v1/services")
    assert r.status_code == 401 and r.headers["x-request-id"]
    body = r.json()
    assert body["error"]["code"] == "unauthorized" and "message" in body["error"]
    v = client.post("/api/v1/auth/login", json={"email": "not-an-email", "password": "x"})
    assert v.status_code == 422 and v.json()["error"]["code"] == "validation_error"
    assert v.json()["error"]["details"][0]["field"] == "email"
    assert client.get("/api/v1/nope").json()["error"]["code"] == "not_found"


def test_unhandled_errors_do_not_leak_details(app):
    from fastapi.testclient import TestClient

    @app.get("/boom")
    def boom():
        raise RuntimeError("secret-internal-detail")

    r = TestClient(app, raise_server_exceptions=False).get("/boom")
    assert r.status_code == 500 and "secret-internal-detail" not in r.text


def test_structured_logs_are_json_and_redacted():
    rec = logging.LogRecord("t", logging.INFO, __file__, 1, "login", None, None)
    rec.fields = {"user": "a@test.dev", "password": "hunter2", "nested": {"access_token": "abc", "ok": 1}}
    out = json.loads(JsonFormatter().format(rec))
    assert out["message"] == "login" and out["level"] == "INFO" and out["user"] == "a@test.dev"
    assert (
        out["password"] == "[REDACTED]" and out["nested"]["access_token"] == "[REDACTED]" and out["nested"]["ok"] == 1
    )


def test_request_log_line_emitted(client, caplog):
    with caplog.at_level(logging.INFO, logger="nexops.http"):
        client.get("/api/v1/health", headers={"Authorization": "Bearer super-secret-token-value"})
    records = [r for r in caplog.records if r.name == "nexops.http" and r.getMessage() == "request"]
    assert records
    fields = records[-1].fields
    assert fields["path"] == "/api/v1/health" and fields["status"] == 200 and "request_id" in fields
    rendered = JsonFormatter().format(records[-1])
    assert "super-secret-token-value" not in rendered and json.loads(rendered)["duration_ms"] >= 0
    _ = log_event
