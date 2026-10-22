from app.services.seed import seed_demo


def seeded_and_detected(client, db, operator_h):
    seed_demo(db)
    r = client.post("/api/v1/incidents/detect", headers=operator_h)
    assert r.status_code == 200, r.text
    return r.json()


def test_detect_requires_operator(client, db, viewer_h, operator_h):
    seed_demo(db)
    assert client.post("/api/v1/incidents/detect").status_code == 401
    assert client.post("/api/v1/incidents/detect", headers=viewer_h).status_code == 403
    assert client.post("/api/v1/incidents/detect", headers=operator_h).status_code == 200


def test_seed_demo_produces_expected_incident_set(client, db, operator_h):
    result = seeded_and_detected(client, db, operator_h)
    got = sorted((i["rule"], i["service_name"], i["severity"]) for i in result["incidents"])
    assert got == sorted(
        [
            ("brute_force", None, "critical"),
            ("high_error_rate", "checkout-api", "high"),
            ("high_latency", "report-worker", "medium"),
            ("privilege_change", None, "high"),
            ("service_down", "inventory-service", "critical"),
            ("suspicious_access", None, "high"),
        ]
    )
    again = client.post("/api/v1/incidents/detect", headers=operator_h).json()
    assert again["created"] == 0  # idempotent


def test_filters_search_and_pagination(client, db, operator_h, viewer_h):
    seeded_and_detected(client, db, operator_h)

    def get(qs):
        return client.get(f"/api/v1/incidents{qs}", headers=viewer_h).json()

    assert get("")["total"] == 6
    assert get("?severity=critical")["total"] == 2
    assert {i["rule"] for i in get("?severity=critical")["items"]} == {"brute_force", "service_down"}
    assert get("?rule=high_latency")["total"] == 1
    assert get("?q=checkout")["total"] == 1
    assert get("?q=ch%25ut")["total"] == 0  # LIKE wildcards are escaped, not interpreted
    assert get("?q=ch_ckout")["total"] == 0
    assert get("?status=resolved")["total"] == 0
    page = get("?limit=2&offset=2")
    assert len(page["items"]) == 2 and page["total"] == 6
    assert client.get("/api/v1/incidents?severity=bogus", headers=viewer_h).status_code == 422
    svc_id = get("?rule=service_down")["items"][0]["service_id"]
    assert get(f"?service_id={svc_id}")["total"] == 1


def test_incident_detail_has_evidence_and_diagnosis(client, db, operator_h, viewer_h):
    result = seeded_and_detected(client, db, operator_h)
    inc = next(i for i in result["incidents"] if i["rule"] == "high_error_rate")
    detail = client.get(f"/api/v1/incidents/{inc['id']}", headers=viewer_h).json()
    kinds = {e["kind"] for e in detail["evidence"]}
    assert {"service_status", "metric", "deployment", "log"} <= kinds
    dep = next(e for e in detail["evidence"] if e["kind"] == "deployment")
    assert dep["data"]["version"] == "2.4.1" and dep["data"]["found"] is True
    dx = detail["latest_diagnosis"]
    assert dx["method"] == "deterministic" and dx["facts"] and dx["hypotheses"] and dx["limitations"]
    assert client.get(f"/api/v1/incidents/{inc['id']}/diagnosis", headers=viewer_h).status_code == 200
    assert client.get("/api/v1/incidents/99999", headers=viewer_h).status_code == 404


def test_inventory_outage_has_no_deployment_evidence(client, db, operator_h, viewer_h):
    result = seeded_and_detected(client, db, operator_h)
    inc = next(i for i in result["incidents"] if i["rule"] == "service_down")
    detail = client.get(f"/api/v1/incidents/{inc['id']}", headers=viewer_h).json()
    dep = next(e for e in detail["evidence"] if e["kind"] == "deployment")
    assert dep["data"]["found"] is False
    assert any("connection refused" in e["summary"] for e in detail["evidence"] if e["kind"] == "log")


def test_status_update_and_diagnose_endpoints(client, db, operator_h, viewer_h):
    result = seeded_and_detected(client, db, operator_h)
    iid = result["incidents"][0]["id"]
    assert (
        client.patch(f"/api/v1/incidents/{iid}/status", json={"status": "resolved"}, headers=viewer_h).status_code
        == 403
    )
    r = client.patch(f"/api/v1/incidents/{iid}/status", json={"status": "resolved"}, headers=operator_h)
    assert r.status_code == 200 and r.json()["resolved_at"] is not None
    assert (
        client.patch(f"/api/v1/incidents/{iid}/status", json={"status": "nope"}, headers=operator_h).status_code == 422
    )
    assert client.post(f"/api/v1/incidents/{iid}/diagnose", headers=operator_h).status_code == 200
    assert client.post(f"/api/v1/incidents/{iid}/diagnose", headers=viewer_h).status_code == 403


def test_event_ingestion_validates_and_redacts(client, db, operator_h, viewer_h):
    seed_demo(db)
    ev = {
        "event_type": "access",
        "source_ip": "198.51.100.1",
        "path": "/x",
        "status_code": 404,
        "detail": {"password": "hunter2-hunter2", "note": "ok"},
    }
    assert client.post("/api/v1/security-events", json=ev, headers=viewer_h).status_code == 403
    r = client.post("/api/v1/security-events", json=ev, headers=operator_h)
    assert r.status_code == 201 and r.json()["detail"]["password"] == "[REDACTED]"
    assert (
        client.post("/api/v1/security-events", json={**ev, "service_id": 9999}, headers=operator_h).status_code == 422
    )
    assert (
        client.post("/api/v1/security-events", json={**ev, "event_type": "bogus"}, headers=operator_h).status_code
        == 422
    )
    assert (
        client.post("/api/v1/security-events", json={**ev, "detail": {"x": "a" * 3000}}, headers=operator_h).status_code
        == 422
    )


def test_dashboard_summary_and_audit_listing(client, db, operator_h, admin_h):
    seeded_and_detected(client, db, operator_h)
    s = client.get("/api/v1/dashboard/summary", headers=operator_h).json()
    assert s["total_open_incidents"] == 6 and s["open_incidents_by_severity"]["critical"] == 2
    assert s["services_by_status"]["down"] == 1 and len(s["recent_deployments"]) == 5
    audit = client.get("/api/v1/audit?action=incident", headers=admin_h).json()
    assert audit and all(a["action"].startswith("incident") for a in audit)
