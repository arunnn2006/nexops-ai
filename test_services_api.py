from datetime import datetime, timedelta, timezone


def test_service_validation_rules(client, admin_h):
    bad_name = client.post("/api/v1/services", json={"name": "Bad Name!"}, headers=admin_h)
    assert bad_name.status_code == 422
    secretish = client.post("/api/v1/services", json={"name": "svc-a", "meta": {"api_key": "abc"}}, headers=admin_h)
    assert secretish.status_code == 422
    unsafe = client.post(
        "/api/v1/services", json={"name": "svc-b", "is_demo": False, "recovery_allowed": True}, headers=admin_h
    )
    assert unsafe.status_code == 422
    ok = client.post("/api/v1/services", json={"name": "svc-c", "meta": {"owner": "team"}}, headers=admin_h)
    assert ok.status_code == 201
    assert client.post("/api/v1/services", json={"name": "svc-c"}, headers=admin_h).status_code == 409


def test_list_and_get_service(client, admin_h, viewer_h):
    sid = client.post("/api/v1/services", json={"name": "svc-list"}, headers=admin_h).json()["id"]
    assert [s["name"] for s in client.get("/api/v1/services", headers=viewer_h).json()] == ["svc-list"]
    assert client.get(f"/api/v1/services/{sid}", headers=viewer_h).status_code == 200
    assert client.get("/api/v1/services/9999", headers=viewer_h).status_code == 404


def test_metric_ingestion_updates_status_and_requires_operator(client, admin_h, operator_h, viewer_h):
    sid = client.post("/api/v1/services", json={"name": "svc-m"}, headers=admin_h).json()["id"]
    sample = {"status": "degraded", "latency_ms": 500, "error_rate": 0.1, "request_count": 10}
    assert client.post(f"/api/v1/services/{sid}/metrics", json=sample, headers=viewer_h).status_code == 403
    assert client.post(f"/api/v1/services/{sid}/metrics", json=sample, headers=operator_h).status_code == 201
    assert client.get(f"/api/v1/services/{sid}", headers=viewer_h).json()["status"] == "degraded"
    assert len(client.get(f"/api/v1/services/{sid}/metrics", headers=viewer_h).json()) == 1


def test_metric_validation(client, admin_h, operator_h):
    sid = client.post("/api/v1/services", json={"name": "svc-v"}, headers=admin_h).json()["id"]
    url = f"/api/v1/services/{sid}/metrics"
    assert (
        client.post(url, json={"status": "healthy", "latency_ms": -1, "error_rate": 0}, headers=operator_h).status_code
        == 422
    )
    assert (
        client.post(url, json={"status": "healthy", "latency_ms": 1, "error_rate": 2}, headers=operator_h).status_code
        == 422
    )
    future = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    assert (
        client.post(
            url, json={"status": "healthy", "latency_ms": 1, "error_rate": 0, "observed_at": future}, headers=operator_h
        ).status_code
        == 422
    )
    assert (
        client.post(
            url,
            json={"status": "healthy", "latency_ms": 1, "error_rate": 0, "observed_at": "2026-01-01T00:00:00"},
            headers=operator_h,
        ).status_code
        == 422
    )


def test_record_deployment_is_labelled_recorded(client, admin_h, operator_h):
    sid = client.post("/api/v1/services", json={"name": "svc-d"}, headers=admin_h).json()["id"]
    r = client.post(
        f"/api/v1/services/{sid}/deployments",
        json={"version": "1.2.3", "status": "succeeded", "commit_sha": "abcdef1"},
        headers=operator_h,
    )
    assert r.status_code == 201
    assert r.json()["source"] == "recorded" and r.json()["deployed_by"] == "operator@test.dev"
    assert client.get(f"/api/v1/services/{sid}", headers=admin_h).json()["current_version"] == "1.2.3"
    bad = client.post(
        f"/api/v1/services/{sid}/deployments",
        json={"version": "bad version!", "status": "succeeded"},
        headers=operator_h,
    )
    assert bad.status_code == 422
    assert len(client.get(f"/api/v1/deployments?service_id={sid}", headers=admin_h).json()) == 1
