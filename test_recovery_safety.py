import ast
from pathlib import Path

from sqlalchemy import select

from app.models import AuditLog, Deployment, RecoveryRequest, Service
from app.services import recovery as recovery_module
from tests.conftest import PASSWORD


def mk_service(client, admin_h, name="demo-svc", **kw):
    body = {"name": name, "is_demo": True, "recovery_allowed": True, "current_version": "1.0.0", **kw}
    r = client.post("/api/v1/services", json=body, headers=admin_h)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def degrade(client, operator_h, sid, status="down"):
    r = client.post(
        f"/api/v1/services/{sid}/metrics",
        json={"status": status, "latency_ms": 100, "error_rate": 0.5},
        headers=operator_h,
    )
    assert r.status_code == 201


def request_recovery(client, operator_h, sid, action="restart_service"):
    return client.post("/api/v1/recovery/requests", json={"service_id": sid, "action": action}, headers=operator_h)


def phrase(action, name):
    return {"confirm": True, "confirmation_phrase": f"{action} {name}"}


def test_allowlist_rejects_arbitrary_actions(client, admin_h, operator_h, db):
    sid = mk_service(client, admin_h)
    for bad in ["rm -rf /", "docker run alpine", "restart_service; reboot", "RESTART_SERVICE", "shell", ""]:
        r = request_recovery(client, operator_h, sid, bad)
        assert r.status_code == 422, bad
    assert db.scalars(select(RecoveryRequest)).all() == []
    assert db.scalars(select(AuditLog).where(AuditLog.outcome == "denied")).all()


def test_non_demo_and_disabled_services_are_refused(client, admin_h, operator_h, db):
    prod = mk_service(client, admin_h, "prod-like", is_demo=False, recovery_allowed=False)
    off = mk_service(client, admin_h, "recovery-off", recovery_allowed=False)
    assert request_recovery(client, operator_h, prod).status_code == 403
    assert request_recovery(client, operator_h, off).status_code == 403
    assert db.scalars(select(RecoveryRequest)).all() == []


def test_viewer_cannot_request_and_operator_cannot_approve(client, admin_h, operator_h, viewer_h):
    sid = mk_service(client, admin_h)
    assert request_recovery(client, viewer_h, sid).status_code == 403
    rid = request_recovery(client, operator_h, sid).json()["id"]
    assert client.post(f"/api/v1/recovery/requests/{rid}/approve", headers=operator_h).status_code == 403
    assert client.post(f"/api/v1/recovery/requests/{rid}/approve", headers=viewer_h).status_code == 403


def test_cannot_execute_without_approval(client, admin_h, operator_h, db):
    sid = mk_service(client, admin_h)
    degrade(client, operator_h, sid)
    rid = request_recovery(client, operator_h, sid).json()["id"]
    r = client.post(
        f"/api/v1/recovery/requests/{rid}/execute", json=phrase("restart_service", "demo-svc"), headers=operator_h
    )
    assert r.status_code == 409
    assert db.get(Service, sid).simulated_state == "down"
    assert db.get(RecoveryRequest, rid).status == "pending"


def test_requester_cannot_self_approve_by_default(client, admin_h, make_user, login):
    sid = mk_service(client, admin_h)
    rid = request_recovery(client, admin_h, sid).json()["id"]
    r = client.post(f"/api/v1/recovery/requests/{rid}/approve", headers=admin_h)
    assert r.status_code == 403 and "own" in r.json()["error"]["message"]


def test_self_approval_allowed_only_when_enabled(settings, make_user):
    from fastapi.testclient import TestClient

    from app.db.base import Base
    from app.main import create_app

    s2 = settings.model_copy(update={"allow_self_approval": True})
    app = create_app(s2)
    Base.metadata.drop_all(app.state.engine)
    Base.metadata.create_all(app.state.engine)
    c = TestClient(app)
    from app.core.security import hash_password
    from app.models import User

    with app.state.session_factory() as db:
        db.add(User(email="solo@test.dev", role="admin", password_hash=hash_password(PASSWORD)))
        db.commit()
    tok = c.post("/api/v1/auth/login", json={"email": "solo@test.dev", "password": PASSWORD}).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    sid = c.post("/api/v1/services", json={"name": "solo-svc", "recovery_allowed": True}, headers=h).json()["id"]
    rid = c.post("/api/v1/recovery/requests", json={"service_id": sid, "action": "restart_service"}, headers=h).json()[
        "id"
    ]
    assert c.post(f"/api/v1/recovery/requests/{rid}/approve", headers=h).status_code == 200
    app.state.engine.dispose()


def full_flow(client, admin_h, operator_h, action="restart_service", state="down"):
    sid = mk_service(client, admin_h)
    degrade(client, operator_h, sid, state)
    rid = request_recovery(client, operator_h, sid, action).json()["id"]
    assert (
        client.post(f"/api/v1/recovery/requests/{rid}/approve", json={"note": "ok"}, headers=admin_h).status_code == 200
    )
    return sid, rid


def test_confirmation_required_and_must_match(client, admin_h, operator_h, db):
    sid, rid = full_flow(client, admin_h, operator_h)
    url = f"/api/v1/recovery/requests/{rid}/execute"
    assert (
        client.post(
            url, json={"confirm": False, "confirmation_phrase": "restart_service demo-svc"}, headers=operator_h
        ).status_code
        == 422
    )
    assert client.post(url, json={"confirm": True, "confirmation_phrase": "yes"}, headers=operator_h).status_code == 422
    assert (
        client.post(
            url, json={"confirm": True, "confirmation_phrase": "restart_service other"}, headers=operator_h
        ).status_code
        == 422
    )
    assert db.get(Service, sid).simulated_state == "down"


def test_successful_simulated_restart_with_verification_and_audit(client, admin_h, operator_h, db):
    sid, rid = full_flow(client, admin_h, operator_h)
    r = client.post(
        f"/api/v1/recovery/requests/{rid}/execute", json=phrase("restart_service", "demo-svc"), headers=operator_h
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "executed" and body["mode"] == "simulated"
    assert body["result"]["simulated"] is True and body["verification"]["passed"] is True
    assert db.get(Service, sid).status == "healthy"
    actions = [a.action for a in db.scalars(select(AuditLog).order_by(AuditLog.id)).all()]
    assert {"recovery.request", "recovery.approve", "recovery.execute"} <= set(actions)
    # executing twice is impossible
    again = client.post(
        f"/api/v1/recovery/requests/{rid}/execute", json=phrase("restart_service", "demo-svc"), headers=operator_h
    )
    assert again.status_code == 409


def test_failed_verification_is_reported_not_hidden(client, admin_h, operator_h):
    sid, rid = full_flow(client, admin_h, operator_h, action="clear_cache", state="down")
    r = client.post(
        f"/api/v1/recovery/requests/{rid}/execute", json=phrase("clear_cache", "demo-svc"), headers=operator_h
    )
    assert r.status_code == 200
    assert r.json()["status"] == "verification_failed" and r.json()["verification"]["passed"] is False


def test_simulated_rollback_restores_previous_version(client, admin_h, operator_h, db):
    sid = mk_service(client, admin_h, current_version=None)
    for version, ago in (("1.0.0", "2026-01-01T00:00:00+00:00"), ("1.1.0", "2026-01-02T00:00:00+00:00")):
        assert (
            client.post(
                f"/api/v1/services/{sid}/deployments",
                json={"version": version, "status": "succeeded", "deployed_at": ago},
                headers=operator_h,
            ).status_code
            == 201
        )
    degrade(client, operator_h, sid, "degraded")
    rid = request_recovery(client, operator_h, sid, "rollback_last_deployment").json()["id"]
    client.post(f"/api/v1/recovery/requests/{rid}/approve", headers=admin_h)
    r = client.post(
        f"/api/v1/recovery/requests/{rid}/execute",
        json=phrase("rollback_last_deployment", "demo-svc"),
        headers=operator_h,
    )
    assert r.json()["status"] == "executed"
    assert db.get(Service, sid).current_version == "1.0.0"
    sim = db.scalars(select(Deployment).where(Deployment.source == "simulated_recovery")).one()
    assert "SIMULATED" in sim.notes


def test_rollback_without_previous_version_fails_cleanly(client, admin_h, operator_h):
    sid = mk_service(client, admin_h, current_version=None)
    client.post(
        f"/api/v1/services/{sid}/deployments", json={"version": "1.0.0", "status": "succeeded"}, headers=operator_h
    )
    rid = request_recovery(client, operator_h, sid, "rollback_last_deployment").json()["id"]
    client.post(f"/api/v1/recovery/requests/{rid}/approve", headers=admin_h)
    r = client.post(
        f"/api/v1/recovery/requests/{rid}/execute",
        json=phrase("rollback_last_deployment", "demo-svc"),
        headers=operator_h,
    )
    assert r.json()["status"] == "failed" and "earlier successful" in r.json()["result"]["error"]


def test_service_made_ineligible_after_approval_blocks_execution(client, admin_h, operator_h, db):
    sid, rid = full_flow(client, admin_h, operator_h)
    svc = db.get(Service, sid)
    svc.recovery_allowed = False
    db.commit()
    r = client.post(
        f"/api/v1/recovery/requests/{rid}/execute", json=phrase("restart_service", "demo-svc"), headers=operator_h
    )
    assert r.status_code == 403


def test_expired_approval_cannot_execute(client, admin_h, operator_h, db):
    from datetime import timedelta

    sid, rid = full_flow(client, admin_h, operator_h)
    rr = db.get(RecoveryRequest, rid)
    rr.decided_at = rr.decided_at - timedelta(hours=2)
    db.commit()
    r = client.post(
        f"/api/v1/recovery/requests/{rid}/execute", json=phrase("restart_service", "demo-svc"), headers=operator_h
    )
    assert r.status_code == 409 and "expired" in r.json()["error"]["message"]


def test_other_operator_cannot_execute_someone_elses_request(client, admin_h, operator_h, make_user, login):
    sid, rid = full_flow(client, admin_h, operator_h)
    make_user("op2@test.dev", "operator")
    h2 = login("op2@test.dev")
    r = client.post(f"/api/v1/recovery/requests/{rid}/execute", json=phrase("restart_service", "demo-svc"), headers=h2)
    assert r.status_code == 403


def test_duplicate_open_requests_rejected(client, admin_h, operator_h):
    sid = mk_service(client, admin_h)
    assert request_recovery(client, operator_h, sid).status_code == 201
    assert request_recovery(client, operator_h, sid).status_code == 409


def test_audit_never_contains_secrets(client, admin_h, operator_h, db):
    sid = mk_service(client, admin_h)
    request_recovery(client, operator_h, sid)
    dump = str([a.detail for a in db.scalars(select(AuditLog)).all()]).lower()
    assert PASSWORD.lower() not in dump and "bearer" not in dump and "hash" not in dump


def test_recovery_module_has_no_process_or_network_capabilities():
    tree = ast.parse(Path(recovery_module.__file__).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    forbidden = {
        "subprocess",
        "os",
        "socket",
        "shlex",
        "docker",
        "requests",
        "httpx",
        "urllib",
        "asyncio",
        "ctypes",
        "pty",
    }
    assert not (imported & forbidden), imported & forbidden
    source = Path(recovery_module.__file__).read_text()
    for needle in ("eval(", "exec(", "__import__", "os.system", "Popen"):
        assert needle not in source
    assert set(recovery_module.ALLOWED_ACTIONS) == {"restart_service", "clear_cache", "rollback_last_deployment"}
