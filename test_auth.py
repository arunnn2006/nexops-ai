import jwt
from sqlalchemy import select

from app.models import AuditLog, SecurityEvent, User
from tests.conftest import PASSWORD


def test_register_creates_viewer_and_hides_hash(client):
    r = client.post("/api/v1/auth/register", json={"email": "New@Test.dev", "password": PASSWORD})
    assert r.status_code == 201
    body = r.json()
    assert body["email"] == "new@test.dev" and body["role"] == "viewer"
    assert "password" not in str(body).lower() and "hash" not in str(body).lower()


def test_register_cannot_escalate_role(client):
    r = client.post("/api/v1/auth/register", json={"email": "x@test.dev", "password": PASSWORD, "role": "admin"})
    assert r.status_code == 201 and r.json()["role"] == "viewer"


def test_register_rejects_weak_password_and_duplicates(client):
    assert client.post("/api/v1/auth/register", json={"email": "a@test.dev", "password": "short"}).status_code == 422
    assert client.post("/api/v1/auth/register", json={"email": "a@test.dev", "password": PASSWORD}).status_code == 201
    assert client.post("/api/v1/auth/register", json={"email": "A@test.dev", "password": PASSWORD}).status_code == 409


def test_login_success_and_token_works(client, make_user):
    make_user("u@test.dev")
    r = client.post("/api/v1/auth/login", json={"email": "u@test.dev", "password": PASSWORD})
    assert r.status_code == 200
    data = r.json()
    assert data["token_type"] == "bearer" and "password_hash" not in str(data)
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {data['access_token']}"})
    assert me.status_code == 200 and me.json()["email"] == "u@test.dev"


def test_login_failure_is_generic_and_recorded(client, make_user, db):
    make_user("u@test.dev")
    wrong = client.post("/api/v1/auth/login", json={"email": "u@test.dev", "password": "wrong-password-123"})
    unknown = client.post("/api/v1/auth/login", json={"email": "nobody@test.dev", "password": "wrong-password-123"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()
    events = db.scalars(select(SecurityEvent).where(SecurityEvent.event_type == "login_failed")).all()
    assert len(events) == 2
    assert "wrong-password-123" not in str([e.detail for e in events] + [e.actor for e in events])


def test_inactive_user_cannot_login_or_use_token(client, make_user, login, db):
    user = make_user("u@test.dev")
    headers = login("u@test.dev")
    user.is_active = False
    db.commit()
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    assert client.post("/api/v1/auth/login", json={"email": "u@test.dev", "password": PASSWORD}).status_code == 401


def test_missing_invalid_tampered_and_expired_tokens(client, make_user, settings):
    make_user("u@test.dev")
    assert client.get("/api/v1/auth/me").status_code == 401
    assert client.get("/api/v1/auth/me", headers={"Authorization": "Bearer garbage"}).status_code == 401
    forged = jwt.encode(
        {"sub": "1", "exp": 9999999999}, "some-other-secret-key-of-32-chars-minimum!", algorithm="HS256"
    )
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    expired = jwt.encode({"sub": "1", "exp": 1}, settings.secret_key, algorithm="HS256")
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired}"}).status_code == 401
    none_alg = jwt.encode({"sub": "1", "exp": 9999999999}, None, algorithm="none")
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {none_alg}"}).status_code == 401


def test_role_enforced_server_side(client, viewer_h, operator_h, admin_h):
    body = {"name": "svc-one", "description": "x"}
    assert client.post("/api/v1/services", json=body).status_code == 401
    assert client.post("/api/v1/services", json=body, headers=viewer_h).status_code == 403
    assert client.post("/api/v1/services", json=body, headers=operator_h).status_code == 403
    assert client.post("/api/v1/services", json=body, headers=admin_h).status_code == 201
    assert client.get("/api/v1/users", headers=operator_h).status_code == 403
    assert client.get("/api/v1/audit", headers=operator_h).status_code == 403
    assert client.get("/api/v1/audit", headers=admin_h).status_code == 200


def test_role_change_records_event_and_audit_and_protects_last_admin(client, admin_h, make_user, db):
    target = make_user("t@test.dev", "viewer")
    r = client.patch(f"/api/v1/users/{target.id}/role", json={"role": "operator"}, headers=admin_h)
    assert r.status_code == 200 and r.json()["role"] == "operator"
    ev = db.scalars(select(SecurityEvent).where(SecurityEvent.event_type == "role_change")).one()
    assert ev.detail["new_role"] == "operator" and ev.actor == "admin@test.dev"
    assert db.scalars(select(AuditLog).where(AuditLog.action == "user.role_change")).one().outcome == "success"
    admin = db.scalars(select(User).where(User.email == "admin@test.dev")).one()
    r = client.patch(f"/api/v1/users/{admin.id}/role", json={"role": "viewer"}, headers=admin_h)
    assert r.status_code == 409


def test_token_role_claim_is_not_trusted(client, make_user, settings):
    user = make_user("v@test.dev", "viewer")
    forged = jwt.encode(
        {"sub": str(user.id), "exp": 9999999999, "role": "admin"}, settings.secret_key, algorithm="HS256"
    )
    r = client.post("/api/v1/services", json={"name": "svc-x"}, headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 403
