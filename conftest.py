import os
import secrets
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.security import hash_password
from app.db.base import Base
from app.main import create_app
from app.models import User

TEST_DB = os.environ.get("TEST_DATABASE_URL", "sqlite://")
PASSWORD = "Str0ng-test-passphrase!"
NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)


def minutes_ago(n: float) -> datetime:
    return NOW - timedelta(minutes=n)


@pytest.fixture()
def settings() -> Settings:
    return Settings(secret_key=secrets.token_urlsafe(48), database_url=TEST_DB, _env_file=None)


@pytest.fixture()
def app(settings):
    application = create_app(settings)
    Base.metadata.drop_all(application.state.engine)
    Base.metadata.create_all(application.state.engine)
    yield application
    Base.metadata.drop_all(application.state.engine)
    application.state.engine.dispose()


@pytest.fixture()
def client(app):
    return TestClient(app)


@pytest.fixture()
def db(app):
    with app.state.session_factory() as session:
        yield session


@pytest.fixture()
def make_user(db):
    def _make(email: str, role: str = "viewer", active: bool = True) -> User:
        user = User(email=email, password_hash=hash_password(PASSWORD), role=role, is_active=active)
        db.add(user)
        db.commit()
        return user

    return _make


@pytest.fixture()
def login(client):
    def _login(email: str) -> dict:
        resp = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        assert resp.status_code == 200, resp.text
        return {"Authorization": f"Bearer {resp.json()['access_token']}"}

    return _login


@pytest.fixture()
def admin_h(make_user, login):
    make_user("admin@test.dev", "admin")
    return login("admin@test.dev")


@pytest.fixture()
def operator_h(make_user, login):
    make_user("operator@test.dev", "operator")
    return login("operator@test.dev")


@pytest.fixture()
def viewer_h(make_user, login):
    make_user("viewer@test.dev", "viewer")
    return login("viewer@test.dev")
