import json

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_secret_key_validation(monkeypatch):
    monkeypatch.delenv("NEXOPS_SECRET_KEY", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # missing: no insecure default exists
    with pytest.raises(ValidationError):
        Settings(secret_key="short", _env_file=None)
    with pytest.raises(ValidationError):
        Settings(secret_key="change-me-" + "x" * 40, _env_file=None)
    assert Settings(secret_key="k" * 40, _env_file=None).recovery_mode == "simulated"


def test_recovery_mode_cannot_be_set_to_real_execution():
    with pytest.raises(ValidationError):
        Settings(secret_key="k" * 40, recovery_mode="real", _env_file=None)


def test_openapi_never_exposes_password_hash_or_token_secrets(client):
    schema = json.dumps(client.get("/api/v1/openapi.json").json())
    assert "password_hash" not in schema
    assert "/api/v1/recovery/requests/{request_id}/execute" in schema


def test_no_default_admin_exists(client, db):
    from sqlalchemy import func, select

    from app.models import User

    assert db.scalar(select(func.count()).select_from(User)) == 0
    assert client.post("/api/v1/auth/login", json={"email": "admin@admin.com", "password": "admin"}).status_code == 401
