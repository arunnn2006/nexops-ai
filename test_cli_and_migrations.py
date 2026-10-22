import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session

from app.cli import main
from app.models import AuditLog, Service, User

BACKEND = Path(__file__).resolve().parents[1]


def cli_env(tmp_path):
    return {**os.environ, "NEXOPS_DATABASE_URL": f"sqlite:///{tmp_path / 'cli.db'}", "NEXOPS_SECRET_KEY": "z" * 48}


def test_alembic_upgrade_creates_all_tables_and_matches_models(tmp_path):
    env = cli_env(tmp_path)
    up = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"], cwd=BACKEND, env=env, capture_output=True, text=True
    )
    assert up.returncode == 0, up.stderr
    tables = set(inspect(create_engine(env["NEXOPS_DATABASE_URL"])).get_table_names())
    assert {
        "users",
        "services",
        "deployments",
        "metric_samples",
        "security_events",
        "incidents",
        "evidence",
        "diagnoses",
        "recovery_requests",
        "audit_logs",
        "alembic_version",
    } <= tables
    chk = subprocess.run(
        [sys.executable, "-m", "alembic", "check"], cwd=BACKEND, env=env, capture_output=True, text=True
    )
    assert chk.returncode == 0, chk.stdout + chk.stderr  # models and migrations agree


def test_cli_create_user_seed_and_detect(tmp_path, monkeypatch):
    env = cli_env(tmp_path)
    for k in ("NEXOPS_DATABASE_URL", "NEXOPS_SECRET_KEY"):
        monkeypatch.setenv(k, env[k])
    monkeypatch.setenv("NEXOPS_NEW_USER_PASSWORD", "A-long-cli-passphrase-1")
    from app.core.config import get_settings

    get_settings.cache_clear()
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"], cwd=BACKEND, env=env, check=True, capture_output=True
    )
    assert main(["create-user", "--email", "Boss@Test.dev", "--role", "admin"]) == 0
    assert main(["create-user", "--email", "boss@test.dev", "--role", "admin"]) == 1  # duplicate
    assert main(["seed-demo", "--detect"]) == 0
    assert main(["seed-demo"]) == 1  # refuses to overwrite without --reset
    assert main(["seed-demo", "--reset"]) == 0
    with Session(create_engine(env["NEXOPS_DATABASE_URL"])) as db:
        user = db.scalars(select(User)).one()
        assert user.role == "admin" and user.email == "boss@test.dev" and "passphrase" not in user.password_hash
        assert len(db.scalars(select(Service)).all()) == 5
        entry = db.scalars(select(AuditLog).where(AuditLog.action == "user.create_cli")).one()
        assert "passphrase" not in str(entry.detail)
    get_settings.cache_clear()
