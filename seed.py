"""Sample data for the demo. All rows are synthetic and labelled (source='sample' / detail.sample=true).
Timestamps are relative to 'now', so run detection soon after seeding (security rules use a short window)."""

import random
from datetime import datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import (
    Deployment,
    Diagnosis,
    Evidence,
    Incident,
    MetricSample,
    RecoveryRequest,
    SecurityEvent,
    Service,
)

SERVICES = [
    ("checkout-api", "Customer checkout API (demo)", True, True),
    ("inventory-service", "Inventory lookups (demo)", True, True),
    ("auth-gateway", "Edge auth gateway (demo; recovery NOT enabled)", True, False),
    ("report-worker", "Nightly report worker (demo)", True, True),
    ("legacy-billing", "Legacy billing, monitored only (non-demo)", False, False),
]
DEPLOYMENTS = {  # service -> [(version, status, days/minutes ago as timedelta, commit)]
    "checkout-api": [
        ("2.3.9", "failed", timedelta(days=6), "9f8e7d6c"),
        ("2.4.0", "succeeded", timedelta(days=5), "5b4a3c2d"),
        ("2.4.1", "succeeded", timedelta(minutes=55), "a1b2c3d4"),
    ],
    "inventory-service": [
        ("1.8.1", "succeeded", timedelta(days=9), "1a2b3c4"),
        ("1.8.2", "succeeded", timedelta(days=3), "4d5e6f7"),
    ],
    "auth-gateway": [
        ("3.1.9", "succeeded", timedelta(days=12), "7a8b9c0"),
        ("3.2.0", "succeeded", timedelta(days=6), "0c9b8a7"),
    ],
    "report-worker": [
        ("0.7.0", "succeeded", timedelta(days=14), "3c4d5e6"),
        ("0.7.2", "succeeded", timedelta(days=8), "6e5d4c3"),
    ],
    "legacy-billing": [("12.4.0", "succeeded", timedelta(days=30), "bb11cc22")],
}


def _sample(name: str, minutes_ago: int, rnd: random.Random) -> tuple[str, float, float, int]:
    healthy = ("healthy", rnd.uniform(140, 220), rnd.uniform(0.002, 0.01), rnd.randint(300, 420))
    if name == "checkout-api" and minutes_ago <= 46:
        return ("degraded", rnd.uniform(420, 700), rnd.uniform(0.10, 0.18), rnd.randint(250, 380))
    if name == "inventory-service" and minutes_ago <= 21:
        return ("down", 0.0, 1.0, 0)
    if name == "report-worker" and minutes_ago <= 36:
        return ("degraded", rnd.uniform(1200, 1700), rnd.uniform(0.01, 0.02), rnd.randint(40, 80))
    return healthy


def reset_demo_data(db: Session) -> None:
    for model in (RecoveryRequest, Diagnosis, Evidence, Incident, SecurityEvent, MetricSample, Deployment, Service):
        db.execute(delete(model))
    db.commit()


def seed_demo(db: Session, now: datetime | None = None) -> dict:
    now = now or utcnow()
    rnd = random.Random(42)
    services: dict[str, Service] = {}
    for name, desc, is_demo, recoverable in SERVICES:
        svc = Service(
            name=name,
            description=desc,
            environment="demo" if is_demo else "monitored-only",
            is_demo=is_demo,
            recovery_allowed=recoverable,
            status="unknown",
            meta={"owner": "platform-team", "sample": True},
        )
        db.add(svc)
        services[name] = svc
    db.flush()

    n_dep = n_samples = 0
    for name, rows in DEPLOYMENTS.items():
        svc = services[name]
        for version, status, ago, sha in rows:
            db.add(
                Deployment(
                    service_id=svc.id,
                    version=version,
                    status=status,
                    commit_sha=sha,
                    deployed_by="ci-pipeline",
                    source="sample",
                    notes="Sample fixture; not a real deployment",
                    deployed_at=now - ago,
                )
            )
            n_dep += 1
            if status == "succeeded":
                svc.current_version = version
    for name, svc in services.items():
        last = None
        for k in range(35, -1, -1):
            ago = 1 + 5 * k
            status, lat, err, req = _sample(name, ago, rnd)
            at = now - timedelta(minutes=ago)
            db.add(
                MetricSample(
                    service_id=svc.id,
                    observed_at=at,
                    status=status,
                    latency_ms=round(lat, 1),
                    error_rate=round(err, 4),
                    request_count=req,
                    source="sample",
                )
            )
            last = (status, at)
            n_samples += 1
        svc.status, svc.simulated_state, svc.last_checked_at = last[0], last[0], last[1]

    def ev(kind, ago, **kw):
        db.add(SecurityEvent(event_type=kind, observed_at=now - ago, **kw))

    sample = {"sample": True}
    for i, m in enumerate(
        [
            "NullPointerException in PaymentSession.validate",
            "NullPointerException in PaymentSession.validate",
            "Timeout calling tax-service after 3000ms",
            "NullPointerException in PaymentSession.validate",
        ]
    ):
        ev(
            "app_error",
            timedelta(minutes=44 - i * 10),
            service_id=services["checkout-api"].id,
            detail={**sample, "message": m},
        )
    for i in range(2):
        ev(
            "app_error",
            timedelta(minutes=20 - i),
            service_id=services["inventory-service"].id,
            detail={**sample, "message": "connection refused to inventory-db:5432"},
        )
    for i in range(7):  # brute force followed by success (RFC 5737 documentation IP)
        ev(
            "login_failed",
            timedelta(minutes=6) - timedelta(seconds=40 * i),
            actor="admin@example.com",
            source_ip="203.0.113.50",
            path="/api/v1/auth/login",
            status_code=401,
            detail=sample,
        )
    ev(
        "login_failed",
        timedelta(minutes=2),
        actor="ops@example.com",
        source_ip="203.0.113.50",
        path="/api/v1/auth/login",
        status_code=401,
        detail=sample,
    )
    ev(
        "login_success",
        timedelta(minutes=1),
        actor="admin@example.com",
        source_ip="203.0.113.50",
        path="/api/v1/auth/login",
        status_code=200,
        detail=sample,
    )
    paths = [
        "/admin",
        "/.env",
        "/.git/config",
        "/wp-login.php",
        "/api/v1/users",
        "/actuator/env",
        "/phpmyadmin",
        "/admin/login",
        "/.env.backup",
        "/admin/config",
        "/api/v1/users/1",
        "/etc/passwd",
    ]
    for i, p in enumerate(paths):
        ev(
            "access",
            timedelta(minutes=5) - timedelta(seconds=15 * i),
            source_ip="198.51.100.23",
            path=p,
            status_code=404 if i % 2 else 403,
            detail=sample,
        )
    ev(
        "role_change",
        timedelta(minutes=3),
        actor="admin@example.com",
        path="/api/v1/users/9/role",
        status_code=200,
        detail={**sample, "target_email": "contractor@example.com", "old_role": "viewer", "new_role": "admin"},
    )
    db.commit()
    return {"services": len(services), "deployments": n_dep, "metric_samples": n_samples}
