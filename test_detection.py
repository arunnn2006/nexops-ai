from sqlalchemy import select

from app.models import Deployment, Incident, MetricSample, SecurityEvent, Service
from app.services.detection import run_detection
from tests.conftest import NOW, minutes_ago


def add_events(db, kind, n, *, ip="203.0.113.9", actor="victim@test.dev", start=8, **kw):
    for i in range(n):
        db.add(
            SecurityEvent(event_type=kind, observed_at=minutes_ago(start - i * 0.5), actor=actor, source_ip=ip, **kw)
        )
    db.commit()


def add_service(db, name="svc-a") -> Service:
    svc = Service(name=name, is_demo=True, recovery_allowed=True, status="healthy", current_version="1.0.0", meta={})
    db.add(svc)
    db.commit()
    return svc


def add_samples(db, svc, specs):
    """specs: list of (minutes_ago, status, latency, error_rate)"""
    for ago, status, lat, err in specs:
        db.add(
            MetricSample(service_id=svc.id, observed_at=minutes_ago(ago), status=status, latency_ms=lat, error_rate=err)
        )
    db.commit()


def incidents(db, rule=None):
    q = select(Incident)
    if rule:
        q = q.where(Incident.rule == rule)
    return db.scalars(q).unique().all()


# ---- brute force
def test_brute_force_below_threshold_creates_nothing(db, settings):
    add_events(db, "login_failed", 4)
    assert run_detection(db, settings, NOW) == []


def test_brute_force_above_threshold_is_high(db, settings):
    add_events(db, "login_failed", 6)
    created = run_detection(db, settings, NOW)
    assert len(created) == 1 and created[0].rule == "brute_force" and created[0].severity == "high"
    assert created[0].subject == "ip:203.0.113.9"
    assert any("6 failed logins" in e.summary for e in created[0].evidence)


def test_brute_force_success_after_failures_is_critical(db, settings):
    add_events(db, "login_failed", 6)
    db.add(
        SecurityEvent(
            event_type="login_success", observed_at=minutes_ago(2), actor="victim@test.dev", source_ip="203.0.113.9"
        )
    )
    db.commit()
    created = run_detection(db, settings, NOW)
    assert created[0].severity == "critical" and "Successful login" in created[0].title


def test_brute_force_outside_window_ignored(db, settings):
    add_events(db, "login_failed", 8, start=60)
    assert run_detection(db, settings, NOW) == []


def test_brute_force_distributed_against_one_account(db, settings):
    for i in range(6):
        db.add(
            SecurityEvent(
                event_type="login_failed",
                observed_at=minutes_ago(5 - i * 0.5),
                actor="victim@test.dev",
                source_ip=f"203.0.113.{i + 1}",
            )
        )
    db.commit()
    created = run_detection(db, settings, NOW)
    assert [c.subject for c in created] == ["user:victim@test.dev"]


def test_detection_deduplicates_open_incidents_but_reopens_after_resolve(db, settings):
    add_events(db, "login_failed", 6)
    assert len(run_detection(db, settings, NOW)) == 1
    assert run_detection(db, settings, NOW) == []
    incidents(db)[0].status = "resolved"
    db.commit()
    assert len(run_detection(db, settings, NOW)) == 1


# ---- service availability / errors / latency
def test_service_down_requires_consecutive_samples(db, settings):
    svc = add_service(db)
    add_samples(db, svc, [(15, "healthy", 100, 0), (10, "down", 0, 1), (5, "healthy", 100, 0), (1, "down", 0, 1)])
    flapping = run_detection(db, settings, NOW)
    assert "service_down" not in [c.rule for c in flapping]  # flapping is not an outage (error-rate rule may fire)
    for inc in flapping:
        inc.status = "resolved"
    db.commit()
    add_samples(db, svc, [(4, "down", 0, 1), (3, "down", 0, 1), (2, "down", 0, 1)])
    created = run_detection(db, settings, NOW)
    assert [c.rule for c in created] == ["service_down"] and created[0].severity == "critical"


def test_high_error_rate_and_severity_levels(db, settings):
    svc = add_service(db)
    add_samples(db, svc, [(a, "degraded", 200, 0.3) for a in (5, 4, 3, 2, 1)])
    inc = run_detection(db, settings, NOW)[0]
    assert inc.rule == "high_error_rate" and inc.severity == "critical"


def test_high_latency_detected_and_healthy_service_clean(db, settings):
    slow = add_service(db, "slow")
    fine = add_service(db, "fine")
    add_samples(db, slow, [(a, "degraded", 1500, 0.0) for a in (5, 4, 3, 2, 1)])
    add_samples(db, fine, [(a, "healthy", 120, 0.001) for a in (5, 4, 3, 2, 1)])
    created = run_detection(db, settings, NOW)
    assert [(c.rule, c.service_name) for c in created] == [("high_latency", "slow")]
    assert created[0].severity == "medium"


def test_too_few_samples_for_rate_rules(db, settings):
    svc = add_service(db)
    add_samples(db, svc, [(2, "degraded", 5000, 0.9), (1, "degraded", 5000, 0.9)])
    assert run_detection(db, settings, NOW) == []


# ---- correlation
def test_deployment_correlated_when_before_onset(db, settings):
    svc = add_service(db)
    db.add(
        Deployment(
            service_id=svc.id, version="2.0.0", status="succeeded", deployed_at=minutes_ago(40), source="recorded"
        )
    )
    db.add(
        Deployment(
            service_id=svc.id, version="9.9.9", status="succeeded", deployed_at=minutes_ago(0.5), source="recorded"
        )
    )
    add_samples(db, svc, [(30, "healthy", 100, 0.001)] + [(a, "degraded", 300, 0.2) for a in (25, 20, 15, 10, 5)])
    inc = run_detection(db, settings, NOW)[0]
    deps = [e for e in inc.evidence if e.kind == "deployment"]
    assert len(deps) == 1 and deps[0].data["found"] is True and deps[0].data["version"] == "2.0.0"
    assert deps[0].data["lead_minutes"] == 15.0  # onset is 25 min ago; deployment 40 min ago


def test_no_deployment_evidence_is_explicit_and_logs_attached(db, settings):
    svc = add_service(db)
    add_samples(db, svc, [(a, "down", 0, 1) for a in (5, 4, 3, 2, 1)])
    db.add(
        SecurityEvent(
            event_type="app_error",
            observed_at=minutes_ago(3),
            service_id=svc.id,
            detail={"message": "connection refused"},
        )
    )
    db.commit()
    inc = run_detection(db, settings, NOW)[0]
    kinds = {e.kind: e for e in inc.evidence}
    assert kinds["deployment"].data["found"] is False
    assert "connection refused" in kinds["log"].summary
    assert {"service_status", "metric"} <= set(kinds)


# ---- suspicious access / privilege
def test_suspicious_access_scanning_pattern(db, settings):
    paths = [f"/admin/{i}" for i in range(6)] + [
        "/.env",
        "/.git/config",
        "/wp-login.php",
        "/actuator/env",
        "/phpmyadmin",
    ]
    for p in paths:
        db.add(
            SecurityEvent(
                event_type="access", observed_at=minutes_ago(5), source_ip="198.51.100.7", path=p, status_code=404
            )
        )
    db.add(
        SecurityEvent(
            event_type="access", observed_at=minutes_ago(5), source_ip="198.51.100.8", path="/home", status_code=404
        )
    )
    db.commit()
    created = run_detection(db, settings, NOW)
    assert [(c.rule, c.subject, c.severity) for c in created] == [("suspicious_access", "ip:198.51.100.7", "high")]


def test_suspicious_access_ignores_normal_paths_and_success(db, settings):
    for _ in range(15):
        db.add(
            SecurityEvent(
                event_type="access", observed_at=minutes_ago(3), source_ip="198.51.100.9", path="/home", status_code=404
            )
        )
        db.add(
            SecurityEvent(
                event_type="access",
                observed_at=minutes_ago(3),
                source_ip="198.51.100.10",
                path="/admin",
                status_code=200,
            )
        )
    db.commit()
    assert run_detection(db, settings, NOW) == []


def test_privilege_change_to_admin_and_burst(db, settings):
    db.add(
        SecurityEvent(
            event_type="role_change",
            observed_at=minutes_ago(2),
            actor="a@test.dev",
            detail={"target_email": "b@test.dev", "old_role": "viewer", "new_role": "admin"},
        )
    )
    db.add(
        SecurityEvent(
            event_type="role_change",
            observed_at=minutes_ago(2),
            actor="a@test.dev",
            detail={"target_email": "c@test.dev", "old_role": "viewer", "new_role": "operator"},
        )
    )
    db.commit()
    created = run_detection(db, settings, NOW)
    assert [(c.rule, c.severity) for c in created] == [("privilege_change", "high")]
    db.add(
        SecurityEvent(
            event_type="role_change",
            observed_at=minutes_ago(1),
            actor="a@test.dev",
            detail={"target_email": "d@test.dev", "old_role": "viewer", "new_role": "operator"},
        )
    )
    db.commit()
    burst = run_detection(db, settings, NOW)
    assert [(c.subject, c.severity) for c in burst] == [("burst", "critical")]


def test_non_admin_role_change_alone_is_not_flagged(db, settings):
    db.add(
        SecurityEvent(
            event_type="role_change",
            observed_at=minutes_ago(2),
            actor="a@test.dev",
            detail={"target_email": "b@test.dev", "old_role": "viewer", "new_role": "operator"},
        )
    )
    db.commit()
    assert run_detection(db, settings, NOW) == []
