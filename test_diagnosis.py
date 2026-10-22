from app.models import Deployment, SecurityEvent, Service
from app.services.detection import run_detection
from app.services.diagnosis import LIMITATIONS, build_diagnosis
from tests.conftest import NOW, minutes_ago
from tests.test_detection import add_events, add_samples, add_service


def diagnose_first(db, settings):
    inc = run_detection(db, settings, NOW)[0]
    db.add(build_diagnosis(inc))
    db.commit()
    return inc, inc.latest_diagnosis


def test_facts_trace_to_evidence_and_hypotheses_are_labelled(db, settings):
    svc = add_service(db)
    db.add(
        Deployment(
            service_id=svc.id, version="2.0.0", status="succeeded", deployed_at=minutes_ago(35), source="recorded"
        )
    )
    add_samples(db, svc, [(30, "healthy", 100, 0.0)] + [(a, "degraded", 300, 0.2) for a in (25, 20, 15, 10, 5)])
    inc, dx = diagnose_first(db, settings)
    ids = {e.id for e in inc.evidence}
    assert dx.method == "deterministic"
    assert all(f["type"] == "fact" for f in dx.facts)
    assert all(f["evidence_id"] in ids for f in dx.facts if f["evidence_id"] is not None)
    assert all(h["type"] == "hypothesis" for h in dx.hypotheses)
    assert all(set(h["supporting_evidence_ids"]) <= ids for h in dx.hypotheses)
    assert dx.limitations == LIMITATIONS


def test_deployment_hypothesis_claims_correlation_not_causation(db, settings):
    svc = add_service(db)
    db.add(
        Deployment(
            service_id=svc.id, version="2.0.0", status="succeeded", deployed_at=minutes_ago(35), source="recorded"
        )
    )
    add_samples(db, svc, [(a, "degraded", 300, 0.2) for a in (25, 20, 15, 10, 5)])
    _, dx = diagnose_first(db, settings)
    text = " ".join(h["statement"] for h in dx.hypotheses)
    assert "2.0.0" in text and "temporal correlation only" in text
    assert "rollback_last_deployment" in " ".join(dx.next_steps)


def test_no_evidence_falls_back_to_low_confidence_and_invents_nothing(db, settings):
    svc = add_service(db)
    add_samples(db, svc, [(a, "degraded", 3000, 0.0) for a in (5, 4, 3, 2, 1)])
    _, dx = diagnose_first(db, settings)
    assert len(dx.hypotheses) == 1 and dx.hypotheses[0]["confidence"] == "low"
    assert "does not identify a cause" in dx.hypotheses[0]["statement"]
    assert dx.hypotheses[0]["missing_evidence"]
    assert "Version" not in dx.hypotheses[0]["statement"]  # no fabricated deployment


def test_confidence_never_exceeds_medium(db, settings):
    svc = add_service(db)
    add_samples(db, svc, [(a, "down", 0, 1) for a in (5, 4, 3, 2, 1)])
    for i in range(5):
        db.add(
            SecurityEvent(
                event_type="app_error", observed_at=minutes_ago(4), service_id=svc.id, detail={"message": f"boom {i}"}
            )
        )
    add_events(db, "login_failed", 20)
    db.commit()
    for inc in run_detection(db, settings, NOW):
        dx = build_diagnosis(inc)
        assert all(h["confidence"] in ("low", "medium") for h in dx.hypotheses)


def test_brute_force_diagnosis_mentions_unconfirmed_compromise(db, settings):
    add_events(db, "login_failed", 6)
    db.add(
        SecurityEvent(
            event_type="login_success", observed_at=minutes_ago(1), actor="victim@test.dev", source_ip="203.0.113.9"
        )
    )
    db.commit()
    _, dx = diagnose_first(db, settings)
    assert any("not confirmed" in h["statement"] for h in dx.hypotheses)


def test_non_recoverable_service_gets_no_recovery_suggestion(db, settings):
    svc = Service(name="legacy", is_demo=False, recovery_allowed=False, status="down", meta={})
    db.add(svc)
    db.commit()
    add_samples(db, svc, [(a, "down", 0, 1) for a in (5, 4, 3, 2, 1)])
    _, dx = diagnose_first(db, settings)
    steps = " ".join(dx.next_steps)
    assert "not an approved demo recovery target" in steps and "restart_service" not in steps
