"""Deterministic incident detection. Every rule is a pure function of stored data and thresholds.

Rules: brute_force, service_down, high_error_rate, high_latency, suspicious_access, privilege_change.
Incidents are de-duplicated by fingerprint while an incident for the same subject is not resolved.
"""

from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.base import utcnow
from app.models import Deployment, Evidence, Incident, MetricSample, SecurityEvent, Service

SENSITIVE_PATH_PREFIXES = (
    "/admin",
    "/.env",
    "/.git",
    "/api/v1/users",
    "/wp-login",
    "/actuator",
    "/phpmyadmin",
    "/etc/passwd",
)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _new_incident(
    db: Session,
    *,
    rule: str,
    severity: str,
    title: str,
    summary: str,
    subject: str,
    evidence: list[dict],
    now: datetime,
    service: Service | None = None,
) -> Incident | None:
    fingerprint = f"{rule}:{subject}"
    existing = db.scalar(
        select(Incident.id).where(Incident.fingerprint == fingerprint, Incident.status != "resolved").limit(1)
    )
    if existing is not None:
        return None
    incident = Incident(
        title=title,
        rule=rule,
        severity=severity,
        status="open",
        subject=subject,
        fingerprint=fingerprint,
        summary=summary,
        detected_at=now,
        updated_at=now,
        service_id=service.id if service else None,
    )
    incident.evidence = [Evidence(**e) for e in evidence]
    db.add(incident)
    db.flush()
    return incident


def _event_evidence(e: SecurityEvent, kind: str = "security_event") -> dict:
    return {
        "kind": kind,
        "observed_at": e.observed_at,
        "summary": f"{e.event_type} actor={e.actor or '-'} ip={e.source_ip or '-'} path={e.path or '-'} status={e.status_code or '-'}",
        "data": {
            "event_id": e.id,
            "event_type": e.event_type,
            "actor": e.actor,
            "source_ip": e.source_ip,
            "path": e.path,
            "status_code": e.status_code,
        },
    }


# ---------------------------------------------------------------- brute force
def detect_brute_force(db: Session, s: Settings, now: datetime) -> list[Incident]:
    since = now - timedelta(minutes=s.detection_window_minutes)
    base = (SecurityEvent.observed_at >= since, SecurityEvent.observed_at <= now)
    fails = db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.event_type == "login_failed", *base)
        .order_by(SecurityEvent.observed_at)
    ).all()
    successes = db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.event_type == "login_success", *base)
        .order_by(SecurityEvent.observed_at)
    ).all()

    by_ip: dict[str, list[SecurityEvent]] = defaultdict(list)
    for e in fails:
        if e.source_ip:
            by_ip[e.source_ip].append(e)
    groups: list[tuple[str, str, list[SecurityEvent]]] = [
        ("ip", ip, evs) for ip, evs in by_ip.items() if len(evs) >= s.brute_force_threshold
    ]
    covered = {e.id for _, _, evs in groups for e in evs}
    by_user: dict[str, list[SecurityEvent]] = defaultdict(list)
    for e in fails:
        if e.actor and e.id not in covered:
            by_user[e.actor.lower()].append(e)
    groups += [("user", u, evs) for u, evs in by_user.items() if len(evs) >= s.brute_force_threshold]

    created: list[Incident] = []
    for kind, key, evs in groups:
        first = evs[0]
        later_ok = [
            x
            for x in successes
            if x.observed_at >= first.observed_at
            and ((kind == "ip" and x.source_ip == key) or (kind == "user" and (x.actor or "").lower() == key))
        ]
        accounts = sorted({(e.actor or "-").lower() for e in evs})
        ips = sorted({e.source_ip or "-" for e in evs})
        severity = "critical" if later_ok else "high"
        who = f"IP {key}" if kind == "ip" else f"account {key}"
        title = f"Successful login after repeated failures ({who})" if later_ok else f"Repeated failed logins ({who})"
        evidence = [
            {
                "kind": "security_event",
                "observed_at": evs[-1].observed_at,
                "summary": f"{len(evs)} failed logins for {who} within {s.detection_window_minutes} min "
                f"({len(accounts)} distinct account(s), {len(ips)} source IP(s))",
                "data": {
                    "count": len(evs),
                    "first_at": _iso(evs[0].observed_at),
                    "last_at": _iso(evs[-1].observed_at),
                    "distinct_accounts": accounts[:10],
                    "distinct_ips": ips[:10],
                    "success_after_failure": bool(later_ok),
                    "threshold": s.brute_force_threshold,
                },
            }
        ]
        evidence += [_event_evidence(e) for e in evs[-5:]]
        evidence += [_event_evidence(x) for x in later_ok[:2]]
        inc = _new_incident(
            db,
            rule="brute_force",
            severity=severity,
            title=title,
            subject=f"{kind}:{key}",
            now=now,
            summary=f"{len(evs)} failed login attempts from {who} in the last {s.detection_window_minutes} minutes."
            + (" A successful login from the same source followed." if later_ok else ""),
            evidence=evidence,
        )
        if inc:
            created.append(inc)
    return created


# ---------------------------------------------------------------- service rules
def _service_evidence(
    db: Session,
    s: Settings,
    svc: Service,
    samples_desc: list[MetricSample],
    onset: datetime,
    now: datetime,
) -> list[dict]:
    window = list(reversed(samples_desc[:6]))
    evidence: list[dict] = [
        {
            "kind": "service_status",
            "observed_at": now,
            "summary": f"{svc.name} reports status '{svc.status}' at version {svc.current_version or 'unknown'}",
            "data": {
                "status": svc.status,
                "current_version": svc.current_version,
                "last_checked_at": _iso(svc.last_checked_at),
            },
        },
        {
            "kind": "metric",
            "observed_at": window[-1].observed_at,
            "summary": f"Last {len(window)} samples: avg latency {_mean([x.latency_ms for x in window]):.0f} ms, "
            f"avg error rate {_mean([x.error_rate for x in window]) * 100:.1f}%, "
            f"statuses {[x.status for x in window]}",
            "data": {
                "onset_at": _iso(onset),
                "samples": [
                    {
                        "observed_at": _iso(x.observed_at),
                        "status": x.status,
                        "latency_ms": x.latency_ms,
                        "error_rate": x.error_rate,
                    }
                    for x in window
                ],
            },
        },
    ]
    lookback = timedelta(minutes=s.correlation_lookback_minutes)
    deploys = db.scalars(
        select(Deployment)
        .where(
            Deployment.service_id == svc.id,
            Deployment.deployed_at >= onset - lookback,
            Deployment.deployed_at <= onset,
        )
        .order_by(Deployment.deployed_at.desc())
    ).all()
    if deploys:
        for d in deploys[:2]:
            lead = (onset - d.deployed_at).total_seconds() / 60
            evidence.append(
                {
                    "kind": "deployment",
                    "observed_at": d.deployed_at,
                    "summary": f"Deployment {d.version} ({d.status}, source={d.source}) recorded {lead:.0f} min before onset",
                    "data": {
                        "found": True,
                        "deployment_id": d.id,
                        "version": d.version,
                        "status": d.status,
                        "source": d.source,
                        "deployed_at": _iso(d.deployed_at),
                        "lead_minutes": round(lead, 1),
                    },
                }
            )
    else:
        evidence.append(
            {
                "kind": "deployment",
                "observed_at": now,
                "summary": f"No deployment recorded for {svc.name} in the {s.correlation_lookback_minutes} min before onset",
                "data": {"found": False, "lookback_minutes": s.correlation_lookback_minutes},
            }
        )
    logs = db.scalars(
        select(SecurityEvent)
        .where(
            SecurityEvent.service_id == svc.id,
            SecurityEvent.event_type == "app_error",
            SecurityEvent.observed_at >= onset - timedelta(minutes=10),
            SecurityEvent.observed_at <= now,
        )
        .order_by(SecurityEvent.observed_at.desc())
        .limit(5)
    ).all()
    for e in reversed(logs):
        msg = str((e.detail or {}).get("message", ""))[:200]
        evidence.append(
            {
                "kind": "log",
                "observed_at": e.observed_at,
                "summary": f"app_error: {msg}",
                "data": {"event_id": e.id, "message": msg},
            }
        )
    return evidence


def _run_start(samples_desc: list[MetricSample], is_bad) -> datetime | None:
    """Onset of the contiguous run of anomalous samples ending at the newest sample."""
    onset = None
    for x in samples_desc:
        if not is_bad(x):
            break
        onset = x.observed_at
    return onset


def detect_service_issues(db: Session, s: Settings, now: datetime) -> list[Incident]:
    created: list[Incident] = []
    horizon = now - timedelta(minutes=max(s.metrics_window_minutes, s.correlation_lookback_minutes))
    recent_cut = now - timedelta(minutes=s.metrics_window_minutes)
    for svc in db.scalars(select(Service).order_by(Service.id)).all():
        samples = db.scalars(
            select(MetricSample)
            .where(
                MetricSample.service_id == svc.id, MetricSample.observed_at >= horizon, MetricSample.observed_at <= now
            )
            .order_by(MetricSample.observed_at.desc())
        ).all()
        recent = [x for x in samples if x.observed_at >= recent_cut]
        if not recent:
            continue
        last_n = recent[: s.service_down_consecutive]
        if len(last_n) == s.service_down_consecutive and all(x.status == "down" for x in last_n):
            onset = _run_start(samples, lambda x: x.status == "down") or last_n[-1].observed_at
            run_len = len([x for x in samples if x.observed_at >= onset and x.status == "down"])
            inc = _new_incident(
                db,
                rule="service_down",
                severity="critical",
                service=svc,
                subject=f"service:{svc.name}",
                now=now,
                title=f"Service unavailable: {svc.name}",
                summary=f"{svc.name} reported 'down' in {run_len} consecutive health samples since {_iso(onset)}.",
                evidence=_service_evidence(db, s, svc, samples, onset, now),
            )
            if inc:
                created.append(inc)
            continue  # error/latency rules would only duplicate an outage

        window = recent[:5]
        if len(window) < s.min_samples_for_rate_rules:
            continue
        avg_err = _mean([x.error_rate for x in window])
        avg_lat = _mean([x.latency_ms for x in window])
        if avg_err > s.error_rate_threshold:
            onset = _run_start(samples, lambda x: x.error_rate > s.error_rate_threshold) or min(
                x.observed_at for x in window if x.error_rate > s.error_rate_threshold
            )
            inc = _new_incident(
                db,
                rule="high_error_rate",
                severity="critical" if avg_err >= 0.2 else "high",
                service=svc,
                subject=f"service:{svc.name}",
                now=now,
                title=f"High error rate: {svc.name}",
                summary=f"Average error rate {avg_err * 100:.1f}% over the last {len(window)} samples "
                f"(threshold {s.error_rate_threshold * 100:.1f}%).",
                evidence=_service_evidence(db, s, svc, samples, onset, now),
            )
            if inc:
                created.append(inc)
        if avg_lat > s.latency_threshold_ms:
            onset = _run_start(samples, lambda x: x.latency_ms > s.latency_threshold_ms) or min(
                x.observed_at for x in window if x.latency_ms > s.latency_threshold_ms
            )
            inc = _new_incident(
                db,
                rule="high_latency",
                severity="high" if avg_lat >= 2 * s.latency_threshold_ms else "medium",
                service=svc,
                subject=f"service:{svc.name}",
                now=now,
                title=f"High latency: {svc.name}",
                summary=f"Average latency {avg_lat:.0f} ms over the last {len(window)} samples "
                f"(threshold {s.latency_threshold_ms:.0f} ms).",
                evidence=_service_evidence(db, s, svc, samples, onset, now),
            )
            if inc:
                created.append(inc)
    return created


# ---------------------------------------------------------------- suspicious access
def detect_suspicious_access(db: Session, s: Settings, now: datetime) -> list[Incident]:
    since = now - timedelta(minutes=s.detection_window_minutes)
    events = db.scalars(
        select(SecurityEvent)
        .where(
            SecurityEvent.event_type == "access",
            SecurityEvent.observed_at >= since,
            SecurityEvent.observed_at <= now,
            SecurityEvent.status_code.in_((401, 403, 404)),
        )
        .order_by(SecurityEvent.observed_at)
    ).all()
    by_ip: dict[str, list[SecurityEvent]] = defaultdict(list)
    for e in events:
        if e.source_ip and (e.path or "").lower().startswith(SENSITIVE_PATH_PREFIXES):
            by_ip[e.source_ip].append(e)
    created = []
    for ip, evs in by_ip.items():
        if len(evs) < s.suspicious_access_threshold:
            continue
        paths = sorted({e.path for e in evs if e.path})
        inc = _new_incident(
            db,
            rule="suspicious_access",
            severity="high" if len(paths) >= 5 else "medium",
            subject=f"ip:{ip}",
            now=now,
            title=f"Suspicious access pattern from {ip}",
            summary=f"{len(evs)} denied/not-found requests to sensitive paths from {ip} "
            f"({len(paths)} distinct paths) in {s.detection_window_minutes} min.",
            evidence=[
                {
                    "kind": "security_event",
                    "observed_at": evs[-1].observed_at,
                    "summary": f"{len(evs)} requests to sensitive paths returned 401/403/404 from {ip}",
                    "data": {
                        "count": len(evs),
                        "distinct_paths": paths[:15],
                        "threshold": s.suspicious_access_threshold,
                    },
                }
            ]
            + [_event_evidence(e) for e in evs[-5:]],
        )
        if inc:
            created.append(inc)
    return created


# ---------------------------------------------------------------- privilege changes
def detect_privilege_changes(db: Session, s: Settings, now: datetime) -> list[Incident]:
    since = now - timedelta(minutes=s.detection_window_minutes)
    changes = db.scalars(
        select(SecurityEvent)
        .where(
            SecurityEvent.event_type == "role_change",
            SecurityEvent.observed_at >= since,
            SecurityEvent.observed_at <= now,
        )
        .order_by(SecurityEvent.observed_at)
    ).all()
    created = []
    for e in changes:
        d = e.detail or {}
        if d.get("new_role") != "admin":
            continue
        target = str(d.get("target_email", "unknown"))
        inc = _new_incident(
            db,
            rule="privilege_change",
            severity="high",
            subject=f"promotion:{target}",
            now=now,
            title=f"Privilege escalation to admin: {target}",
            summary=f"{e.actor or 'unknown actor'} changed {target} from '{d.get('old_role')}' to 'admin'.",
            evidence=[
                _event_evidence(e, "security_event")
                | {
                    "summary": f"role_change by {e.actor or '-'}: {target} {d.get('old_role')} -> {d.get('new_role')}",
                    "data": {
                        "event_id": e.id,
                        "actor": e.actor,
                        "target_email": target,
                        "old_role": d.get("old_role"),
                        "new_role": d.get("new_role"),
                    },
                }
            ],
        )
        if inc:
            created.append(inc)
    if len(changes) >= s.privilege_burst_threshold:
        inc = _new_incident(
            db,
            rule="privilege_change",
            severity="critical",
            subject="burst",
            now=now,
            title=f"Burst of {len(changes)} role changes",
            summary=f"{len(changes)} role changes in {s.detection_window_minutes} minutes "
            f"(threshold {s.privilege_burst_threshold}).",
            evidence=[
                {
                    "kind": "security_event",
                    "observed_at": changes[-1].observed_at,
                    "summary": f"{len(changes)} role changes in window",
                    "data": {"count": len(changes), "threshold": s.privilege_burst_threshold},
                }
            ]
            + [_event_evidence(c) for c in changes[-5:]],
        )
        if inc:
            created.append(inc)
    return created


def run_detection(db: Session, settings: Settings, now: datetime | None = None) -> list[Incident]:
    now = now or utcnow()
    created: list[Incident] = []
    for rule in (detect_brute_force, detect_service_issues, detect_suspicious_access, detect_privilege_changes):
        created.extend(rule(db, settings, now))
    db.commit()
    return created
