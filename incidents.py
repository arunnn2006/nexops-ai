from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_settings_dep, require_role
from app.core.config import Settings
from app.core.constants import redact
from app.db.base import utcnow
from app.models import Incident, SecurityEvent, Service, User
from app.schemas.api import (
    DetectionResult,
    DiagnosisOut,
    IncidentDetail,
    IncidentOut,
    IncidentPage,
    SecurityEventIn,
    SecurityEventOut,
    StatusUpdate,
)
from app.services.audit import record_audit
from app.services.detection import run_detection
from app.services.diagnosis import build_diagnosis

router = APIRouter(tags=["incidents"])


def _get_incident(db: Session, incident_id: int) -> Incident:
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "Incident not found")
    return inc


@router.get("/incidents", response_model=IncidentPage)
def list_incidents(
    status: str | None = Query(None, pattern="^(open|investigating|resolved)$"),
    severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    rule: str | None = Query(None, max_length=40),
    service_id: int | None = None,
    q: str | None = Query(None, max_length=100),
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    _: User = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    conds = []
    if status:
        conds.append(Incident.status == status)
    if severity:
        conds.append(Incident.severity == severity)
    if rule:
        conds.append(Incident.rule == rule)
    if service_id is not None:
        conds.append(Incident.service_id == service_id)
    if q:
        conds.append(Incident.title.icontains(q, autoescape=True) | Incident.summary.icontains(q, autoescape=True))
    total = db.scalar(select(func.count()).select_from(Incident).where(*conds)) or 0
    items = (
        db.scalars(
            select(Incident)
            .where(*conds)
            .order_by(Incident.detected_at.desc(), Incident.id.desc())
            .limit(limit)
            .offset(offset)
        )
        .unique()
        .all()
    )
    return IncidentPage(items=[IncidentOut.model_validate(i) for i in items], total=total)


@router.post("/incidents/detect", response_model=DetectionResult)
def detect(
    user: User = Depends(require_role("operator")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
):
    created = run_detection(db, settings)
    for inc in created:
        db.add(build_diagnosis(inc))
    record_audit(
        db, actor=user, action="incident.detect", target_type="incident", detail={"created": [i.id for i in created]}
    )
    db.commit()
    return DetectionResult(created=len(created), incidents=[IncidentOut.model_validate(i) for i in created])


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: int, _: User = Depends(require_role("viewer")), db: Session = Depends(get_db)):
    return _get_incident(db, incident_id)


@router.patch("/incidents/{incident_id}/status", response_model=IncidentOut)
def update_status(
    incident_id: int, body: StatusUpdate, user: User = Depends(require_role("operator")), db: Session = Depends(get_db)
):
    inc = _get_incident(db, incident_id)
    old = inc.status
    inc.status = body.status
    inc.updated_at = utcnow()
    inc.resolved_at = inc.updated_at if body.status == "resolved" else None
    record_audit(
        db,
        actor=user,
        action="incident.status",
        target_type="incident",
        target_id=inc.id,
        detail={"from": old, "to": body.status},
    )
    db.commit()
    return inc


@router.post("/incidents/{incident_id}/diagnose", response_model=DiagnosisOut)
def diagnose(incident_id: int, user: User = Depends(require_role("operator")), db: Session = Depends(get_db)):
    inc = _get_incident(db, incident_id)
    diagnosis = build_diagnosis(inc)
    db.add(diagnosis)
    record_audit(
        db,
        actor=user,
        action="incident.diagnose",
        target_type="incident",
        target_id=inc.id,
        detail={"method": diagnosis.method},
    )
    db.commit()
    return diagnosis


@router.get("/incidents/{incident_id}/diagnosis", response_model=DiagnosisOut)
def get_diagnosis(incident_id: int, _: User = Depends(require_role("viewer")), db: Session = Depends(get_db)):
    inc = _get_incident(db, incident_id)
    if inc.latest_diagnosis is None:
        raise HTTPException(404, "No diagnosis generated yet")
    return inc.latest_diagnosis


@router.get("/security-events", response_model=list[SecurityEventOut])
def list_events(
    event_type: str | None = Query(None, max_length=30),
    limit: int = Query(50, ge=1, le=200),
    _: User = Depends(require_role("operator")),
    db: Session = Depends(get_db),
):
    q = select(SecurityEvent).order_by(SecurityEvent.observed_at.desc()).limit(limit)
    if event_type:
        q = q.where(SecurityEvent.event_type == event_type)
    return db.scalars(q).all()


@router.post("/security-events", response_model=SecurityEventOut, status_code=201)
def ingest_event(body: SecurityEventIn, user: User = Depends(require_role("operator")), db: Session = Depends(get_db)):
    """Ingest an access/app log line for detection. Detail is redacted and size-limited."""
    if body.service_id is not None and db.get(Service, body.service_id) is None:
        raise HTTPException(422, "Unknown service_id")
    observed = body.observed_at or utcnow()
    if observed.tzinfo is None:
        raise HTTPException(422, "observed_at must include a timezone offset")
    detail = redact(body.detail)
    if len(str(detail)) > 2000:
        raise HTTPException(422, "detail is too large (max 2000 characters)")
    event = SecurityEvent(
        event_type=body.event_type,
        observed_at=observed,
        actor=body.actor,
        source_ip=body.source_ip,
        path=body.path,
        status_code=body.status_code,
        service_id=body.service_id,
        detail=detail,
    )
    db.add(event)
    db.commit()
    return event
