from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role
from app.models import AuditLog, Deployment, Incident, RecoveryRequest, Service, User
from app.schemas.api import AuditOut, DashboardSummary, DeploymentOut

router = APIRouter()


@router.get("/health", tags=["health"])
def health():
    return {"status": "ok"}


@router.get("/ready", tags=["health"])
def ready(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(503, "Database not ready") from None
    return {"status": "ready"}


@router.get("/audit", response_model=list[AuditOut], tags=["audit"])
def list_audit(
    action: str | None = Query(None, max_length=60),
    outcome: str | None = Query(None, max_length=20),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    q = select(AuditLog).order_by(AuditLog.observed_at.desc(), AuditLog.id.desc()).limit(limit).offset(offset)
    if action:
        q = q.where(AuditLog.action.startswith(action, autoescape=True))
    if outcome:
        q = q.where(AuditLog.outcome == outcome)
    return db.scalars(q).all()


@router.get("/dashboard/summary", response_model=DashboardSummary, tags=["dashboard"])
def summary(_: User = Depends(require_role("viewer")), db: Session = Depends(get_db)):
    by_status = {s: 0 for s in ("healthy", "degraded", "down", "unknown")}
    for status, n in db.execute(select(Service.status, func.count()).group_by(Service.status)).all():
        by_status[status] = n
    by_sev = {s: 0 for s in ("low", "medium", "high", "critical")}
    for sev, n in db.execute(
        select(Incident.severity, func.count()).where(Incident.status != "resolved").group_by(Incident.severity)
    ).all():
        by_sev[sev] = n
    pending = (
        db.scalar(select(func.count()).select_from(RecoveryRequest).where(RecoveryRequest.status == "pending")) or 0
    )
    recent = db.scalars(select(Deployment).order_by(Deployment.deployed_at.desc()).limit(5)).unique().all()
    return DashboardSummary(
        services_by_status=by_status,
        open_incidents_by_severity=by_sev,
        total_open_incidents=sum(by_sev.values()),
        pending_recovery_requests=pending,
        recent_deployments=[DeploymentOut.model_validate(d) for d in recent],
    )
