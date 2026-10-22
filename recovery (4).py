from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.api.deps import get_db, get_settings_dep, require_role
from app.core.config import Settings
from app.db.base import utcnow
from app.models import Incident, RecoveryRequest, Service, User
from app.schemas.api import DecisionIn, ExecuteIn, RecoveryActionOut, RecoveryCreate, RecoveryOut
from app.services.audit import record_audit
from app.services.recovery import (
    ALLOWED_ACTIONS,
    RecoveryError,
    confirmation_phrase,
    eligibility_error,
    execute_simulated,
    verify_health_simulated,
)

router = APIRouter(prefix="/recovery", tags=["recovery"])


def _deny(
    db: Session, user: User, action: str, target_id, reason: str, status_code: int = 403, detail: dict | None = None
):
    record_audit(
        db,
        actor=user,
        action=action,
        target_type="recovery_request",
        target_id=target_id,
        outcome="denied",
        detail={"reason": reason, **(detail or {})},
    )
    db.commit()
    raise HTTPException(status_code, reason)


def _get_request(db: Session, request_id: int) -> RecoveryRequest:
    rr = db.get(RecoveryRequest, request_id)
    if rr is None:
        raise HTTPException(404, "Recovery request not found")
    return rr


@router.get("/actions", response_model=list[RecoveryActionOut])
def list_actions(_: User = Depends(require_role("viewer"))):
    return [RecoveryActionOut(name=k, **v) for k, v in ALLOWED_ACTIONS.items()]


@router.get("/requests", response_model=list[RecoveryOut])
def list_requests(
    status: str | None = Query(None, max_length=30),
    limit: int = Query(50, ge=1, le=200),
    _: User = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    q = select(RecoveryRequest).order_by(RecoveryRequest.created_at.desc(), RecoveryRequest.id.desc()).limit(limit)
    if status:
        q = q.where(RecoveryRequest.status == status)
    return db.scalars(q).unique().all()


@router.post("/requests", response_model=RecoveryOut, status_code=201)
def create_request(
    body: RecoveryCreate,
    request: Request,
    user: User = Depends(require_role("operator")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
):
    if body.action not in ALLOWED_ACTIONS:
        _deny(
            db,
            user,
            "recovery.request",
            None,
            "Action is not in the recovery allowlist",
            422,
            {"action": body.action[:40]},
        )
    svc = db.get(Service, body.service_id)
    if svc is None:
        raise HTTPException(404, "Service not found")
    problem = eligibility_error(svc)
    if problem:
        _deny(db, user, "recovery.request", None, problem, 403, {"service": svc.name, "action": body.action})
    if body.incident_id is not None:
        inc = db.get(Incident, body.incident_id)
        if inc is None:
            raise HTTPException(404, "Incident not found")
        if inc.service_id is not None and inc.service_id != svc.id:
            raise HTTPException(422, "Incident does not belong to that service")
    open_dup = db.scalar(
        select(RecoveryRequest.id)
        .where(
            RecoveryRequest.service_id == svc.id,
            RecoveryRequest.action == body.action,
            RecoveryRequest.status.in_(("pending", "approved")),
        )
        .limit(1)
    )
    if open_dup:
        raise HTTPException(409, "An open request for this action and service already exists")
    rr = RecoveryRequest(
        service_id=svc.id,
        action=body.action,
        incident_id=body.incident_id,
        reason=body.reason,
        status="pending",
        mode=settings.recovery_mode,
        requested_by_id=user.id,
    )
    db.add(rr)
    db.flush()
    record_audit(
        db,
        actor=user,
        action="recovery.request",
        target_type="recovery_request",
        target_id=rr.id,
        detail={"service": svc.name, "action": body.action, "mode": rr.mode},
    )
    db.commit()
    request.app.state.metrics.recovery.labels("requested").inc()
    return rr


def _decide(request_id: int, decision: str, note: str, admin: User, db: Session, settings: Settings, request: Request):
    rr = _get_request(db, request_id)
    action = f"recovery.{decision}"
    if rr.status != "pending":
        _deny(db, admin, action, rr.id, f"Request is '{rr.status}', not pending", 409)
    if decision == "approve":
        if rr.requested_by_id == admin.id and not settings.allow_self_approval:
            _deny(db, admin, action, rr.id, "Requesters cannot approve their own recovery request")
        problem = eligibility_error(rr.service)
        if problem:
            _deny(db, admin, action, rr.id, problem)
    rr.status = "approved" if decision == "approve" else "rejected"
    rr.decided_by_id = admin.id
    rr.decided_at = utcnow()
    rr.decision_note = note
    record_audit(
        db,
        actor=admin,
        action=action,
        target_type="recovery_request",
        target_id=rr.id,
        detail={"service": rr.service.name, "action": rr.action},
    )
    db.commit()
    db.refresh(rr)
    request.app.state.metrics.recovery.labels(rr.status).inc()
    return rr


@router.post("/requests/{request_id}/approve", response_model=RecoveryOut)
def approve(
    request_id: int,
    request: Request,
    body: DecisionIn | None = None,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
):
    return _decide(request_id, "approve", body.note if body else "", admin, db, settings, request)


@router.post("/requests/{request_id}/reject", response_model=RecoveryOut)
def reject(
    request_id: int,
    request: Request,
    body: DecisionIn | None = None,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
):
    return _decide(request_id, "reject", body.note if body else "", admin, db, settings, request)


@router.post("/requests/{request_id}/execute", response_model=RecoveryOut)
def execute(
    request_id: int,
    body: ExecuteIn,
    request: Request,
    user: User = Depends(require_role("operator")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
):
    rr = _get_request(db, request_id)
    svc = rr.service
    if rr.status != "approved":
        _deny(
            db,
            user,
            "recovery.execute",
            rr.id,
            f"Request is '{rr.status}'; only approved requests can be executed",
            409,
        )
    now = utcnow()
    if (now - rr.decided_at).total_seconds() > settings.approval_ttl_minutes * 60:
        rr.status = "expired"
        _deny(db, user, "recovery.execute", rr.id, "Approval has expired; submit a new request", 409)
    if user.role != "admin" and user.id != rr.requested_by_id:
        _deny(db, user, "recovery.execute", rr.id, "Only the requester or an admin may execute this request")
    if rr.action not in ALLOWED_ACTIONS:
        _deny(db, user, "recovery.execute", rr.id, "Action is not in the recovery allowlist", 422)
    problem = eligibility_error(svc)
    if problem:
        _deny(db, user, "recovery.execute", rr.id, problem)
    if settings.recovery_mode != "simulated":
        _deny(db, user, "recovery.execute", rr.id, "Only simulated recovery mode is supported", 501)
    if not body.confirm or body.confirmation_phrase != confirmation_phrase(rr.action, svc):
        _deny(
            db,
            user,
            "recovery.execute",
            rr.id,
            f"Confirmation required: type exactly '{confirmation_phrase(rr.action, svc)}'",
            422,
        )

    rr.executed_by_id = user.id
    rr.executed_at = now
    try:
        rr.result = execute_simulated(db, svc, rr.action, now)
    except RecoveryError as exc:
        rr.status = "failed"
        rr.result = {"simulated": True, "error": str(exc)}
        record_audit(
            db,
            actor=user,
            action="recovery.execute",
            target_type="recovery_request",
            target_id=rr.id,
            outcome="failed",
            detail={"service": svc.name, "action": rr.action, "error": str(exc)},
        )
        db.commit()
        request.app.state.metrics.recovery.labels("failed").inc()
        return rr
    rr.verification = verify_health_simulated(db, svc, utcnow())
    rr.status = "executed" if rr.verification["passed"] else "verification_failed"
    record_audit(
        db,
        actor=user,
        action="recovery.execute",
        target_type="recovery_request",
        target_id=rr.id,
        outcome="success" if rr.verification["passed"] else "failed",
        detail={
            "service": svc.name,
            "action": rr.action,
            "mode": "simulated",
            "verification_passed": rr.verification["passed"],
        },
    )
    db.commit()
    request.app.state.metrics.recovery.labels(rr.status).inc()
    return rr
