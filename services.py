from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role
from app.db.base import utcnow
from app.models import Deployment, MetricSample, Service, User
from app.schemas.api import DeploymentCreate, DeploymentOut, MetricIn, MetricOut, ServiceCreate, ServiceOut
from app.services.audit import record_audit

router = APIRouter(tags=["services"])


def _get_service(db: Session, service_id: int) -> Service:
    svc = db.get(Service, service_id)
    if svc is None:
        raise HTTPException(404, "Service not found")
    return svc


def _check_time(value):
    if value is None:
        return utcnow()
    if value.tzinfo is None:
        raise HTTPException(422, "observed_at/deployed_at must include a timezone offset")
    if value > utcnow() + timedelta(minutes=5):
        raise HTTPException(422, "Timestamp is in the future")
    return value


@router.get("/services", response_model=list[ServiceOut])
def list_services(_: User = Depends(require_role("viewer")), db: Session = Depends(get_db)):
    return db.scalars(select(Service).order_by(Service.name)).all()


@router.post("/services", response_model=ServiceOut, status_code=201)
def create_service(body: ServiceCreate, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    if body.recovery_allowed and not body.is_demo:
        raise HTTPException(
            422, "recovery_allowed requires is_demo=true; only disposable demo services may be recovered"
        )
    svc = Service(**body.model_dump(), status="unknown")
    db.add(svc)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A service with that name already exists") from None
    record_audit(
        db,
        actor=admin,
        action="service.create",
        target_type="service",
        target_id=svc.id,
        detail={"name": svc.name, "is_demo": svc.is_demo, "recovery_allowed": svc.recovery_allowed},
    )
    db.commit()
    return svc


@router.get("/services/{service_id}", response_model=ServiceOut)
def get_service(service_id: int, _: User = Depends(require_role("viewer")), db: Session = Depends(get_db)):
    return _get_service(db, service_id)


@router.get("/services/{service_id}/metrics", response_model=list[MetricOut])
def get_metrics(
    service_id: int,
    limit: int = Query(100, ge=1, le=500),
    _: User = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    _get_service(db, service_id)
    rows = db.scalars(
        select(MetricSample)
        .where(MetricSample.service_id == service_id)
        .order_by(MetricSample.observed_at.desc())
        .limit(limit)
    ).all()
    return list(reversed(rows))


@router.post("/services/{service_id}/metrics", response_model=MetricOut, status_code=201)
def add_metric(
    service_id: int, body: MetricIn, _: User = Depends(require_role("operator")), db: Session = Depends(get_db)
):
    svc = _get_service(db, service_id)
    observed = _check_time(body.observed_at)
    sample = MetricSample(
        service_id=svc.id,
        observed_at=observed,
        status=body.status,
        latency_ms=body.latency_ms,
        error_rate=body.error_rate,
        request_count=body.request_count,
        source="ingested",
    )
    db.add(sample)
    if svc.last_checked_at is None or observed >= svc.last_checked_at:
        svc.status = body.status
        svc.last_checked_at = observed
        if svc.is_demo and body.status != "unknown":
            svc.simulated_state = body.status  # the demo simulator follows ingested telemetry
    db.commit()
    return sample


@router.get("/deployments", response_model=list[DeploymentOut])
def list_deployments(
    service_id: int | None = None,
    limit: int = Query(50, ge=1, le=200),
    _: User = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    q = select(Deployment).order_by(Deployment.deployed_at.desc()).limit(limit)
    if service_id is not None:
        q = q.where(Deployment.service_id == service_id)
    return db.scalars(q).unique().all()


@router.post("/services/{service_id}/deployments", response_model=DeploymentOut, status_code=201)
def record_deployment(
    service_id: int,
    body: DeploymentCreate,
    user: User = Depends(require_role("operator")),
    db: Session = Depends(get_db),
):
    """Records that a deployment happened. NexOps does not perform deployments."""
    svc = _get_service(db, service_id)
    when = _check_time(body.deployed_at)
    dep = Deployment(
        service_id=svc.id,
        version=body.version,
        status=body.status,
        commit_sha=body.commit_sha,
        deployed_by=user.email,
        source="recorded",
        notes=body.notes,
        deployed_at=when,
    )
    db.add(dep)
    if body.status == "succeeded":
        latest = db.scalar(
            select(Deployment.deployed_at)
            .where(Deployment.service_id == svc.id, Deployment.status == "succeeded")
            .order_by(Deployment.deployed_at.desc())
            .limit(1)
        )
        if latest is None or when >= latest:
            svc.current_version = body.version
    record_audit(
        db,
        actor=user,
        action="deployment.record",
        target_type="service",
        target_id=svc.id,
        detail={"version": body.version, "status": body.status},
    )
    db.commit()
    db.refresh(dep)
    return dep
