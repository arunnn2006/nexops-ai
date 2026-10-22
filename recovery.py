"""Allowlisted, SIMULATED recovery for disposable demo services.

Safety design:
  * Actions are a closed allowlist (a dict); a request can only name a key of it.
  * Nothing here runs shell commands, touches Docker, or contacts any host. This module intentionally
    imports no process/OS-execution modules; a test asserts that.
  * Only services flagged is_demo AND recovery_allowed are eligible.
  * "Execution" changes the simulated state stored in the NexOps database, then a simulated
    post-action health verification reads that state back and records a sample.
"""

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Deployment, MetricSample, Service

ALLOWED_ACTIONS: dict[str, dict[str, str]] = {
    "restart_service": {
        "description": "Restart the (simulated) demo service process.",
        "simulated_effect": "Sets simulated state to 'healthy' if it was 'degraded' or 'down'.",
    },
    "clear_cache": {
        "description": "Clear the (simulated) demo service cache.",
        "simulated_effect": "Sets simulated state to 'healthy' only if it was 'degraded'; a 'down' service stays down.",
    },
    "rollback_last_deployment": {
        "description": "Roll the (simulated) demo service back to the previous successful version.",
        "simulated_effect": "Records a simulated rollback deployment, restores the previous version, sets state to 'healthy'.",
    },
}


class RecoveryError(Exception):
    pass


def eligibility_error(service: Service) -> str | None:
    if not service.is_demo:
        return "Service is not a disposable demo service; recovery is not permitted"
    if not service.recovery_allowed:
        return "Service is not enabled for recovery actions"
    return None


def confirmation_phrase(action: str, service: Service) -> str:
    return f"{action} {service.name}"


def execute_simulated(db: Session, service: Service, action: str, now: datetime) -> dict:
    if action not in ALLOWED_ACTIONS:
        raise RecoveryError("Action is not in the allowlist")
    before = service.simulated_state
    detail = ""
    if action == "restart_service":
        if before in ("down", "degraded"):
            service.simulated_state = "healthy"
        detail = "Simulated restart."
    elif action == "clear_cache":
        if before == "degraded":
            service.simulated_state = "healthy"
        detail = "Simulated cache clear."
    elif action == "rollback_last_deployment":
        deployments = db.scalars(
            select(Deployment).where(Deployment.service_id == service.id).order_by(Deployment.deployed_at.desc())
        ).all()
        current = next(
            (d for d in deployments if d.status == "succeeded" and d.version == service.current_version), None
        )
        if current is None:
            raise RecoveryError("No successful deployment matches the current version")
        previous = next(
            (
                d
                for d in deployments
                if d.status == "succeeded" and d.deployed_at < current.deployed_at and d.version != current.version
            ),
            None,
        )
        if previous is None:
            raise RecoveryError("No earlier successful deployment to roll back to")
        current.status = "rolled_back"
        db.add(
            Deployment(
                service_id=service.id,
                version=previous.version,
                status="succeeded",
                source="simulated_recovery",
                deployed_by="nexops-simulated-recovery",
                deployed_at=now,
                notes=f"SIMULATED rollback from {current.version} to {previous.version}",
            )
        )
        service.current_version = previous.version
        service.simulated_state = "healthy"
        detail = f"Simulated rollback {current.version} -> {previous.version}."
    return {
        "simulated": True,
        "action": action,
        "state_before": before,
        "state_after": service.simulated_state,
        "detail": detail,
    }


def verify_health_simulated(db: Session, service: Service, now: datetime) -> dict:
    state = service.simulated_state
    healthy = state == "healthy"
    db.add(
        MetricSample(
            service_id=service.id,
            observed_at=now,
            status=state,
            latency_ms=120.0 if healthy else 2500.0,
            error_rate=0.0 if healthy else 0.5,
            request_count=0,
            source="simulated_verification",
        )
    )
    service.status = state
    service.last_checked_at = now
    return {
        "simulated": True,
        "method": "simulated_state_read",
        "observed_state": state,
        "passed": healthy,
        "checked_at": now.isoformat(),
    }
