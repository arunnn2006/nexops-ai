from sqlalchemy.orm import Session

from app.core.constants import redact
from app.models import AuditLog, User


def record_audit(
    db: Session,
    *,
    actor: User | None,
    action: str,
    target_type: str,
    target_id: int | str | None = None,
    outcome: str = "success",
    detail: dict | None = None,
    actor_email: str | None = None,
) -> AuditLog:
    """Adds an audit row (caller commits). Detail is redacted so secrets can never be persisted."""
    entry = AuditLog(
        actor_id=actor.id if actor else None,
        actor_email=actor.email if actor else actor_email,
        action=action,
        target_type=target_type,
        target_id=None if target_id is None else str(target_id),
        outcome=outcome,
        detail=redact(detail or {}),
    )
    db.add(entry)
    return entry
