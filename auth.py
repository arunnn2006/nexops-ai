from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, get_settings_dep, require_role
from app.core.config import Settings
from app.core.security import create_access_token, hash_password, verify_password
from app.models import SecurityEvent, User
from app.schemas.api import LoginRequest, RegisterRequest, RoleUpdate, TokenOut, UserOut
from app.services.audit import record_audit

auth_router = APIRouter(prefix="/auth", tags=["auth"])
users_router = APIRouter(prefix="/users", tags=["users"])


def client_ip(request: Request) -> str | None:
    # X-Forwarded-For is deliberately not trusted (it is client-controlled without a trusted proxy).
    return request.client.host if request.client else None


@auth_router.post("/register", response_model=UserOut, status_code=201)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    """Self-registration always creates a read-only 'viewer'. Roles are raised by an admin only."""
    email = body.email.lower()
    if db.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(409, "Email already registered") from None
    user = User(email=email, password_hash=hash_password(body.password), role="viewer")
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Email already registered") from None
    record_audit(db, actor=user, action="user.register", target_type="user", target_id=user.id)
    db.commit()
    return user


@auth_router.post("/login", response_model=TokenOut)
def login(
    body: LoginRequest, request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings_dep)
):
    email = body.email.lower()
    user = db.scalar(select(User).where(User.email == email))
    ok = verify_password(body.password, user.password_hash if user else None)
    metrics = request.app.state.metrics
    if not ok or user is None or not user.is_active:
        db.add(
            SecurityEvent(
                event_type="login_failed",
                actor=email,
                source_ip=client_ip(request),
                path="/api/v1/auth/login",
                status_code=401,
                detail={},
            )
        )
        db.commit()
        metrics.logins.labels("failure").inc()
        raise HTTPException(401, "Invalid email or password")
    db.add(
        SecurityEvent(
            event_type="login_success",
            actor=email,
            source_ip=client_ip(request),
            path="/api/v1/auth/login",
            status_code=200,
            detail={},
        )
    )
    record_audit(db, actor=user, action="user.login", target_type="user", target_id=user.id)
    db.commit()
    metrics.logins.labels("success").inc()
    token, expires = create_access_token(user.id, settings.secret_key, settings.access_token_minutes)
    return TokenOut(access_token=token, expires_at=expires, user=UserOut.model_validate(user))


@auth_router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@users_router.get("", response_model=list[UserOut])
def list_users(_: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    return db.scalars(select(User).order_by(User.id)).all()


@users_router.patch("/{user_id}/role", response_model=UserOut)
def set_role(
    user_id: int,
    body: RoleUpdate,
    request: Request,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "User not found")
    if target.role == body.role:
        return target
    if target.role == "admin":
        admins = db.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.is_active.is_(True)))
        if (admins or 0) <= 1:
            raise HTTPException(409, "Cannot demote the last active admin")
    old = target.role
    target.role = body.role
    detail = {"target_email": target.email, "old_role": old, "new_role": body.role}
    db.add(
        SecurityEvent(
            event_type="role_change",
            actor=admin.email,
            source_ip=client_ip(request),
            path=f"/api/v1/users/{user_id}/role",
            status_code=200,
            detail=detail,
        )
    )
    record_audit(db, actor=admin, action="user.role_change", target_type="user", target_id=target.id, detail=detail)
    db.commit()
    return target
