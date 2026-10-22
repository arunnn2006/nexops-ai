from collections.abc import Iterator

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.constants import ROLE_RANK
from app.core.security import decode_access_token
from app.models import User

_bearer = HTTPBearer(auto_error=False)


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def get_db(request: Request) -> Iterator[Session]:
    db: Session = request.app.state.session_factory()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    unauthorized = HTTPException(status_code=401, detail="Not authenticated", headers={"WWW-Authenticate": "Bearer"})
    if creds is None:
        raise unauthorized
    user_id = decode_access_token(creds.credentials, request.app.state.settings.secret_key)
    if user_id is None:
        raise unauthorized
    user = db.get(User, user_id)
    # Role and active flag are always read from the DB, never trusted from the token.
    if user is None or not user.is_active:
        raise unauthorized
    return user


def require_role(minimum: str):
    def checker(user: User = Depends(get_current_user)) -> User:
        if ROLE_RANK[user.role] < ROLE_RANK[minimum]:
            raise HTTPException(status_code=403, detail=f"Requires role '{minimum}' or higher")
        return user

    return checker
