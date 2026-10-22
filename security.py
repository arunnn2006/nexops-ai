from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()
# Used to keep login timing similar when the user does not exist.
_DUMMY_HASH = _hasher.hash("nexops-timing-equalizer-not-a-real-password")
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Always performs one hash verification; unknown users can never succeed."""
    try:
        ok = _hasher.verify(password_hash or _DUMMY_HASH, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return bool(ok) and password_hash is not None


def create_access_token(user_id: int, secret: str, minutes: int) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=minutes)
    payload = {"sub": str(user_id), "iat": now, "exp": expires}
    return jwt.encode(payload, secret, algorithm=ALGORITHM), expires


def decode_access_token(token: str, secret: str) -> int | None:
    try:
        payload = jwt.decode(token, secret, algorithms=[ALGORITHM], options={"require": ["exp", "sub"]})
        return int(payload["sub"])
    except (jwt.PyJWTError, ValueError, KeyError):
        return None
