"""Shared constants. Roles, severities and statuses are plain strings stored in the DB."""

from typing import Literal

Role = Literal["viewer", "operator", "admin"]
ROLE_RANK = {"viewer": 1, "operator": 2, "admin": 3}

Severity = Literal["low", "medium", "high", "critical"]
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

IncidentStatus = Literal["open", "investigating", "resolved"]
ServiceStatus = Literal["healthy", "degraded", "down", "unknown"]
DeploymentStatus = Literal["succeeded", "failed", "rolled_back"]
EventType = Literal["login_failed", "login_success", "access", "role_change", "app_error"]

# Keys that must never be persisted in audit records, logs or service metadata.
SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "api_key",
    "apikey",
    "private_key",
    "credential",
)


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in SENSITIVE_KEY_PARTS)


def redact(value, _depth: int = 0):
    """Recursively replace values of sensitive-looking keys with a placeholder."""
    if _depth > 6:
        return "[truncated]"
    if isinstance(value, dict):
        return {str(k): ("[REDACTED]" if is_sensitive_key(str(k)) else redact(v, _depth + 1)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, _depth + 1) for v in value]
    return value
