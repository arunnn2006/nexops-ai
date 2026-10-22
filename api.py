import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.core.constants import (
    DeploymentStatus,
    EventType,
    IncidentStatus,
    Role,
    ServiceStatus,
    Severity,
    is_sensitive_key,
)

ORM = ConfigDict(from_attributes=True)
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,78}[a-z0-9]$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,48}$")


# ---- auth / users
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class UserOut(BaseModel):
    model_config = ORM
    id: int
    email: str
    role: Role
    is_active: bool
    created_at: datetime


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime
    user: UserOut


class RoleUpdate(BaseModel):
    role: Role


# ---- services
class ServiceCreate(BaseModel):
    name: str
    description: str = Field(default="", max_length=500)
    environment: str = Field(default="demo", max_length=30)
    is_demo: bool = True
    recovery_allowed: bool = False
    current_version: str | None = None
    meta: dict[str, str | int | float | bool] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not _NAME_RE.match(v):
            raise ValueError("name must be 3-80 chars: lowercase letters, digits, '-' or '_'")
        return v

    @field_validator("current_version")
    @classmethod
    def _ver(cls, v: str | None) -> str | None:
        if v is not None and not _VERSION_RE.match(v):
            raise ValueError("invalid version string")
        return v

    @field_validator("meta")
    @classmethod
    def _meta(cls, v: dict) -> dict:
        if len(v) > 20:
            raise ValueError("at most 20 metadata entries")
        for key, val in v.items():
            if is_sensitive_key(key):
                raise ValueError(f"metadata key '{key}' looks like a secret and is not allowed")
            if isinstance(val, str) and len(val) > 200:
                raise ValueError("metadata values must be at most 200 characters")
        return v


class ServiceOut(BaseModel):
    model_config = ORM
    id: int
    name: str
    description: str
    environment: str
    is_demo: bool
    recovery_allowed: bool
    status: ServiceStatus
    current_version: str | None
    meta: dict[str, Any]
    last_checked_at: datetime | None
    created_at: datetime


class MetricIn(BaseModel):
    observed_at: datetime | None = None
    status: ServiceStatus
    latency_ms: float = Field(ge=0, le=600_000)
    error_rate: float = Field(ge=0, le=1)
    request_count: int = Field(default=0, ge=0, le=10_000_000)


class MetricOut(BaseModel):
    model_config = ORM
    id: int
    service_id: int
    observed_at: datetime
    status: ServiceStatus
    latency_ms: float
    error_rate: float
    request_count: int
    source: str


class DeploymentCreate(BaseModel):
    version: str
    status: DeploymentStatus
    commit_sha: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{7,40}$")
    notes: str = Field(default="", max_length=500)
    deployed_at: datetime | None = None

    @field_validator("version")
    @classmethod
    def _ver(cls, v: str) -> str:
        if not _VERSION_RE.match(v):
            raise ValueError("invalid version string")
        return v


class DeploymentOut(BaseModel):
    model_config = ORM
    id: int
    service_id: int
    service_name: str
    version: str
    status: DeploymentStatus
    commit_sha: str | None
    deployed_by: str | None
    source: str
    notes: str
    deployed_at: datetime


# ---- security events
class SecurityEventIn(BaseModel):
    event_type: EventType
    observed_at: datetime | None = None
    actor: str | None = Field(default=None, max_length=254)
    source_ip: str | None = Field(default=None, max_length=45)
    path: str | None = Field(default=None, max_length=300)
    status_code: int | None = Field(default=None, ge=100, le=599)
    service_id: int | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class SecurityEventOut(BaseModel):
    model_config = ORM
    id: int
    observed_at: datetime
    event_type: EventType
    actor: str | None
    source_ip: str | None
    path: str | None
    status_code: int | None
    service_id: int | None
    detail: dict[str, Any]


# ---- incidents
class EvidenceOut(BaseModel):
    model_config = ORM
    id: int
    kind: str
    observed_at: datetime
    summary: str
    data: dict[str, Any]


class DiagnosisOut(BaseModel):
    model_config = ORM
    id: int
    incident_id: int
    generated_at: datetime
    method: str
    summary: str
    facts: list[dict[str, Any]]
    hypotheses: list[dict[str, Any]]
    next_steps: list[str]
    limitations: list[str]


class IncidentOut(BaseModel):
    model_config = ORM
    id: int
    title: str
    rule: str
    severity: Severity
    status: IncidentStatus
    service_id: int | None
    service_name: str | None
    subject: str
    summary: str
    detected_at: datetime
    updated_at: datetime
    resolved_at: datetime | None


class IncidentDetail(IncidentOut):
    evidence: list[EvidenceOut]
    latest_diagnosis: DiagnosisOut | None


class IncidentPage(BaseModel):
    items: list[IncidentOut]
    total: int


class StatusUpdate(BaseModel):
    status: IncidentStatus


class DetectionResult(BaseModel):
    created: int
    incidents: list[IncidentOut]


# ---- recovery
RecoveryActionName = str


class RecoveryActionOut(BaseModel):
    name: str
    description: str
    simulated_effect: str


class RecoveryCreate(BaseModel):
    service_id: int
    action: str = Field(max_length=40)
    incident_id: int | None = None
    reason: str = Field(default="", max_length=500)


class DecisionIn(BaseModel):
    note: str = Field(default="", max_length=500)


class ExecuteIn(BaseModel):
    confirm: bool
    confirmation_phrase: str = Field(max_length=200)


class RecoveryOut(BaseModel):
    model_config = ORM
    id: int
    incident_id: int | None
    service_id: int
    service_name: str
    action: str
    reason: str
    status: str
    mode: str
    requested_by_email: str
    decided_by_email: str | None
    decision_note: str
    created_at: datetime
    decided_at: datetime | None
    executed_at: datetime | None
    result: dict[str, Any] | None
    verification: dict[str, Any] | None


# ---- audit / dashboard
class AuditOut(BaseModel):
    model_config = ORM
    id: int
    observed_at: datetime
    actor_email: str | None
    action: str
    target_type: str
    target_id: str | None
    outcome: str
    detail: dict[str, Any]


class DashboardSummary(BaseModel):
    services_by_status: dict[str, int]
    open_incidents_by_severity: dict[str, int]
    total_open_incidents: int
    pending_recovery_requests: int
    recent_deployments: list[DeploymentOut]
