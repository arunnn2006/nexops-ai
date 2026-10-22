from datetime import datetime

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UTCDateTime, utcnow


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Service(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    description: Mapped[str] = mapped_column(String(500), default="")
    environment: Mapped[str] = mapped_column(String(30), default="demo")
    is_demo: Mapped[bool] = mapped_column(Boolean, default=True)
    recovery_allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default="unknown")
    # State of the *simulated* disposable demo service used by simulated recovery.
    simulated_state: Mapped[str] = mapped_column(String(20), default="healthy")
    current_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    meta: Mapped[dict] = mapped_column("meta", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_checked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class Deployment(Base):
    __tablename__ = "deployments"
    __table_args__ = (Index("ix_deployments_service_time", "service_id", "deployed_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"))
    version: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(20))
    commit_sha: Mapped[str | None] = mapped_column(String(40), nullable=True)
    deployed_by: Mapped[str | None] = mapped_column(String(254), nullable=True)
    # 'sample' = seeded fixture, 'recorded' = entered via API, 'simulated_recovery' = created by simulated rollback
    source: Mapped[str] = mapped_column(String(30), default="recorded")
    notes: Mapped[str] = mapped_column(String(500), default="")
    deployed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    service: Mapped[Service] = relationship(lazy="joined")

    @property
    def service_name(self) -> str:
        return self.service.name


class MetricSample(Base):
    __tablename__ = "metric_samples"
    __table_args__ = (Index("ix_samples_service_time", "service_id", "observed_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"))
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    status: Mapped[str] = mapped_column(String(20))
    latency_ms: Mapped[float] = mapped_column(Float)
    error_rate: Mapped[float] = mapped_column(Float)
    request_count: Mapped[int] = mapped_column(Integer, default=0)
    source: Mapped[str] = mapped_column(String(30), default="ingested")


class SecurityEvent(Base):
    """Log-like events: auth events written by the API itself plus ingested access/app logs."""

    __tablename__ = "security_events"
    __table_args__ = (Index("ix_events_type_time", "event_type", "observed_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    event_type: Mapped[str] = mapped_column(String(30))
    actor: Mapped[str | None] = mapped_column(String(254), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    path: Mapped[str | None] = mapped_column(String(300), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id", ondelete="SET NULL"), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    rule: Mapped[str] = mapped_column(String(40), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id", ondelete="SET NULL"), nullable=True)
    subject: Mapped[str] = mapped_column(String(300))
    fingerprint: Mapped[str] = mapped_column(String(350), index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    detected_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    service: Mapped[Service | None] = relationship(lazy="joined")
    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="Evidence.id", lazy="selectin"
    )
    diagnoses: Mapped[list["Diagnosis"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="Diagnosis.id", lazy="selectin"
    )

    @property
    def service_name(self) -> str | None:
        return self.service.name if self.service else None

    @property
    def latest_diagnosis(self) -> "Diagnosis | None":
        return self.diagnoses[-1] if self.diagnoses else None


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(30))  # metric | log | deployment | service_status | security_event
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    summary: Mapped[str] = mapped_column(String(500))
    data: Mapped[dict] = mapped_column(JSON, default=dict)

    incident: Mapped[Incident] = relationship(back_populates="evidence")


class Diagnosis(Base):
    __tablename__ = "diagnoses"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    generated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    method: Mapped[str] = mapped_column(String(30), default="deterministic")
    summary: Mapped[str] = mapped_column(Text)
    facts: Mapped[list] = mapped_column(JSON, default=list)
    hypotheses: Mapped[list] = mapped_column(JSON, default=list)
    next_steps: Mapped[list] = mapped_column(JSON, default=list)
    limitations: Mapped[list] = mapped_column(JSON, default=list)

    incident: Mapped[Incident] = relationship(back_populates="diagnoses")


class RecoveryRequest(Base):
    __tablename__ = "recovery_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"))
    action: Mapped[str] = mapped_column(String(40))
    reason: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    mode: Mapped[str] = mapped_column(String(20), default="simulated")
    requested_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    decided_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    decision_note: Mapped[str] = mapped_column(String(500), default="")
    executed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    verification: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    service: Mapped[Service] = relationship(lazy="joined")
    requested_by: Mapped[User] = relationship(foreign_keys=[requested_by_id], lazy="joined")
    decided_by: Mapped[User | None] = relationship(foreign_keys=[decided_by_id], lazy="joined")

    @property
    def service_name(self) -> str:
        return self.service.name

    @property
    def requested_by_email(self) -> str:
        return self.requested_by.email

    @property
    def decided_by_email(self) -> str | None:
        return self.decided_by.email if self.decided_by else None


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    actor_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actor_email: Mapped[str | None] = mapped_column(String(254), nullable=True)
    action: Mapped[str] = mapped_column(String(60), index=True)
    target_type: Mapped[str] = mapped_column(String(40))
    target_id: Mapped[str | None] = mapped_column(String(60), nullable=True)
    outcome: Mapped[str] = mapped_column(String(20))  # success | denied | failed
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
