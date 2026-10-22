import logging
import time
import uuid

from fastapi import FastAPI, Request
from prometheus_client import CollectorRegistry, Counter, Histogram
from prometheus_client.core import GaugeMetricFamily
from sqlalchemy import func, select

from app.core.logging import log_event
from app.models import Incident, MetricSample, Service

logger = logging.getLogger("nexops.http")
STATUSES = ("healthy", "degraded", "down", "unknown")


class DbCollector:
    """Exposes service/incident state from the database at scrape time."""

    def __init__(self, session_factory):
        self._sf = session_factory

    def collect(self):
        status = GaugeMetricFamily(
            "nexops_service_status", "1 for the service's current status", labels=["service", "status"]
        )
        lat = GaugeMetricFamily("nexops_service_latest_latency_ms", "Latest ingested latency", labels=["service"])
        err = GaugeMetricFamily(
            "nexops_service_latest_error_rate", "Latest ingested error rate (0-1)", labels=["service"]
        )
        inc = GaugeMetricFamily("nexops_open_incidents", "Unresolved incidents", labels=["severity"])
        try:
            with self._sf() as db:
                for svc in db.scalars(select(Service)).all():
                    for st in STATUSES:
                        status.add_metric([svc.name, st], 1.0 if svc.status == st else 0.0)
                    last = db.scalar(
                        select(MetricSample)
                        .where(MetricSample.service_id == svc.id)
                        .order_by(MetricSample.observed_at.desc())
                        .limit(1)
                    )
                    if last:
                        lat.add_metric([svc.name], last.latency_ms)
                        err.add_metric([svc.name], last.error_rate)
                counts = dict(
                    db.execute(
                        select(Incident.severity, func.count())
                        .where(Incident.status != "resolved")
                        .group_by(Incident.severity)
                    ).all()
                )
                for sev in ("low", "medium", "high", "critical"):
                    inc.add_metric([sev], counts.get(sev, 0))
        except Exception:  # a broken DB must not break the scrape endpoint
            log_event(logger, "metrics_collect_failed", level=logging.ERROR)
        yield from (status, lat, err, inc)


class Metrics:
    def __init__(self, session_factory):
        self.registry = CollectorRegistry()
        self.requests = Counter(
            "nexops_http_requests_total", "HTTP requests", ["method", "path", "status"], registry=self.registry
        )
        self.latency = Histogram(
            "nexops_http_request_duration_seconds", "HTTP request duration", ["method", "path"], registry=self.registry
        )
        self.logins = Counter("nexops_login_attempts_total", "Login attempts", ["outcome"], registry=self.registry)
        self.recovery = Counter(
            "nexops_recovery_events_total", "Recovery lifecycle events", ["event"], registry=self.registry
        )
        self.registry.register(DbCollector(session_factory))


def _path_template(request: Request) -> str:
    """Low-cardinality path label: full URL path with path parameters replaced by {name}."""
    if request.scope.get("route") is None:
        return "unmatched"
    parts = request.url.path.split("/")
    for name, value in request.scope.get("path_params", {}).items():
        for i in range(len(parts) - 1, -1, -1):
            if parts[i] == str(value):
                parts[i] = "{" + name + "}"
                break
    return "/".join(parts)


def install_request_middleware(app: FastAPI) -> None:
    @app.middleware("http")
    async def request_context(request: Request, call_next):
        incoming = request.headers.get("x-request-id", "")
        request_id = incoming if incoming.isalnum() and len(incoming) <= 64 else uuid.uuid4().hex
        start = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            elapsed = time.perf_counter() - start
            path = _path_template(request)
            metrics: Metrics = request.app.state.metrics
            metrics.requests.labels(request.method, path, str(status)).inc()
            metrics.latency.labels(request.method, path).observe(elapsed)
            log_event(
                logger,
                "request",
                request_id=request_id,
                method=request.method,
                path=path,
                status=status,
                duration_ms=round(elapsed * 1000, 2),
                client=request.client.host if request.client else None,
            )
