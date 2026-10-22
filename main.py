import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.v1.router import api_router
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging, log_event
from app.db.session import make_engine, make_session_factory
from app.observability import Metrics, install_request_middleware

logger = logging.getLogger("nexops.app")
_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    422: "validation_error",
    429: "rate_limited",
    501: "not_implemented",
    503: "unavailable",
}


def _error(status: int, message: str, details=None, headers=None) -> JSONResponse:
    body = {"error": {"code": _CODES.get(status, "error"), "message": message}}
    if details is not None:
        body["error"]["details"] = details
    return JSONResponse(body, status_code=status, headers=headers)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    engine = make_engine(settings.database_url)
    session_factory = make_session_factory(engine)

    app = FastAPI(
        title="NexOps AI API",
        version="1.0.0",
        description="CloudOps/SRE platform API. Recovery is SIMULATED for demo services only.",
        openapi_url="/api/v1/openapi.json",
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.metrics = Metrics(session_factory)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        allow_credentials=False,
    )
    install_request_middleware(app)

    @app.exception_handler(StarletteHTTPException)
    async def http_exc(_: Request, exc: StarletteHTTPException):
        return _error(exc.status_code, str(exc.detail), headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def validation_exc(_: Request, exc: RequestValidationError):
        details = [{"field": ".".join(str(p) for p in e["loc"][1:]), "message": e["msg"]} for e in exc.errors()]
        return _error(422, "Request validation failed", details)

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception):
        log_event(logger, "unhandled_exception", level=logging.ERROR, error_type=type(exc).__name__)
        return _error(500, "Internal server error")

    app.include_router(api_router, prefix="/api/v1")

    if settings.metrics_enabled:

        @app.get("/metrics", include_in_schema=False)
        def metrics() -> Response:
            return Response(generate_latest(app.state.metrics.registry), media_type=CONTENT_TYPE_LATEST)

    return app
