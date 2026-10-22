import json
import logging
import sys
from datetime import datetime, timezone

from app.core.constants import redact


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if fields:
            payload.update(redact(fields))
        if record.exc_info and record.exc_info[0]:
            payload["exception"] = record.exc_info[0].__name__  # type only; no traceback values
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level.upper())
    logging.getLogger("uvicorn.access").disabled = True  # replaced by request middleware


def log_event(logger: logging.Logger, message: str, level: int = logging.INFO, **fields) -> None:
    logger.log(level, message, extra={"fields": fields})
