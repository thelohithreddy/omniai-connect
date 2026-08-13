"""structlog configuration: JSON in staging/production, human-readable locally.

Every event carries `request_id` and (once resolved) `workspace_id` via contextvars, so
one grep reconstructs a request across web → api → celery → outbound (OBSERVABILITY.md §4).
Contextvars are the right mechanism because they follow `await` boundaries — a module
global would bleed between concurrently-served requests on the same event loop.

The redaction processor is defense-in-depth, not the primary control (P-16): response
schemas simply do not contain secret fields. This catches what a bug leaks anyway.
"""

from __future__ import annotations

from typing import Any

import structlog

from app.core.config import settings

# Substring match, lowercased. Deliberately broad — a false-positive redaction costs a
# debugging session; a false negative costs the company (SECURITY.md §2.3).
_SECRET_KEY_MARKERS = (
    "authorization",
    "api_key",
    "apikey",
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "cookie",
    "private_key",
)

REDACTED = "«redacted»"

# Spelled out rather than reaching into `structlog.stdlib.NAME_TO_LEVEL`, which is not a
# declared part of structlog's public API and would break silently on an upgrade. These
# are the stdlib `logging` numeric levels and they are not going to change.
_LOG_LEVELS = {"debug": 10, "info": 20, "warning": 30, "error": 40, "critical": 50}


def redact_secrets(
    _logger: object, _method: str, event_dict: structlog.types.EventDict
) -> structlog.types.EventDict:
    """Scrub known-sensitive keys anywhere in the event, including nested dicts."""

    def scrub(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: (REDACTED if _is_secret_key(str(k)) else scrub(v)) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [scrub(v) for v in value]
        return value

    return {k: (REDACTED if _is_secret_key(k) else scrub(v)) for k, v in event_dict.items()}


def _is_secret_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in _SECRET_KEY_MARKERS)


def configure_logging() -> None:
    """Idempotent; safe to call from app startup and from tests."""
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        redact_secrets,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    renderer: structlog.types.Processor = (
        structlog.processors.JSONRenderer()
        if settings.app_env != "development"
        else structlog.dev.ConsoleRenderer(colors=True)
    )

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            _LOG_LEVELS.get(settings.log_level.lower(), _LOG_LEVELS["info"])
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)  # type: ignore[no-any-return]
