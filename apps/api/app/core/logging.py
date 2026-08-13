"""structlog configuration: JSON in staging/production, human-readable locally.

Every event carries `request_id` and (once resolved) `workspace_id` via contextvars, so
one grep reconstructs a request across web → api → celery → outbound (OBSERVABILITY.md §4).
Contextvars are the right mechanism because they follow `await` boundaries — a module
global would bleed between concurrently-served requests on the same event loop.

The redaction processor is defense-in-depth, not the primary control (P-16): response
schemas simply do not contain secret fields. This catches what a bug leaks anyway.
"""

from __future__ import annotations

import re
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


# Matches `marker=value`, `marker: value`, and `"marker": "value"` inside free text.
# Needed because exception messages and tracebacks are *strings*: key-based redaction
# cannot see a secret that lives inside `ValueError("api_key=SUPERSECRET")`.
_SECRET_IN_TEXT = re.compile(
    r"(?i)\b(" + "|".join(_SECRET_KEY_MARKERS) + r")\b"  # a secret-ish name
    r"(\"?\s*[:=]\s*\"?)"  # separator, optional quotes
    r"((?:bearer|basic|digest|token)\s+)?"  # optional auth scheme
    r"([^\s,;\"'}\)]+)"  # the credential itself
)


def redact_secrets(
    _logger: object, _method: str, event_dict: structlog.types.EventDict
) -> structlog.types.EventDict:
    """Scrub secrets by key name anywhere in the event, and by pattern inside strings.

    Two mechanisms, because one is not enough:

    1. **Key-based** — any key whose name matches a secret marker is replaced wholesale,
       recursively through dicts and sequences.
    2. **Value-based** — `marker=value` patterns are scrubbed inside string values. This
       exists because `format_exc_info` renders exceptions and tracebacks into plain
       strings, and a secret inside `ValueError("api_key=…")` has no key to match on.
       An upstream API that echoes a credential in its error message reaches us as
       exception text, so this is the path that matters most (SECURITY.md §2.3).

    Ordering is load-bearing: this processor must run *after* `format_exc_info` and
    `StackInfoRenderer`, or the `exception`/`stack` strings do not exist yet and pass
    through unscrubbed.
    """

    def scrub(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: (REDACTED if _is_secret_key(str(k)) else scrub(v)) for k, v in value.items()}
        if isinstance(value, tuple):
            # Preserve the container type; rewriting tuples to lists silently changes the
            # shape of whatever a caller logged.
            return tuple(scrub(v) for v in value)
        if isinstance(value, list):
            return [scrub(v) for v in value]
        if isinstance(value, str):
            # Keep the scheme (\3) visible — "Bearer «redacted»" still tells an engineer
            # which auth mechanism was in play — but never the credential itself (\4).
            # Without the scheme group, `Authorization=Bearer XYZ` redacted only "Bearer"
            # and left the token, because the value pattern stops at whitespace.
            return _SECRET_IN_TEXT.sub(rf"\1\2\3{REDACTED}", value)
        return value

    return {k: (REDACTED if _is_secret_key(str(k)) else scrub(v)) for k, v in event_dict.items()}


def _is_secret_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in _SECRET_KEY_MARKERS)


def configure_logging() -> None:
    """Idempotent; safe to call from app startup and from tests."""
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        # MUST come last. `format_exc_info` is what turns `exc_info` into the `exception`
        # string; running redaction before it means tracebacks are emitted unscrubbed —
        # an upstream error body echoing a credential would land verbatim in the logs.
        redact_secrets,
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
