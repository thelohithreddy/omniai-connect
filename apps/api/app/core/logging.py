"""structlog configuration: JSON in staging/production, human-readable locally.

Every event carries `request_id` and (once resolved) `workspace_id` via contextvars, so
one grep reconstructs a request across web → api → celery → outbound (OBSERVABILITY.md §4).
Contextvars are the right mechanism because they follow `await` boundaries — a module
global would bleed between concurrently-served requests on the same event loop.

The redaction processor is defense-in-depth, not the primary control (P-16): response
schemas simply do not contain secret fields. This catches what a bug leaks anyway.
"""

from __future__ import annotations

import logging
import re
import traceback
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
            return {
                k: (
                    REDACTED
                    if _is_secret_key(str(k)) and not _is_reference_id(str(k), v)
                    else scrub(v)
                )
                for k, v in value.items()
            }
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
            return scrub_text(value)
        return value

    return {
        k: (REDACTED if _is_secret_key(str(k)) and not _is_reference_id(str(k), v) else scrub(v))
        for k, v in event_dict.items()
    }


#: Exact field names that contain a secret marker but never carry a secret value. An
#: exact-name allowlist rather than a suffix rule, so it cannot widen by accident — adding a
#: name here is a deliberate, reviewable act.
#:
#: `credential_type` is a discriminator from a closed six-value set (`api_key`, `oauth2`, …).
#: It matched "credential" and so was emitted as «redacted», which quietly gutted the M2.6
#: vault-access audit: the record could say *that* a credential was opened but not *what kind*.
#: Caught by the release audit, because the unit test observed the event before this processor ran.
_NEVER_SECRET_KEYS = frozenset({"credential_type"})


def _is_secret_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in _NEVER_SECRET_KEYS:
        return False
    return any(marker in lowered for marker in _SECRET_KEY_MARKERS)


# A canonical UUID, anchored. Used only to recognise *references*.
_UUID_VALUE = re.compile(
    r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z", re.IGNORECASE
)


def _is_reference_id(key: str, value: object) -> bool:
    """True for `<something>_id` holding a UUID — an identifier, not a secret.

    Narrow on purpose, and it exists because the broad marker match was actively harmful: keys
    like `credential_id` and `api_token_id` contain "credential"/"token", so the M2.6 vault-access
    audit recorded *"someone opened «redacted»"* — an audit trail that cannot name what was
    accessed, which defeats the control it was ratified to provide.

    **Both** conditions are required, so this cannot become a hole. A key naming a secret still
    redacts unless its value is structurally a UUID, and a UUID is not a credential this system
    issues — `api_tokens` stores a hash, and every bearer artifact is high-entropy random text,
    never a UUID. So `token_id="sk-live-…"` is still redacted; only `token_id="0192…-…"` is kept.
    """
    return (
        key.lower().endswith("_id")
        and isinstance(value, str)
        and _UUID_VALUE.match(value) is not None
    )


def scrub_text(value: str) -> str:
    """Scrub `marker=value` patterns out of free text. The value-based half of the redactor,
    exposed because the stdlib bridge below needs exactly the same rules."""
    return _SECRET_IN_TEXT.sub(rf"\1\2\3{REDACTED}", value)


def _scrub_stdlib_record(record: logging.LogRecord) -> logging.LogRecord:
    """Apply redaction to one stdlib `LogRecord`, in place.

    The message is rendered (`msg % args`) and scrubbed **as one string**, then `args` is cleared.
    Scrubbing the two halves separately would not work: `logger.info("api_key=%s", secret)` has no
    secret in `msg` and no marker in `args`, so each half looks innocent and the leak only exists
    once they are joined. Rendering first is the only point where the pattern is visible.

    Exception and stack text are rendered here too, for the same reason the structlog processor
    runs after `format_exc_info`: a traceback is a string, and `ValueError("api_key=…")` has no
    key to match on. Pre-setting `exc_text` is what makes it stick — `logging.Formatter` appends
    `exc_text` verbatim when it is already populated instead of re-rendering the traceback.
    """
    try:
        rendered = record.getMessage()
    except Exception:  # a broken format string must never take down the logging path
        rendered = str(record.msg)
    record.msg = scrub_text(rendered)
    record.args = ()
    if record.exc_info and not record.exc_text:
        record.exc_text = scrub_text("".join(traceback.format_exception(*record.exc_info)))
    elif record.exc_text:
        record.exc_text = scrub_text(record.exc_text)
    if record.stack_info:
        record.stack_info = scrub_text(record.stack_info)
    # `extra={...}` puts arbitrary attributes on the record; a formatter configured with a custom
    # style can emit them. Key-based redaction, same markers as the structlog processor.
    for key, value in list(record.__dict__.items()):
        if key not in _RECORD_RESERVED and _is_secret_key(key) and not _is_reference_id(key, value):
            record.__dict__[key] = REDACTED
        elif isinstance(value, str) and key not in _RECORD_RESERVED:
            record.__dict__[key] = scrub_text(value)
    return record


#: Attributes stdlib owns on every record. Never rewritten — `name`, `pathname`, `funcName` and
#: friends are structure, and scrubbing them would corrupt log routing to no security benefit.
_RECORD_RESERVED = frozenset(logging.LogRecord("", 0, "", 0, "", None, None).__dict__) | {
    "message",
    "asctime",
}


def _install_stdlib_redaction() -> None:
    """Route **stdlib** logging through the same redaction as structlog.

    This is the sink structlog does not cover. `PrintLoggerFactory` means structlog never touches
    the stdlib tree, so every record from a library — Celery logging a failed task *with its
    arguments*, SQLAlchemy logging a statement, httpx, uvicorn — reached the output completely
    unscrubbed. Verified before this existed: a `celery.worker` warning containing `api_key=…`
    was emitted verbatim.

    Hooked at `Logger.makeRecord`, which is the only place that sees a *complete* record. Two
    more obvious hooks were tried and are wrong:

    - A **handler filter** only sees records reaching the handler it is attached to, so it misses
      any logger a library configures with `propagate = False` — uvicorn does exactly this for
      access logs — and needs re-attaching whenever something adds a handler.
    - The **record factory** (`setLogRecordFactory`) is the official hook and covers every logger,
      but `Logger.makeRecord` applies `extra={...}` fields to the record *after* calling it, so
      `logger.warning("ctx", extra={"authorization": token})` slipped past unredacted. That was
      caught by a test, not by reading the docs.

    Patching the method on the class covers every logger instance — those already created at
    import by Celery and SQLAlchemy as well as any created later — with one hook and no topology
    to keep up with.
    """
    if getattr(logging.Logger.makeRecord, "_omniai_redacting", False):
        return  # idempotent: configure_logging runs at import and freely in tests
    original = logging.Logger.makeRecord

    def make_record(*args: Any, **kwargs: Any) -> logging.LogRecord:
        return _scrub_stdlib_record(original(*args, **kwargs))

    make_record._omniai_redacting = True  # type: ignore[attr-defined]
    logging.Logger.makeRecord = make_record  # type: ignore[method-assign]


def configure_logging() -> None:
    """Idempotent; safe to call from app startup and from tests."""
    # Covers every deployed process: the API imports this at startup, and `workers/celery_app.py`
    # calls it at import — which is the entry point for the worker, worker-runtime, and scheduler
    # containers alike, since all three run `celery -A app.workers.celery_app`.
    _install_stdlib_redaction()
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
