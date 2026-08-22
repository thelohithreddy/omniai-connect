"""Secret redaction in the structlog pipeline (SECURITY.md §2.3).

Regression cover for a real defect in M1.1: `redact_secrets` was ordered *before*
`format_exc_info`, so exception messages and tracebacks — the strings that carry upstream
error bodies — were emitted completely unscrubbed while key-based redaction appeared to
work. Key-only redaction is also insufficient on its own, because a secret inside
`ValueError("api_key=...")` has no key to match against.
"""

from __future__ import annotations

import contextlib
import io
import logging as stdlib_logging
import uuid

import pytest
import structlog

from app.core.config import settings
from app.core.logging import (
    REDACTED,
    _install_stdlib_redaction,
    configure_logging,
    redact_secrets,
)


@pytest.fixture(autouse=True)
def _verbose_logging() -> object:
    """Force a permissive log level for the duration of each test.

    Without this the suite is environment-dependent: CI sets LOG_LEVEL=warning, structlog's
    filtering bound logger drops `.info()` entirely, and every assertion runs against an
    empty string — which passes the "secret not in output" half and fails the rest for the
    wrong reason.
    """
    original = settings.log_level
    settings.log_level = "debug"
    configure_logging()
    yield
    settings.log_level = original
    configure_logging()


def _emit(**kwargs: object) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        structlog.get_logger("test").info("event", **kwargs)
    out = buf.getvalue()
    assert out, "nothing was emitted — the log level filtered the event out"
    return out


def test_secret_named_keys_are_redacted() -> None:
    # noqa S106: deliberate fake secrets — the whole point is proving they get scrubbed.
    out = _emit(authorization="Bearer LEAKME", api_key="AK_123", password="hunter2")  # noqa: S106
    for secret in ("LEAKME", "AK_123", "hunter2"):
        assert secret not in out
    assert REDACTED in out


def test_nested_structures_are_redacted() -> None:
    out = _emit(ctx={"headers": {"authorization": "Bearer DEEP"}}, items=[{"token": "T_1"}])
    assert "DEEP" not in out
    assert "T_1" not in out


def test_exception_text_is_redacted() -> None:
    """The ordering regression: tracebacks are rendered by format_exc_info.

    If `redact_secrets` runs before it, this leaks.
    """
    buf = io.StringIO()
    try:
        raise ValueError("upstream rejected: api_key=SUPERSECRET123")
    except ValueError:
        with contextlib.redirect_stdout(buf):
            structlog.get_logger("test").exception("boom")
    out = buf.getvalue()
    assert "SUPERSECRET123" not in out, "secret leaked through exception text"
    assert REDACTED in out


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("api_key=ABC123", "ABC123"),
        ("token: TOK_9", "TOK_9"),
        ('{"password": "p@ss"}', "p@ss"),
        # The auth-scheme case: a value pattern that stops at whitespace redacts only
        # "Bearer" and leaves the credential behind.
        ("Authorization=Bearer XYZ789", "XYZ789"),
        ("authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("upstream said secret=s3cr3t, retry later", "s3cr3t"),
    ],
)
def test_secret_patterns_inside_free_text_are_redacted(text: str, secret: str) -> None:
    scrubbed = redact_secrets(None, "info", {"event": text})["event"]
    assert secret not in scrubbed, f"{secret!r} survived in {scrubbed!r}"
    assert REDACTED in scrubbed


def test_non_secret_values_are_left_alone() -> None:
    """Over-redaction is preferred, but it must not eat ordinary fields."""
    out = redact_secrets(None, "info", {"event": "http.request", "status": 200, "path": "/health"})
    assert out["event"] == "http.request"
    assert out["status"] == 200
    assert out["path"] == "/health"


def test_container_types_are_preserved() -> None:
    """Redaction must not silently turn a tuple into a list."""
    out = redact_secrets(None, "info", {"pair": ("a", "b")})
    assert isinstance(out["pair"], tuple)


# ==================================================== M2.6 — the stdlib sink (P2, ADR-0039)
#
# structlog uses `PrintLoggerFactory`, so it never touches the stdlib logging tree. Every record
# from a library — Celery logging a failed task *with its arguments*, SQLAlchemy logging a failing
# statement, httpx, uvicorn — went out unscrubbed. These tests pin the bridge that closed it.
#
# Each one fails if `_install_stdlib_redaction` is removed, which is the point: a redaction control
# whose test still passes without the control is not testing the control.


@pytest.fixture
def stdlib_capture() -> object:
    """Capture what a stdlib handler would actually emit, after formatting."""
    configure_logging()  # installs the record factory (idempotent)
    records: list[stdlib_logging.LogRecord] = []

    class Sink(stdlib_logging.Handler):
        def emit(self, record: stdlib_logging.LogRecord) -> None:
            records.append(record)

    handler = Sink()
    logger = stdlib_logging.getLogger("omniai.test.redaction")
    logger.addHandler(handler)
    logger.setLevel(stdlib_logging.DEBUG)
    logger.propagate = False
    formatter = stdlib_logging.Formatter("%(message)s")

    def emitted() -> str:
        return "\n".join(formatter.format(r) for r in records)

    try:
        yield emitted
    finally:
        logger.removeHandler(handler)


def test_stdlib_message_is_redacted(stdlib_capture) -> None:
    stdlib_logging.getLogger("omniai.test.redaction").warning(
        "task failed args=(api_key=SUPERSECRET456,)"
    )
    output = stdlib_capture()
    assert "SUPERSECRET456" not in output
    assert REDACTED in output


def test_stdlib_percent_interpolation_is_redacted(stdlib_capture) -> None:
    """The case that defeats scrubbing msg and args separately: neither half is suspicious on its
    own — `token=%s` has no secret and `SUPERSECRET` has no marker — so the leak only exists once
    they are joined. Redaction must therefore happen on the rendered string."""
    stdlib_logging.getLogger("omniai.test.redaction").warning("token=%s", "SUPERSECRET999")
    output = stdlib_capture()
    assert "SUPERSECRET999" not in output
    assert REDACTED in output


def test_stdlib_traceback_is_redacted(stdlib_capture) -> None:
    """An upstream API that echoes a credential in its error body reaches us as exception text."""
    try:
        raise ValueError("upstream said api_key=SUPERSECRET789")
    except ValueError:
        stdlib_logging.getLogger("omniai.test.redaction").exception("boom")
    formatter = stdlib_logging.Formatter("%(message)s")
    del formatter
    output = stdlib_capture()
    assert "SUPERSECRET789" not in output


def test_stdlib_extra_fields_are_redacted_by_key(stdlib_capture) -> None:
    record_holder: list[stdlib_logging.LogRecord] = []

    class Grab(stdlib_logging.Handler):
        def emit(self, record: stdlib_logging.LogRecord) -> None:
            record_holder.append(record)

    logger = stdlib_logging.getLogger("omniai.test.redaction")
    grab = Grab()
    logger.addHandler(grab)
    try:
        logger.warning("ctx", extra={"authorization": "Bearer SUPERSECRET111"})
    finally:
        logger.removeHandler(grab)
    assert record_holder[-1].authorization == REDACTED


def test_the_stdlib_hook_is_idempotent() -> None:
    """`configure_logging` runs at import in the API *and* in every Celery process, and tests call
    it freely. Stacking a wrapper per call would rescrub already-scrubbed text on every record."""
    _install_stdlib_redaction()
    first = stdlib_logging.Logger.makeRecord
    _install_stdlib_redaction()
    _install_stdlib_redaction()
    assert stdlib_logging.Logger.makeRecord is first


def test_reserved_record_attributes_are_not_rewritten(stdlib_capture) -> None:
    """`funcName`, `pathname` and friends are log *structure*. Scrubbing them would corrupt
    routing for no security benefit — and `name` containing 'token' is a module name, not a
    secret."""
    logger = stdlib_logging.getLogger("omniai.test.redaction")
    records: list[stdlib_logging.LogRecord] = []

    class Grab(stdlib_logging.Handler):
        def emit(self, record: stdlib_logging.LogRecord) -> None:
            records.append(record)

    grab = Grab()
    logger.addHandler(grab)
    try:
        logger.warning("plain message")
    finally:
        logger.removeHandler(grab)
    assert records[-1].name == "omniai.test.redaction"
    assert records[-1].levelname == "WARNING"


# ============================================ reference ids survive redaction (M2.6, ADR-0039)
#
# The broad marker match was actively harmful for audit records: `credential_id` contains
# "credential" and `api_token_id` contains "token", so the vault-access audit logged
# "someone opened «redacted»". The exemption is deliberately two-condition — `*_id` AND a UUID
# value — so it cannot become a way to smuggle a secret past the redactor under an id-shaped name.


def test_uuid_reference_ids_are_kept_so_the_audit_can_name_what_was_accessed() -> None:
    credential_id, workspace_id = str(uuid.uuid4()), str(uuid.uuid4())
    out = redact_secrets(
        None,
        "info",
        {
            "event": "vault.credential_opened",
            "credential_id": credential_id,
            "workspace_id": workspace_id,
            "api_token_id": str(uuid.uuid4()),
        },
    )
    assert out["credential_id"] == credential_id
    assert out["workspace_id"] == workspace_id
    assert out["api_token_id"] != REDACTED


def test_an_id_shaped_key_holding_a_non_uuid_is_still_redacted() -> None:
    """Both conditions are required. A secret mislabelled as an id does not get a free pass."""
    out = redact_secrets(None, "info", {"token_id": "sk-live-NOT-A-UUID", "secret_id": "hunter2"})
    assert out["token_id"] == REDACTED
    assert out["secret_id"] == REDACTED


def test_secret_keys_that_are_not_ids_are_unaffected_by_the_exemption() -> None:
    out = redact_secrets(
        None,
        "info",
        {"api_key": str(uuid.uuid4()), "authorization": "Bearer x", "password": "p"},
    )
    assert out["api_key"] == REDACTED  # a UUID-valued *secret* is still a secret
    assert out["authorization"] == REDACTED
    assert out["password"] == REDACTED


def test_the_exemption_applies_inside_nested_structures() -> None:
    credential_id = str(uuid.uuid4())
    out = redact_secrets(
        None, "info", {"ctx": {"credential_id": credential_id, "api_key": "sk-live-LEAK"}}
    )
    assert out["ctx"]["credential_id"] == credential_id
    assert out["ctx"]["api_key"] == REDACTED
