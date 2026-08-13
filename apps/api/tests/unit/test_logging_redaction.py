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

import pytest
import structlog

from app.core.logging import REDACTED, configure_logging, redact_secrets


def _emit(**kwargs: object) -> str:
    configure_logging()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        structlog.get_logger("test").info("event", **kwargs)
    return buf.getvalue()


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
    configure_logging()
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
