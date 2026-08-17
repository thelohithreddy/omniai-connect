"""Redaction + text sanitization (M1 Execution Runtime, SECURITY §2.3, BACKEND_SPEC §7)."""

from __future__ import annotations

from app.domains.runtime.redaction import REDACTED, is_secret_key, redact_arguments, sanitize_text


def test_denylist_keys_are_redacted_case_insensitive() -> None:
    assert is_secret_key("Authorization")
    assert is_secret_key("x-api-key")
    assert is_secret_key("access_token")
    assert is_secret_key("client_secret")
    assert is_secret_key("PASSWORD")
    assert not is_secret_key("customer_id")


def test_extra_registered_keys_are_secret() -> None:
    assert is_secret_key("X-Custom", frozenset({"x-custom"}))
    assert is_secret_key("x-custom", frozenset({"X-Custom"}))


def test_redact_arguments_masks_secret_keys() -> None:
    out = redact_arguments({"token": "abc", "name": "ok", "amount": 5})
    assert out == {"token": REDACTED, "name": "ok", "amount": 5}


def test_redact_arguments_masks_query_placed_api_key() -> None:
    out = redact_arguments({"api_key": "sk-live-x"}, extra_secret_keys=frozenset({"api_key"}))
    assert out == {"api_key": REDACTED}


def test_long_strings_are_truncated() -> None:
    out = redact_arguments({"note": "x" * 500})
    assert out["note"].endswith("…")
    assert len(out["note"]) <= 300


def test_nested_structures_are_summarized_by_shape_not_value() -> None:
    out = redact_arguments({"items": [1, 2, 3], "obj": {"secret": "leak"}})
    assert out["items"] == {"_type": "array", "_len": 3}
    assert out["obj"] == {"_type": "object", "_keys": ["secret"]}
    assert "leak" not in str(out)


def test_sanitize_text_strips_control_and_invisible_characters() -> None:
    # C0 null, zero-width space (200b), RLO bidi override (202e), BOM (feff), ESC (1b).
    dirty = "he" + chr(0) + "llo" + chr(0x200B) + chr(0x202E) + "world" + chr(0xFEFF) + chr(0x1B)
    assert sanitize_text(dirty) == "helloworld"


def test_sanitize_text_keeps_tab_newline_return() -> None:
    assert sanitize_text("a\tb\nc\rd") == "a\tb\nc\rd"
