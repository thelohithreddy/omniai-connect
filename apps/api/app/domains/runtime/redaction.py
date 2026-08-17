"""Redaction + text sanitization for audit and LLM content (SECURITY.md §2.3, BACKEND_SPEC §7).

Two jobs, both mandatory before anything is persisted or returned:

- **`redact_arguments`** builds the `tool_calls.input_summary` — a shallow, size-bounded, secret-
free
  projection of the call arguments. Any key on the secret denylist (or a per-Connector-registered
  credential field, e.g. a query-placed api_key) is replaced with `[redacted]`; strings are
  truncated; nested structures are summarized by shape, never by value (so a nested secret or PII
  blob cannot ride into the audit row).
- **`sanitize_text`** strips C0/C1 control characters and zero-width / bidirectional / invisible
  Unicode from upstream text before it becomes Tool content — the runtime cannot make text safe for
  an LLM, but it removes the control/invisible characters used to smuggle hidden instructions
  (AI_RUNTIME.md §7).
"""

from __future__ import annotations

from typing import Any

REDACTED = "[redacted]"

#: Secret markers, matched against the key with separators (`-`/`_`) removed, so every casing and
#: hyphen/underscore variant matches: `x-api-key`, `access_token`, `client_secret`, `Authorization`.
_SECRET_SUBSTRINGS = ("authorization", "apikey", "token", "secret", "password")

_MAX_STR = 256  # per-string cap in the input summary

# Codepoints deleted from upstream text: C0 controls except tab(09)/LF(0a)/CR(0d), DEL+C1, and the
# zero-width / bidi-control / invisible ranges (ZW space–RLM, line/para separators, bidi
# embeds/overrides, word-joiner–bidi-isolates/deprecated, BOM/ZWNBSP). Built by codepoint so no
# literal invisible character ever appears in this source file.
_STRIP_CODEPOINTS: tuple[int, ...] = (
    *range(0x00, 0x09),
    0x0B,
    0x0C,
    *range(0x0E, 0x20),
    *range(0x7F, 0xA0),
    *range(0x200B, 0x2010),  # ZW space, ZWNJ, ZWJ, LRM, RLM, …
    0x2028,
    0x2029,
    *range(0x202A, 0x202F),  # LRE/RLE/PDF/LRO/RLO
    *range(0x2060, 0x2070),  # word joiner, invisible operators, bidi isolates, deprecated
    0xFEFF,  # BOM / ZWNBSP
)
_STRIP_TABLE = dict.fromkeys(_STRIP_CODEPOINTS)


def is_secret_key(key: str, extra_keys: frozenset[str] = frozenset()) -> bool:
    """True if `key` names a secret — on the denylist or a per-Connector credential field."""
    low = key.lower()
    if key in extra_keys or low in {k.lower() for k in extra_keys}:
        return True
    normalized = low.replace("-", "").replace("_", "")
    return any(token in normalized for token in _SECRET_SUBSTRINGS)


def _summarize(value: Any) -> Any:
    """A safe, value-free shape marker for a nested structure."""
    if isinstance(value, list):
        return {"_type": "array", "_len": len(value)}
    if isinstance(value, dict):
        return {"_type": "object", "_keys": sorted(str(k) for k in value)[:20]}
    return value


def redact_arguments(
    arguments: dict[str, Any], *, extra_secret_keys: frozenset[str] = frozenset()
) -> dict[str, Any]:
    """A shallow, secret-free, size-bounded copy of `arguments` for the audit `input_summary`."""
    summary: dict[str, Any] = {}
    for key, value in arguments.items():
        if is_secret_key(key, extra_secret_keys):
            summary[key] = REDACTED
        elif isinstance(value, str):
            summary[key] = value[:_MAX_STR] + "…" if len(value) > _MAX_STR else value
        elif value is None or isinstance(value, (int, float)):  # bool is an int subclass
            summary[key] = value
        else:
            summary[key] = _summarize(value)
    return summary


def sanitize_text(text: str) -> str:
    """Strip control and invisible/bidi characters from upstream text (AI_RUNTIME.md §7)."""
    return text.translate(_STRIP_TABLE)


__all__ = ["REDACTED", "is_secret_key", "redact_arguments", "sanitize_text"]
