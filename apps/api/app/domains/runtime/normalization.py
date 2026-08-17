"""Response normalization (AI_RUNTIME.md §2 stage 6).

Turns the guarded upstream response into two things:

- **content** — the LLM-facing payload. JSON is parsed to structured data; text is decoded and
  control/invisible characters stripped (`redaction.sanitize_text`); anything binary becomes a typed
  *reference* (content-type + byte count), never inline bytes. Every shape carries `truncated`.
- **output_summary** — the audit row's `output_summary`: response *metadata only* (status,
  content-type, size, truncation). Never the raw body, never a header, never a secret (SECURITY.md
  §2.3 / DATABASE_DESIGN.md `tool_calls`).

The upstream body is untrusted data; this module never re-interprets it as instructions and never
echoes it verbatim into an error or a log (BACKEND_SPEC.md §7, AI_RUNTIME.md §7).
"""

from __future__ import annotations

import json
from typing import Any

from app.core.net import GuardedResponse
from app.domains.runtime.redaction import sanitize_text


def _content_type(response: GuardedResponse) -> str:
    raw = str(response.headers.get("content-type", ""))
    return raw.split(";", 1)[0].strip().lower()


def _is_json(content_type: str) -> bool:
    return content_type == "application/json" or content_type.endswith("+json")


def _is_text(content_type: str) -> bool:
    return content_type.startswith("text/") or content_type in {
        "application/xml",
        "application/javascript",
        "application/x-www-form-urlencoded",
    }


def normalize_response(response: GuardedResponse) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return `(content, output_summary)`. `content` is safe for LLM consumption; `output_summary`
    is safe for the audit row. Neither carries a secret or a verbatim untrusted body in a header."""
    content_type = _content_type(response)
    body = response.body

    output_summary: dict[str, Any] = {
        "status_code": response.status_code,
        "content_type": content_type or None,
        "bytes": len(body),
        "truncated": response.truncated,
    }

    content: dict[str, Any]
    if _is_json(content_type) and not response.truncated:
        try:
            content = {"type": "json", "json": json.loads(body), "truncated": False}
        except (json.JSONDecodeError, UnicodeDecodeError):
            content = {
                "type": "text",
                "text": sanitize_text(body.decode("utf-8", errors="replace")),
                "truncated": response.truncated,
            }
    elif _is_json(content_type) or _is_text(content_type):
        content = {
            "type": "text",
            "text": sanitize_text(body.decode("utf-8", errors="replace")),
            "truncated": response.truncated,
        }
    else:
        # Binary or unknown: a typed reference, never inline bytes.
        content = {
            "type": "binary",
            "content_type": content_type or "application/octet-stream",
            "bytes": len(body),
            "truncated": response.truncated,
        }

    return content, output_summary


__all__ = ["normalize_response"]
