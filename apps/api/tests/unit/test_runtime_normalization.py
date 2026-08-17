"""Response normalization + audit summary (M1 Execution Runtime, AI_RUNTIME §2 stage 6)."""

from __future__ import annotations

import httpx

from app.core.net import GuardedResponse
from app.domains.runtime.normalization import normalize_response


def _resp(
    body: bytes, content_type: str, *, status: int = 200, truncated: bool = False
) -> GuardedResponse:
    return GuardedResponse(
        status_code=status,
        headers=httpx.Headers({"content-type": content_type}),
        body=body,
        truncated=truncated,
    )


def test_json_is_parsed_to_structured_content() -> None:
    content, summary = normalize_response(_resp(b'{"id":1,"ok":true}', "application/json"))
    assert content == {"type": "json", "json": {"id": 1, "ok": True}, "truncated": False}
    assert summary == {
        "status_code": 200,
        "content_type": "application/json",
        "bytes": 18,
        "truncated": False,
    }


def test_vendor_json_suffix_is_parsed() -> None:
    content, _ = normalize_response(_resp(b'{"a":1}', "application/vnd.api+json"))
    assert content["type"] == "json"


def test_text_is_decoded_and_control_chars_stripped() -> None:
    content, _ = normalize_response(_resp(b"hello\x00\x07 world", "text/plain"))
    assert content == {"type": "text", "text": "hello world", "truncated": False}


def test_truncated_json_falls_back_to_text() -> None:
    # A body cut mid-stream cannot parse as JSON; it degrades to (truncated) text.
    content, summary = normalize_response(_resp(b'{"a":1', "application/json", truncated=True))
    assert content["type"] == "text"
    assert content["truncated"] is True
    assert summary["truncated"] is True


def test_binary_becomes_a_typed_reference_never_inline() -> None:
    content, _ = normalize_response(_resp(b"\x89PNG\r\n\x1a\n", "image/png"))
    assert content == {
        "type": "binary",
        "content_type": "image/png",
        "bytes": 8,
        "truncated": False,
    }
    assert "bytes" not in {k for k, v in content.items() if isinstance(v, (bytes, bytearray))}


def test_summary_never_contains_the_body() -> None:
    _, summary = normalize_response(_resp(b'{"secret":"leak"}', "application/json"))
    assert "leak" not in str(summary)


def test_upstream_status_is_recorded_in_summary() -> None:
    _, summary = normalize_response(_resp(b"nope", "text/plain", status=503))
    assert summary["status_code"] == 503
