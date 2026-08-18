"""MCP tools/call result/error mapping — pure translation, no runtime (M2.3, ADR-0036).

Proves the ToolCallResult → MCP-result and DomainError → MCP-error(`isError`) projections in
isolation: success carries a text block + structuredContent (+ correlation `_meta`); an audited
failure carries `isError: true` with exactly `<code>: <safe message>` and no details/exception
text. The full runtime-integrated behavior is proven end to end in the integration suite.
"""

from __future__ import annotations

import json
import uuid

from app.core.exceptions import EgressBlockedError, UpstreamAPIError, UpstreamTimeoutError
from app.domains.runtime.schemas import CallUsage, ToolCallResult
from app.interfaces.mcp.execution import _error_result, _success_result


def _result(content: object) -> ToolCallResult:
    return ToolCallResult(
        id=uuid.uuid4(),
        status="succeeded",
        tool_name="demo_op",
        connection_id=uuid.uuid4(),
        content=content,  # type: ignore[arg-type]
        usage=CallUsage(duration_ms=12),
        request_id="req_map",
    )


def test_success_maps_object_content_with_structured_and_text() -> None:
    result = _result({"ok": True, "n": 3})
    mapped = _success_result(result)
    assert mapped["isError"] is False
    assert mapped["content"] == [
        {"type": "text", "text": json.dumps({"ok": True, "n": 3}, separators=(",", ":"))}
    ]
    assert mapped["structuredContent"] == {"ok": True, "n": 3}
    assert mapped["_meta"] == {
        "omniai/toolCallId": str(result.id),
        "omniai/requestId": "req_map",
    }


def test_success_maps_null_content() -> None:
    mapped = _success_result(_result(None))
    assert mapped["isError"] is False
    assert mapped["content"][0]["text"] == "null"
    assert "structuredContent" not in mapped


def test_error_maps_iserror_with_stable_code_and_safe_message() -> None:
    tcid = uuid.uuid4()
    for exc, code in (
        (UpstreamAPIError("The upstream API returned an error."), "connector_error"),
        (UpstreamTimeoutError("The upstream API timed out."), "upstream_timeout"),
        (EgressBlockedError("The outbound request was blocked by egress policy."), "ssrf_blocked"),
    ):
        mapped = _error_result(exc, tool_call_id=tcid, request_id="req_err")
        assert mapped["isError"] is True
        assert mapped["content"][0]["text"] == f"{code}: {exc.message}"
        assert mapped["_meta"]["omniai/toolCallId"] == str(tcid)


def test_error_text_never_carries_details_or_targets() -> None:
    # An error built with details (e.g. upstream_status, a would-be URL) must not surface them.
    exc = EgressBlockedError(
        "The outbound request was blocked by egress policy.",
        details={"target": "http://169.254.169.254/latest/meta-data"},
    )
    mapped = _error_result(exc, tool_call_id=uuid.uuid4(), request_id="req_err")
    flat = json.dumps(mapped)
    assert "169.254" not in flat and "target" not in flat and "meta-data" not in flat
