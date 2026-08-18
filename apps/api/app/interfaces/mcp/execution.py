"""MCP `tools/call` → Execution Runtime bridge (M2.3, ADR-0036) — translation, nothing more.

The one execution path (MCP_RUNTIME §4): MCP params → `ToolCallCreate` → the *existing*
`RuntimeService.execute` → `ExecutionOutcome` → MCP tool result. Every authority stays where
M1 put it — the Runtime alone resolves and authorizes the Tool at execution time (a stale
tools/list cache is never authorization), binds the Connection, validates arguments against
the canonical `input_schema`, decrypts the Credential at use inside its own boundary, enforces
SSRF/egress policy and the timeout, and writes the single audit row (`caller.interface="mcp"`).
This module performs no HTTP, no credential access, no validation beyond protocol shape, no
retries (a Tool Call may be destructive — exactly one execution attempt per request), and no
second audit.

Error split (MCP_RUNTIME §4): failures the Runtime *raises* (pre-audit: unknown/disabled/
foreign Tool — one uniform phrase, never an oracle; bad protocol shape; ambiguous Connection)
become JSON-RPC errors. Failures the Runtime *returns* (audited outcomes: upstream errors,
timeout, egress denial, credential failure) become MCP tool results with `isError: true` and
the stable canonical code — `ssrf_blocked` stays distinguishable as a security refusal, and no
message ever carries a target URL, an address, a header, or credential material (the Runtime's
messages are safe by contract; this module adds nothing to them). `_meta` carries the audit
correlation (`tool_call_id`, `request_id`) — the same ids the audit ledger and logs use.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from app.core.db import UnitOfWork
from app.core.exceptions import (
    ConflictError,
    DomainError,
    NotFoundError,
    ValidationFailedError,
)
from app.core.logging import get_logger
from app.core.security import WorkspaceContext
from app.domains.runtime.schemas import ToolCallCreate, ToolCallResult
from app.domains.runtime.service import RuntimeService
from app.interfaces.mcp import protocol

log = get_logger(__name__)

# One phrase for every unresolvable Tool (missing, disabled, deprecated, foreign, no active
# Connection): the Runtime already answers all of them with the uniform not-found, and the MCP
# surface must not become an existence oracle either.
_UNKNOWN_TOOL = "Unknown tool."


def _success_result(result: ToolCallResult) -> dict[str, Any]:
    """Map a succeeded ToolCallResult to the MCP tool-result shape: a text block (JSON-serialized
    normalized content) plus `structuredContent` when the content is an object — only canonical,
    already-normalized, truncation-aware payload ever crosses (AI_RUNTIME truncation rules)."""
    content = result.content
    text = json.dumps(content, separators=(",", ":"), ensure_ascii=False)
    mapped: dict[str, Any] = {
        "content": [{"type": "text", "text": text}],
        "isError": False,
        "_meta": {"omniai/toolCallId": str(result.id), "omniai/requestId": result.request_id},
    }
    if isinstance(content, dict):
        mapped["structuredContent"] = content
    return mapped


def _error_result(error: DomainError, *, tool_call_id: Any, request_id: str) -> dict[str, Any]:
    """Map an audited Runtime failure to an MCP tool result with `isError: true`.

    The text is exactly `<stable code>: <canonical safe message>` — the Runtime's messages carry
    no target, address, header, or secret by contract (SECURITY §3, API_GUIDELINES §6), and this
    adapter appends nothing (no details, no exception text, no status internals).
    """
    return {
        "content": [{"type": "text", "text": f"{error.code}: {error.message}"}],
        "isError": True,
        "_meta": {"omniai/toolCallId": str(tool_call_id), "omniai/requestId": request_id},
    }


async def execute_tool_call(
    uow: UnitOfWork, ctx: WorkspaceContext, msg_id: object, params: dict[str, Any]
) -> dict[str, Any]:
    """Run one MCP `tools/call` through the canonical Runtime; return the JSON-RPC response.

    The workspace is `ctx` — the authenticated, server-derived context. Params carry only the
    protocol's `name` + `arguments`; anything else is ignored, never read (a client cannot name
    a workspace, a connection, or any authority here — `ToolCallCreate` additionally forbids
    extra fields at the model boundary).
    """
    name = params.get("name")
    arguments = params.get("arguments", {})
    if not isinstance(name, str) or not name:
        return protocol.error_response(msg_id, protocol.INVALID_PARAMS, "name is required")
    if not isinstance(arguments, dict):
        return protocol.error_response(
            msg_id, protocol.INVALID_PARAMS, "arguments must be an object"
        )
    try:
        payload = ToolCallCreate(tool_name=name, arguments=arguments)
    except ValidationError:
        return protocol.error_response(msg_id, protocol.INVALID_PARAMS, "invalid tool name")

    service = RuntimeService(uow, ctx, interface="mcp")
    try:
        outcome = await service.execute(payload)
    except NotFoundError:
        # Uniform: absent, disabled, deprecated, foreign, or no live binding — all one phrase.
        return protocol.error_response(msg_id, protocol.INVALID_PARAMS, _UNKNOWN_TOOL)
    except (ValidationFailedError, ConflictError) as exc:
        # Pre-audit request problems (canonically safe messages): bad arguments rejected before
        # any egress, or an ambiguous Connection binding.
        return protocol.error_response(msg_id, protocol.INVALID_PARAMS, exc.message)
    except DomainError:
        # Anything else pre-audit is an internal condition; the app's exception log has the
        # detail under this request_id — the wire gets a stable, empty-handed phrase.
        log.warning("mcp.tools_call_failed", workspace_id=str(ctx.workspace_id))
        return protocol.error_response(msg_id, protocol.INTERNAL_ERROR, "Internal error.")

    if outcome.result is not None:
        return protocol.result_response(msg_id, _success_result(outcome.result))
    assert outcome.error is not None  # ExecutionOutcome invariant: exactly one side is set
    return protocol.result_response(
        msg_id,
        _error_result(outcome.error, tool_call_id=outcome.tool_call_id, request_id=ctx.request_id),
    )


__all__ = ["execute_tool_call"]
