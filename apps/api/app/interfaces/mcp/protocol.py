"""MCP protocol contract for the tools/list surface (M2.2, ADR-0035).

Pins the founder-ratified protocol-revision allowlist (MCP_RUNTIME §7 — pinned explicitly,
never implicitly by a dependency), negotiates `initialize`, validates single JSON-RPC messages
(batching was removed from the spec in 2025-06-18 and is rejected), and maps the canonical Tool
Schema to the MCP wire representation. Pure functions over plain data — no IO, no transport,
no domain imports beyond the Tool projection's duck-typed fields.

The mapping is a strict projection: only the canonical LLM-facing fields (`name`,
`description`, `input_schema`) and the three canonical safety annotations cross the boundary
(`readonly`/`destructive`/`idempotent` → MCP `readOnlyHint`/`destructiveHint`/
`idempotentHint`, MCP_RUNTIME §3). Internal metadata (`tags`, `rate_hints`, ids, tenant,
timestamps, endpoint bindings) never enters an MCP response by construction.
"""

from __future__ import annotations

from typing import Any, Final

# Founder-ratified allowlist (M2.2 decision gate): advertise the first entry; accept any listed
# revision. 2026-07-28 is deliberately excluded until its stateless model is reconciled with
# MCP_RUNTIME's session language and its SDKs stabilise — adopting it is a normal upgrade PR
# with contract tests, never a silent bump (MCP_RUNTIME §7).
SUPPORTED_PROTOCOL_VERSIONS: Final[tuple[str, ...]] = ("2025-11-25", "2025-06-18")
ADVERTISED_PROTOCOL_VERSION: Final[str] = SUPPORTED_PROTOCOL_VERSIONS[0]

SERVER_NAME: Final[str] = "omniai-connect"
SERVER_VERSION: Final[str] = "1.0"

# JSON-RPC 2.0 error codes (the spec's canonical set — no invented codes).
PARSE_ERROR: Final[int] = -32700
INVALID_REQUEST: Final[int] = -32600
METHOD_NOT_FOUND: Final[int] = -32601
INVALID_PARAMS: Final[int] = -32602
INTERNAL_ERROR: Final[int] = -32603


def negotiate_version(requested: object) -> str:
    """Spec version negotiation: echo a supported requested revision; otherwise respond with the
    server's advertised revision (the client disconnects if it cannot work with it)."""
    if isinstance(requested, str) and requested in SUPPORTED_PROTOCOL_VERSIONS:
        return requested
    return ADVERTISED_PROTOCOL_VERSION


def validate_message(body: object) -> tuple[str, object | None, dict[str, Any]] | str:
    """Validate one JSON-RPC message; return `(method, id, params)` or an error string.

    A JSON array (batch) is rejected: batching was removed from the protocol in 2025-06-18,
    the oldest revision this server speaks. `id` is None for notifications.
    """
    if not isinstance(body, dict):
        return "a single JSON-RPC message object is required"
    if body.get("jsonrpc") != "2.0":
        return "jsonrpc must be '2.0'"
    method = body.get("method")
    if not isinstance(method, str) or not method:
        return "method is required"
    msg_id = body.get("id")
    if msg_id is not None and not isinstance(msg_id, str | int):
        return "id must be a string or integer"
    params = body.get("params", {})
    if not isinstance(params, dict):
        return "params must be an object"
    return method, msg_id, params


def result_response(msg_id: object, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def error_response(msg_id: object, code: int, message: str) -> dict[str, Any]:
    """A JSON-RPC error. `message` is a stable, non-secret phrase — never a stack trace, an SQL
    error, a target URL, or credential material (SECURITY §3)."""
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def initialize_result(requested_version: object) -> dict[str, Any]:
    """The `initialize` result: negotiated revision, capabilities, identity. `listChanged` is
    declared false — this server does not open server→client notification streams in M2.2 (the
    eviction-driven `listChanged` emission is deferred with tools/call, ADR-0035)."""
    return {
        "protocolVersion": negotiate_version(requested_version),
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
    }


_ANNOTATION_HINTS: Final[tuple[tuple[str, str], ...]] = (
    ("readonly", "readOnlyHint"),
    ("destructive", "destructiveHint"),
    ("idempotent", "idempotentHint"),
)


def mcp_tool(tool: Any) -> dict[str, Any]:
    """Project one canonical Tool row to its MCP wire representation (strict allowlist)."""
    entry: dict[str, Any] = {
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.input_schema,
    }
    annotations = tool.annotations if isinstance(tool.annotations, dict) else {}
    hints = {
        target: value
        for source, target in _ANNOTATION_HINTS
        if isinstance(value := annotations.get(source), bool)
    }
    if hints:
        entry["annotations"] = hints
    return entry


__all__ = [
    "ADVERTISED_PROTOCOL_VERSION",
    "INTERNAL_ERROR",
    "INVALID_PARAMS",
    "INVALID_REQUEST",
    "METHOD_NOT_FOUND",
    "PARSE_ERROR",
    "SERVER_NAME",
    "SERVER_VERSION",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "error_response",
    "initialize_result",
    "mcp_tool",
    "negotiate_version",
    "result_response",
    "validate_message",
]
