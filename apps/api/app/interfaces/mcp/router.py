"""MCP Streamable HTTP endpoint — `POST /mcp/v1/{workspace_slug}` (M2.2, ADR-0035).

The transport + authentication boundary of the MCP adapter, kept thin: parse one JSON-RPC
message, dispatch `initialize` / `ping` / `tools/list`, map everything else to the protocol's
own errors. Canonically the surface is `https://mcp.omniaiconnect.com/v1/{workspace_slug}`
(MCP_RUNTIME §2); the edge maps that host's `/v1/*` onto this app's `/mcp/v1/*` — the internal
prefix keeps user-chosen workspace slugs out of the REST `/v1` route namespace.

Security order (each step fail-closed before the next):

1. **Origin** — Streamable HTTP requires DNS-rebinding protection: a browser-origin request
   (any `Origin` header) is refused. Non-browser MCP clients send none; browsers additionally
   cannot preflight an `Authorization` header here (no CORS surface is configured).
2. **Authentication** — the workspace-scoped `omc_` machine token (ADR-0002: machine identity,
   never human sessions). A human JWT is refused with the uniform 401: MCP is not a human
   surface. The token alone selects the workspace — server-derived, never a client field.
3. **Token/slug binding** — the path slug must name the token's own Workspace (MCP_RUNTIME §2:
   "a token/slug mismatch is rejected before any listing"), as the uniform 401 — the slug
   namespace is not an existence oracle.
4. **Protocol revision** — non-`initialize` requests must carry `MCP-Protocol-Version` naming a
   pinned revision (SUPPORTED_PROTOCOL_VERSIONS); anything else is a 400. The spec's fallback
   default (2025-03-26) is below our floor, so a missing header is refused rather than downgraded.

`tools/call` is deliberately absent (M2.3): it returns the protocol's method-not-found. GET/
DELETE (SSE stream / session teardown) are 405 by construction — this server is sessionless.
HTTP-level failures (401/403) leave through the app's canonical error envelope; JSON-RPC-level
failures use the protocol's error objects. Neither ever carries a secret or a stack trace.
"""

from __future__ import annotations

from typing import Annotated, Any, Final

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select

from app.core.db import UnitOfWork, get_uow
from app.core.exceptions import PermissionDeniedError, UnauthorizedError
from app.core.logging import get_logger
from app.core.security import CurrentWorkspace, WorkspaceContext
from app.domains.tools.repository import ToolRepository
from app.domains.workspaces.models import Workspace
from app.interfaces.mcp import protocol
from app.interfaces.mcp.cache import read_tools_cache, write_tools_cache
from app.interfaces.mcp.execution import execute_tool_call

log = get_logger(__name__)

mcp_router = APIRouter(prefix="/mcp/v1", tags=["mcp"])

_PROTOCOL_VERSION_HEADER: Final = "MCP-Protocol-Version"
_MACHINE_IDENTITY: Final = "api_token"
_UNIFORM_401: Final = "Invalid or revoked API token."


def _reject_browser_origins(request: Request) -> None:
    """Streamable HTTP DNS-rebinding guard: this endpoint serves MCP clients, not browsers."""
    if request.headers.get("origin") is not None:
        raise PermissionDeniedError("Browser-origin requests are not accepted.")


async def _require_mcp_workspace(
    request: Request,
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    ctx: CurrentWorkspace,
    workspace_slug: str,
) -> WorkspaceContext:
    """Admit only a machine token whose Workspace owns the path slug (MCP_RUNTIME §2)."""
    _reject_browser_origins(request)
    if ctx.caller.kind != _MACHINE_IDENTITY:
        raise UnauthorizedError(_UNIFORM_401)
    slug = await uow.session.scalar(select(Workspace.slug).where(Workspace.id == ctx.workspace_id))
    if slug != workspace_slug:
        raise UnauthorizedError(_UNIFORM_401)
    return ctx


async def _discover_tools(uow: UnitOfWork, ctx: WorkspaceContext) -> list[dict[str, Any]]:
    """Cache-aside discovery: the Redis projection when fresh, the authoritative RLS-scoped
    database otherwise. Any cache failure degrades to the database — never to an empty list."""
    cached = await read_tools_cache(ctx.workspace_id)
    if cached is not None:
        log.info("mcp.tools_list", workspace_id=str(ctx.workspace_id), cache="hit")
        return cached
    rows = await ToolRepository(uow.session, ctx).list_discoverable()
    tools = [protocol.mcp_tool(row) for row in rows]
    await write_tools_cache(ctx.workspace_id, tools)
    log.info("mcp.tools_list", workspace_id=str(ctx.workspace_id), cache="miss", count=len(tools))
    return tools


def _jsonrpc(payload: dict[str, Any], status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code)


@mcp_router.post(
    "/{workspace_slug}",
    summary="Workspace MCP endpoint (Streamable HTTP)",
    responses={
        200: {"description": "A JSON-RPC response (result or protocol error)."},
        202: {"description": "Notification accepted."},
        400: {"description": "Malformed JSON, or an unsupported MCP protocol revision."},
        401: {"description": "Missing/invalid token, human session, or token/slug mismatch."},
        403: {"description": "Browser-origin request refused."},
    },
)
async def mcp_endpoint(
    workspace_slug: str,
    request: Request,
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    ctx: Annotated[WorkspaceContext, Depends(_require_mcp_workspace)],
) -> Response:
    """One MCP message per request (sessionless Streamable HTTP, JSON responses)."""
    try:
        body = await request.json()
    except ValueError:
        return _jsonrpc(protocol.error_response(None, protocol.PARSE_ERROR, "Invalid JSON."), 400)

    validated = protocol.validate_message(body)
    if isinstance(validated, str):
        return _jsonrpc(protocol.error_response(None, protocol.INVALID_REQUEST, validated), 400)
    method, msg_id, params = validated

    # Notifications carry no id and expect no body. The only one this server recognises is the
    # post-initialize handshake; unknown notifications are accepted-and-ignored per JSON-RPC.
    if msg_id is None:
        return Response(status_code=202)

    if method == "initialize":
        return _jsonrpc(
            protocol.result_response(
                msg_id, protocol.initialize_result(params.get("protocolVersion"))
            )
        )

    # Every post-initialize request must name a pinned protocol revision (module docstring §4).
    presented = request.headers.get(_PROTOCOL_VERSION_HEADER)
    if presented not in protocol.SUPPORTED_PROTOCOL_VERSIONS:
        return _jsonrpc(
            protocol.error_response(
                msg_id, protocol.INVALID_REQUEST, "Unsupported MCP protocol version."
            ),
            400,
        )

    if method == "ping":
        return _jsonrpc(protocol.result_response(msg_id, {}))

    if method == "tools/list":
        if "cursor" in params:
            # This server returns the complete listing in one page and never issues a cursor.
            return _jsonrpc(
                protocol.error_response(msg_id, protocol.INVALID_PARAMS, "Unknown cursor.")
            )
        tools = await _discover_tools(uow, ctx)
        return _jsonrpc(protocol.result_response(msg_id, {"tools": tools}))

    if method == "tools/call":
        # M2.3 (ADR-0036): translation into the one canonical execution path — the Runtime
        # re-resolves and re-authorizes the Tool at call time (the discovery cache is never
        # execution authority), decrypts at use, enforces egress policy, and writes the audit.
        return _jsonrpc(await execute_tool_call(uow, ctx, msg_id, params))

    return _jsonrpc(protocol.error_response(msg_id, protocol.METHOD_NOT_FOUND, "Method not found."))


__all__ = ["mcp_router"]
