"""HTTP surface for the Execution Runtime — `/v1/tool-calls` (M1, AI_RUNTIME.md, API_GUIDELINES §1).

Thin: parse, delegate, shape. Two endpoints:

- `POST /v1/tool-calls` — invoke a Tool. Authorized by `require_tool_execution` (human RBAC or a
valid
  machine token). An optional `Idempotency-Key` makes retries safe (API_GUIDELINES §5). A
  *successful*
  call returns `200` + the `ToolCallResult`; an *audited failure* (the call executed and failed)
  returns the standard error envelope — built here without raising, so the audit row the service
  already wrote survives the request commit. A *pre-audit failure* (unknown Tool, no/ambiguous
  Connection, authz) is a raised `DomainError` the global handler renders, and its transaction rolls
  back (there is nothing to audit).
- `GET /v1/tool-calls/{id}` — fetch one audit row (redacted metadata). Workspace-scoped: a foreign
id
  is a uniform 404.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse

from app.core.db import UnitOfWork, get_uow
from app.core.exceptions import DomainError
from app.core.security import WorkspaceContext
from app.domains.runtime import idempotency
from app.domains.runtime.policy import require_tool_execution
from app.domains.runtime.schemas import ToolCallCreate, ToolCallRead, ToolCallResult
from app.domains.runtime.service import RuntimeService

tool_calls_router = APIRouter(prefix="/v1/tool-calls", tags=["tool-calls"])

#: Executing (and reading) Tool Calls: humans need `tools:execute`; a valid machine token qualifies.
AuthorizedToolCaller = Annotated[WorkspaceContext, Depends(require_tool_execution)]


def get_runtime_service(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    ctx: AuthorizedToolCaller,
) -> RuntimeService:
    """Composition root: authorization is checked before this runs, so the service is always scoped
    to a workspace the caller may execute in."""
    return RuntimeService(uow, ctx)


def _error_body(error: DomainError, request_id: str) -> dict[str, Any]:
    """The API_GUIDELINES §6 envelope, byte-identical to the global handler's `_envelope`."""
    body: dict[str, Any] = {
        "error": {"code": error.code, "message": error.message, "request_id": request_id}
    }
    if error.details:
        body["error"]["details"] = error.details
    return body


@tool_calls_router.post(
    "",
    response_model=ToolCallResult,
    summary="Execute a Tool Call",
    responses={
        200: {"description": "The Tool Call succeeded; the normalized result and its audit id."},
        400: {"description": "Invalid arguments, ambiguous connection, or a bad Idempotency-Key."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller may not execute Tools, or egress was blocked (ssrf_blocked)."},
        404: {"description": "No such live Tool, or no matching active Connection."},
        409: {"description": "Connection not active / no credential, or an Idempotency-Key clash."},
        502: {"description": "The upstream API errored or the connector auth is misconfigured."},
        504: {"description": "The upstream API timed out."},
    },
)
async def create_tool_call(
    payload: ToolCallCreate,
    request: Request,
    service: Annotated[RuntimeService, Depends(get_runtime_service)],
    ctx: AuthorizedToolCaller,
) -> JSONResponse:
    """Execute one Tool Call synchronously and return its normalized result (or a safe error).

    The Tool is named by canonical `tool_name`; the Connection is explicit (`connection_id`) or the
    single active one for the Connector (ambiguity is a 400, never a guess). Arguments are validated
    against the Tool's input schema before any egress. The credential is decrypted in memory for the
    single outbound request and never returned. An optional `Idempotency-Key` (a UUID) replays the
    original response on retry rather than executing twice.
    """
    idem_key = request.headers.get(idempotency.HEADER)
    digest = ""
    if idem_key is not None:
        idem_key = idempotency.validate_key(idem_key)
        digest = idempotency.body_digest(payload.model_dump(mode="json"))
        replay = await idempotency.begin(ctx.workspace_id, idem_key, digest)
        if replay is not None:
            return JSONResponse(status_code=replay.status_code, content=replay.body)

    try:
        outcome = await service.execute(payload)
    except DomainError:
        # Pre-audit failure rolls back; free the reservation so a genuine retry is not blocked.
        if idem_key is not None:
            await idempotency.release(ctx.workspace_id, idem_key)
        raise

    headers: dict[str, str] = {}
    if outcome.result is not None:
        status_code = status.HTTP_200_OK
        body: dict[str, Any] = outcome.result.model_dump(mode="json")
    else:
        assert outcome.error is not None
        status_code = outcome.error.http_status
        body = _error_body(outcome.error, ctx.request_id)
        if status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            # API_GUIDELINES §6.1/§7: 429 responses set Retry-After. The value comes from the
            # limiter's own non-secret details (bucket refill delay or quota reset horizon).
            # The general every-response X-RateLimit-* stamping is deferred (D5, ADR-0037).
            retry_after = (outcome.error.details or {}).get("retry_after_seconds")
            if isinstance(retry_after, int):
                headers["Retry-After"] = str(retry_after)

    if idem_key is not None:
        await idempotency.complete(ctx.workspace_id, idem_key, digest, status_code, body)
    return JSONResponse(status_code=status_code, content=body, headers=headers)


@tool_calls_router.get(
    "/{tool_call_id}",
    response_model=ToolCallRead,
    summary="Fetch a Tool Call audit record",
    responses={
        200: {"description": "The Tool Call audit row (redacted metadata)."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller may not read Tool Calls in this Workspace."},
        404: {"description": "No such Tool Call in this Workspace."},
    },
)
async def get_tool_call(
    tool_call_id: uuid.UUID,
    service: Annotated[RuntimeService, Depends(get_runtime_service)],
) -> ToolCallRead:
    """One Tool Call audit record by id. Workspace-scoped: a foreign id is a uniform 404, so the
    endpoint is not a cross-tenant oracle. Returns redacted metadata only, never the body."""
    return ToolCallRead.model_validate(await service.get_tool_call(tool_call_id))


__all__ = ["tool_calls_router"]
