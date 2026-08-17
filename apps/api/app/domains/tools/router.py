"""HTTP surface for Tools administration — `/v1/tools` (M1-Tools-v1). Thin: parse, delegate, shape.

Two authorization planes, straight from the canonical matrix (SECURITY §4.1, `core/authz.py`):

- **Reading** Tools is `tools:execute` — its capability is literally "Execute Tool Calls, *view
  Tools* and own logs" (OWNER/ADMIN/MEMBER; VIEWER denied). `GET /v1/tools`, `GET /v1/tools/{id}`.
- **Enabling/disabling** a Tool is Connector configuration (FR-CE-4, "per-Tool enable/disable on a
  Connector") → `connectors:manage` (OWNER/ADMIN). `PATCH /v1/tools/{id}`.

The Workspace is the authenticated context (never a field), so a cross-workspace request is not one
this API can express; a foreign or deprecated Tool is a uniform 404. No hand-built error responses.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Query, Request

from app.core.authorization import require_permission
from app.core.authz import Permission
from app.core.db import UnitOfWork, get_uow
from app.core.exceptions import ValidationFailedError
from app.core.pagination import DEFAULT_LIMIT, MAX_LIMIT
from app.core.security import WorkspaceContext
from app.domains.tools.repository import ToolRepository
from app.domains.tools.schemas import ToolList, ToolRead, ToolUpdate
from app.domains.tools.service import ToolService

tools_router = APIRouter(prefix="/v1/tools", tags=["tools"])

#: Viewing Tools — `tools:execute` (owner/admin/member); enable/disable — `connectors:manage`.
AuthorizedToolReader = Annotated[
    WorkspaceContext, Depends(require_permission(Permission.TOOLS_EXECUTE))
]
AuthorizedToolAdmin = Annotated[
    WorkspaceContext, Depends(require_permission(Permission.CONNECTORS_MANAGE))
]

_ALLOWED_LIST_PARAMS: Final = frozenset({"limit", "cursor", "connector_id"})


def _reader_service(
    uow: Annotated[UnitOfWork, Depends(get_uow)], ctx: AuthorizedToolReader
) -> ToolService:
    """Composition root for reads: `tools:execute` is checked before the repository is built."""
    return ToolService(ToolRepository(uow.session, ctx))


def _admin_service(
    uow: Annotated[UnitOfWork, Depends(get_uow)], ctx: AuthorizedToolAdmin
) -> ToolService:
    """Composition root for enable/disable: `connectors:manage` checked before the service runs."""
    return ToolService(ToolRepository(uow.session, ctx))


def _reject_unknown_query_params(request: Request) -> None:
    """API_GUIDELINES §4: unknown filter/sort fields are a `validation_error`, never ignored."""
    unknown = sorted(set(request.query_params) - _ALLOWED_LIST_PARAMS)
    if unknown:
        raise ValidationFailedError(
            "Unknown query parameters.",
            details={"unknown": unknown, "allowed": sorted(_ALLOWED_LIST_PARAMS)},
        )


@tools_router.get(
    "",
    response_model=ToolList,
    summary="List the Workspace's Tools",
    responses={
        200: {"description": "A page of this Workspace's live tools (enabled and disabled)."},
        400: {"description": "Unknown query parameter, bad limit, or an invalid cursor."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `tools:execute` in this Workspace."},
    },
)
async def list_tools(
    service: Annotated[ToolService, Depends(_reader_service)],
    _: Annotated[None, Depends(_reject_unknown_query_params)],
    limit: Annotated[
        int, Query(ge=1, le=MAX_LIMIT, description="Page size. Defaults to 50, maximum 100.")
    ] = DEFAULT_LIMIT,
    cursor: Annotated[str | None, Query(description="Opaque cursor from a prior page.")] = None,
    connector_id: Annotated[
        uuid.UUID | None, Query(description="Optional: only tools of this Connector.")
    ] = None,
) -> ToolList:
    """Page through this Workspace's live tools, newest first. The Workspace comes from the
    authenticated context and appears in no parameter, so a cross-workspace listing is not a request
    this API can express. Disabled tools are listed (still manageable); deprecated tools are not."""
    page = await service.list_page(limit=limit, cursor=cursor, connector_id=connector_id)
    return ToolList(
        data=[ToolRead.model_validate(t) for t in page.tools],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )


@tools_router.get(
    "/{tool_id}",
    response_model=ToolRead,
    summary="Get one Tool",
    responses={
        200: {"description": "The Tool metadata."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `tools:execute` in this Workspace."},
        404: {"description": "No such live tool in this Workspace."},
    },
)
async def get_tool(
    tool_id: uuid.UUID,
    service: Annotated[ToolService, Depends(_reader_service)],
) -> ToolRead:
    """One Tool by id. Workspace-scoped: a foreign or deprecated id is a uniform 404, byte-identical
    to one that never existed, so the endpoint is not a cross-tenant oracle."""
    return ToolRead.model_validate(await service.get(tool_id))


@tools_router.patch(
    "/{tool_id}",
    response_model=ToolRead,
    summary="Enable or disable a Tool",
    responses={
        200: {"description": "The updated Tool."},
        400: {"description": "Invalid body (only `enabled` is accepted)."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `connectors:manage` in this Workspace."},
        404: {"description": "No such live tool in this Workspace."},
    },
)
async def update_tool(
    tool_id: uuid.UUID,
    payload: ToolUpdate,
    service: Annotated[ToolService, Depends(_admin_service)],
) -> ToolRead:
    """Enable or disable a Tool. `enabled` is the only mutable field — `extra="forbid"` rejects any
    attempt to rewrite the name, description, schema, or connector identity (those come from
    ingestion/promotion). Idempotent and race-safe; a disabled Tool cannot be executed by the
    Runtime, and a deprecated Tool is a uniform 404 (it cannot be revived here)."""
    tool = await service.set_enabled(tool_id, enabled=payload.enabled)
    return ToolRead.model_validate(tool)


__all__ = ["tools_router"]
