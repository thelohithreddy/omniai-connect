"""HTTP surface for the Audit Log Viewer — `GET /v1/tool-calls` (M1-Audit-Viewer-v1).

Thin: parse, delegate, shape. This is the **full workspace audit log** viewer (PRD FR-CP-3 / UJ-5),
gated by `audit:read` — "View full audit log — every member's activity, not just one's own" — so
OWNER/ADMIN only; MEMBER and VIEWER are denied (a member's own-logs view is deferred M1 work). The
list shares the canonical `/v1/tool-calls` resource with the runtime's `POST` (invoke) and
`GET /{id}` (fetch a result); those are unchanged. The Workspace is the authenticated context, never
a field, so a cross-workspace listing is not a request this API can express. Read-only: no POST /
PATCH / PUT / DELETE here, and the response is an explicit schema — never a raw ORM row.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Query, Request

from app.core.authorization import require_permission
from app.core.authz import Permission
from app.core.db import UnitOfWork, get_uow
from app.core.exceptions import ValidationFailedError
from app.core.pagination import DEFAULT_LIMIT, MAX_LIMIT
from app.core.security import WorkspaceContext
from app.domains.audit.repository import LogFilters, ToolCallLogRepository
from app.domains.audit.schemas import ToolCallLogList, ToolCallLogRead
from app.domains.audit.service import ToolCallLogService

audit_router = APIRouter(prefix="/v1/tool-calls", tags=["audit"])

#: Viewing the full Tool Call audit log is `audit:read` (owner/admin).
AuditReader = Annotated[WorkspaceContext, Depends(require_permission(Permission.AUDIT_READ))]

_ALLOWED_LIST_PARAMS: Final = frozenset(
    {
        "limit",
        "cursor",
        "connection_id",
        "tool_id",
        "status",
        "interface",
        "created_after",
        "created_before",
    }
)


def _log_service(
    uow: Annotated[UnitOfWork, Depends(get_uow)], ctx: AuditReader
) -> ToolCallLogService:
    """Composition root: `audit:read` is checked before the repository is built."""
    return ToolCallLogService(ToolCallLogRepository(uow.session, ctx))


def _reject_unknown_query_params(request: Request) -> None:
    """API_GUIDELINES §4: unknown filter/sort fields are a `validation_error`, never ignored."""
    unknown = sorted(set(request.query_params) - _ALLOWED_LIST_PARAMS)
    if unknown:
        raise ValidationFailedError(
            "Unknown query parameters.",
            details={"unknown": unknown, "allowed": sorted(_ALLOWED_LIST_PARAMS)},
        )


@audit_router.get(
    "",
    response_model=ToolCallLogList,
    summary="List the Workspace's Tool Call audit log",
    responses={
        200: {"description": "A page of this Workspace's Tool Call audit records, newest first."},
        400: {"description": "Unknown query parameter, bad limit/status, or an invalid cursor."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `audit:read` in this Workspace."},
    },
)
async def list_tool_call_log(
    service: Annotated[ToolCallLogService, Depends(_log_service)],
    _: Annotated[None, Depends(_reject_unknown_query_params)],
    limit: Annotated[
        int, Query(ge=1, le=MAX_LIMIT, description="Page size. Defaults to 50, maximum 100.")
    ] = DEFAULT_LIMIT,
    cursor: Annotated[str | None, Query(description="Opaque cursor from a prior page.")] = None,
    connection_id: Annotated[uuid.UUID | None, Query(description="Filter by Connection.")] = None,
    tool_id: Annotated[uuid.UUID | None, Query(description="Filter by Tool.")] = None,
    status: Annotated[
        str | None, Query(description="Filter by status (succeeded|failed|denied|timeout).")
    ] = None,
    interface: Annotated[str | None, Query(description="Filter by Interface (e.g. rest).")] = None,
    created_after: Annotated[
        datetime | None, Query(description="Only records at/after this RFC 3339 time.")
    ] = None,
    created_before: Annotated[
        datetime | None, Query(description="Only records at/before this RFC 3339 time.")
    ] = None,
) -> ToolCallLogList:
    """Page through this Workspace's Tool Call audit log, newest first, with the canonical UJ-5.3
    filters. Redacted metadata only — credentials, tokens, and raw bodies never appear (they were
    scrubbed at write time). The Workspace comes from the authenticated context and appears in no
    parameter, so a cross-workspace listing is not a request this API can express."""
    filters = LogFilters(
        connection_id=connection_id,
        tool_id=tool_id,
        status=status,
        interface=interface,
        created_after=created_after,
        created_before=created_before,
    )
    page = await service.list_page(limit=limit, cursor=cursor, filters=filters)
    return ToolCallLogList(
        data=[ToolCallLogRead.model_validate(r) for r in page.rows],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )


__all__ = ["audit_router"]
