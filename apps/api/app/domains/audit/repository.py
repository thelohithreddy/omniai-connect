"""Data access for the Audit Log Viewer — the only layer that touches the DB (SELECT only).

Reads the existing `tool_calls` ledger (owned by the runtime domain), scoped like every other
repository (P-14): `ctx` is required and every statement filters on `workspace_id` explicitly on top
of RLS. Keyset pagination on `(created_at, id)` DESC — deterministic (UUIDv7 `id` breaks timestamp
ties), index-backed (`ix_tool_calls_workspace_id_created_at`), and bounded (LIMIT), so no client can
force an unbounded scan or in-memory pagination. This repository issues no UPDATE/DELETE — the audit
ledger is immutable, and the app role holds no such grant on `tool_calls`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pagination import CursorPosition
from app.core.security import WorkspaceContext
from app.domains.runtime.models import ToolCall


@dataclass(frozen=True, slots=True)
class LogFilters:
    """The canonical UJ-5.3 filters. Each is an additional AND predicate over the workspace scope —
    none can widen the result beyond the caller's own tenant."""

    connection_id: uuid.UUID | None = None
    tool_id: uuid.UUID | None = None
    status: str | None = None
    interface: str | None = None
    created_after: datetime | None = None
    created_before: datetime | None = None


class ToolCallLogRepository:
    def __init__(self, session: AsyncSession, ctx: WorkspaceContext) -> None:
        self._session = session
        self._ctx = ctx

    async def list_page(
        self, *, limit: int, after: CursorPosition | None, filters: LogFilters
    ) -> list[ToolCall]:
        """One page of this Workspace's Tool Call audit rows, newest first, matching `filters`."""
        stmt = select(ToolCall).where(ToolCall.workspace_id == self._ctx.workspace_id)

        if filters.connection_id is not None:
            stmt = stmt.where(ToolCall.connection_id == filters.connection_id)
        if filters.tool_id is not None:
            stmt = stmt.where(ToolCall.tool_id == filters.tool_id)
        if filters.status is not None:
            stmt = stmt.where(ToolCall.status == filters.status)
        if filters.interface is not None:
            stmt = stmt.where(ToolCall.caller["interface"].astext == filters.interface)
        if filters.created_after is not None:
            stmt = stmt.where(ToolCall.created_at >= filters.created_after)
        if filters.created_before is not None:
            stmt = stmt.where(ToolCall.created_at <= filters.created_before)

        if after is not None:
            stmt = stmt.where(
                tuple_(ToolCall.created_at, ToolCall.id) < (after.created_at, after.id)
            )

        stmt = stmt.order_by(ToolCall.created_at.desc(), ToolCall.id.desc()).limit(limit)
        return list((await self._session.scalars(stmt)).all())


__all__ = ["LogFilters", "ToolCallLogRepository"]
