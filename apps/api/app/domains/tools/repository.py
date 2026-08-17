"""Data access for the Tools administration domain — the only layer that touches the DB.

Scoped like every other repository (P-14): `ctx` is a required constructor argument, and every
statement filters on `workspace_id` explicitly even though RLS enforces the same boundary. The live
set is `deleted_at IS NULL` — a soft-deleted (deprecated) Tool is invisible here, as it is to
the Runtime, so a removed Tool can never be listed, fetched, or re-enabled (no resurrection).
Enable/disable is a single conditional `UPDATE ... RETURNING` — a race-safe operation, never
a read-modify-write — so two concurrent toggles resolve to deterministic last-writer-wins with no
lost or corrupted state.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select, tuple_, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pagination import CursorPosition
from app.core.security import WorkspaceContext
from app.domains.connectors.models import Tool


class ToolRepository:
    def __init__(self, session: AsyncSession, ctx: WorkspaceContext) -> None:
        self._session = session
        self._ctx = ctx

    async def list_page(
        self,
        *,
        limit: int,
        after: CursorPosition | None = None,
        connector_id: uuid.UUID | None = None,
    ) -> list[Tool]:
        """One page of this Workspace's LIVE tools (enabled *and* disabled), newest first.

        Keyset on `(created_at, id)`. An optional `connector_id` narrows to one Connector's tools;
        it is applied *in addition to* the workspace predicate, so it can never widen the result to
        another tenant — a foreign connector id simply matches nothing.
        """
        stmt = select(Tool).where(
            Tool.workspace_id == self._ctx.workspace_id,
            Tool.deleted_at.is_(None),
        )
        if connector_id is not None:
            stmt = stmt.where(Tool.connector_id == connector_id)
        if after is not None:
            stmt = stmt.where(tuple_(Tool.created_at, Tool.id) < (after.created_at, after.id))
        stmt = stmt.order_by(Tool.created_at.desc(), Tool.id.desc()).limit(limit)
        return list((await self._session.scalars(stmt)).all())

    async def get(self, tool_id: uuid.UUID) -> Tool | None:
        """One LIVE Tool by id, within the current Workspace.

        The `workspace_id` predicate is not redundant just because `id` is globally unique: dropping
        it would turn a guessed id into a cross-tenant read the moment RLS were misconfigured. A
        soft-deleted (deprecated) Tool is invisible, exactly like a missing one.
        """
        stmt = select(Tool).where(
            Tool.id == tool_id,
            Tool.workspace_id == self._ctx.workspace_id,
            Tool.deleted_at.is_(None),
        )
        tool: Tool | None = await self._session.scalar(stmt)
        return tool

    async def set_enabled(self, tool_id: uuid.UUID, *, enabled: bool) -> Tool | None:
        """Flip a LIVE Tool's `enabled` flag with a single atomic, workspace-scoped UPDATE; return
        the updated row, or None if no live Tool matched (missing, foreign, or deprecated).

        Idempotent — enabling an enabled Tool sets it to enabled again — and race-safe: the state is
        never read-then-written, so concurrent toggles cannot corrupt each other. `updated_at`
        is set explicitly because the ORM `onupdate` does not fire on a Core statement.
        """
        stmt = (
            update(Tool)
            .where(
                Tool.id == tool_id,
                Tool.workspace_id == self._ctx.workspace_id,
                Tool.deleted_at.is_(None),
            )
            .values(enabled=enabled, updated_at=func.now())
            .returning(Tool.id)
        )
        updated_id: uuid.UUID | None = await self._session.scalar(stmt)
        if updated_id is None:
            return None
        return await self.get(tool_id)


__all__ = ["ToolRepository"]
