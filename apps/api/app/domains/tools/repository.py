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
from app.domains.connections.models import Connection
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

    async def list_discoverable(self) -> list[Tool]:
        """Every Tool of this Workspace that an AI surface may currently discover (M2.2): live and
        enabled, with its Connector bound by at least one live `active` Connection — exactly the
        set the Runtime will execute (its resolve stage requires live+enabled and binds an active
        Connection), so discovery and execution authority can never diverge on state.

        Workspace-scoped in both the outer query and the EXISTS subquery (defense in depth over
        RLS, P-14) — the tenant boundary is enforced server-side in SQL, never by filtering in
        Python. Ordered `(created_at, id) DESC`, the canonical Tool listing order (deterministic:
        UUIDv7 tie-break), matching `GET /v1/tools`.
        """
        bound_by_active_connection = (
            select(Connection.id)
            .where(
                Connection.workspace_id == self._ctx.workspace_id,
                Connection.connector_id == Tool.connector_id,
                Connection.status == "active",
                Connection.deleted_at.is_(None),
            )
            .exists()
        )
        stmt = (
            select(Tool)
            .where(
                Tool.workspace_id == self._ctx.workspace_id,
                Tool.deleted_at.is_(None),
                Tool.enabled.is_(True),
                bound_by_active_connection,
            )
            .order_by(Tool.created_at.desc(), Tool.id.desc())
        )
        return list((await self._session.scalars(stmt)).all())

    async def set_enabled(self, tool_id: uuid.UUID, *, enabled: bool) -> tuple[Tool | None, bool]:
        """Flip a LIVE Tool's `enabled` flag with a single atomic, workspace-scoped UPDATE; return
        `(tool, changed)` — the current row (or None if no live Tool matched: missing, foreign, or
        deprecated) and whether this statement actually transitioned the persisted state.

        Idempotent at the API — enabling an enabled Tool is a 200 no-op — and race-safe: the
        UPDATE is value-guarded (`enabled != :desired`, M2.1), so it matches only when a real flip
        occurs. Two concurrent identical PATCHes serialize on the row lock and exactly one sees
        `changed=True` (READ COMMITTED re-evaluates the predicate after the lock), which is what
        makes `tool.enabled`/`tool.disabled` emit exactly once per persisted transition — a no-op
        touches nothing (not even `updated_at`) and emits nothing. `updated_at` is set explicitly
        because the ORM `onupdate` does not fire on a Core statement.
        """
        stmt = (
            update(Tool)
            .where(
                Tool.id == tool_id,
                Tool.workspace_id == self._ctx.workspace_id,
                Tool.deleted_at.is_(None),
                Tool.enabled != enabled,
            )
            .values(enabled=enabled, updated_at=func.now())
            .returning(Tool.id)
        )
        updated_id: uuid.UUID | None = await self._session.scalar(stmt)
        # `get` distinguishes the two zero-row cases: no live Tool (→ 404 upstream) versus a
        # no-op on an existing row (→ idempotent 200, no event). Same-transaction read, so a
        # changed row reflects this statement's own write.
        return await self.get(tool_id), updated_id is not None


__all__ = ["ToolRepository"]
