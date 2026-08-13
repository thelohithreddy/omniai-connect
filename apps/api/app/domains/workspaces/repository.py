"""Data access for the workspaces domain. The only layer that touches the DB.

Every repository takes a `WorkspaceContext` in its constructor. That is the point: there
is no way to build one without a tenant, so "I forgot the WHERE clause" is not a mistake
this code can express (P-14). RLS is the second net, not the first.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import WorkspaceContext
from app.domains.workspaces.models import ApiToken, Workspace


class WorkspaceRepository:
    def __init__(self, session: AsyncSession, ctx: WorkspaceContext) -> None:
        self._session = session
        self._ctx = ctx

    async def get_current(self) -> Workspace | None:
        """The caller's own Workspace.

        Filtered on `id` explicitly even though RLS also constrains it — the application
        scoping is the primary control and must stand on its own if RLS is ever misapplied
        (DATABASE_DESIGN.md §6: RLS is defense-in-depth, not the mechanism).
        """
        stmt = select(Workspace).where(Workspace.id == self._ctx.workspace_id)
        # Annotated because AsyncSession.scalar() is typed as returning Any; under mypy
        # strict an unannotated return would silently widen the domain's contract.
        workspace: Workspace | None = await self._session.scalar(stmt)
        return workspace


class ApiTokenRepository:
    def __init__(self, session: AsyncSession, ctx: WorkspaceContext) -> None:
        self._session = session
        self._ctx = ctx

    async def list_for_workspace(self) -> list[ApiToken]:
        stmt = (
            select(ApiToken)
            .where(ApiToken.workspace_id == self._ctx.workspace_id)
            .order_by(ApiToken.created_at.desc())
        )
        return list((await self._session.scalars(stmt)).all())

    async def get(self, token_id: uuid.UUID) -> ApiToken | None:
        stmt = select(ApiToken).where(
            ApiToken.id == token_id,
            ApiToken.workspace_id == self._ctx.workspace_id,
        )
        token: ApiToken | None = await self._session.scalar(stmt)
        return token
