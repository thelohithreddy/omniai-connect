"""Data access for notifications. Two reads, both tenant-scoped by construction.

Like every repository here, it cannot be built without a `WorkspaceContext` (P-14), so "I forgot
the WHERE clause" is not a mistake this code can express. Both statements carry the tenant
predicate explicitly rather than relying on RLS: RLS is the second net (DATABASE_DESIGN §6), and
the notification task runs in a worker where a misconfigured `SET LOCAL` would otherwise be the
only thing standing between one tenant's Connection and another tenant's address.

The destination is read **server-side, from the Workspace row**, and is never accepted from a
caller. That is what makes the Celery task incapable of being used to mail an arbitrary address:
there is no parameter to supply one.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import WorkspaceContext
from app.domains.connections.models import Connection
from app.domains.workspaces.models import Workspace


@dataclass(frozen=True, slots=True)
class NotifiableConnection:
    """The minimum a notification needs about a Connection. Metadata only, never a credential."""

    id: uuid.UUID
    name: str


class NotificationRepository:
    def __init__(self, session: AsyncSession, ctx: WorkspaceContext) -> None:
        self._session = session
        self._ctx = ctx

    async def destination(self) -> str | None:
        """The Workspace's configured notification address, or None when notifications are off."""
        stmt = select(Workspace.notification_email).where(Workspace.id == self._ctx.workspace_id)
        address: str | None = await self._session.scalar(stmt)
        return address

    async def connection(self, connection_id: uuid.UUID) -> NotifiableConnection | None:
        """One live Connection's display metadata, scoped to the bound tenant.

        Soft-deleted Connections are excluded: a deleted Connection has no health worth reporting,
        and a queued notification that arrives after a deletion should evaporate rather than email
        someone about a resource they removed.
        """
        stmt = select(Connection.id, Connection.name).where(
            Connection.id == connection_id,
            Connection.workspace_id == self._ctx.workspace_id,
            Connection.deleted_at.is_(None),
        )
        row = (await self._session.execute(stmt)).first()
        if row is None:
            return None
        return NotifiableConnection(id=row[0], name=row[1])


__all__ = ["NotifiableConnection", "NotificationRepository"]
