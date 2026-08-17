"""Data access for the connections domain — the only layer that touches the DB.

Scoped exactly like the connectors/workspaces repositories: `ctx` is a required constructor
argument, so an unscoped instance cannot be built, and every statement filters on `workspace_id`
explicitly even though RLS enforces the same boundary (defense in depth, P-14). Live rows only —
every read and the revoke filter `deleted_at IS NULL`. Transactions belong to the UnitOfWork.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select, tuple_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictError
from app.core.pagination import CursorPosition
from app.core.security import WorkspaceContext
from app.domains.connections.models import Connection
from app.domains.connectors.models import Connector


class ConnectionRepository:
    def __init__(self, session: AsyncSession, ctx: WorkspaceContext) -> None:
        self._session = session
        self._ctx = ctx

    async def live_connector_exists(self, connector_id: uuid.UUID) -> bool:
        """Whether a LIVE Connector with this id exists in the current Workspace.

        The workspace predicate is the whole point: a connector id from another tenant simply is
        not found here, so a connection can never bind a foreign connector (the composite FK is the
        second net). A soft-deleted connector is invisible, exactly like a missing one.
        """
        stmt = select(Connector.id).where(
            Connector.id == connector_id,
            Connector.workspace_id == self._ctx.workspace_id,
            Connector.deleted_at.is_(None),
        )
        return (await self._session.scalar(stmt)) is not None

    async def create(
        self, *, connector_id: uuid.UUID, name: str, config_overrides: dict[str, Any]
    ) -> Connection:
        """Persist a new Connection (`pending_auth`) into the current Workspace.

        `workspace_id`/`status` are server-set, never parameters. The partial unique index on
        `(workspace_id, name) WHERE deleted_at IS NULL` is the DB arbiter that stops two live
        connections sharing a name under concurrency; a violation surfaces as a `ConflictError`.
        """
        connection = Connection(
            workspace_id=self._ctx.workspace_id,
            connector_id=connector_id,
            name=name,
            status="pending_auth",
            config_overrides=config_overrides,
        )
        self._session.add(connection)
        try:
            await self._session.flush()
        except IntegrityError as err:
            if "uq_connections_workspace_id_name" in str(getattr(err, "orig", err)):
                raise ConflictError(
                    "A connection with that name already exists in this workspace.",
                    details={"name": name},
                ) from err
            raise
        return connection

    async def get(self, connection_id: uuid.UUID) -> Connection | None:
        """One live Connection by id, within the current Workspace.

        The `workspace_id` predicate is not redundant just because `id` is globally unique: dropping
        it would turn a guessed id into a cross-tenant read the moment RLS were misconfigured. A
        revoked (soft-deleted) connection is invisible, exactly like a missing one.
        """
        stmt = select(Connection).where(
            Connection.id == connection_id,
            Connection.workspace_id == self._ctx.workspace_id,
            Connection.deleted_at.is_(None),
        )
        connection: Connection | None = await self._session.scalar(stmt)
        return connection

    async def list_page(
        self, *, limit: int, after: CursorPosition | None = None
    ) -> list[Connection]:
        """One page of this Workspace's live Connections, newest first (keyset created_at, id)."""
        stmt = select(Connection).where(
            Connection.workspace_id == self._ctx.workspace_id,
            Connection.deleted_at.is_(None),
        )
        if after is not None:
            stmt = stmt.where(
                tuple_(Connection.created_at, Connection.id) < (after.created_at, after.id)
            )
        stmt = stmt.order_by(Connection.created_at.desc(), Connection.id.desc()).limit(limit)
        return list((await self._session.scalars(stmt)).all())

    async def update(
        self,
        connection_id: uuid.UUID,
        *,
        name: str | None,
        config_overrides: dict[str, Any] | None,
    ) -> Connection | None:
        """Update a live Connection's `name`/`config_overrides`, or None if not found.

        Loads the row scoped to the Workspace, mutates only the two mutable fields, and flushes —
        a rename that collides with another live connection surfaces as a `ConflictError` from the
        partial unique index (the DB, not an application check, is the arbiter). `status`,
        `credential_id`, `connector_id`, and `workspace_id` are never touched.
        """
        connection = await self.get(connection_id)
        if connection is None:
            return None
        if name is not None:
            connection.name = name
        if config_overrides is not None:
            connection.config_overrides = config_overrides
        try:
            await self._session.flush()
        except IntegrityError as err:
            if "uq_connections_workspace_id_name" in str(getattr(err, "orig", err)):
                raise ConflictError(
                    "A connection with that name already exists in this workspace.",
                    details={"name": name},
                ) from err
            raise
        return connection

    async def revoke(self, connection_id: uuid.UUID) -> bool:
        """Revoke a live Connection: `status=revoked` + `deleted_at` set. Returns whether it moved.

        A scoped Core `UPDATE … WHERE deleted_at IS NULL RETURNING`: idempotent (a second revoke
        matches nothing → False), workspace-scoped (a foreign id is simply not found), and it sets
        `updated_at` explicitly because the ORM `onupdate` does not fire on a Core statement.
        """
        stmt = (
            update(Connection)
            .where(
                Connection.id == connection_id,
                Connection.workspace_id == self._ctx.workspace_id,
                Connection.deleted_at.is_(None),
            )
            .values(status="revoked", deleted_at=func.now(), updated_at=func.now())
            .returning(Connection.id)
        )
        revoked_id: uuid.UUID | None = await self._session.scalar(stmt)
        return revoked_id is not None


__all__ = ["ConnectionRepository"]
