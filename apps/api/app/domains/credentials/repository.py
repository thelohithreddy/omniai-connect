"""Data access for the credentials domain — the only layer that touches the DB.

Scoped like every other domain repository: `ctx` is required, and every statement filters on
`workspace_id` even though RLS enforces the same boundary (defense in depth, P-14). The connection
is loaded **row-locked** so the credential attach/revoke and the connection's `credential_id` +
status transition happen atomically under one lock. Transactions belong to the UnitOfWork.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictError
from app.core.security import WorkspaceContext
from app.domains.connections.models import Connection
from app.domains.credentials.models import Credential


class CredentialRepository:
    def __init__(self, session: AsyncSession, ctx: WorkspaceContext) -> None:
        self._session = session
        self._ctx = ctx

    async def connection_for_update(self, connection_id: uuid.UUID) -> Connection | None:
        """One live Connection by id, row-locked for the transaction (`SELECT … FOR UPDATE`).

        Locking serializes concurrent attach/rotate/revoke on the same connection so the credential
        row and the connection's `credential_id`/`status` never interleave. Workspace-scoped: a
        foreign or revoked connection is simply not found.
        """
        stmt = (
            select(Connection)
            .where(
                Connection.id == connection_id,
                Connection.workspace_id == self._ctx.workspace_id,
                Connection.deleted_at.is_(None),
            )
            .with_for_update()
        )
        connection: Connection | None = await self._session.scalar(stmt)
        return connection

    async def get_by_connection(self, connection_id: uuid.UUID) -> Credential | None:
        """The Connection's Credential (metadata), or None. Workspace-scoped."""
        stmt = select(Credential).where(
            Credential.connection_id == connection_id,
            Credential.workspace_id == self._ctx.workspace_id,
        )
        credential: Credential | None = await self._session.scalar(stmt)
        return credential

    async def credential_for_update(self, credential_id: uuid.UUID) -> Credential | None:
        """One Credential by id, row-locked for the transaction (M2.6 key rotation, ADR-0039).

        The re-wrap sweep locks the credential itself rather than its Connection: it is the only
        writer that targets a Credential by its own id, and it must serialize against an attach /
        rotate / OAuth refresh re-sealing the same row with a fresh DEK. Workspace-scoped like
        every other statement here — a foreign id is simply not found, even for a platform job.
        """
        stmt = (
            select(Credential)
            .where(
                Credential.id == credential_id,
                Credential.workspace_id == self._ctx.workspace_id,
            )
            .with_for_update()
        )
        credential: Credential | None = await self._session.scalar(stmt)
        return credential

    async def insert(self, credential: Credential) -> Credential:
        """Persist a new Credential. The unique `(connection_id)` index is the DB arbiter that a
        connection has at most one credential; a violation surfaces as a `ConflictError`."""
        self._session.add(credential)
        try:
            await self._session.flush()
        except IntegrityError as err:
            if "uq_credentials_connection_id" in str(getattr(err, "orig", err)):
                raise ConflictError(
                    "This connection already has a credential; rotate it instead."
                ) from err
            raise
        return credential

    async def flush(self) -> None:
        """Flush pending ORM changes — used to clear a connection's `credential_id` pointer to the
        DB *before* the credential row is deleted (the composite FK has no SET NULL)."""
        await self._session.flush()

    async def delete(self, credential: Credential) -> None:
        """Hard-delete a Credential — revocation destroys the material (no soft delete)."""
        await self._session.delete(credential)
        await self._session.flush()


__all__ = ["CredentialRepository"]
