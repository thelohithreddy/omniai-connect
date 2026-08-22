"""Data access for the connections domain — the only layer that touches the DB.

Scoped exactly like the connectors/workspaces repositories: `ctx` is a required constructor
argument, so an unscoped instance cannot be built, and every statement filters on `workspace_id`
explicitly even though RLS enforces the same boundary (defense in depth, P-14). Live rows only —
every read and the revoke filter `deleted_at IS NULL`. Transactions belong to the UnitOfWork.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select, text, tuple_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictError
from app.core.pagination import CursorPosition
from app.core.security import WorkspaceContext
from app.domains.connections.models import Connection
from app.domains.connectors.models import Connector, Tool
from app.domains.credentials.models import Credential
from app.domains.runtime.models import ToolCall


@dataclass(frozen=True, slots=True)
class RevokedConnection:
    """The identifiers of a row `revoke` actually moved — read back from the UPDATE's RETURNING,
    so they describe what the database did, not what the caller asked for (M2.1 event source)."""

    id: uuid.UUID
    workspace_id: uuid.UUID
    connector_id: uuid.UUID


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

    async def probe_candidates(self, connector_id: uuid.UUID) -> list[Tool]:
        """Every **live, enabled** Tool of this Connector in the current Workspace (M2.7).

        Deliberately returns candidates rather than "the safe one": eligibility is a domain rule
        (`health.is_probe_eligible`), and pushing `readonly`/argument filtering into SQL would put
        a security decision in a place no unit test can reach without a database. The `enabled` and
        `deleted_at` predicates stay here because they are the same liveness filter every other
        Tool read applies — a disabled Tool must not even be a candidate.
        """
        stmt = (
            select(Tool)
            .where(
                Tool.connector_id == connector_id,
                Tool.workspace_id == self._ctx.workspace_id,
                Tool.deleted_at.is_(None),
                Tool.enabled.is_(True),
            )
            .order_by(Tool.name.asc())
        )
        return list((await self._session.scalars(stmt)).all())

    async def credential_type_for(self, connection_id: uuid.UUID) -> str | None:
        """The Connection's credential *type* (never its material), or None when unattached.

        Reads one non-secret discriminator column — the `needs_reauth` derivation needs to know
        whether the credential is `oauth2`, and nothing more. No ciphertext, no wrapped key, no
        vault access: this is metadata, and keeping it metadata is what stops a health projection
        from becoming a reason to decrypt.
        """
        stmt = select(Credential.credential_type).where(
            Credential.connection_id == connection_id,
            Credential.workspace_id == self._ctx.workspace_id,
        )
        credential_type: str | None = await self._session.scalar(stmt)
        return credential_type

    async def health_check_status(self, connection_id: uuid.UUID, checked_at: Any) -> str | None:
        """The audit status of the health check that stamped `last_health_check_at`.

        Bound by exact `created_at` equality to the audit row that check produced, which is why
        `last_health_check_at` is written from the row's own timestamp rather than from a fresh
        clock read. That equality is what keeps the projection about *health checks* specifically:
        ordinary Tool Call traffic on the same Connection shares the table but never this instant,
        so it can neither fake a green light nor poison one. `id DESC` is a deterministic tie-break
        for the pathological case of two rows sharing a microsecond.
        """
        stmt = (
            select(ToolCall.status)
            .where(
                ToolCall.connection_id == connection_id,
                ToolCall.workspace_id == self._ctx.workspace_id,
                ToolCall.created_at == checked_at,
            )
            .order_by(ToolCall.id.desc())
            .limit(1)
        )
        check_status: str | None = await self._session.scalar(stmt)
        return check_status

    async def health_inputs(
        self, connection_ids: list[uuid.UUID]
    ) -> dict[uuid.UUID, tuple[str | None, str | None]]:
        """Everything the health projection needs, for many Connections, in one round trip.

        Batched deliberately: the projection is rendered on every connection list, and a per-row
        credential lookup plus a per-row audit lookup would make a page of 50 Connections cost 101
        queries. The lateral join binds each Connection to the audit row its own last health check
        produced (`created_at = last_health_check_at`), which is what keeps ordinary Tool Call
        traffic out of the health signal.

        Returns `{connection_id: (credential_type, last_check_status)}`; either element may be
        None, and the domain layer decides what that means.
        """
        if not connection_ids:
            return {}
        stmt = text("""
            SELECT c.id AS connection_id,
                   cr.credential_type AS credential_type,
                   tc.status AS last_check_status
            FROM connections c
            LEFT JOIN credentials cr
                   ON cr.connection_id = c.id AND cr.workspace_id = c.workspace_id
            LEFT JOIN LATERAL (
                SELECT t.status
                FROM tool_calls t
                WHERE t.workspace_id = c.workspace_id
                  AND t.connection_id = c.id
                  AND t.created_at = c.last_health_check_at
                ORDER BY t.id DESC
                LIMIT 1
            ) tc ON TRUE
            WHERE c.workspace_id = :workspace_id
              AND c.id = ANY(:ids)
        """)
        rows = await self._session.execute(
            stmt, {"workspace_id": self._ctx.workspace_id, "ids": connection_ids}
        )
        return {r.connection_id: (r.credential_type, r.last_check_status) for r in rows}

    async def audit_row(self, tool_call_id: uuid.UUID) -> Any | None:
        """The `(created_at, status)` of one audit row this Workspace owns, or None.

        Read back rather than trusted from the caller: the Runtime owns the audit write, so the
        row's own server-side `created_at` is the authoritative instant a health check completed.
        Stamping a Connection with a separately-read clock would drift from the ledger and break
        the equality join the projection depends on.
        """
        stmt = select(ToolCall.created_at, ToolCall.status).where(
            ToolCall.id == tool_call_id,
            ToolCall.workspace_id == self._ctx.workspace_id,
        )
        return (await self._session.execute(stmt)).one_or_none()

    async def stamp_health_check(self, connection: Connection, checked_at: Any) -> None:
        """Record that a health check completed. The only write this feature makes to a Connection.

        `status` is untouched on purpose: a failed probe is not a lifecycle transition. Only the
        OAuth refresh worker moves a Connection to `error` (ADR-0038 D2), and letting a health
        check do it would hand any caller with `tools:execute` a way to deactivate a Connection by
        pointing it at a temporarily-flaky endpoint.
        """
        connection.last_health_check_at = checked_at

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

    async def revoke(self, connection_id: uuid.UUID) -> RevokedConnection | None:
        """Revoke a live Connection: `status=revoked` + `deleted_at` set. Returns the revoked
        row's identifiers, or None if nothing moved.

        A scoped Core `UPDATE … WHERE deleted_at IS NULL RETURNING`: idempotent (a second revoke
        matches nothing → None), workspace-scoped (a foreign id is simply not found), and it sets
        `updated_at` explicitly because the ORM `onupdate` does not fire on a Core statement.
        The returned identifiers come from the persisted row itself (M2.1) so the service can
        stamp `connection.revoked` from what the database actually did, never from a parameter.
        """
        stmt = (
            update(Connection)
            .where(
                Connection.id == connection_id,
                Connection.workspace_id == self._ctx.workspace_id,
                Connection.deleted_at.is_(None),
            )
            .values(status="revoked", deleted_at=func.now(), updated_at=func.now())
            .returning(Connection.id, Connection.workspace_id, Connection.connector_id)
        )
        row = (await self._session.execute(stmt)).first()
        if row is None:
            return None
        return RevokedConnection(
            id=row.id, workspace_id=row.workspace_id, connector_id=row.connector_id
        )


__all__ = ["ConnectionRepository", "RevokedConnection"]
