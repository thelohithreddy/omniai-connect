"""Data access for the connectors domain — the only layer that touches the DB.

Scoped exactly like the workspaces-domain repositories: `ctx` is a required constructor
argument, so an unscoped instance cannot be built, and every statement filters on
`workspace_id` explicitly even though RLS enforces the same boundary. Application scoping is
the primary control; RLS is the second net (DATABASE_DESIGN.md §6, P-14). Live rows only —
every read and the delete filter `deleted_at IS NULL`. Transactions belong to the UnitOfWork;
nothing here commits.
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
from app.domains.connectors.models import Connector


class ConnectorRepository:
    def __init__(self, session: AsyncSession, ctx: WorkspaceContext) -> None:
        self._session = session
        self._ctx = ctx

    async def create(
        self,
        *,
        name: str,
        slug: str,
        source_type: str,
        base_url: str,
        auth_config: dict[str, Any],
        source_url: str | None = None,
        status: str = "draft",
    ) -> Connector:
        """Persist a new Connector into the current Workspace.

        `workspace_id` comes from the context, never a parameter. The partial unique index on
        `(workspace_id, slug) WHERE deleted_at IS NULL` is the invariant that stops two live
        connectors sharing a slug; a violation surfaces here as a `ConflictError` so the
        service never has to interpret SQLAlchemy (BACKEND_SPEC §6).
        """
        connector = Connector(
            workspace_id=self._ctx.workspace_id,
            name=name,
            slug=slug,
            source_type=source_type,
            source_url=source_url,
            base_url=base_url,
            auth_config=auth_config,
            status=status,
        )
        self._session.add(connector)
        try:
            await self._session.flush()
        except IntegrityError as err:
            if "uq_connectors_workspace_id_slug" in str(getattr(err, "orig", err)):
                raise ConflictError(
                    "A connector with that slug already exists in this workspace.",
                    details={"slug": slug},
                ) from err
            raise
        return connector

    async def list_page(
        self, *, limit: int, after: CursorPosition | None = None
    ) -> list[Connector]:
        """One page of this Workspace's live Connectors, newest first.

        Keyset pagination on `(created_at DESC, id DESC)` — the row-comparison predicate is a
        single index range scan on `ix_connectors_workspace_id_created_at`, and `id` (UUIDv7)
        breaks `created_at` ties so no row is skipped or repeated. `workspace_id` is from the
        context, not a parameter: there is no argument through which a caller could name
        another tenant.
        """
        stmt = select(Connector).where(
            Connector.workspace_id == self._ctx.workspace_id,
            Connector.deleted_at.is_(None),
        )
        if after is not None:
            stmt = stmt.where(
                tuple_(Connector.created_at, Connector.id) < (after.created_at, after.id)
            )
        stmt = stmt.order_by(Connector.created_at.desc(), Connector.id.desc()).limit(limit)
        return list((await self._session.scalars(stmt)).all())

    async def get(self, connector_id: uuid.UUID) -> Connector | None:
        """One live Connector by id, within the current Workspace.

        The `workspace_id` predicate is not redundant just because `id` is globally unique:
        dropping it would turn a leaked or guessed id into a cross-tenant read the moment RLS
        were misconfigured. A soft-deleted connector is invisible, exactly like a missing one.
        """
        stmt = select(Connector).where(
            Connector.id == connector_id,
            Connector.workspace_id == self._ctx.workspace_id,
            Connector.deleted_at.is_(None),
        )
        connector: Connector | None = await self._session.scalar(stmt)
        return connector

    async def mark_ingesting(self, connector_id: uuid.UUID) -> bool:
        """Transition a live Connector into `ingesting`. Returns whether a row moved.

        Scoped Core UPDATE with a status guard: only a `draft`/`active`/`failed` connector may
        start ingesting, so a connector already `ingesting` is not re-triggered (the guard is the
        concurrency lock — a second submission while a run is in flight matches nothing). Foreign
        or deleted ids simply match nothing → False (a uniform 404 at the service).
        """
        stmt = (
            update(Connector)
            .where(
                Connector.id == connector_id,
                Connector.workspace_id == self._ctx.workspace_id,
                Connector.deleted_at.is_(None),
                Connector.status.in_(("draft", "active", "failed")),
            )
            .values(status="ingesting", updated_at=func.now())
            .returning(Connector.id)
        )
        moved: uuid.UUID | None = await self._session.scalar(stmt)
        return moved is not None

    async def soft_delete(self, connector_id: uuid.UUID) -> bool:
        """Soft-delete a live Connector. Returns whether a row was affected.

        A scoped Core `UPDATE ... WHERE deleted_at IS NULL RETURNING`: idempotent (a second
        delete matches nothing → False), workspace-scoped (a foreign id is simply not found),
        and it sets `updated_at` explicitly because `TimestampMixin.onupdate` fires only
        through the ORM flush path, not a Core statement.
        """
        stmt = (
            update(Connector)
            .where(
                Connector.id == connector_id,
                Connector.workspace_id == self._ctx.workspace_id,
                Connector.deleted_at.is_(None),
            )
            .values(deleted_at=func.now(), updated_at=func.now())
            .returning(Connector.id)
        )
        deleted_id: uuid.UUID | None = await self._session.scalar(stmt)
        return deleted_id is not None


__all__ = ["ConnectorRepository"]
