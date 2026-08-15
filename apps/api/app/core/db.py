"""Async engine, session factory, and the UnitOfWork that binds tenant context.

One request = one session = one transaction (BACKEND_SPEC.md §3), committed on success
and rolled back on any exception.

The critical line in this module is `SET LOCAL app.workspace_id`, issued via
`set_config(..., is_local => true)`. Three properties matter and all three are load-bearing:

1. **Transaction-local, not session-scoped.** A plain `SET` persists for the life of the
   *connection*. Pooled connections outlive requests, so the next checkout — a different
   tenant — inherits the previous tenant's workspace_id and every RLS policy evaluates
   against the wrong tenant. `SET LOCAL` dies at COMMIT/ROLLBACK.
2. **Pooler-compatible.** Transaction-mode poolers (PgBouncer, and therefore Neon's
   pooled endpoint) do not preserve session state between transactions, so session-scoped
   GUCs are not merely risky there — they silently do not work at all.
3. **Parameterised.** `set_config()` takes bind parameters; `SET LOCAL x = 'y'` does not,
   which would force string interpolation of a value into SQL.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.core.events import (
    Event,
    EventWorkspaceMismatchError,
    current_sink,
    event_bus,
)

WORKSPACE_GUC = "app.workspace_id"

engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_pre_ping=True,
    # Modest defaults; sized properly when we know real concurrency (SYSTEM_ARCHITECTURE §6).
    pool_size=5,
    max_overflow=10,
)

SessionFactory = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)


class WorkspaceNotBoundError(RuntimeError):
    """Raised when tenant-scoped work is attempted before a workspace is bound.

    This is a programming error, not a user error: it means a repository was constructed
    without a WorkspaceContext, which the type system is supposed to make impossible.
    """


@dataclass(frozen=True, slots=True)
class UnitOfWork:
    """One transaction, optionally bound to a tenant, and the buffer of domain events it will
    emit *after* it commits.

    Held as a dependency for the life of a request. `bind_workspace` is called exactly
    once, by `get_workspace_context`, after the caller's identity resolves.

    Two private single-slot lists act as mutable cells on this frozen dataclass (frozen blocks
    rebinding the field, not mutating the list): `_pending_events` is the post-commit buffer,
    `_bound` caches the bound workspace so `buffer_event` can enforce the tenant-match check
    without a round-trip. Both carry defaults, so every existing `UnitOfWork(session=...)`
    construction is unchanged.
    """

    session: AsyncSession
    _pending_events: list[Event] = field(default_factory=list, repr=False, compare=False)
    _bound: list[uuid.UUID] = field(default_factory=list, repr=False, compare=False)

    async def bind_workspace(self, workspace_id: uuid.UUID) -> None:
        """Bind this transaction to a tenant so RLS policies can evaluate."""
        await self.session.execute(
            text("SELECT set_config(:guc, :value, true)"),
            {"guc": WORKSPACE_GUC, "value": str(workspace_id)},
        )
        # Remember the bound tenant so an event can be checked against it at buffer time.
        self._bound.clear()
        self._bound.append(workspace_id)

    async def current_workspace(self) -> uuid.UUID | None:
        """Read back the bound tenant. Used by the isolation tests, not by domain code."""
        raw = await self.session.scalar(
            text("SELECT current_setting(:guc, true)"), {"guc": WORKSPACE_GUC}
        )
        return uuid.UUID(raw) if raw else None

    def buffer_event(self, event: Event) -> None:
        """Record a domain event to emit after this transaction commits (`EventSink`).

        Fail closed unless the event's tenant matches this transaction's bound workspace: an
        event can never target a tenant other than the one the transaction is RLS-bound to, so
        event metadata can never become a tenant selector (ADR-0022). Called via
        `event_bus.publish`, never directly by domain code.
        """
        bound = self._bound[0] if self._bound else None
        if bound is None:
            raise WorkspaceNotBoundError("cannot publish an event before a workspace is bound")
        if event.workspace_id != bound:
            raise EventWorkspaceMismatchError(
                "event workspace_id does not match the transaction's bound tenant"
            )
        self._pending_events.append(event)

    def drain_events(self) -> list[Event]:
        """Take and clear the buffered events (called once, post-commit). Clearing is what
        prevents a second drain from re-emitting the same events."""
        drained = list(self._pending_events)
        self._pending_events.clear()
        return drained


async def get_uow() -> AsyncIterator[UnitOfWork]:
    """FastAPI dependency: one session, one transaction, per request.

    The transaction is opened eagerly so that `SET LOCAL` in `bind_workspace` has a
    transaction to be local *to*. Outside a transaction, `is_local => true` is a silent
    no-op — the GUC is simply never set, RLS sees NULL, and every tenant query returns
    zero rows. Failing loudly would be better; Postgres does not offer that, so the
    invariant lives here.

    This UoW is also the ambient event sink (`event_bus.publish` buffers onto it) and the
    owner of post-commit dispatch. The order is load-bearing (BACKEND_SPEC §4): the buffered
    events are dispatched only *after* the `session.begin()` block exits without raising —
    i.e. after COMMIT. A handler that raised, or a commit that failed, propagates out of the
    block and skips the dispatch, so a rolled-back transaction emits nothing.
    """
    async with SessionFactory() as session, session.begin():
        uow = UnitOfWork(session=session)
        # Save-and-restore rather than reset(token): an async generator's teardown can run in a
        # different context than its `set`, and reset(token) is context-bound. set(previous) is
        # not, and correctly nests. Task-scoped, so concurrent requests never share a sink.
        previous = current_sink.get()
        current_sink.set(uow)
        try:
            yield uow
        finally:
            current_sink.set(previous)
    await event_bus.dispatch(uow.drain_events())
