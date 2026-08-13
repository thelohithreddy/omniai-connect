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
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings

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
    """One transaction, optionally bound to a tenant.

    Held as a dependency for the life of a request. `bind_workspace` is called exactly
    once, by `get_workspace_context`, after the caller's identity resolves.
    """

    session: AsyncSession

    async def bind_workspace(self, workspace_id: uuid.UUID) -> None:
        """Bind this transaction to a tenant so RLS policies can evaluate."""
        await self.session.execute(
            text("SELECT set_config(:guc, :value, true)"),
            {"guc": WORKSPACE_GUC, "value": str(workspace_id)},
        )

    async def current_workspace(self) -> uuid.UUID | None:
        """Read back the bound tenant. Used by the isolation tests, not by domain code."""
        raw = await self.session.scalar(
            text("SELECT current_setting(:guc, true)"), {"guc": WORKSPACE_GUC}
        )
        return uuid.UUID(raw) if raw else None


async def get_uow() -> AsyncIterator[UnitOfWork]:
    """FastAPI dependency: one session, one transaction, per request.

    The transaction is opened eagerly so that `SET LOCAL` in `bind_workspace` has a
    transaction to be local *to*. Outside a transaction, `is_local => true` is a silent
    no-op — the GUC is simply never set, RLS sees NULL, and every tenant query returns
    zero rows. Failing loudly would be better; Postgres does not offer that, so the
    invariant lives here.
    """
    async with SessionFactory() as session, session.begin():
        yield UnitOfWork(session=session)
