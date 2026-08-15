"""Worker tenant execution boundary (M1.4-B0.3).

A background task has no HTTP request, no JWT, and no membership lookup, so its tenant scope
must arrive as *server-established task metadata* — a `workspace_id` the enqueuer already
authorized — and be BOUND, transaction-locally, before any tenant DB access. This establishes
**WHERE**, never WHO / ROLE / PERMISSION: the persisted database and RLS remain the sole
authority. The worker trusts `workspace_id` only as a tenant *selector*, and a role / permission
/ member id in a task payload confers nothing — there is no code path here that reads them.

Reuse, not reinvention: the same `UnitOfWork` and the same `bind_workspace`
(`SET LOCAL app.workspace_id` via `set_config(..., true)`) the request path uses. `SET LOCAL`
dies at COMMIT/ROLLBACK, so no tenant state survives to the next task.

Engine choice is the one worker-specific detail. A prefork worker runs each task on a *fresh*
event loop (`asyncio.run`), and an asyncpg connection is bound to the loop that opened it, so a
pooled connection cannot cross tasks. A `NullPool` engine opens a fresh connection per checkout
on the current loop — fork-safe (no connection survives the fork) and loop-safe. Transaction-
local binding still guarantees isolation even without pooling.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.core.db import UnitOfWork


class WorkerContextError(Exception):
    """A task's tenant context is missing or malformed.

    Fail-closed: raised *before* any DB access, so a task without a valid workspace never opens
    a tenant transaction. Never carries the offending value into a message a caller might log.
    """


def validate_workspace_id(raw: object) -> uuid.UUID:
    """The task's `workspace_id` → a UUID, or fail closed. No default, no first-workspace
    fallback, no system/global tenant — anything that is not exactly one canonical UUID string
    is refused."""
    if not isinstance(raw, str) or not raw.strip():
        raise WorkerContextError("missing_workspace_id")
    try:
        return uuid.UUID(raw)
    except ValueError as exc:
        raise WorkerContextError("malformed_workspace_id") from exc


# The worker's own NullPool engine/sessionmaker (see the module docstring for why NullPool).
_worker_engine = create_async_engine(settings.database_url, poolclass=NullPool)
worker_sessions = async_sessionmaker(_worker_engine, expire_on_commit=False, autoflush=False)


@asynccontextmanager
async def worker_tenant_uow(
    workspace_id: object,
    *,
    sessions: async_sessionmaker[AsyncSession] = worker_sessions,  # test seam only
) -> AsyncIterator[UnitOfWork]:
    """Yield a `UnitOfWork` bound, transaction-locally, to `workspace_id` for tenant work.

    The order is load-bearing (BACKEND_SPEC §3, DATABASE_DESIGN §6): **validate → BEGIN →
    SET LOCAL → verify the binding read back → yield**. Nothing tenant-scoped runs before the GUC
    is bound; the transaction's end (COMMIT on success, ROLLBACK on exception) clears it. A
    binding that does not read back is a fail-closed `WorkerContextError`, never a silent unbound
    execution (which RLS would render as zero rows, but we refuse to proceed regardless).

    `sessions` is a test seam so a pool_size=1 engine can force connection reuse and prove the
    binding is transaction-local; production always uses the NullPool `worker_sessions`.
    """
    bound = validate_workspace_id(workspace_id)
    async with sessions() as session, session.begin():
        uow = UnitOfWork(session=session)
        await uow.bind_workspace(bound)
        if await uow.current_workspace() != bound:
            raise WorkerContextError("workspace_binding_failed")
        yield uow


__all__ = ["WorkerContextError", "validate_workspace_id", "worker_sessions", "worker_tenant_uow"]
