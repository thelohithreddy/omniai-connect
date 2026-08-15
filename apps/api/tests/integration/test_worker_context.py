"""Worker tenant execution boundary — real Postgres, real RLS (M1.4-B0.3).

Proves the worker's `worker_tenant_uow` establishes WHERE (the tenant) fail-closed and
transaction-locally, that RLS then enforces isolation, that the binding cannot leak across a
reused connection or survive a rollback, and that concurrent tenants never cross. WHO/ROLE/
PERMISSION never enter: the boundary reads only `workspace_id`.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.workers.context import (
    WorkerContextError,
    validate_workspace_id,
    worker_tenant_uow,
)
from tests.conftest import SeededWorkspace

GOOD_URL = "https://api.example.com"


async def _seed_connectors(engine: AsyncEngine, workspace_id: uuid.UUID, n: int) -> None:
    """Insert n connectors into a workspace via the RLS-exempt admin engine."""
    async with engine.begin() as conn:
        for i in range(n):
            await conn.execute(
                text(
                    "INSERT INTO connectors (id, workspace_id, name, slug, source_type, base_url,"
                    " status) VALUES (:i, :w, :n, :s, 'manual', :u, 'draft')"
                ),
                {"i": uuid.uuid4(), "w": workspace_id, "n": f"c{i}", "s": f"c{i}", "u": GOOD_URL},
            )


async def _count(workspace_id: uuid.UUID) -> int:
    async with worker_tenant_uow(str(workspace_id)) as uow:
        return int(await uow.session.scalar(text("SELECT count(*) FROM connectors")) or 0)


# --------------------------------------------------------------------- fail-closed context


@pytest.mark.parametrize("bad", [None, "", "   ", "not-a-uuid", "123", 123, {}, [], b"x"])
def test_validation_fails_closed_for_anything_but_a_uuid(bad: object) -> None:
    with pytest.raises(WorkerContextError):
        validate_workspace_id(bad)


def test_a_valid_uuid_string_validates() -> None:
    wid = uuid.uuid4()
    assert validate_workspace_id(str(wid)) == wid


async def test_worker_tenant_uow_refuses_a_missing_or_malformed_workspace() -> None:
    """No default, no fallback: a bad context never opens a tenant transaction."""
    for bad in (None, "", "not-a-uuid", 999):
        with pytest.raises(WorkerContextError):
            async with worker_tenant_uow(bad):
                pytest.fail("worker_tenant_uow must not yield for an invalid workspace")


# ------------------------------------------------------------ RLS isolation via the worker


async def test_the_worker_sees_only_its_bound_tenants_rows(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    await _seed_connectors(admin_engine, workspace_a.id, 2)
    await _seed_connectors(admin_engine, workspace_b.id, 1)

    assert await _count(workspace_a.id) == 2, "A must see exactly A's connectors"
    assert await _count(workspace_b.id) == 1, "B must see exactly B's connectors"
    # Re-binding A after B returns A again — no state carried from the B run (NullPool + SET LOCAL).
    assert await _count(workspace_a.id) == 2


async def test_a_bound_worker_cannot_see_a_foreign_tenants_rows(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    await _seed_connectors(admin_engine, workspace_b.id, 3)
    # A is bound; B has rows (ground truth via admin), but A counts zero of them.
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        a_view = int(await uow.session.scalar(text("SELECT count(*) FROM connectors")) or 0)
    async with admin_engine.connect() as conn:
        b_truth = await conn.scalar(
            text("SELECT count(*) FROM connectors WHERE workspace_id = :w"), {"w": workspace_b.id}
        )
    assert b_truth == 3 and a_view == 0


# ------------------------------------------------------ RLS-independent: the binding is correct


async def test_the_bound_guc_is_exactly_the_requested_workspace(
    workspace_a: SeededWorkspace,
) -> None:
    """RLS-independent proof: the GUC the worker sets equals the validated workspace — the
    boundary is correct at the application layer, not merely because RLS happened to filter."""
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        assert await uow.current_workspace() == workspace_a.id
        raw = await uow.session.scalar(text("SELECT current_setting('app.workspace_id', true)"))
        assert raw == str(workspace_a.id)


# ---------------------------------------------- GUC is transaction-local (no cross-task leak)


@pytest.fixture
async def pooled_one() -> AsyncIterator[async_sessionmaker]:
    """A pool of exactly one connection, so the next checkout is guaranteed the same backend —
    the deterministic way to prove `SET LOCAL` does not survive to the next task."""
    engine = create_async_engine(settings.database_url, pool_size=1, max_overflow=0)
    try:
        yield async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
    finally:
        await engine.dispose()


async def test_guc_does_not_survive_connection_reuse(
    pooled_one: async_sessionmaker, workspace_a: SeededWorkspace
) -> None:
    """After a bound worker transaction commits, the reused connection carries NO tenant GUC —
    if `bind_workspace` used `SET` instead of `SET LOCAL`, the next unbound task would inherit
    workspace A on the same backend. Fail closed: the unbound read sees NULL and zero rows."""
    async with worker_tenant_uow(str(workspace_a.id), sessions=pooled_one) as uow:
        first_pid = await uow.session.scalar(text("SELECT pg_backend_pid()"))

    async with pooled_one() as second, second.begin():
        assert await second.scalar(text("SELECT pg_backend_pid()")) == first_pid, "not reused"
        leaked = await second.scalar(text("SELECT current_setting('app.workspace_id', true)"))
        assert not leaked, f"tenant GUC leaked across tasks: {leaked!r}"
        assert await second.scalar(text("SELECT count(*) FROM workspaces")) == 0


async def test_rollback_clears_the_guc_before_the_next_task(
    pooled_one: async_sessionmaker,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """A task that binds A and then raises rolls back; the reused connection is clean, so the
    next task binding B sees only B — a rollback never leaks the previous tenant."""
    await _seed_connectors(admin_engine, workspace_b.id, 1)

    with pytest.raises(RuntimeError):
        async with worker_tenant_uow(str(workspace_a.id), sessions=pooled_one):
            raise RuntimeError("boom after binding A")

    async with worker_tenant_uow(str(workspace_b.id), sessions=pooled_one) as uow:
        assert await uow.current_workspace() == workspace_b.id
        assert int(await uow.session.scalar(text("SELECT count(*) FROM connectors")) or 0) == 1


# ------------------------------------------------------- the boundary commits on success


async def test_a_successful_task_commits_its_tenant_writes(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """The boundary's transaction COMMITS on success: a row written inside `worker_tenant_uow`
    persists (visible via the RLS-exempt admin engine). Without the explicit transaction the
    write would roll back on context exit and silently vanish — a task that reported success
    while losing its work."""
    written = uuid.uuid4()
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await uow.session.execute(
            text(
                "INSERT INTO connectors (id, workspace_id, name, slug, source_type, base_url,"
                " status) VALUES (:i, :w, 'w', 'w', 'manual', :u, 'draft')"
            ),
            {"i": written, "w": workspace_a.id, "u": GOOD_URL},
        )
    async with admin_engine.connect() as conn:
        persisted = await conn.scalar(
            text("SELECT count(*) FROM connectors WHERE id = :i"), {"i": written}
        )
    assert persisted == 1, "a successful worker task must commit its tenant writes"


# ------------------------------------------------------------------------- concurrency


async def test_concurrent_tenants_never_cross(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """A×8 and B×8 interleaved, each on its own NullPool connection + transaction-local GUC.
    Every A result is A's count and every B result is B's — no interleaving leaks a tenant."""
    await _seed_connectors(admin_engine, workspace_a.id, 2)
    await _seed_connectors(admin_engine, workspace_b.id, 5)

    async def one(ws: uuid.UUID) -> tuple[uuid.UUID, int]:
        await asyncio.sleep(0)  # yield control to force interleaving
        return ws, await _count(ws)

    jobs = [one(workspace_a.id) for _ in range(8)] + [one(workspace_b.id) for _ in range(8)]
    results = await asyncio.gather(*jobs)

    for ws, count in results:
        expected = 2 if ws == workspace_a.id else 5
        assert count == expected, f"{ws} saw {count}, expected {expected} — tenant crossover"
