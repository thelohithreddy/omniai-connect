"""Tenant isolation: the tests P-29 makes mandatory for every new repository.

Read `test_app_role_is_not_superuser` first. Postgres exempts superusers from Row-Level
Security unconditionally — `FORCE` does not stop them — so a suite run as a superuser
passes every assertion below while the system leaks every row. That test is not a
formality; it is what makes the rest of this file mean anything.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings
from app.core.db import UnitOfWork
from app.core.ids import new_id
from tests.conftest import SeededWorkspace

# --------------------------------------------------------------------------- guards


async def test_app_role_has_neither_rls_bypass(app_session: AsyncSession) -> None:
    """The connection under test must be constrained by RLS.

    Postgres has **two** unconditional bypasses and `FORCE` stops neither:

    - `rolsuper` — the well-known one.
    - `rolbypassrls` — the one that gets missed. A role can be a non-superuser that owns
      nothing and still read every tenant's rows. Asserting only `rolsuper` yields a suite
      that passes green while isolation is entirely disabled.

    If this fails, every other test in this file is vacuous.
    """
    row = (
        await app_session.execute(
            text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
        )
    ).one()
    assert row.rolsuper is False, (
        "The application role is a superuser. Superusers bypass RLS unconditionally, "
        "so tenant isolation is not actually enforced and this suite proves nothing."
    )
    assert row.rolbypassrls is False, (
        "The application role holds BYPASSRLS. It bypasses RLS unconditionally even as a "
        "non-superuser owning nothing, so tenant isolation is not actually enforced."
    )


async def test_app_role_does_not_own_the_tenant_tables(app_session: AsyncSession) -> None:
    """Ownership is the other RLS bypass.

    `ENABLE ROW LEVEL SECURITY` exempts the table owner; only `FORCE` closes that, and
    relying on FORCE alone means one forgotten ALTER re-opens the hole. The app role owns
    nothing, so both doors are shut.
    """
    owned = await app_session.scalar(
        text(
            "SELECT count(*) FROM pg_tables "
            "WHERE schemaname = 'public' AND tableowner = current_user"
        )
    )
    assert owned == 0


async def test_force_row_level_security_is_enabled(app_session: AsyncSession) -> None:
    """Assert the DDL flag directly, so a future migration cannot quietly drop it."""
    rows = (
        await app_session.execute(
            text(
                "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname IN ('workspaces', 'api_tokens')"
            )
        )
    ).all()
    assert len(rows) == 2
    for name, enabled, forced in rows:
        assert enabled is True, f"RLS not enabled on {name}"
        assert forced is True, f"RLS not FORCEd on {name}"


# ----------------------------------------------------------------------- isolation


async def test_bound_workspace_sees_only_its_own_rows(
    app_session: AsyncSession, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    uow = UnitOfWork(session=app_session)
    async with app_session.begin():
        await uow.bind_workspace(workspace_a.id)

        visible = (await app_session.execute(text("SELECT id FROM workspaces"))).scalars().all()
        assert list(visible) == [workspace_a.id]

        # And the specific cross-tenant probe: B exists, but not for A.
        found = await app_session.scalar(
            text("SELECT id FROM workspaces WHERE id = :id"), {"id": workspace_b.id}
        )
        assert found is None


async def test_cross_tenant_token_read_returns_nothing(
    app_session: AsyncSession, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    uow = UnitOfWork(session=app_session)
    async with app_session.begin():
        await uow.bind_workspace(workspace_a.id)
        count = await app_session.scalar(
            text("SELECT count(*) FROM api_tokens WHERE workspace_id = :ws"),
            {"ws": workspace_b.id},
        )
        assert count == 0


async def test_cross_tenant_insert_is_rejected(
    app_session: AsyncSession, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    """WITH CHECK stops a bound tenant writing rows attributed to another.

    Without it, RLS would block reading other tenants' data but happily let A create rows
    inside B — a write-side leak that is easy to miss because the read tests pass.
    """
    uow = UnitOfWork(session=app_session)
    with pytest.raises(DBAPIError):
        async with app_session.begin():
            await uow.bind_workspace(workspace_a.id)
            await app_session.execute(
                text(
                    "INSERT INTO api_tokens "
                    "(id, workspace_id, name, token_hash, token_prefix, scopes) "
                    "VALUES (:id, :ws, 'smuggled', :hash, 'omc_xxxxxxxx', '[]'::jsonb)"
                ),
                {"id": new_id(), "ws": workspace_b.id, "hash": new_id().hex},
            )


async def test_unbound_context_sees_nothing(
    app_session: AsyncSession, workspace_a: SeededWorkspace
) -> None:
    """No tenant bound → zero rows, not every row.

    The policy compares against NULL when the GUC is unset, and `x = NULL` is NULL, not
    true — so the failure mode is an empty result set rather than a full table scan of
    every tenant. Fail closed.
    """
    async with app_session.begin():
        count = await app_session.scalar(text("SELECT count(*) FROM workspaces"))
        assert count == 0


# -------------------------------------------------------------- the pool-reuse test


async def test_workspace_context_does_not_survive_connection_reuse(
    workspace_a: SeededWorkspace,
) -> None:
    """The regression test for session-scoped GUCs.

    A pool of exactly one connection makes reuse deterministic: the second session is
    guaranteed the same backend as the first. If `bind_workspace` used `SET` instead of
    `SET LOCAL`, workspace A's id would still be set on that connection and the second,
    unbound session would read A's rows — one tenant reading another's data with no code
    change and no error. That is the leak this asserts against.
    """
    engine: AsyncEngine = create_async_engine(
        settings.database_url, pool_size=1, max_overflow=0, poolclass=None
    )
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as first, first.begin():
            await UnitOfWork(session=first).bind_workspace(workspace_a.id)
            first_pid = await first.scalar(text("SELECT pg_backend_pid()"))
            assert (await first.scalar(text("SELECT count(*) FROM workspaces"))) == 1

        async with factory() as second, second.begin():
            second_pid = await second.scalar(text("SELECT pg_backend_pid()"))
            # Same physical connection — otherwise the test isn't exercising reuse.
            assert first_pid == second_pid

            leaked = await second.scalar(text("SELECT current_setting('app.workspace_id', true)"))
            assert not leaked, f"workspace context leaked across requests: {leaked!r}"

            assert (await second.scalar(text("SELECT count(*) FROM workspaces"))) == 0
    finally:
        await engine.dispose()


async def test_guc_is_cleared_after_transaction_end(
    app_session: AsyncSession, workspace_a: SeededWorkspace
) -> None:
    """`SET LOCAL` dies at COMMIT. Verified on the same session, not just the same pool."""
    uow = UnitOfWork(session=app_session)
    async with app_session.begin():
        await uow.bind_workspace(workspace_a.id)
        assert await uow.current_workspace() == workspace_a.id

    async with app_session.begin():
        assert await uow.current_workspace() is None
