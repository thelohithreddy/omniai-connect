"""Members: schema correctness and tenant isolation at the database boundary.

The question this file answers is not "does the table work?" but "can I demonstrate that
the table cannot be accessed incorrectly through the database boundary?" — so every
positive assertion has a negative counterpart, and every assertion is made through the
least-privileged application role, never through the seeding superuser.

`test_app_role_has_neither_rls_bypass` in test_tenant_isolation.py is the guard that makes
this file mean anything: Postgres exempts superusers and `BYPASSRLS` roles from RLS
unconditionally, so an isolation suite run on such a connection passes while enforcing
nothing.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
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

# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------

_INSERT_MEMBER = text(
    "INSERT INTO members (id, workspace_id, user_id, role, invited_by) "
    "VALUES (:id, :ws, :uid, :role, :inv)"
)


async def seed_member(
    engine: AsyncEngine,
    workspace_id: uuid.UUID,
    *,
    user_id: str | None = None,
    role: str = "member",
    invited_by: uuid.UUID | None = None,
) -> uuid.UUID:
    """Create a member out-of-band, as the superuser.

    Deliberately bypasses RLS: these rows are the *precondition* the isolation tests then
    try, and fail, to reach from another tenant. Application code must never do this.
    """
    member_id = new_id()
    async with engine.begin() as conn:
        await conn.execute(
            _INSERT_MEMBER,
            {
                "id": member_id,
                "ws": workspace_id,
                "uid": user_id or f"user_{member_id.hex[:12]}",
                "role": role,
                "inv": invited_by,
            },
        )
    return member_id


# --------------------------------------------------------------------------------------
# A. schema existence   B. column correctness
# --------------------------------------------------------------------------------------


async def test_members_table_exists(app_session: AsyncSession) -> None:
    assert (
        await app_session.scalar(
            text("SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename='members'")
        )
        == 1
    )


async def test_column_shape_matches_canonical_design(app_session: AsyncSession) -> None:
    """Columns, types, and nullability per DATABASE_DESIGN.md §3."""
    rows = (
        await app_session.execute(
            text(
                "SELECT column_name, data_type, is_nullable, column_default "
                "FROM information_schema.columns WHERE table_name='members'"
            )
        )
    ).all()
    cols = {r.column_name: r for r in rows}

    assert set(cols) == {
        "id",
        "workspace_id",
        "user_id",
        "role",
        "invited_by",
        "created_at",
        "updated_at",
    }
    assert cols["id"].data_type == "uuid"
    assert cols["workspace_id"].data_type == "uuid"
    assert cols["user_id"].data_type == "character varying"
    assert cols["role"].data_type == "character varying"
    assert cols["invited_by"].data_type == "uuid"
    assert cols["created_at"].data_type == "timestamp with time zone"
    assert cols["updated_at"].data_type == "timestamp with time zone"

    # `role` must NOT have a default: a membership with an unstated role is an application
    # bug, and a default would silently mint a privilege level instead of failing.
    assert cols["role"].column_default is None


async def test_workspace_id_is_not_null(app_session: AsyncSession) -> None:
    """Tenancy is a schema property, not an application convention (P-41)."""
    assert (
        await app_session.scalar(
            text(
                "SELECT is_nullable FROM information_schema.columns "
                "WHERE table_name='members' AND column_name='workspace_id'"
            )
        )
        == "NO"
    )


# --------------------------------------------------------------------------------------
# C. NOT NULL enforcement
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("omitted", ["user_id", "role"])
async def test_required_columns_reject_null(
    app_session: AsyncSession, workspace_a: SeededWorkspace, omitted: str
) -> None:
    values = {"uid": "u1", "role": "member"}
    values[{"user_id": "uid", "role": "role"}[omitted]] = None  # type: ignore[assignment]
    uow = UnitOfWork(session=app_session)
    with pytest.raises(IntegrityError):
        async with app_session.begin():
            await uow.bind_workspace(workspace_a.id)
            await app_session.execute(
                _INSERT_MEMBER,
                {"id": new_id(), "ws": workspace_a.id, "inv": None, **values},
            )


# --------------------------------------------------------------------------------------
# D. FK enforcement
# --------------------------------------------------------------------------------------


async def test_workspace_fk_rejects_unknown_workspace(admin_engine: AsyncEngine) -> None:
    """Asserted as superuser so RLS cannot be what rejects it — this proves the FK."""
    with pytest.raises(IntegrityError):
        async with admin_engine.begin() as conn:
            await conn.execute(
                _INSERT_MEMBER,
                {"id": new_id(), "ws": new_id(), "uid": "u", "role": "member", "inv": None},
            )


async def test_deleting_a_workspace_cascades_to_its_members(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    await seed_member(admin_engine, workspace_a.id)
    async with admin_engine.begin() as conn:
        before = await conn.scalar(
            text("SELECT count(*) FROM members WHERE workspace_id = :w"), {"w": workspace_a.id}
        )
        assert before == 1
        await conn.execute(text("DELETE FROM workspaces WHERE id = :w"), {"w": workspace_a.id})
        after = await conn.scalar(
            text("SELECT count(*) FROM members WHERE workspace_id = :w"), {"w": workspace_a.id}
        )
    assert after == 0


async def test_invited_by_cannot_reference_another_workspaces_member(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    """The composite FK is a tenant-isolation control.

    Postgres validates referential integrity with RLS bypassed, so a single-column
    `invited_by -> members.id` would let workspace A reference workspace B's member and
    RLS would never see it. Carrying workspace_id into the key makes that structurally
    impossible — asserted here as superuser, precisely so RLS cannot be credited.
    """
    b_member = await seed_member(admin_engine, workspace_b.id)
    with pytest.raises(IntegrityError):
        async with admin_engine.begin() as conn:
            await conn.execute(
                _INSERT_MEMBER,
                {
                    "id": new_id(),
                    "ws": workspace_a.id,
                    "uid": "smuggler",
                    "role": "member",
                    "inv": b_member,
                },
            )


async def test_invited_by_within_the_same_workspace_is_accepted(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    inviter = await seed_member(admin_engine, workspace_a.id, role="owner")
    invitee = await seed_member(admin_engine, workspace_a.id, invited_by=inviter)
    async with admin_engine.begin() as conn:
        assert (
            await conn.scalar(text("SELECT invited_by FROM members WHERE id = :i"), {"i": invitee})
            == inviter
        )


async def test_deleting_an_inviter_nulls_invited_by_and_keeps_the_row(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Column-scoped `ON DELETE SET NULL (invited_by)`.

    A bare SET NULL would also target workspace_id, which is NOT NULL, and every inviter
    deletion would fail instead.
    """
    inviter = await seed_member(admin_engine, workspace_a.id, role="owner")
    invitee = await seed_member(admin_engine, workspace_a.id, invited_by=inviter)
    async with admin_engine.begin() as conn:
        await conn.execute(text("DELETE FROM members WHERE id = :i"), {"i": inviter})
        row = (
            await conn.execute(
                text("SELECT workspace_id, invited_by FROM members WHERE id = :i"), {"i": invitee}
            )
        ).one()
    assert row.invited_by is None
    assert row.workspace_id == workspace_a.id


# --------------------------------------------------------------------------------------
# E. role-domain enforcement
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["owner", "admin", "member", "viewer"])
async def test_canonical_roles_are_accepted(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, role: str
) -> None:
    assert await seed_member(admin_engine, workspace_a.id, role=role)


@pytest.mark.parametrize("role", ["superuser", "OWNER", "", "admin ", "root", "guest"])
async def test_non_canonical_roles_are_rejected(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, role: str
) -> None:
    """Case-sensitive and whitespace-sensitive: the CHECK is an exact-membership test."""
    with pytest.raises(IntegrityError):
        await seed_member(admin_engine, workspace_a.id, role=role)


# --------------------------------------------------------------------------------------
# F. membership uniqueness
# --------------------------------------------------------------------------------------


async def test_same_user_cannot_join_one_workspace_twice(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    await seed_member(admin_engine, workspace_a.id, user_id="dup_user")
    with pytest.raises(IntegrityError):
        await seed_member(admin_engine, workspace_a.id, user_id="dup_user")


async def test_same_user_may_belong_to_several_workspaces(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    """The uniqueness boundary is (workspace_id, user_id), never user_id alone.

    A global unique on user_id would silently make the product single-workspace-per-user.
    """
    await seed_member(admin_engine, workspace_a.id, user_id="shared_user")
    await seed_member(admin_engine, workspace_b.id, user_id="shared_user")
    async with admin_engine.begin() as conn:
        assert (
            await conn.scalar(text("SELECT count(*) FROM members WHERE user_id = 'shared_user'"))
            == 2
        )


# --------------------------------------------------------------------------------------
# G/H. RLS enabled and FORCED
# --------------------------------------------------------------------------------------


async def test_rls_is_enabled_and_forced(app_session: AsyncSession) -> None:
    """`FORCE` is what subjects the table owner to its own policies."""
    row = (
        await app_session.execute(
            text("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname='members'")
        )
    ).one()
    assert row.relrowsecurity is True
    assert row.relforcerowsecurity is True


async def test_tenant_policy_carries_both_using_and_with_check(
    app_session: AsyncSession,
) -> None:
    """USING alone filters reads; WITH CHECK is what stops cross-tenant writes."""
    row = (
        await app_session.execute(
            text(
                "SELECT qual, with_check, cmd FROM pg_policies "
                "WHERE tablename='members' AND policyname='tenant_isolation'"
            )
        )
    ).one()
    assert row.cmd == "ALL"
    for clause in (row.qual, row.with_check):
        assert clause is not None
        assert "app.workspace_id" in clause
        assert "NULLIF" in clause, "empty-string guard missing; ''::uuid would raise"


async def test_app_role_does_not_own_members(app_session: AsyncSession) -> None:
    """Ownership is an RLS bypass that `FORCE` closes — but owning nothing shuts both."""
    assert (
        await app_session.scalar(
            text(
                "SELECT count(*) FROM pg_tables WHERE tablename='members' "
                "AND tableowner = current_user"
            )
        )
        == 0
    )


# --------------------------------------------------------------------------------------
# I/J/K. per-workspace isolation and cross-workspace SELECT denial
# --------------------------------------------------------------------------------------


async def test_each_workspace_sees_only_its_own_members(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    a_member = await seed_member(admin_engine, workspace_a.id, user_id="a_user")
    b_member = await seed_member(admin_engine, workspace_b.id, user_id="b_user")
    uow = UnitOfWork(session=app_session)

    async with app_session.begin():
        await uow.bind_workspace(workspace_a.id)
        visible = list((await app_session.execute(text("SELECT id FROM members"))).scalars())
        assert visible == [a_member]
        # The targeted cross-tenant probe: B's row exists, but not for A.
        assert (
            await app_session.scalar(text("SELECT id FROM members WHERE id = :i"), {"i": b_member})
            is None
        )

    async with app_session.begin():
        await uow.bind_workspace(workspace_b.id)
        visible = list((await app_session.execute(text("SELECT id FROM members"))).scalars())
        assert visible == [b_member]


# --------------------------------------------------------------------------------------
# L. cross-workspace INSERT denial
# --------------------------------------------------------------------------------------


async def test_bound_tenant_cannot_insert_into_another_workspace(
    app_session: AsyncSession, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    uow = UnitOfWork(session=app_session)
    with pytest.raises(DBAPIError):
        async with app_session.begin():
            await uow.bind_workspace(workspace_a.id)
            await app_session.execute(
                _INSERT_MEMBER,
                {
                    "id": new_id(),
                    "ws": workspace_b.id,
                    "uid": "smuggled",
                    "role": "member",
                    "inv": None,
                },
            )


# --------------------------------------------------------------------------------------
# M. cross-workspace UPDATE and DELETE denial
# --------------------------------------------------------------------------------------


async def test_bound_tenant_cannot_update_another_workspaces_member(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    b_member = await seed_member(admin_engine, workspace_b.id, role="member")
    uow = UnitOfWork(session=app_session)
    async with app_session.begin():
        await uow.bind_workspace(workspace_a.id)
        result = await app_session.execute(
            text("UPDATE members SET role='owner' WHERE id = :i"), {"i": b_member}
        )
        # RLS makes the row invisible, so the UPDATE matches nothing rather than erroring.
        assert result.rowcount == 0

    async with admin_engine.begin() as conn:
        assert (
            await conn.scalar(text("SELECT role FROM members WHERE id = :i"), {"i": b_member})
            == "member"
        ), "privilege escalation across tenants"


async def test_bound_tenant_cannot_delete_another_workspaces_member(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    b_member = await seed_member(admin_engine, workspace_b.id)
    uow = UnitOfWork(session=app_session)
    async with app_session.begin():
        await uow.bind_workspace(workspace_a.id)
        result = await app_session.execute(
            text("DELETE FROM members WHERE id = :i"), {"i": b_member}
        )
        assert result.rowcount == 0

    async with admin_engine.begin() as conn:
        assert (
            await conn.scalar(text("SELECT count(*) FROM members WHERE id = :i"), {"i": b_member})
            == 1
        )


async def test_bound_tenant_cannot_reassign_its_member_to_another_workspace(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """WITH CHECK applies to the *post-image* of an UPDATE, not just to INSERT."""
    a_member = await seed_member(admin_engine, workspace_a.id)
    uow = UnitOfWork(session=app_session)
    with pytest.raises(DBAPIError):
        async with app_session.begin():
            await uow.bind_workspace(workspace_a.id)
            await app_session.execute(
                text("UPDATE members SET workspace_id = :b WHERE id = :i"),
                {"b": workspace_b.id, "i": a_member},
            )


# --------------------------------------------------------------------------------------
# N. unbound-context denial
# --------------------------------------------------------------------------------------


async def test_unbound_context_sees_no_members(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """No workspace bound -> zero rows, not every row.

    The policy compares against NULL when the GUC is unset, and `x = NULL` is NULL rather
    than true, so the failure mode is an empty result set. Fail closed.

    Seeds a row first, so this cannot pass trivially against an empty table.
    """
    await seed_member(admin_engine, workspace_a.id)
    async with app_session.begin():
        assert await app_session.scalar(text("SELECT count(*) FROM members")) == 0


async def test_unbound_context_cannot_insert_a_member(
    app_session: AsyncSession, workspace_a: SeededWorkspace
) -> None:
    with pytest.raises(DBAPIError):
        async with app_session.begin():
            await app_session.execute(
                _INSERT_MEMBER,
                {
                    "id": new_id(),
                    "ws": workspace_a.id,
                    "uid": "unbound",
                    "role": "member",
                    "inv": None,
                },
            )


# --------------------------------------------------------------------------------------
# O. connection reuse / transaction boundary safety
# --------------------------------------------------------------------------------------


async def test_member_visibility_does_not_survive_connection_reuse(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """The pooled-connection leak, asserted against members specifically.

    A pool of exactly one connection makes reuse deterministic. If `bind_workspace` used
    session-scoped `SET` instead of `SET LOCAL`, workspace A's id would still be set on
    that backend and the second, unbound session would read A's members — one tenant
    reading another's data with no code change and no error.
    """
    await seed_member(admin_engine, workspace_a.id)
    engine = create_async_engine(settings.database_url, pool_size=1, max_overflow=0)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as first, first.begin():
            await UnitOfWork(session=first).bind_workspace(workspace_a.id)
            first_pid = await first.scalar(text("SELECT pg_backend_pid()"))
            assert await first.scalar(text("SELECT count(*) FROM members")) == 1

        async with factory() as second, second.begin():
            # Same physical backend, or the test is not exercising reuse at all.
            assert await second.scalar(text("SELECT pg_backend_pid()")) == first_pid
            leaked = await second.scalar(text("SELECT current_setting('app.workspace_id', true)"))
            assert not leaked, f"workspace context leaked across requests: {leaked!r}"
            assert await second.scalar(text("SELECT count(*) FROM members")) == 0
    finally:
        await engine.dispose()


async def test_rebinding_within_one_session_switches_tenant_cleanly(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Sequential transactions on one session must not accumulate visibility."""
    await seed_member(admin_engine, workspace_a.id)
    await seed_member(admin_engine, workspace_b.id)
    uow = UnitOfWork(session=app_session)

    async with app_session.begin():
        await uow.bind_workspace(workspace_a.id)
        assert await app_session.scalar(text("SELECT count(*) FROM members")) == 1

    async with app_session.begin():
        await uow.bind_workspace(workspace_b.id)
        assert await app_session.scalar(text("SELECT count(*) FROM members")) == 1

    async with app_session.begin():
        assert await uow.current_workspace() is None
        assert await app_session.scalar(text("SELECT count(*) FROM members")) == 0
