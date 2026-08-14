"""MemberRepository: tenant safety of the data-access layer.

These tests exercise the repository against a real database as the least-privileged
runtime role, so both defenses are live at once. That raises a question every assertion
here has to answer: *which* layer actually refused?

The suite settles it by asserting on both sides of the boundary. Where the repository is
the control under test, the row is seeded through the superuser engine and the assertion
is that the repository does not return it; RLS would also hide it, so a mutation of the
repository predicate alone is separately proven to fail these tests in the mutation pass
(see the module's commit message). Where RLS is the control under test, the query is
issued directly rather than through the repository.

Layer 1 (repository scoping) and Layer 2 (RLS) are complementary, not redundant
(DATABASE_DESIGN.md §6). Neither is allowed to be the only thing standing.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.core.db import UnitOfWork
from app.core.exceptions import ConflictError
from app.core.security import CallerIdentity, WorkspaceContext
from app.domains.workspaces.models import Member
from app.domains.workspaces.repository import MemberRepository
from tests.conftest import SeededWorkspace
from tests.integration.test_members_tenancy import seed_member


def make_context(workspace_id: uuid.UUID) -> WorkspaceContext:
    """A WorkspaceContext for an arbitrary workspace, as the auth layer would build it."""
    return WorkspaceContext(
        workspace_id=workspace_id,
        caller=CallerIdentity(kind="api_token", api_token_id=uuid.uuid4()),
        request_id="req_test",
    )


async def bound_repo(session: AsyncSession, workspace: SeededWorkspace) -> MemberRepository:
    """Bind the transaction to a tenant and return a repository scoped to the same one.

    Both halves matter: `bind_workspace` arms RLS, the context arms the repository.
    """
    await UnitOfWork(session=session).bind_workspace(workspace.id)
    return MemberRepository(session, make_context(workspace.id))


# --------------------------------------------------------------------------------------
# 1. the repository cannot be constructed unscoped
# --------------------------------------------------------------------------------------


def test_repository_requires_a_workspace_context(app_session: AsyncSession) -> None:
    """An unscoped repository is not representable, not merely discouraged (P-14)."""
    with pytest.raises(TypeError):
        MemberRepository(app_session)  # type: ignore[call-arg]


def test_workspace_context_cannot_omit_a_workspace_id() -> None:
    """The context itself has no unscoped form, so there is no valid empty tenant."""
    with pytest.raises(TypeError):
        WorkspaceContext(  # type: ignore[call-arg]
            caller=CallerIdentity(kind="api_token"), request_id="r"
        )


# --------------------------------------------------------------------------------------
# 2-6. reads are workspace-scoped
# --------------------------------------------------------------------------------------


async def test_workspace_can_read_its_own_member(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    member_id = await seed_member(admin_engine, workspace_a.id, user_id="alice")
    async with app_session.begin():
        repo = await bound_repo(app_session, workspace_a)
        member = await repo.get(member_id)
    assert member is not None
    assert member.id == member_id
    assert member.workspace_id == workspace_a.id


async def test_get_does_not_return_another_workspaces_member(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """A globally-unique id is not an access grant."""
    b_member = await seed_member(admin_engine, workspace_b.id)
    async with app_session.begin():
        repo = await bound_repo(app_session, workspace_a)
        assert await repo.get(b_member) is None


async def test_get_by_user_id_is_workspace_scoped(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """The same human in two workspaces must resolve to the *bound* workspace's row."""
    a_member = await seed_member(admin_engine, workspace_a.id, user_id="shared", role="owner")
    b_member = await seed_member(admin_engine, workspace_b.id, user_id="shared", role="viewer")

    async with app_session.begin():
        repo = await bound_repo(app_session, workspace_a)
        found = await repo.get_by_user_id("shared")
    assert found is not None
    assert found.id == a_member
    assert found.id != b_member
    assert found.role == "owner", "resolved the wrong workspace's membership"


async def test_get_by_user_id_returns_none_for_a_foreign_members_user(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    await seed_member(admin_engine, workspace_b.id, user_id="only_in_b")
    async with app_session.begin():
        repo = await bound_repo(app_session, workspace_a)
        assert await repo.get_by_user_id("only_in_b") is None


async def test_list_returns_only_the_current_workspace(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    a1 = await seed_member(admin_engine, workspace_a.id, user_id="a1")
    a2 = await seed_member(admin_engine, workspace_a.id, user_id="a2")
    await seed_member(admin_engine, workspace_b.id, user_id="b1")

    async with app_session.begin():
        repo = await bound_repo(app_session, workspace_a)
        members = await repo.list_for_workspace()

    assert {m.id for m in members} == {a1, a2}
    assert all(m.workspace_id == workspace_a.id for m in members)


async def test_list_is_empty_for_a_workspace_with_no_members(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Empty because it owns none — not because the table is empty."""
    await seed_member(admin_engine, workspace_b.id)
    async with app_session.begin():
        repo = await bound_repo(app_session, workspace_a)
        assert await repo.list_for_workspace() == []


# --------------------------------------------------------------------------------------
# 7. writes cannot target another workspace
# --------------------------------------------------------------------------------------


async def test_create_persists_into_the_bound_workspace(
    app_session: AsyncSession, workspace_a: SeededWorkspace
) -> None:
    async with app_session.begin():
        repo = await bound_repo(app_session, workspace_a)
        member = await repo.create(user_id="new_user", role="admin")
        assert member.workspace_id == workspace_a.id
        assert member.role == "admin"
        assert member.id is not None
        assert member.created_at is not None, "server default did not materialise on flush"


async def test_create_has_no_workspace_parameter_to_abuse() -> None:
    """The cross-tenant write is unrepresentable: there is nowhere to put a foreign id.

    Asserted against the signature rather than by attempting a call, because the point is
    that the unsafe call cannot be written at all.
    """
    import inspect

    params = set(inspect.signature(MemberRepository.create).parameters)
    assert "workspace_id" not in params
    assert params == {"self", "user_id", "role", "invited_by"}


async def test_create_rejects_a_duplicate_membership_as_a_domain_error(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Raw IntegrityError must not reach the service layer (BACKEND_SPEC.md §6)."""
    await seed_member(admin_engine, workspace_a.id, user_id="dupe")
    with pytest.raises(ConflictError):
        async with app_session.begin():
            repo = await bound_repo(app_session, workspace_a)
            await repo.create(user_id="dupe", role="member")


async def test_create_allows_the_same_user_in_a_second_workspace(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Scoping must not degrade into a global unique on user_id."""
    await seed_member(admin_engine, workspace_a.id, user_id="multi")
    async with app_session.begin():
        repo = await bound_repo(app_session, workspace_b)
        member = await repo.create(user_id="multi", role="viewer")
    assert member.workspace_id == workspace_b.id


# --------------------------------------------------------------------------------------
# 8-9. update and delete cannot reach another workspace
# --------------------------------------------------------------------------------------


async def test_update_role_within_the_workspace_succeeds(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    member_id = await seed_member(admin_engine, workspace_a.id, role="member")
    async with app_session.begin():
        repo = await bound_repo(app_session, workspace_a)
        updated = await repo.update_role(member_id, "admin")
    assert updated is not None
    assert updated.role == "admin"


async def test_update_role_cannot_touch_another_workspaces_member(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Returns None *and* leaves the row untouched — verified out-of-band."""
    b_member = await seed_member(admin_engine, workspace_b.id, role="viewer")
    async with app_session.begin():
        repo = await bound_repo(app_session, workspace_a)
        assert await repo.update_role(b_member, "owner") is None

    async with admin_engine.begin() as conn:
        role = await conn.scalar(text("SELECT role FROM members WHERE id = :i"), {"i": b_member})
    assert role == "viewer", "cross-tenant privilege escalation"


async def test_delete_within_the_workspace_succeeds(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    member_id = await seed_member(admin_engine, workspace_a.id)
    async with app_session.begin():
        repo = await bound_repo(app_session, workspace_a)
        assert await repo.delete(member_id) is True

    async with admin_engine.begin() as conn:
        assert (
            await conn.scalar(text("SELECT count(*) FROM members WHERE id = :i"), {"i": member_id})
            == 0
        )


async def test_delete_cannot_remove_another_workspaces_member(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    b_member = await seed_member(admin_engine, workspace_b.id)
    async with app_session.begin():
        repo = await bound_repo(app_session, workspace_a)
        assert await repo.delete(b_member) is False

    async with admin_engine.begin() as conn:
        assert (
            await conn.scalar(text("SELECT count(*) FROM members WHERE id = :i"), {"i": b_member})
            == 1
        ), "cross-tenant delete succeeded"


# --------------------------------------------------------------------------------------
# 10. an unbound transaction yields nothing, whatever the context says
# --------------------------------------------------------------------------------------


async def test_repository_reads_nothing_when_the_transaction_is_unbound(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """A correct context is not enough if RLS was never armed.

    Constructs the repository with a valid context but skips `bind_workspace`. The
    repository predicate matches, yet RLS sees a NULL tenant and the result is empty —
    the two layers failing closed independently.
    """
    await seed_member(admin_engine, workspace_a.id)
    async with app_session.begin():
        repo = MemberRepository(app_session, make_context(workspace_a.id))
        assert await repo.list_for_workspace() == []


async def test_repository_write_fails_when_the_transaction_is_unbound(
    app_session: AsyncSession, workspace_a: SeededWorkspace
) -> None:
    from sqlalchemy.exc import DBAPIError

    with pytest.raises(DBAPIError):
        async with app_session.begin():
            repo = MemberRepository(app_session, make_context(workspace_a.id))
            await repo.create(user_id="unbound", role="member")


# --------------------------------------------------------------------------------------
# 11. RLS remains the final defense, independent of the repository
# --------------------------------------------------------------------------------------


async def test_rls_still_blocks_a_context_that_disagrees_with_the_bound_tenant(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """The decisive test for defense in depth.

    Binds the transaction to workspace A but hands the repository a context claiming
    workspace B — simulating a compromised or buggy auth layer. The repository's predicate
    now *asks for* B's rows, so Layer 1 is actively working against us; RLS alone decides
    the outcome, and it returns nothing.
    """
    await seed_member(admin_engine, workspace_b.id, user_id="b_only")

    async with app_session.begin():
        await UnitOfWork(session=app_session).bind_workspace(workspace_a.id)
        mismatched = MemberRepository(app_session, make_context(workspace_b.id))
        assert await mismatched.list_for_workspace() == []
        assert await mismatched.get_by_user_id("b_only") is None


# --- Layer 1 in isolation -------------------------------------------------------------
#
# Everything above runs on the least-privileged role, where RLS is live. That makes those
# tests unable to distinguish "the repository scoped correctly" from "RLS hid the rows" —
# and a mutation pass proved the distinction is real: deleting the workspace predicate
# from every method left all of them green.
#
# The tests below therefore run the repository on the **superuser** session, where RLS is
# bypassed unconditionally. The connection can see every tenant's rows, so the
# repository's own predicate is the only thing that can possibly narrow the result. This
# is what makes "Layer 1 stands on its own" a claim backed by evidence rather than by
# arrangement (DATABASE_DESIGN.md §6).


async def _admin_session(admin_engine: AsyncEngine) -> AsyncSession:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    return async_sessionmaker(admin_engine, expire_on_commit=False)()


async def test_list_is_scoped_by_the_repository_alone(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    """RLS bypassed: only the repository predicate can narrow this."""
    a_member = await seed_member(admin_engine, workspace_a.id, user_id="a_only")
    await seed_member(admin_engine, workspace_b.id, user_id="b_only")

    session = await _admin_session(admin_engine)
    try:
        async with session.begin():
            # Proof the connection really is unconstrained: it can see both tenants.
            visible = await session.scalar(text("SELECT count(*) FROM members"))
            assert visible == 2, "expected an RLS-exempt connection for this test"

            repo = MemberRepository(session, make_context(workspace_a.id))
            listed = await repo.list_for_workspace()
    finally:
        await session.close()

    assert [m.id for m in listed] == [a_member], "repository leaked another tenant's members"


async def test_get_is_scoped_by_the_repository_alone(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    b_member = await seed_member(admin_engine, workspace_b.id)
    session = await _admin_session(admin_engine)
    try:
        async with session.begin():
            repo = MemberRepository(session, make_context(workspace_a.id))
            assert await repo.get(b_member) is None, "repository returned a foreign member"
    finally:
        await session.close()


async def test_get_by_user_id_finds_nothing_for_a_foreign_user_without_rls(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    """The deterministic form of the `get_by_user_id` scoping check.

    The two-workspaces-one-user variant below cannot catch a missing predicate reliably:
    an unscoped `WHERE user_id = ...` matches two rows and `scalar()` returns whichever
    the planner emits first, so the assertion passes or fails by luck. Here the user
    exists in **one** workspace only, so an unscoped query has exactly one row to return
    and returning anything at all is the failure.
    """
    await seed_member(admin_engine, workspace_b.id, user_id="only_in_b", role="owner")

    session = await _admin_session(admin_engine)
    try:
        async with session.begin():
            repo = MemberRepository(session, make_context(workspace_a.id))
            found = await repo.get_by_user_id("only_in_b")
    finally:
        await session.close()

    assert found is None, "repository resolved a user belonging to another workspace"


async def test_get_by_user_id_picks_the_context_workspace_without_rls(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    """Two workspaces, one `user_id` — the predicate must pick the context's row.

    B is seeded first so that an unscoped scan would surface it first, but the test above
    is what actually guarantees detection; this one documents the intended semantics.
    """
    await seed_member(admin_engine, workspace_b.id, user_id="shared", role="viewer")
    a_member = await seed_member(admin_engine, workspace_a.id, user_id="shared", role="owner")

    session = await _admin_session(admin_engine)
    try:
        async with session.begin():
            repo = MemberRepository(session, make_context(workspace_a.id))
            found = await repo.get_by_user_id("shared")
    finally:
        await session.close()

    assert found is not None
    assert found.id == a_member
    assert found.role == "owner", "repository resolved the wrong workspace's membership"


async def test_update_role_is_scoped_by_the_repository_alone(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    b_member = await seed_member(admin_engine, workspace_b.id, role="viewer")
    session = await _admin_session(admin_engine)
    try:
        async with session.begin():
            repo = MemberRepository(session, make_context(workspace_a.id))
            assert await repo.update_role(b_member, "owner") is None
    finally:
        await session.close()

    async with admin_engine.begin() as conn:
        role = await conn.scalar(text("SELECT role FROM members WHERE id = :i"), {"i": b_member})
    assert role == "viewer", "repository escalated a foreign member's role"


async def test_delete_is_scoped_by_the_repository_alone(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    b_member = await seed_member(admin_engine, workspace_b.id)
    session = await _admin_session(admin_engine)
    try:
        async with session.begin():
            repo = MemberRepository(session, make_context(workspace_a.id))
            assert await repo.delete(b_member) is False
    finally:
        await session.close()

    async with admin_engine.begin() as conn:
        remaining = await conn.scalar(
            text("SELECT count(*) FROM members WHERE id = :i"), {"i": b_member}
        )
    assert remaining == 1, "repository deleted a foreign member"


async def test_create_writes_the_context_workspace_even_without_rls(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    """With WITH CHECK bypassed, only `create()` decides which tenant owns the row."""
    session = await _admin_session(admin_engine)
    try:
        async with session.begin():
            repo = MemberRepository(session, make_context(workspace_a.id))
            member = await repo.create(user_id="ctx_owned", role="member")
            created_id = member.id
    finally:
        await session.close()

    async with admin_engine.begin() as conn:
        owner = await conn.scalar(
            text("SELECT workspace_id FROM members WHERE id = :i"), {"i": created_id}
        )
    assert owner == workspace_a.id
    assert owner != workspace_b.id


# --------------------------------------------------------------------------------------
# transaction ownership
# --------------------------------------------------------------------------------------


async def test_repository_does_not_commit(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """The UnitOfWork owns the transaction boundary (BACKEND_SPEC.md §3).

    A repository that committed internally would make the request-scoped rollback
    guarantee a lie. Rolling back must therefore discard the write entirely.
    """
    async with app_session.begin():
        repo = await bound_repo(app_session, workspace_a)
        member = await repo.create(user_id="rolled_back", role="member")
        created_id = member.id
        await app_session.rollback()

    async with admin_engine.begin() as conn:
        assert (
            await conn.scalar(text("SELECT count(*) FROM members WHERE id = :i"), {"i": created_id})
            == 0
        ), "repository committed on its own; rollback did not discard the write"


async def test_flush_surfaces_server_defaults_without_committing(
    app_session: AsyncSession, workspace_a: SeededWorkspace
) -> None:
    async with app_session.begin():
        repo = await bound_repo(app_session, workspace_a)
        member = await repo.create(user_id="flushed", role="member")
        assert isinstance(member, Member)
        assert member.created_at is not None
        assert member.updated_at is not None
        assert app_session.in_transaction(), "flush must not end the transaction"
