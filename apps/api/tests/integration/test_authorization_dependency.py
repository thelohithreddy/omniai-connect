"""Request authorization boundary: does the caller hold the endpoint's permission here?

Two layers of evidence.

Unit-level tests drive `resolve_member_role` and the dependency directly against the real
database, because the guarantees being proved — that membership is workspace-scoped, that
the role comes from a persisted row — are database facts.

Transport-level tests mount a throwaway FastAPI app with protected routes, because 401 vs
403, the error envelope, and "the caller cannot supply the permission" are HTTP facts that
a direct function call cannot demonstrate. That app exists only in this module; M1.2-E
attaches authorization to no real endpoint.
"""

from __future__ import annotations

import ast
import inspect
import uuid
from typing import Annotated

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.core.authorization import require_permission, resolve_member_role
from app.core.authz import Permission, Role
from app.core.db import UnitOfWork, get_uow
from app.core.exceptions import PermissionDeniedError
from app.core.ids import new_id
from app.core.security import CallerIdentity, WorkspaceContext, get_workspace_context
from app.domains.workspaces.repository import MemberRepository
from app.main import app as real_app
from tests.conftest import SeededWorkspace
from tests.integration.test_members_tenancy import seed_member

# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def member_context(workspace_id: uuid.UUID, member_id: uuid.UUID) -> WorkspaceContext:
    """A human-plane context — what Better Auth will produce once it lands (M1.2+)."""
    return WorkspaceContext(
        workspace_id=workspace_id,
        caller=CallerIdentity(kind="member", member_id=member_id),
        request_id="req_test",
    )


def token_context(workspace_id: uuid.UUID) -> WorkspaceContext:
    """A machine-plane context — what every request produces today."""
    return WorkspaceContext(
        workspace_id=workspace_id,
        caller=CallerIdentity(kind="api_token", api_token_id=uuid.uuid4()),
        request_id="req_test",
    )


async def bind(session: AsyncSession, workspace: SeededWorkspace) -> None:
    await UnitOfWork(session=session).bind_workspace(workspace.id)


async def role_for(session: AsyncSession, ctx: WorkspaceContext) -> Role | None:
    return await resolve_member_role(ctx, MemberRepository(session, ctx))


async def decide(session: AsyncSession, ctx: WorkspaceContext, permission: Permission) -> bool:
    """Run the dependency body; True if it allowed, False if it raised 403."""
    dependency = require_permission(permission)
    try:
        await dependency(UnitOfWork(session=session), ctx)  # type: ignore[arg-type]
        return True
    except PermissionDeniedError:
        return False


# --------------------------------------------------------------------------------------
# A-E. role resolution and the policy decision, per role
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role", "permission", "allowed"),
    [
        ("owner", Permission.WORKSPACE_MANAGE, True),
        ("owner", Permission.MEMBERS_MANAGE, True),
        ("admin", Permission.MEMBERS_MANAGE, True),
        ("admin", Permission.WORKSPACE_MANAGE, False),
        ("member", Permission.TOOLS_EXECUTE, True),
        ("member", Permission.MEMBERS_MANAGE, False),
        ("member", Permission.AUDIT_READ, False),
        ("viewer", Permission.TOOLS_EXECUTE, False),
        ("viewer", Permission.MEMBERS_MANAGE, False),
    ],
)
async def test_decision_matches_the_policy_for_a_real_membership(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    role: str,
    permission: Permission,
    allowed: bool,
) -> None:
    member_id = await seed_member(admin_engine, workspace_a.id, role=role)
    async with app_session.begin():
        await bind(app_session, workspace_a)
        ctx = member_context(workspace_a.id, member_id)
        assert await role_for(app_session, ctx) is Role(role)
        assert await decide(app_session, ctx, permission) is allowed


# --------------------------------------------------------------------------------------
# I. missing membership   +   machine identity
# --------------------------------------------------------------------------------------


async def test_machine_identity_resolves_no_role_and_is_denied(
    app_session: AsyncSession, workspace_a: SeededWorkspace
) -> None:
    """An API token is not a Member (ADR-0002); it must not inherit anyone's role."""
    async with app_session.begin():
        await bind(app_session, workspace_a)
        ctx = token_context(workspace_a.id)
        assert await role_for(app_session, ctx) is None
        for permission in Permission:
            assert await decide(app_session, ctx, permission) is False


async def test_machine_identity_is_denied_even_when_the_workspace_has_an_owner(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """The specific forbidden shortcut: falling back to workspace/token ownership."""
    await seed_member(admin_engine, workspace_a.id, role="owner")
    async with app_session.begin():
        await bind(app_session, workspace_a)
        assert (
            await decide(app_session, token_context(workspace_a.id), Permission.TOOLS_EXECUTE)
            is False
        )


async def test_machine_identity_carrying_a_member_id_cannot_assume_that_role(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """The confused deputy this boundary exists to prevent.

    A machine credential presenting a *real, valid* membership id must not inherit that
    human's role. This is not hypothetical: DATABASE_DESIGN.md §3 plans
    `api_tokens.created_by_member_id`, so a future token-issuance path will have a member
    id in hand, and populating `caller.member_id` from it would silently promote every
    token to the privileges of whoever created it — a machine credential acting with a
    human's authority, which ADR-0002's "never mixed" rule exists to forbid.

    Only the identity-plane check stands between those two planes. The membership id here
    is genuine and resolvable; the caller is refused because of *what kind of identity it
    is*, not because the lookup failed.
    """
    owner_member = await seed_member(admin_engine, workspace_a.id, role="owner")

    impersonating = WorkspaceContext(
        workspace_id=workspace_a.id,
        caller=CallerIdentity(
            kind="api_token",
            api_token_id=uuid.uuid4(),
            member_id=owner_member,  # a real owner membership in this very workspace
        ),
        request_id="req_test",
    )

    async with app_session.begin():
        await bind(app_session, workspace_a)
        # Sanity: the membership is genuinely resolvable — the denial is not a lookup miss.
        assert await MemberRepository(app_session, impersonating).get(owner_member) is not None

        assert await role_for(app_session, impersonating) is None, (
            "machine identity assumed a human membership's role"
        )
        for permission in Permission:
            assert await decide(app_session, impersonating, permission) is False


async def test_unknown_member_id_is_denied(
    app_session: AsyncSession, workspace_a: SeededWorkspace
) -> None:
    async with app_session.begin():
        await bind(app_session, workspace_a)
        ctx = member_context(workspace_a.id, new_id())
        assert await role_for(app_session, ctx) is None
        assert await decide(app_session, ctx, Permission.TOOLS_EXECUTE) is False


async def test_member_kind_without_a_member_id_is_denied(
    app_session: AsyncSession, workspace_a: SeededWorkspace
) -> None:
    ctx = WorkspaceContext(
        workspace_id=workspace_a.id,
        caller=CallerIdentity(kind="member", member_id=None),
        request_id="r",
    )
    async with app_session.begin():
        await bind(app_session, workspace_a)
        assert await role_for(app_session, ctx) is None
        assert await decide(app_session, ctx, Permission.TOOLS_EXECUTE) is False


async def test_role_outside_the_canonical_domain_denies_rather_than_raises(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """A corrupted row must not convert authorization into a crash."""
    member_id = await seed_member(admin_engine, workspace_a.id, role="member")
    async with admin_engine.begin() as conn:  # bypasses the CHECK via a direct write
        await conn.execute(text("ALTER TABLE members DROP CONSTRAINT ck_members_role_valid"))
        await conn.execute(
            text("UPDATE members SET role = 'superuser' WHERE id = :i"), {"i": member_id}
        )
    try:
        async with app_session.begin():
            await bind(app_session, workspace_a)
            ctx = member_context(workspace_a.id, member_id)
            assert await role_for(app_session, ctx) is None
            assert await decide(app_session, ctx, Permission.TOOLS_EXECUTE) is False
    finally:
        async with admin_engine.begin() as conn:
            await conn.execute(text("DELETE FROM members WHERE id = :i"), {"i": member_id})
            await conn.execute(
                text(
                    "ALTER TABLE members ADD CONSTRAINT ck_members_role_valid "
                    "CHECK (role IN ('owner','admin','member','viewer'))"
                )
            )


# --------------------------------------------------------------------------------------
# J/K. THE cross-workspace test — the most important in the module
# --------------------------------------------------------------------------------------


async def test_authorization_uses_the_current_workspace_not_the_strongest_membership(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """One human, owner in A and viewer in B. Authority must follow the active tenant.

    Authenticated against B, the caller must NOT inherit A's owner rights. Authenticated
    against A, the same human must get them. This is what stops authorization from
    collapsing into "the strongest role this identity holds anywhere".
    """
    user = "shared-human"
    a_member = await seed_member(admin_engine, workspace_a.id, user_id=user, role="owner")
    b_member = await seed_member(admin_engine, workspace_b.id, user_id=user, role="viewer")

    # Authenticated against B → viewer → denied.
    async with app_session.begin():
        await bind(app_session, workspace_b)
        ctx_b = member_context(workspace_b.id, b_member)
        assert await role_for(app_session, ctx_b) is Role.VIEWER
        assert await decide(app_session, ctx_b, Permission.WORKSPACE_MANAGE) is False
        assert await decide(app_session, ctx_b, Permission.TOOLS_EXECUTE) is False

    # Authenticated against A → owner → allowed.
    async with app_session.begin():
        await bind(app_session, workspace_a)
        ctx_a = member_context(workspace_a.id, a_member)
        assert await role_for(app_session, ctx_a) is Role.OWNER
        assert await decide(app_session, ctx_a, Permission.WORKSPACE_MANAGE) is True


async def test_a_membership_id_from_another_workspace_is_unusable(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Presenting A's owner membership id while authenticated against B resolves nothing.

    The repository is scoped to B, so A's row is simply unreachable — no comparison in the
    authorization code is doing this work.
    """
    a_owner = await seed_member(admin_engine, workspace_a.id, role="owner")
    async with app_session.begin():
        await bind(app_session, workspace_b)
        smuggled = member_context(workspace_b.id, a_owner)
        assert await role_for(app_session, smuggled) is None
        assert await decide(app_session, smuggled, Permission.WORKSPACE_MANAGE) is False


async def test_membership_resolution_is_scoped_without_relying_on_rls(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    """Defense in depth: prove Layer 1 holds when Layer 2 cannot be what refused.

    Every test above runs as the least-privileged role with RLS armed, which means they
    cannot distinguish "the repository scoped the lookup" from "RLS hid the row". That
    distinction is not academic — replacing the repository call with a global
    `SELECT ... WHERE id = ?` passes all of them, because RLS quietly does the work.

    This runs resolution on the **superuser** session, where RLS is bypassed
    unconditionally and the connection can see every tenant's members. The repository's
    own workspace predicate is then the only thing that can refuse, so a global lookup
    fails here and nowhere else.
    """
    a_owner = await seed_member(admin_engine, workspace_a.id, role="owner")
    factory = async_sessionmaker(admin_engine, expire_on_commit=False)
    session = factory()
    try:
        async with session.begin():
            # Sanity: this connection really is unconstrained.
            visible = await session.scalar(text("SELECT count(*) FROM members"))
            assert visible and visible >= 1, "expected an RLS-exempt connection"

            # Authenticated against B, presenting A's owner membership.
            smuggled = member_context(workspace_b.id, a_owner)
            role = await resolve_member_role(smuggled, MemberRepository(session, smuggled))
            assert role is None, "membership resolved across workspaces without RLS"

            # And the same id under A's context does resolve — proving the row is reachable
            # on this connection, so the denial above was scoping, not a missing row.
            legitimate = member_context(workspace_a.id, a_owner)
            assert (
                await resolve_member_role(legitimate, MemberRepository(session, legitimate))
                is Role.OWNER
            )
    finally:
        await session.close()


# --------------------------------------------------------------------------------------
# R/S. the policy is invoked, and is the only source of truth
# --------------------------------------------------------------------------------------


def test_authorization_module_delegates_to_the_rbac_policy() -> None:
    import app.core.authorization as authorization

    source = inspect.getsource(authorization)
    assert "is_allowed" in source, "the dependency must call the M1.2-D policy"


def test_authorization_module_contains_no_second_role_matrix() -> None:
    """No role literal comparison, no local permission mapping.

    Structural, not textual: a comparison against a role literal is what a duplicated
    matrix looks like in the AST, whereas `Role(member.role)` — constructing the enum from
    a persisted value — is not.
    """
    import app.core.authorization as authorization

    tree = ast.parse(inspect.getsource(authorization))
    roles = {r.value for r in Role}
    permissions = {p.value for p in Permission}

    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for operand in [node.left, *node.comparators]:
                if isinstance(operand, ast.Constant) and operand.value in roles | permissions:
                    raise AssertionError(
                        f"role/permission literal compared at line {node.lineno} — "
                        "that is a duplicated matrix; delegate to authz.is_allowed"
                    )
        # A dict/set literal of role or permission strings would be a local mapping.
        if isinstance(node, ast.Dict):
            keys = {k.value for k in node.keys if isinstance(k, ast.Constant)}
            assert not keys & (roles | permissions), (
                f"local role/permission mapping at line {node.lineno}"
            )


def test_policy_is_the_single_source_of_grants() -> None:
    """Changing the policy changes the dependency's answer — proving no second copy."""
    from app.core import authz

    assert authz.is_allowed(Role.MEMBER, Permission.MEMBERS_MANAGE) is False
    assert authz.is_allowed(Role.ADMIN, Permission.MEMBERS_MANAGE) is True


# --------------------------------------------------------------------------------------
# L/M. trust boundaries — the caller controls neither role nor permission
# --------------------------------------------------------------------------------------


def test_the_dependency_signature_exposes_no_role_or_permission_parameter() -> None:
    """The endpoint declares the requirement; the request cannot carry it.

    `permission` is closed over at route-definition time and is absent from the
    dependency's signature, so FastAPI will never bind it from a body, query, header, or
    path.
    """
    dependency = require_permission(Permission.WORKSPACE_MANAGE)
    params = set(inspect.signature(dependency).parameters)
    assert params == {"uow", "ctx"}
    for forbidden in ("role", "permission", "required_permission", "workspace_id", "request"):
        assert forbidden not in params


def test_two_dependencies_carry_independent_permissions() -> None:
    """Reusable and non-aliasing: one closure must not leak into another."""
    manage = require_permission(Permission.WORKSPACE_MANAGE)
    execute = require_permission(Permission.TOOLS_EXECUTE)
    assert manage is not execute
    assert inspect.getclosurevars(manage).nonlocals["permission"] is Permission.WORKSPACE_MANAGE
    assert inspect.getclosurevars(execute).nonlocals["permission"] is Permission.TOOLS_EXECUTE


async def test_role_is_read_from_the_database_not_the_context(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """The persisted row wins. A context cannot assert a role because it carries none."""
    member_id = await seed_member(admin_engine, workspace_a.id, role="viewer")
    ctx = member_context(workspace_a.id, member_id)
    assert not hasattr(ctx.caller, "role")
    assert not hasattr(ctx, "role")

    async with app_session.begin():
        await bind(app_session, workspace_a)
        assert await role_for(app_session, ctx) is Role.VIEWER

    # Promote the row; the same context now resolves differently. The context never changed.
    async with admin_engine.begin() as conn:
        await conn.execute(
            text("UPDATE members SET role = 'owner' WHERE id = :i"), {"i": member_id}
        )
    async with app_session.begin():
        await bind(app_session, workspace_a)
        assert await role_for(app_session, ctx) is Role.OWNER


# --------------------------------------------------------------------------------------
# F/G/H, W/X. transport semantics — 401 vs 403, envelope, caller-supplied fields
# --------------------------------------------------------------------------------------


@pytest.fixture
async def protected_client(app_engine: AsyncEngine) -> AsyncClient:
    """A throwaway app with protected routes.

    Exists only to exercise transport semantics. M1.2-E attaches authorization to no real
    endpoint — see the module docstring on machine identity.
    """
    factory = async_sessionmaker(app_engine, expire_on_commit=False, autoflush=False)
    test_app = FastAPI()

    # Reuse the real error handlers so the envelope under test is the production one.
    for exc, handler in real_app.exception_handlers.items():
        test_app.add_exception_handler(exc, handler)  # type: ignore[arg-type]

    @test_app.get("/needs-members-manage")
    async def needs_members_manage(  # pyright: ignore[reportUnusedFunction]
        ctx: Annotated[WorkspaceContext, Depends(require_permission(Permission.MEMBERS_MANAGE))],
    ) -> dict[str, str]:
        return {"ok": str(ctx.workspace_id)}

    @test_app.post("/needs-workspace-manage")
    async def needs_workspace_manage(  # pyright: ignore[reportUnusedFunction]
        ctx: Annotated[WorkspaceContext, Depends(require_permission(Permission.WORKSPACE_MANAGE))],
    ) -> dict[str, str]:
        return {"ok": str(ctx.workspace_id)}

    async def override_uow() -> object:
        async with factory() as session, session.begin():
            yield UnitOfWork(session=session)

    test_app.dependency_overrides[get_uow] = override_uow
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://t") as c:
        yield c


async def test_unauthenticated_request_is_401_not_403(protected_client: AsyncClient) -> None:
    """Authentication failure must not be reported as an authorization failure."""
    response = await protected_client.get("/needs-members-manage")
    assert response.status_code == 401
    body = response.json()
    assert body["error"]["code"] == "unauthorized"
    assert set(body) == {"error"}
    assert body["error"]["request_id"] is not None


async def test_invalid_token_is_401(protected_client: AsyncClient) -> None:
    response = await protected_client.get(
        "/needs-members-manage", headers={"Authorization": "Bearer omc_not-real"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


async def test_authenticated_but_unauthorized_is_403(
    protected_client: AsyncClient, workspace_a: SeededWorkspace
) -> None:
    """A valid API token authenticates but resolves no membership → 403, not 401."""
    response = await protected_client.get(
        "/needs-members-manage",
        headers={"Authorization": f"Bearer {workspace_a.token.plaintext}"},
    )
    assert response.status_code == 403
    body = response.json()
    assert body["error"]["code"] == "forbidden"
    assert set(body) == {"error"}


async def test_denial_message_is_identical_across_permissions_and_reasons(
    protected_client: AsyncClient, workspace_a: SeededWorkspace
) -> None:
    """No membership-enumeration primitive: every denial reads the same.

    A different message for "not a member here" versus "role lacks this permission" would
    let a caller probe membership across workspaces from the 403 body alone.
    """
    headers = {"Authorization": f"Bearer {workspace_a.token.plaintext}"}
    first = await protected_client.get("/needs-members-manage", headers=headers)
    second = await protected_client.post("/needs-workspace-manage", headers=headers)
    assert first.status_code == second.status_code == 403
    assert first.json()["error"]["message"] == second.json()["error"]["message"]


async def test_denial_leaks_no_internal_detail(
    protected_client: AsyncClient, workspace_a: SeededWorkspace
) -> None:
    response = await protected_client.get(
        "/needs-members-manage",
        headers={"Authorization": f"Bearer {workspace_a.token.plaintext}"},
    )
    raw = response.text
    for leaked in (
        str(workspace_a.id),
        workspace_a.token.plaintext,
        workspace_a.token.token_hash,
        "members",
        "role",
        "SELECT",
        "Traceback",
        "sqlalchemy",
    ):
        assert leaked not in raw, f"denial leaked {leaked!r}"


@pytest.mark.parametrize(
    "attack",
    [
        {"json": {"role": "owner"}},
        {"json": {"permission": "workspace:manage"}},
        {"json": {"role": "owner", "permission": "workspace:manage"}},
        {"params": {"role": "owner"}},
        {"params": {"permission": "workspace:manage"}},
        {"headers": {"X-Role": "owner"}},
        {"headers": {"X-Permission": "workspace:manage"}},
    ],
)
async def test_caller_cannot_escalate_by_supplying_role_or_permission(
    protected_client: AsyncClient, workspace_a: SeededWorkspace, attack: dict[str, object]
) -> None:
    """Body, query, and header injection of both role and required permission."""
    headers = {"Authorization": f"Bearer {workspace_a.token.plaintext}"}
    headers.update(attack.pop("headers", {}))  # type: ignore[arg-type]
    response = await protected_client.post(
        "/needs-workspace-manage",
        headers=headers,
        **attack,  # type: ignore[arg-type]
    )
    assert response.status_code == 403, "caller-supplied field changed the decision"


def build_authorized_app(
    app_engine: AsyncEngine, workspace_id: uuid.UUID, member_id: uuid.UUID
) -> FastAPI:
    """A test app whose authentication yields a *human* context, as M1.2+ eventually will.

    `get_workspace_context` is overridden rather than reimplemented: the override receives
    the request's `UnitOfWork` through the normal dependency and binds the tenant on it,
    exactly as the real authenticator does. Everything downstream — membership lookup,
    policy, the 403 — is untouched production code.
    """
    factory = async_sessionmaker(app_engine, expire_on_commit=False, autoflush=False)
    test_app = FastAPI()
    for exc, handler in real_app.exception_handlers.items():
        test_app.add_exception_handler(exc, handler)  # type: ignore[arg-type]

    @test_app.get("/needs-members-manage")
    async def needs_members_manage(  # pyright: ignore[reportUnusedFunction]
        ctx: Annotated[WorkspaceContext, Depends(require_permission(Permission.MEMBERS_MANAGE))],
    ) -> dict[str, str]:
        return {"workspace": str(ctx.workspace_id)}

    async def override_uow() -> object:
        async with factory() as session, session.begin():
            yield UnitOfWork(session=session)

    async def override_context(uow: Annotated[UnitOfWork, Depends(get_uow)]) -> WorkspaceContext:
        await uow.bind_workspace(workspace_id)
        return member_context(workspace_id, member_id)

    test_app.dependency_overrides[get_uow] = override_uow
    test_app.dependency_overrides[get_workspace_context] = override_context
    return test_app


@pytest.mark.parametrize(
    ("role", "expected"), [("owner", 200), ("admin", 200), ("member", 403), ("viewer", 403)]
)
async def test_end_to_end_through_real_dependency_injection(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    role: str,
    expected: int,
) -> None:
    """The only allow path exercised through the real FastAPI dependency graph.

    Everything else in this file is a denial, and denials are the weaker evidence: if
    FastAPI's per-request dependency caching ever stopped sharing one `UnitOfWork` between
    authentication and authorization, the membership lookup would run on an *unbound*
    transaction, RLS would hide every row, and every check would deny. Fail-closed, so not
    a security hole — but the authorization system would be silently inert and a suite of
    denial tests would still be green.

    A 200 here proves the whole chain: the tenant was bound on the same transaction the
    membership lookup used, the role came out of the row, and the policy allowed it.
    """
    member_id = await seed_member(admin_engine, workspace_a.id, role=role)
    test_app = build_authorized_app(app_engine, workspace_a.id, member_id)
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://t") as client:
        response = await client.get("/needs-members-manage")

    assert response.status_code == expected, (
        f"{role} on members:manage expected {expected}, got {response.status_code}: "
        f"{response.text[:200]}"
    )
    if expected == 200:
        assert response.json() == {"workspace": str(workspace_a.id)}
    else:
        assert response.json()["error"]["code"] == "forbidden"


async def test_end_to_end_denies_a_membership_from_another_workspace(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Cross-workspace escalation, through the real request path rather than in-process.

    An owner membership belonging to workspace A, presented while the request is
    authenticated against workspace B. 403, not 200.
    """
    a_owner = await seed_member(admin_engine, workspace_a.id, role="owner")
    test_app = build_authorized_app(app_engine, workspace_b.id, a_owner)
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://t") as client:
        response = await client.get("/needs-members-manage")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


# --------------------------------------------------------------------------------------
# U/V. no side effects
# --------------------------------------------------------------------------------------


async def test_authorization_does_not_mutate_the_database(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    member_id = await seed_member(admin_engine, workspace_a.id, role="admin")

    async def snapshot() -> tuple[int, int, str, object]:
        async with admin_engine.begin() as conn:
            members = await conn.scalar(text("SELECT count(*) FROM members"))
            tokens = await conn.scalar(text("SELECT count(*) FROM api_tokens"))
            role = await conn.scalar(text("SELECT role FROM members WHERE id=:i"), {"i": member_id})
            used = await conn.scalar(
                text("SELECT last_used_at FROM api_tokens WHERE workspace_id=:w"),
                {"w": workspace_a.id},
            )
        return members, tokens, role, used

    before = await snapshot()
    async with app_session.begin():
        await bind(app_session, workspace_a)
        ctx = member_context(workspace_a.id, member_id)
        for permission in Permission:
            await decide(app_session, ctx, permission)
    assert await snapshot() == before, "authorization wrote to the database"


def test_authorization_module_opens_no_transaction_and_commits_nothing() -> None:
    import app.core.authorization as authorization

    source = inspect.getsource(authorization)
    for forbidden in (
        "commit()",
        "rollback()",
        "begin()",
        "flush()",
        "SessionFactory",
        "create_async_engine",
        "sessionmaker",
    ):
        assert forbidden not in source, f"authorization manages persistence via {forbidden}"


def test_authorization_module_has_no_redis_or_network_dependency() -> None:
    import app.core.authorization as authorization

    imported: set[str] = set()
    for node in ast.walk(ast.parse(inspect.getsource(authorization))):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for banned in ("redis", "httpx", "requests", "aiohttp", "boto3"):
        assert banned not in imported, f"authorization reaches out to {banned}"


# --------------------------------------------------------------------------------------
# dependency ordering
# --------------------------------------------------------------------------------------


def test_dependency_requires_authentication_and_tenant_context() -> None:
    """Authorization cannot run before authentication has produced a bound context."""
    dependency = require_permission(Permission.TOOLS_EXECUTE)
    hints = inspect.signature(dependency).parameters
    ctx_annotation = str(hints["ctx"].annotation)
    assert "CurrentWorkspace" in ctx_annotation or "WorkspaceContext" in ctx_annotation
    assert "UnitOfWork" in str(hints["uow"].annotation)


async def test_dependency_cannot_authorize_without_a_bound_transaction(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Without `bind_workspace`, RLS hides the membership and the decision is deny.

    Belt and braces: even if a future refactor forgot to bind, authorization fails closed
    rather than authorizing against an unscoped read.
    """
    member_id = await seed_member(admin_engine, workspace_a.id, role="owner")
    async with app_session.begin():
        ctx = member_context(workspace_a.id, member_id)  # no bind()
        assert await role_for(app_session, ctx) is None
        assert await decide(app_session, ctx, Permission.WORKSPACE_MANAGE) is False
