"""MemberService: the application boundary over Members.

Two kinds of evidence live here and they are deliberately not interchangeable.

Orchestration claims — "the service called the repository", "it did not invent a
workspace", "it did not pre-check before inserting" — are asserted against a recording
fake repository, because a real database cannot tell you *which* calls were made.

Everything that depends on PostgreSQL — the uniqueness constraint, the CHECK domain, RLS,
transaction boundaries, the concurrency race — runs against the real database, because a
fake would only be re-asserting the assumptions under test.
"""

from __future__ import annotations

import asyncio
import inspect
import uuid
from dataclasses import dataclass, field
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.core.db import UnitOfWork
from app.core.exceptions import ConflictError, NotFoundError, ValidationFailedError
from app.core.security import CallerIdentity, WorkspaceContext
from app.domains.workspaces.models import MEMBER_ROLES, Member
from app.domains.workspaces.repository import MemberRepository
from app.domains.workspaces.service import MemberService
from tests.conftest import SeededWorkspace
from tests.integration.test_members_tenancy import seed_member

# --------------------------------------------------------------------------------------
# fakes — for orchestration assertions only
# --------------------------------------------------------------------------------------


@dataclass
class RecordingRepository:
    """Records calls so orchestration can be asserted.

    Intentionally does **not** subclass MemberRepository: the point is to observe what the
    service asks for, and inheriting real query methods would let a bug pass by falling
    through to a real implementation.
    """

    members: dict[uuid.UUID, Member] = field(default_factory=dict)
    calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = field(default_factory=list)
    create_raises: Exception | None = None

    def _record(self, name: str, *args: Any, **kwargs: Any) -> None:
        self.calls.append((name, args, kwargs))

    @property
    def call_names(self) -> list[str]:
        return [c[0] for c in self.calls]

    async def get(self, member_id: uuid.UUID) -> Member | None:
        self._record("get", member_id)
        return self.members.get(member_id)

    async def get_by_user_id(self, user_id: str) -> Member | None:
        self._record("get_by_user_id", user_id)
        return next((m for m in self.members.values() if m.user_id == user_id), None)

    async def list_for_workspace(self) -> list[Member]:
        self._record("list_for_workspace")
        return list(self.members.values())

    async def create(
        self, *, user_id: str, role: str, invited_by: uuid.UUID | None = None
    ) -> Member:
        self._record("create", user_id=user_id, role=role, invited_by=invited_by)
        if self.create_raises is not None:
            raise self.create_raises
        member = Member(id=uuid.uuid4(), user_id=user_id, role=role, invited_by=invited_by)
        self.members[member.id] = member
        return member

    async def update_role(self, member_id: uuid.UUID, role: str) -> Member | None:
        self._record("update_role", member_id, role)
        member = self.members.get(member_id)
        if member is not None:
            member.role = role
        return member

    async def delete(self, member_id: uuid.UUID) -> bool:
        self._record("delete", member_id)
        return self.members.pop(member_id, None) is not None


def service_with_fake() -> tuple[MemberService, RecordingRepository]:
    repo = RecordingRepository()
    return MemberService(repo), repo  # type: ignore[arg-type]


def make_context(workspace_id: uuid.UUID) -> WorkspaceContext:
    return WorkspaceContext(
        workspace_id=workspace_id,
        caller=CallerIdentity(kind="api_token", api_token_id=uuid.uuid4()),
        request_id="req_test",
    )


async def real_service(session: AsyncSession, workspace: SeededWorkspace) -> MemberService:
    """Service over the real repository, with the transaction bound to the tenant."""
    await UnitOfWork(session=session).bind_workspace(workspace.id)
    return MemberService(MemberRepository(session, make_context(workspace.id)))


# --------------------------------------------------------------------------------------
# A. construction / dependency wiring
# --------------------------------------------------------------------------------------


def test_service_requires_a_repository() -> None:
    with pytest.raises(TypeError):
        MemberService()  # type: ignore[call-arg]


def test_service_takes_only_a_repository() -> None:
    """The tenancy guarantee is structural.

    The service holds no WorkspaceContext and no workspace_id, so there is no parameter
    through which a caller could redirect it at another tenant. If this signature ever
    grows a workspace argument, that guarantee is gone.
    """
    params = list(inspect.signature(MemberService.__init__).parameters)
    assert params == ["self", "repository"]


def test_no_public_method_accepts_a_workspace_argument() -> None:
    """No method may offer a tenant override, however well-intentioned."""
    for name, fn in inspect.getmembers(MemberService, inspect.isfunction):
        if name.startswith("_"):
            continue
        params = set(inspect.signature(fn).parameters)
        assert not params & {"workspace_id", "workspace", "tenant_id", "ctx", "context"}, (
            f"{name}() exposes a tenant override"
        )


def service_code() -> str:
    """The service module's *executable* code, with comments and docstrings removed.

    Scanning raw source for forbidden strings punishes documentation: a docstring saying
    "this performs no permission check" trips a search for "permission". `ast.unparse`
    drops comments, and docstrings are stripped explicitly, so what remains is only what
    the module actually does.
    """
    import ast

    import app.domains.workspaces.service as svc

    tree = ast.parse(inspect.getsource(svc))
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


def test_service_module_imports_no_web_or_database_machinery() -> None:
    """Framework-free (BACKEND_SPEC.md §2), and not a second persistence layer.

    Checked against the *import graph* rather than by searching for spellings. A substring
    scan is trivially evaded — `from sqlalchemy import text as _t` then `_t(...)` contains
    neither "sqlalchemy import text" nor "text(" at the call site — and a test that can be
    sidestepped by renaming an import is not a control. `ast.walk` also descends into
    function bodies, so a deferred import inside a method is caught as well.
    """
    import ast

    import app.domains.workspaces.service as svc

    tree = ast.parse(inspect.getsource(svc))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    banned_roots = {"fastapi", "starlette", "sqlalchemy", "asyncpg", "psycopg", "psycopg2"}
    offenders = {m for m in imported if m.split(".")[0] in banned_roots}
    assert not offenders, f"service imports transport/persistence machinery: {sorted(offenders)}"

    # The session/engine lives in app.core.db; the service must reach the database only
    # through the repository it was handed.
    assert not {m for m in imported if m.startswith("app.core.db")}, (
        "service imports the database session layer directly"
    )


def test_service_contains_no_raw_sql() -> None:
    """No SQL text may appear anywhere in the module, in any spelling.

    Reads `service_code()`, which has already stripped docstrings — otherwise prose
    containing the word "from" would trip the pattern.
    """
    import ast
    import re

    sql = re.compile(r"\b(select|insert\s+into|update|delete\s+from|from)\b\s", re.IGNORECASE)
    for node in ast.walk(ast.parse(service_code())):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and sql.search(node.value)
        ):
            raise AssertionError(f"raw SQL in the service layer: {node.value[:60]!r}")


def test_no_public_method_accepts_a_session_or_connection() -> None:
    """The repository is the persistence boundary; handing the service a session moves it."""
    for name, fn in inspect.getmembers(MemberService, inspect.isfunction):
        if name.startswith("_"):
            continue
        params = set(inspect.signature(fn).parameters)
        assert not params & {"session", "conn", "connection", "engine", "uow", "db"}, (
            f"{name}() accepts a persistence handle, bypassing the repository"
        )


# --------------------------------------------------------------------------------------
# B/C. context propagation and repository invocation
# --------------------------------------------------------------------------------------


async def test_reads_delegate_to_the_repository() -> None:
    service, repo = service_with_fake()
    member = await service.add_member(user_id="u1", role="member")
    repo.calls.clear()

    await service.get_member(member.id)
    await service.get_member_by_user_id("u1")
    await service.list_members()

    assert repo.call_names == ["get", "get_by_user_id", "list_for_workspace"]


async def test_service_never_reaches_past_the_repository(
    app_session: AsyncSession, workspace_a: SeededWorkspace
) -> None:
    """Every operation must be expressible through the repository alone."""
    service, repo = service_with_fake()
    m = await service.add_member(user_id="u", role="admin")
    await service.change_member_role(m.id, "viewer")
    await service.remove_member(m.id)
    assert set(repo.call_names) <= {
        "get",
        "get_by_user_id",
        "list_for_workspace",
        "create",
        "update_role",
        "delete",
    }


# --------------------------------------------------------------------------------------
# D-G. successful operations, against the real database
# --------------------------------------------------------------------------------------


async def test_add_member_persists(app_session: AsyncSession, workspace_a: SeededWorkspace) -> None:
    async with app_session.begin():
        service = await real_service(app_session, workspace_a)
        member = await service.add_member(user_id="alice", role="admin")
        assert member.workspace_id == workspace_a.id
        assert member.role == "admin"


async def test_get_member_returns_the_row(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    member_id = await seed_member(admin_engine, workspace_a.id, user_id="bob")
    async with app_session.begin():
        service = await real_service(app_session, workspace_a)
        assert (await service.get_member(member_id)).user_id == "bob"


async def test_get_member_by_user_id_returns_the_row(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    await seed_member(admin_engine, workspace_a.id, user_id="carol", role="viewer")
    async with app_session.begin():
        service = await real_service(app_session, workspace_a)
        assert (await service.get_member_by_user_id("carol")).role == "viewer"


async def test_list_members_returns_this_workspace_only(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    a1 = await seed_member(admin_engine, workspace_a.id, user_id="a1")
    await seed_member(admin_engine, workspace_b.id, user_id="b1")
    async with app_session.begin():
        service = await real_service(app_session, workspace_a)
        assert [m.id for m in await service.list_members()] == [a1]


async def test_change_member_role_and_remove_member(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    member_id = await seed_member(admin_engine, workspace_a.id, role="member")
    async with app_session.begin():
        service = await real_service(app_session, workspace_a)
        assert (await service.change_member_role(member_id, "owner")).role == "owner"
        await service.remove_member(member_id)
        with pytest.raises(NotFoundError):
            await service.get_member(member_id)


# --------------------------------------------------------------------------------------
# H. duplicate membership — including the concurrency race
# --------------------------------------------------------------------------------------


async def test_duplicate_membership_raises_conflict(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    await seed_member(admin_engine, workspace_a.id, user_id="dupe")
    with pytest.raises(ConflictError):
        async with app_session.begin():
            service = await real_service(app_session, workspace_a)
            await service.add_member(user_id="dupe", role="member")


async def test_add_member_does_not_pre_check_existence() -> None:
    """The concurrency-safety assertion, made structurally.

    A SELECT-then-INSERT is a race: two concurrent requests can both observe "not a
    member" and both proceed. Asserting that `add_member` issues exactly one repository
    call — the insert — is what stops someone "helpfully" adding a pre-check later and
    reintroducing the illusion that the application guarantees uniqueness.
    """
    service, repo = service_with_fake()
    await service.add_member(user_id="u", role="member")
    assert repo.call_names == ["create"], (
        f"expected a bare insert; got {repo.call_names} — a pre-check is a race, not a guard"
    )


async def test_concurrent_duplicate_creation_yields_exactly_one_member(
    admin_engine: AsyncEngine, app_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Two real concurrent transactions racing to add the same user.

    Exactly one must win and the database must end with one row. The loser may surface as
    ConflictError or as a serialization/constraint failure at commit — both are correct;
    what is not acceptable is two memberships.
    """
    factory = async_sessionmaker(app_engine, expire_on_commit=False)

    async def attempt() -> str:
        async with factory() as session:
            try:
                async with session.begin():
                    service = await real_service(session, workspace_a)
                    await service.add_member(user_id="racer", role="member")
                return "won"
            except Exception as err:  # noqa: BLE001 - classifying, not swallowing
                return type(err).__name__

    outcomes = await asyncio.gather(attempt(), attempt())

    async with admin_engine.begin() as conn:
        count = await conn.scalar(
            text("SELECT count(*) FROM members WHERE workspace_id = :w AND user_id = 'racer'"),
            {"w": workspace_a.id},
        )
    assert count == 1, f"race produced {count} memberships; outcomes={outcomes}"
    assert "won" in outcomes, f"neither attempt succeeded: {outcomes}"


# --------------------------------------------------------------------------------------
# I. input validation and error translation
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("bad_role", ["superuser", "OWNER", "", "root", "admin "])
async def test_invalid_role_is_a_domain_error_not_a_database_error(bad_role: str) -> None:
    """Without this the DB CHECK violation would reach the caller as an IntegrityError."""
    service, repo = service_with_fake()
    with pytest.raises(ValidationFailedError):
        await service.add_member(user_id="u", role=bad_role)
    assert repo.call_names == [], "invalid input reached persistence"


@pytest.mark.parametrize("role", list(MEMBER_ROLES))
async def test_every_canonical_role_is_accepted(role: str) -> None:
    service, _ = service_with_fake()
    assert (await service.add_member(user_id=f"u_{role}", role=role)).role == role


@pytest.mark.parametrize("bad_user", ["", "   ", "\t\n"])
async def test_blank_user_identity_is_rejected(bad_user: str) -> None:
    service, repo = service_with_fake()
    with pytest.raises(ValidationFailedError):
        await service.add_member(user_id=bad_user, role="member")
    assert repo.call_names == []


async def test_invalid_role_is_rejected_on_update_too() -> None:
    service, repo = service_with_fake()
    member = await service.add_member(user_id="u", role="member")
    repo.calls.clear()
    with pytest.raises(ValidationFailedError):
        await service.change_member_role(member.id, "sudo")
    assert repo.call_names == []


async def test_database_check_constraint_remains_authoritative(
    app_session: AsyncSession, workspace_a: SeededWorkspace
) -> None:
    """Service validation must not be treated as a replacement for the constraint."""
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        async with app_session.begin():
            await UnitOfWork(session=app_session).bind_workspace(workspace_a.id)
            await app_session.execute(
                text(
                    "INSERT INTO members (id, workspace_id, user_id, role) "
                    "VALUES (:i, :w, 'x', 'sudo')"
                ),
                {"i": uuid.uuid4(), "w": workspace_a.id},
            )


# --------------------------------------------------------------------------------------
# J. missing member behaviour
# --------------------------------------------------------------------------------------


async def test_missing_member_raises_not_found() -> None:
    service, _ = service_with_fake()
    with pytest.raises(NotFoundError):
        await service.get_member(uuid.uuid4())
    with pytest.raises(NotFoundError):
        await service.get_member_by_user_id("nobody")
    with pytest.raises(NotFoundError):
        await service.change_member_role(uuid.uuid4(), "member")
    with pytest.raises(NotFoundError):
        await service.remove_member(uuid.uuid4())


async def test_foreign_member_is_indistinguishable_from_absent(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """No existence oracle across tenants (P-17)."""
    b_member = await seed_member(admin_engine, workspace_b.id)
    async with app_session.begin():
        service = await real_service(app_session, workspace_a)
        with pytest.raises(NotFoundError) as foreign:
            await service.get_member(b_member)
        with pytest.raises(NotFoundError) as absent:
            await service.get_member(uuid.uuid4())
    assert str(foreign.value) == str(absent.value)


# --------------------------------------------------------------------------------------
# K. transaction behaviour
# --------------------------------------------------------------------------------------


async def test_service_does_not_commit(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """A rollback must discard the write; a hidden commit would make it survive."""
    async with app_session.begin():
        service = await real_service(app_session, workspace_a)
        member = await service.add_member(user_id="rolled_back", role="member")
        created = member.id
        await app_session.rollback()

    async with admin_engine.begin() as conn:
        assert (
            await conn.scalar(text("SELECT count(*) FROM members WHERE id = :i"), {"i": created})
            == 0
        ), "service committed on its own"


def test_service_source_contains_no_transaction_control() -> None:
    code = service_code()
    for forbidden in ("commit()", "rollback()", "begin()", "flush()"):
        assert forbidden not in code, f"service manages transactions via {forbidden}"


# --------------------------------------------------------------------------------------
# L/M. workspace isolation preserved; no override
# --------------------------------------------------------------------------------------


async def test_service_cannot_reach_another_workspace(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    b_member = await seed_member(admin_engine, workspace_b.id, user_id="b_only")
    async with app_session.begin():
        service = await real_service(app_session, workspace_a)
        assert await service.list_members() == []
        with pytest.raises(NotFoundError):
            await service.get_member(b_member)
        with pytest.raises(NotFoundError):
            await service.get_member_by_user_id("b_only")


async def test_service_writes_land_in_its_own_workspace(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    async with app_session.begin():
        service = await real_service(app_session, workspace_a)
        member = await service.add_member(user_id="owned", role="member")
        created = member.id

    async with admin_engine.begin() as conn:
        owner = await conn.scalar(
            text("SELECT workspace_id FROM members WHERE id = :i"), {"i": created}
        )
    assert owner == workspace_a.id
    assert owner != workspace_b.id


# --------------------------------------------------------------------------------------
# N. no authorization logic
# --------------------------------------------------------------------------------------


def test_service_contains_no_role_based_permission_logic() -> None:
    """RBAC is M1.2-D. This asserts it has not leaked in early.

    Analysed structurally rather than by text search, because the two cases look alike in
    prose but are entirely different in the AST:

    - `role not in MEMBER_ROLES` — validation against the canonical domain *constant*.
      Permitted: it branches on whether a value is well-formed.
    - `role == "owner"` / `role in ("owner", "admin")` — a comparison against specific
      role *literals*. Forbidden: that is a policy decision about what may happen, and it
      belongs to the authorization layer.
    """
    import ast

    import app.domains.workspaces.service as svc

    tree = ast.parse(inspect.getsource(svc))
    roles = set(MEMBER_ROLES)

    def literal_roles(node: ast.AST) -> set[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return {node.value} & roles
        if isinstance(node, ast.Tuple | ast.List | ast.Set):
            return {
                e.value
                for e in node.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)
            } & roles
        return set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            hits: set[str] = set()
            for operand in operands:
                hits |= literal_roles(operand)
            if hits:
                raise AssertionError(
                    f"role-literal comparison found ({sorted(hits)}) at line {node.lineno} — "
                    "that is an authorization decision and belongs to M1.2-D"
                )

    # A permission-denial import would be the other tell.
    code = service_code()
    for forbidden in ("PermissionDeniedError", "has_permission", "is_owner", "authorize("):
        assert forbidden not in code, f"authorization machinery present: {forbidden!r}"


async def test_any_canonical_role_may_perform_any_service_operation() -> None:
    """Behavioural counterpart: the service must not gate on the stored role.

    A `viewer` can be created, renamed and removed exactly like an `owner`, because this
    layer expresses no policy. When M1.2-D lands, that becomes the authorization layer's
    job — not a change to these tests' expectations here.
    """
    for role in MEMBER_ROLES:
        service, _ = service_with_fake()
        member = await service.add_member(user_id=f"u_{role}", role=role)
        assert (await service.change_member_role(member.id, "viewer")).role == "viewer"
        await service.remove_member(member.id)


def test_no_cross_workspace_or_global_lookup_is_exposed() -> None:
    names = {
        n for n, _ in inspect.getmembers(MemberService, inspect.isfunction) if not n.startswith("_")
    }
    for forbidden in (
        "list_all",
        "get_all",
        "find_user",
        "list_workspaces_for_user",
        "get_by_user_id_global",
        "list_across_workspaces",
    ):
        assert forbidden not in names, f"cross-tenant operation exposed: {forbidden}"
