"""The database boundary between Better Auth and the application (M1.3-D).

Better Auth runs in `apps/web` and owns human identity (ADR-0002). Its tables live in the
`identity` schema, reached through the `omniai_identity` role — neither of which the API
uses. Nothing in `apps/api` imports Better Auth, so the only thing this suite can test is
also the only thing that matters: that the separation actually holds in Postgres.

These assertions exist because the boundary is invisible from Python. No FastAPI test would
fail if someone granted `omniai_app` read access to `identity`, or if a future migration
created a table there — the API would keep working, and the isolation would be gone. The
catalog is the only witness.

The suite deliberately fails rather than skips when `identity` is absent. A missing security
boundary is a failure, not an inapplicable test; skipping would let the whole file evaporate
in exactly the environment where it should scream.
"""

from __future__ import annotations

import ast
import re
import uuid
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

# No `pytestmark = pytest.mark.asyncio` here: `asyncio_mode = "auto"` already handles the
# async tests, and this file deliberately mixes in one synchronous static check that a
# module-wide asyncio marker would warn about.

# Better Auth 1.6.28 with the JWT plugin: four core tables plus `jwks`. Named explicitly so
# that a version bump adding a table surfaces here as a decision to make rather than as
# silent drift.
BETTER_AUTH_TABLES = frozenset({"user", "session", "account", "verification", "jwks"})

PROVISIONING_HINT = (
    "the `identity` schema is missing — it is created by "
    "infra/docker/postgres-init/02-identity-role.sh (fresh volume) or by the "
    "'Provision the Better Auth identity schema' step in CI"
)


async def _scalar(engine: AsyncEngine, sql: str, **params: object) -> object:
    async with engine.connect() as conn:
        return (await conn.execute(text(sql), params)).scalar_one()


async def test_identity_schema_exists_and_is_owned_by_its_own_role(
    admin_engine: AsyncEngine,
) -> None:
    owner = await _scalar(
        admin_engine,
        "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'identity'",
    )
    assert owner == "omniai_identity", PROVISIONING_HINT


async def test_better_auth_tables_are_present_in_identity(admin_engine: AsyncEngine) -> None:
    """The positive control the rest of this file depends on.

    Several assertions below are of the form "no Better Auth table exists in the wrong
    place" and "the application role holds no privilege on any identity table". Both pass
    trivially in a database where Better Auth has never run — the wrong-place check finds
    nothing because nothing exists anywhere, and the privilege check iterates an empty set.
    That is precisely the shape of a test suite that is green and proving nothing.

    So this asserts the tables are really there, which is what makes their absence elsewhere
    meaningful. CI creates them by running Better Auth's own migration before pytest.
    """
    async with admin_engine.connect() as conn:
        rows = (
            await conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'identity'")
            )
        ).all()
    present = {row.tablename for row in rows}
    missing = BETTER_AUTH_TABLES - present
    assert not missing, (
        f"Better Auth tables missing from identity: {sorted(missing)} — {PROVISIONING_HINT}, "
        "and the schema is applied by `pnpm --filter web migrate:identity`"
    )


async def test_application_role_cannot_use_the_identity_schema(
    admin_engine: AsyncEngine,
) -> None:
    """`omniai_app` has no USAGE, so it cannot name anything inside `identity` at all.

    This is the outermost gate. Without USAGE on the schema, table-level grants are
    unreachable even if one were somehow added, so a single revoked privilege closes the
    entire surface.
    """
    for privilege in ("USAGE", "CREATE"):
        granted = await _scalar(
            admin_engine,
            "SELECT has_schema_privilege('omniai_app', 'identity', :priv)",
            priv=privilege,
        )
        assert granted is False, f"omniai_app must not hold {privilege} on identity"


async def test_application_role_holds_no_privilege_on_any_identity_table(
    admin_engine: AsyncEngine,
) -> None:
    """Defence in depth: even with USAGE restored, no table would be readable.

    Checked per table rather than per schema because `GRANT SELECT ON ALL TABLES` and a
    stray per-table grant look identical from the schema's ACL, and the second is the one a
    hurried fix produces.
    """
    async with admin_engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    """
                    SELECT c.relname, p.priv
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace,
                    LATERAL (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'))
                        AS p(priv)
                    WHERE n.nspname = 'identity'
                      AND c.relkind = 'r'
                      AND has_table_privilege('omniai_app', c.oid, p.priv)
                    """
                )
            )
        ).all()
    assert rows == [], f"omniai_app holds privileges it should not: {rows}"


async def test_identity_schema_grants_nothing_to_public(admin_engine: AsyncEngine) -> None:
    """A grant to PUBLIC would hand every current and future role the same access.

    Postgres renders a PUBLIC grantee as an ACL entry with an empty grantee name, i.e. one
    beginning with `=`.
    """
    acl = await _scalar(
        admin_engine,
        "SELECT coalesce(array_to_string(nspacl, ','), '') "
        "FROM pg_namespace WHERE nspname = 'identity'",
    )
    assert isinstance(acl, str)
    public_entries = [entry for entry in acl.split(",") if entry.startswith("=")]
    assert public_entries == [], f"identity is granted to PUBLIC: {public_entries}"


async def test_identity_role_cannot_read_tenant_data(admin_engine: AsyncEngine) -> None:
    """The boundary is symmetric: a stolen identity credential reads no tenant data.

    Worth asserting separately from the app-side check. The two directions are enforced by
    different grants, and protecting only the direction someone happened to think about is
    the usual way half a boundary ships.
    """
    for table in ("workspaces", "members", "api_tokens"):
        granted = await _scalar(
            admin_engine,
            "SELECT has_table_privilege('omniai_identity', :tbl, 'SELECT')",
            tbl=f"public.{table}",
        )
        assert granted is False, f"omniai_identity can read public.{table}"


async def test_identity_role_holds_no_privilege_escalation_attributes(
    admin_engine: AsyncEngine,
) -> None:
    """Neither SUPERUSER nor BYPASSRLS — either would defeat the grants above outright."""
    async with admin_engine.connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'omniai_identity'"
                )
            )
        ).one()
    assert row.rolsuper is False
    assert row.rolbypassrls is False


async def test_no_better_auth_table_exists_outside_identity(
    admin_engine: AsyncEngine,
) -> None:
    """Placement is the decision this module made; this is what makes it stick.

    `public` may not hold tables without `workspace_id` (DATABASE_DESIGN.md §1), and `auth`
    is dropped with CASCADE by migration 0001's downgrade — a path CI runs on every push, so
    a Better Auth table landing there would be destroyed by a routine rollback.
    """
    async with admin_engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT schemaname, tablename FROM pg_tables "
                    "WHERE schemaname IN ('public', 'auth') AND tablename = ANY(:names)"
                ),
                {"names": sorted(BETTER_AUTH_TABLES)},
            )
        ).all()
    assert rows == [], f"Better Auth tables found outside identity: {rows}"


async def test_token_resolution_function_still_lives_in_auth(
    admin_engine: AsyncEngine,
) -> None:
    """`auth` predates this module and must be left exactly as ADR-0008 defined it.

    Choosing a schema name that was already taken is how the first attempt at this module
    would have silently broken machine authentication.
    """
    async with admin_engine.connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT pg_get_userbyid(p.proowner) AS owner, p.prosecdef "
                    "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'auth' AND p.proname = 'resolve_api_token'"
                )
            )
        ).one()
    assert row.owner == "omniai_auth"
    assert row.prosecdef is True


def _executable_strings(source: str) -> list[str]:
    """String literals a migration actually runs, excluding docstrings.

    Every way Alembic can touch a schema routes through a string: `op.execute("...")`,
    `schema="..."`, `sa.text("...")`. Prose does not — so narrowing to non-docstring string
    literals is what separates `DROP SCHEMA identity` from a comment using the English word,
    which is precisely the false positive a bare text search produces on 0002_members.py.
    """
    tree = ast.parse(source)
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    }
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


def test_no_alembic_migration_references_the_identity_schema() -> None:
    """Alembic must never learn the schema's name — that is what keeps rollback safe.

    `alembic downgrade base` runs in CI on every push. The proof that it cannot destroy
    identity data is not that today's migrations happen to leave it alone; it is that no
    migration names it in anything executable. This is a static check on purpose: it fails
    when someone *writes* the dangerous migration, not after they have run it.

    `env.py` sets `include_schemas=False`, so autogenerate cannot produce such a reference
    by accident; this catches the hand-written case.
    """
    versions = Path(__file__).resolve().parents[2] / "alembic" / "versions"
    migrations = sorted(versions.glob("*.py"))
    assert migrations, "no Alembic migrations found — the check would be vacuous"

    offenders = {
        path.name: [
            literal
            for literal in _executable_strings(path.read_text())
            if re.search(r"\bidentity\b", literal, re.IGNORECASE)
        ]
        for path in migrations
    }
    offenders = {name: hits for name, hits in offenders.items() if hits}
    assert offenders == {}, (
        f"migrations reference the identity schema: {offenders}. Better Auth owns its own "
        "migrations; Alembic must not touch that schema."
    )


async def test_members_user_id_round_trips_a_better_auth_user_id(
    admin_engine: AsyncEngine,
) -> None:
    """`members.user_id` is the join between the two planes, and it must not truncate.

    Better Auth generates a 32-character identifier and puts it in the JWT `sub` claim.
    M1.3-B will look a Member up by that value, so a silent truncation here would produce
    the worst possible failure: a lookup that matches the wrong human. Asserted by
    round-trip rather than by reading the column width, because equality is the property
    that actually matters.
    """
    # Generated rather than pasted from a real sign-up. Better Auth ids are 32 characters
    # and `uuid4().hex` is exactly 32, so the length under test is identical — but a
    # high-entropy 32-character literal in the source is indistinguishable from a leaked
    # credential to a secret scanner, and gitleaks flagged the pasted one.
    better_auth_user_id = uuid.uuid4().hex
    assert len(better_auth_user_id) == 32

    workspace_id = uuid.uuid4()
    async with admin_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO workspaces (id, name, slug) VALUES (:id, 'identity boundary', :slug)"
            ),
            {"id": workspace_id, "slug": f"identity-boundary-{workspace_id.hex[:12]}"},
        )
        await conn.execute(
            text(
                "INSERT INTO members (id, workspace_id, user_id, role) "
                "VALUES (:id, :ws, :uid, 'owner')"
            ),
            {"id": uuid.uuid4(), "ws": workspace_id, "uid": better_auth_user_id},
        )
        stored = (
            await conn.execute(
                text("SELECT user_id FROM members WHERE workspace_id = :ws"),
                {"ws": workspace_id},
            )
        ).scalar_one()

        await conn.execute(text("DELETE FROM workspaces WHERE id = :ws"), {"ws": workspace_id})

    assert stored == better_auth_user_id
