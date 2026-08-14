"""HTTP surface for Member management: list, re-role, remove.

M1.2-C built `MemberService` and deliberately shipped no router. This file tests the
adapter that closes that gap, so almost everything here is about the *boundary* rather
than the business logic the service already owns and tests:

- authority comes from the persisted membership, never from the request;
- the Workspace comes from the authenticated context and appears in no parameter;
- another tenant's Member is indistinguishable from one that never existed;
- a role change binds on the target's very next request, with nothing to invalidate.

The same seam as every other M1.2/M1.3 suite applies: `members:manage` is a human-plane
capability and production authentication issues machine identity only (ADR-0002), so
management runs against an app whose `get_workspace_context` is overridden to yield a human
context — the M1.2-E technique, where the permission dependency, membership lookup, policy,
service and repository are all untouched production code.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Annotated, Any

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from app.core.db import UnitOfWork, get_uow
from app.core.ids import new_id
from app.core.middleware import RequestContextMiddleware
from app.core.security import WorkspaceContext, get_workspace_context
from app.domains.workspaces.repository import MemberRepository
from app.domains.workspaces.router import members_router
from app.main import app as real_app
from tests.conftest import SeededWorkspace
from tests.integration.test_api_token_creation import api_token_context, member_context
from tests.integration.test_members_tenancy import seed_member

pytestmark = pytest.mark.asyncio

#: SECURITY.md §4.1, "Manage Members and roles" → `members:manage`.
MEMBERS_MANAGE_MATRIX = {"owner": True, "admin": True, "member": False, "viewer": False}


def build_members_app(app_engine: AsyncEngine, context_factory: Any) -> FastAPI:
    """The real members router, with only authentication replaced by a chosen identity.

    Everything below the override is untouched production code: the permission dependency,
    the membership lookup, the policy, the service and the repository.

    `Annotated`, `Depends` and `UnitOfWork` must be importable at **module** level, not
    inside this function. `from __future__ import annotations` makes every annotation a
    string, and FastAPI resolves them against the function's module globals — a local import
    leaves `uow` unresolvable, and FastAPI then silently treats it as a query parameter.
    """
    factory = async_sessionmaker(app_engine, expire_on_commit=False, autoflush=False)
    test_app = FastAPI()
    for exc, handler in real_app.exception_handlers.items():
        test_app.add_exception_handler(exc, handler)  # type: ignore[arg-type]
    test_app.add_middleware(RequestContextMiddleware)
    test_app.include_router(members_router)

    async def override_uow() -> AsyncIterator[UnitOfWork]:
        async with factory() as session, session.begin():
            yield UnitOfWork(session=session)

    async def override_context(
        uow: Annotated[UnitOfWork, Depends(get_uow)],
    ) -> WorkspaceContext:
        ctx: WorkspaceContext = context_factory()
        await uow.bind_workspace(ctx.workspace_id)
        return ctx

    test_app.dependency_overrides[get_uow] = override_uow
    test_app.dependency_overrides[get_workspace_context] = override_context
    return test_app


def admin_client(
    app_engine: AsyncEngine, workspace_id: uuid.UUID, member_id: uuid.UUID
) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(
            app=build_members_app(app_engine, lambda: member_context(workspace_id, member_id))
        ),
        base_url="http://t",
    )


async def role_of(engine: AsyncEngine, member_id: uuid.UUID) -> Any:
    async with engine.begin() as conn:
        return await conn.scalar(text("SELECT role FROM members WHERE id = :i"), {"i": member_id})


async def member_exists(engine: AsyncEngine, member_id: uuid.UUID) -> bool:
    async with engine.begin() as conn:
        return bool(
            await conn.scalar(text("SELECT count(*) FROM members WHERE id = :i"), {"i": member_id})
        )


# =======================================================================================
# Listing
# =======================================================================================


async def test_listing_returns_the_workspaces_members_newest_first(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    await seed_member(admin_engine, workspace_a.id, user_id="second", role="member")
    await seed_member(admin_engine, workspace_a.id, user_id="third", role="viewer")

    async with admin_client(app_engine, workspace_a.id, owner) as client:
        response = await client.get("/v1/members")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["has_more"] is False and body["next_cursor"] is None
    assert {i["user_id"] for i in body["data"]} == {"owner", "second", "third"}
    assert [i["user_id"] for i in body["data"]][0] == "third", "not newest-first"


async def test_listing_exposes_only_the_permitted_fields(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Checked against the raw bytes as well as the key set.

    `invited_by` is deliberately absent — exposing provenance is a disclosure decision no
    canonical document has made, exactly as `created_by_member_id` is absent from
    `ApiTokenRead`. `workspace_id` must never appear: it would echo tenant identity back to
    a caller who already implicitly knows it, and would invite clients to start sending it.
    """
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    invited = await seed_member(
        admin_engine, workspace_a.id, user_id="invited", role="member", invited_by=owner
    )

    async with admin_client(app_engine, workspace_a.id, owner) as client:
        response = await client.get("/v1/members")

    for item in response.json()["data"]:
        assert set(item) == {"id", "user_id", "role", "created_at"}
    raw = response.text
    assert str(workspace_a.id) not in raw, "the response echoed the workspace id"
    assert "invited_by" not in raw
    assert str(invited) in raw  # the member itself is listed; only its provenance is hidden


async def test_listing_pages_through_every_member_exactly_once(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Cursor pagination per §3, asserted for completeness and non-duplication."""
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    for index in range(6):
        await seed_member(admin_engine, workspace_a.id, user_id=f"u{index}", role="member")

    seen: list[str] = []
    cursor: str | None = None
    async with admin_client(app_engine, workspace_a.id, owner) as client:
        for _ in range(20):
            params: dict[str, Any] = {"limit": 2} | ({"cursor": cursor} if cursor else {})
            page = (await client.get("/v1/members", params=params)).json()
            seen.extend(i["id"] for i in page["data"])
            cursor = page["next_cursor"]
            if not page["has_more"]:
                break

    assert cursor is None, "pagination did not terminate"
    assert len(seen) == 7, seen
    assert len(set(seen)) == len(seen), "a member was served on more than one page"


@pytest.mark.parametrize("limit", [0, -1, 101, 1000])
async def test_listing_rejects_an_out_of_range_limit(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, limit: int
) -> None:
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    async with admin_client(app_engine, workspace_a.id, owner) as client:
        assert (await client.get("/v1/members", params={"limit": limit})).status_code == 400


@pytest.mark.parametrize("cursor", ["not-base64", "!!!", ""])
async def test_listing_rejects_an_unusable_cursor(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, cursor: str
) -> None:
    """§3: an expired or malformed cursor is a `validation_error`, never a silent page one."""
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    async with admin_client(app_engine, workspace_a.id, owner) as client:
        response = await client.get("/v1/members", params={"cursor": cursor})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "validation_error"


async def test_an_empty_workspace_lists_nothing_rather_than_erroring(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """The caller is themself a member, so "empty" means exactly one row — their own."""
    owner = await seed_member(admin_engine, workspace_a.id, user_id="only", role="owner")
    async with admin_client(app_engine, workspace_a.id, owner) as client:
        body = (await client.get("/v1/members")).json()
    assert [i["user_id"] for i in body["data"]] == ["only"]
    assert body == {"data": body["data"], "next_cursor": None, "has_more": False}


# =======================================================================================
# Role change
# =======================================================================================


async def test_a_role_change_persists_and_binds_on_the_targets_next_request(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """The property that makes this endpoint worth having, asserted behaviourally.

    Promoting a plain member must let them manage members on their *next* call, and
    demoting them must stop it — with no restart, cache flush, or re-login. That holds
    because M1.2-E reads the role from the persisted row on every request.
    """
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    target = await seed_member(admin_engine, workspace_a.id, user_id="target", role="member")

    async with admin_client(app_engine, workspace_a.id, target) as target_client:
        assert (await target_client.get("/v1/members")).status_code == 403

    async with admin_client(app_engine, workspace_a.id, owner) as owner_client:
        promoted = await owner_client.patch(f"/v1/members/{target}", json={"role": "admin"})
    assert promoted.status_code == 200, promoted.text
    assert promoted.json()["role"] == "admin"
    assert await role_of(admin_engine, target) == "admin"

    async with admin_client(app_engine, workspace_a.id, target) as target_client:
        assert (await target_client.get("/v1/members")).status_code == 200

    async with admin_client(app_engine, workspace_a.id, owner) as owner_client:
        await owner_client.patch(f"/v1/members/{target}", json={"role": "viewer"})
    async with admin_client(app_engine, workspace_a.id, target) as target_client:
        assert (await target_client.get("/v1/members")).status_code == 403


@pytest.mark.parametrize("role", ["owner", "admin", "member", "viewer"])
async def test_every_canonical_role_is_assignable(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, role: str
) -> None:
    """All four values in the CHECK domain are assignable — no invented transition rules."""
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    target = await seed_member(admin_engine, workspace_a.id, user_id="target", role="member")

    async with admin_client(app_engine, workspace_a.id, owner) as client:
        response = await client.patch(f"/v1/members/{target}", json={"role": role})

    assert response.status_code == 200, response.text
    assert await role_of(admin_engine, target) == role


@pytest.mark.parametrize("body", [{"role": "superuser"}, {"role": ""}, {"role": "OWNER"}])
async def test_a_role_outside_the_domain_is_rejected(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    body: dict[str, str],
) -> None:
    """Rejected by the service's canonical check, not by a duplicated list in the schema.

    `"OWNER"` matters: role matching is case-sensitive because the CHECK constraint is, and
    a case-insensitive door would let a value through that the database then refuses.
    """
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    target = await seed_member(admin_engine, workspace_a.id, user_id="target", role="member")

    async with admin_client(app_engine, workspace_a.id, owner) as client:
        response = await client.patch(f"/v1/members/{target}", json=body)

    assert response.status_code == 400, response.text
    assert response.json()["error"]["code"] == "validation_error"
    assert await role_of(admin_engine, target) == "member", "a rejected change still applied"


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"role": "admin", "user_id": "someone-else"},
        {"role": "admin", "workspace_id": "11111111-1111-1111-1111-111111111111"},
        {"role": "admin", "invited_by": "11111111-1111-1111-1111-111111111111"},
        {"user_id": "someone-else"},
    ],
)
async def test_only_role_is_mutable(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    body: dict[str, Any],
) -> None:
    """Server-owned fields are refused, not ignored.

    Pydantic's default is to drop unknown keys, which would return 200 and leave the caller
    believing their `user_id` or `workspace_id` change was applied.
    """
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    target = await seed_member(admin_engine, workspace_a.id, user_id="target", role="member")

    async with admin_client(app_engine, workspace_a.id, owner) as client:
        response = await client.patch(f"/v1/members/{target}", json=body)

    assert response.status_code == 400, response.text
    async with admin_engine.begin() as conn:
        row = (
            (
                await conn.execute(
                    text("SELECT user_id, role FROM members WHERE id = :i"), {"i": target}
                )
            )
            .mappings()
            .one()
        )
    assert row["user_id"] == "target" and row["role"] == "member"


# =======================================================================================
# Removal
# =======================================================================================


async def test_removing_a_member_ends_their_membership_and_their_authority(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    target = await seed_member(admin_engine, workspace_a.id, user_id="target", role="admin")

    async with admin_client(app_engine, workspace_a.id, target) as target_client:
        assert (await target_client.get("/v1/members")).status_code == 200

    async with admin_client(app_engine, workspace_a.id, owner) as client:
        removed = await client.delete(f"/v1/members/{target}")

    assert removed.status_code == 204
    assert removed.content == b""
    assert not await member_exists(admin_engine, target)

    async with admin_client(app_engine, workspace_a.id, target) as target_client:
        assert (await target_client.get("/v1/members")).status_code == 403, (
            "a removed member kept their authority"
        )


async def test_repeating_a_removal_answers_not_found(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """The documented interpretation, asserted so it cannot drift silently.

    API_GUIDELINES.md §2 says both "deleting a deleted resource is 204" *and* "cross-tenant
    access attempts always return 404". For a hard-deleted row those cannot both hold — a
    repeat delete is indistinguishable from absent, which is indistinguishable from foreign.
    Answering 204 for absence would mean answering 204 for another tenant's id too, or
    distinguishing them and becoming the oracle SECURITY.md §3 forbids. Security wins, and
    it matches ADR-0012 for the analogous token endpoint.
    """
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    target = await seed_member(admin_engine, workspace_a.id, user_id="target", role="member")

    async with admin_client(app_engine, workspace_a.id, owner) as client:
        first = await client.delete(f"/v1/members/{target}")
        second = await client.delete(f"/v1/members/{target}")
        third = await client.delete(f"/v1/members/{new_id()}")

    assert first.status_code == 204
    assert second.status_code == third.status_code == 404
    assert second.json()["error"] == third.json()["error"] | {
        "request_id": second.json()["error"]["request_id"]
    }


async def test_removing_a_member_does_not_revoke_the_tokens_they_created(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Offboarding a person must not break production.

    The composite FK carries `ON DELETE SET NULL (created_by_member_id)` (M1.2-A), so
    provenance is cleared and the credential survives. A `CASCADE` — the obvious choice —
    would delete every token the departing member had ever issued.
    """
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    leaver = await seed_member(admin_engine, workspace_a.id, user_id="leaver", role="admin")
    token_id = new_id()
    from app.core.security import generate_token

    generated = generate_token()
    async with admin_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO api_tokens (id, workspace_id, name, token_hash, token_prefix,"
                " scopes, created_by_member_id) VALUES (:i,:w,'theirs',:h,:p,'[]'::jsonb,:m)"
            ),
            {
                "i": token_id,
                "w": workspace_a.id,
                "h": generated.token_hash,
                "p": generated.token_prefix,
                "m": leaver,
            },
        )

    async with admin_client(app_engine, workspace_a.id, owner) as client:
        assert (await client.delete(f"/v1/members/{leaver}")).status_code == 204

    async with admin_engine.begin() as conn:
        row = (
            (
                await conn.execute(
                    text("SELECT created_by_member_id, revoked_at FROM api_tokens WHERE id = :i"),
                    {"i": token_id},
                )
            )
            .mappings()
            .one()
        )
    assert row["created_by_member_id"] is None
    assert row["revoked_at"] is None, "offboarding revoked a live credential"


# =======================================================================================
# Authorization
# =======================================================================================


@pytest.mark.parametrize("role", ["owner", "admin", "member", "viewer"])
async def test_every_endpoint_agrees_with_the_members_manage_matrix(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, role: str
) -> None:
    """The matrix swept across all three endpoints at once.

    Testing them separately would let one endpoint quietly require a different capability
    while each module's own test still passed.
    """
    actor = await seed_member(admin_engine, workspace_a.id, user_id=f"a-{role}", role=role)
    target = await seed_member(admin_engine, workspace_a.id, user_id="target", role="member")
    allowed = MEMBERS_MANAGE_MATRIX[role]

    async with admin_client(app_engine, workspace_a.id, actor) as client:
        outcomes = {
            "list": (await client.get("/v1/members")).status_code,
            "patch": (
                await client.patch(f"/v1/members/{target}", json={"role": "admin"})
            ).status_code,
            "delete": (await client.delete(f"/v1/members/{target}")).status_code,
        }

    if allowed:
        assert outcomes == {"list": 200, "patch": 200, "delete": 204}, outcomes
    else:
        assert set(outcomes.values()) == {403}, outcomes
        assert await role_of(admin_engine, target) == "member", "a denied call still mutated"


async def test_a_machine_token_cannot_manage_members(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """A leaked credential must not be able to enumerate staff or seize the workspace.

    Listing members is reconnaissance; re-roling one is escalation; removing them is denial
    of service. Machine identity resolves to no membership (ADR-0002), so all three deny.
    """
    target = await seed_member(admin_engine, workspace_a.id, user_id="target", role="member")

    async with AsyncClient(
        transport=ASGITransport(
            app=build_members_app(app_engine, lambda: api_token_context(workspace_a.id))
        ),
        base_url="http://t",
    ) as client:
        assert (await client.get("/v1/members")).status_code == 403
        assert (
            await client.patch(f"/v1/members/{target}", json={"role": "owner"})
        ).status_code == 403
        assert (await client.delete(f"/v1/members/{target}")).status_code == 403

    assert await role_of(admin_engine, target) == "member"


async def test_a_confused_deputy_token_naming_a_real_owner_is_denied(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    from app.core.security import CallerIdentity

    owner = await seed_member(admin_engine, workspace_a.id, user_id="real-owner", role="owner")
    target = await seed_member(admin_engine, workspace_a.id, user_id="target", role="member")
    deputy = WorkspaceContext(
        workspace_id=workspace_a.id,
        caller=CallerIdentity(kind="api_token", api_token_id=uuid.uuid4(), member_id=owner),
        request_id="req_test",
    )

    async with AsyncClient(
        transport=ASGITransport(app=build_members_app(app_engine, lambda: deputy)),
        base_url="http://t",
    ) as client:
        assert (await client.get("/v1/members")).status_code == 403
        assert (await client.delete(f"/v1/members/{target}")).status_code == 403


async def test_all_three_endpoints_require_authentication(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Through the *real* app, with no override at all."""
    target = await seed_member(admin_engine, workspace_a.id, user_id="target", role="member")

    assert (await client.get("/v1/members")).status_code == 401
    assert (await client.patch(f"/v1/members/{target}", json={"role": "admin"})).status_code == 401
    assert (await client.delete(f"/v1/members/{target}")).status_code == 401


# =======================================================================================
# Tenant isolation and information disclosure
# =======================================================================================


async def test_another_workspaces_members_are_invisible_and_untouchable(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    a_owner = await seed_member(admin_engine, workspace_a.id, user_id="a-own", role="owner")
    b_member = await seed_member(admin_engine, workspace_b.id, user_id="b-mem", role="admin")

    async with admin_client(app_engine, workspace_a.id, a_owner) as client:
        listed = (await client.get("/v1/members", params={"limit": 100})).json()
        assert str(b_member) not in {i["id"] for i in listed["data"]}

        patched = await client.patch(f"/v1/members/{b_member}", json={"role": "viewer"})
        deleted = await client.delete(f"/v1/members/{b_member}")

    assert patched.status_code == deleted.status_code == 404
    assert patched.json()["error"]["code"] == "not_found"
    assert await role_of(admin_engine, b_member) == "admin", "cross-tenant re-role succeeded"
    assert await member_exists(admin_engine, b_member), "cross-tenant removal succeeded"


async def test_a_foreign_member_is_byte_identical_to_a_nonexistent_one(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """No existence oracle: the two 404s must differ only in `request_id`."""
    a_owner = await seed_member(admin_engine, workspace_a.id, user_id="a-own", role="owner")
    b_member = await seed_member(admin_engine, workspace_b.id, user_id="b-mem", role="member")
    absent = new_id()

    async with admin_client(app_engine, workspace_a.id, a_owner) as client:
        foreign = (await client.delete(f"/v1/members/{b_member}")).json()["error"]
        missing = (await client.delete(f"/v1/members/{absent}")).json()["error"]

    assert foreign["code"] == missing["code"]
    assert foreign["message"] == missing["message"]
    assert foreign.get("details") == missing.get("details")


async def test_the_same_human_in_two_workspaces_manages_only_the_authenticated_one(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Owner of B, nothing in A. Roles are per-workspace by construction."""
    b_owner = await seed_member(admin_engine, workspace_b.id, user_id="dual", role="owner")

    async with admin_client(app_engine, workspace_a.id, b_owner) as client:
        assert (await client.get("/v1/members")).status_code == 403


@pytest.mark.parametrize(
    "attempt",
    [
        {"params": {"workspace_id": "11111111-1111-1111-1111-111111111111"}},
        {"params": {"role": "owner"}},
        {"params": {"permission": "members:manage"}},
        {"params": {"member_id": "11111111-1111-1111-1111-111111111111"}},
        {"headers": {"X-Workspace-Id": "11111111-1111-1111-1111-111111111111"}},
        {"headers": {"X-Role": "owner", "X-Permission": "members:manage"}},
    ],
)
async def test_no_request_field_can_supply_workspace_role_or_permission(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    attempt: dict[str, Any],
) -> None:
    """Every escalation surface at once, from a member who holds nothing.

    Query parameters are rejected outright on the list endpoint (§4) and are simply not read
    anywhere; headers are not read at all. Either way authority comes from the persisted
    membership and the answer stays 403 — and B's member is untouched.
    """
    actor = await seed_member(admin_engine, workspace_a.id, user_id="plain", role="member")
    b_member = await seed_member(admin_engine, workspace_b.id, user_id="b-mem", role="member")

    async with admin_client(app_engine, workspace_a.id, actor) as client:
        assert (await client.get("/v1/members", **attempt)).status_code in (400, 403)
        assert (await client.delete(f"/v1/members/{b_member}", **attempt)).status_code == 403

    assert await member_exists(admin_engine, b_member)


async def test_unknown_query_parameters_are_refused_not_ignored(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """§4: a misspelled or unsupported filter must not yield a cheerful unfiltered 200."""
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    async with admin_client(app_engine, workspace_a.id, owner) as client:
        for params in ({"role": "admin"}, {"sort": "-created_at"}, {"limlt": "5"}):
            response = await client.get("/v1/members", params=params)
            assert response.status_code == 400, params
            assert response.json()["error"]["code"] == "validation_error"


async def test_application_scoping_holds_with_rls_bypassed(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    """Layer 1 alone, with Postgres's net removed.

    Every HTTP test above runs with RLS armed, so none of them can tell whether isolation
    came from the repository predicate or the policy. Driving the repository on a superuser
    session — where RLS does not apply — leaves the application predicate as the only
    control standing.
    """
    a_member = await seed_member(admin_engine, workspace_a.id, user_id="a", role="owner")
    b_member = await seed_member(admin_engine, workspace_b.id, user_id="b", role="owner")

    factory = async_sessionmaker(admin_engine, expire_on_commit=False)
    async with factory() as session, session.begin():
        assert await session.scalar(
            text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
        ), "this test proves nothing unless RLS is genuinely bypassed"

        repository = MemberRepository(session, api_token_context(workspace_a.id))
        listed = {m.id for m in await repository.list_page(limit=100)}
        foreign = await repository.get(b_member)
        # Every mutating path, not just the reads. Omitting `update_role` here let a
        # mutation that dropped its tenant predicate survive the whole suite — RLS was
        # silently doing the work, which is exactly what this test exists to rule out.
        rerole = await repository.update_role(b_member, "viewer")
        removed = await repository.delete(b_member)

    assert a_member in listed
    assert b_member not in listed, "another tenant's member was listed with RLS bypassed"
    assert foreign is None
    assert rerole is None, "another tenant's member was re-rolled with RLS bypassed"
    assert removed is False, "another tenant's member was deletable with RLS bypassed"
    assert await member_exists(admin_engine, b_member)
    assert await role_of(admin_engine, b_member) == "owner", "cross-tenant role change applied"


# =======================================================================================
# Contract, transactions, and layering
# =======================================================================================


async def test_errors_use_the_canonical_envelope_with_a_matching_request_id(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    async with admin_client(app_engine, workspace_a.id, owner) as client:
        response = await client.delete(f"/v1/members/{new_id()}")

    error = response.json()["error"]
    assert set(error) >= {"code", "message", "request_id"}
    assert error["code"] == "not_found"
    assert error["request_id"] == response.headers["X-Request-Id"]


@pytest.mark.parametrize("bad_id", ["not-a-uuid", "123", "' OR 1=1 --"])
async def test_a_malformed_member_id_is_a_validation_error(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, bad_id: str
) -> None:
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    async with admin_client(app_engine, workspace_a.id, owner) as client:
        assert (await client.delete(f"/v1/members/{bad_id}")).status_code == 400
        assert (
            await client.patch(f"/v1/members/{bad_id}", json={"role": "admin"})
        ).status_code == 400


async def test_listing_writes_nothing(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """A read must stay a read — compared across the whole table, not just one row."""
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    await seed_member(admin_engine, workspace_a.id, user_id="other", role="member")

    async def snapshot() -> list[tuple[Any, ...]]:
        async with admin_engine.begin() as conn:
            rows = await conn.execute(
                text(
                    "SELECT id, user_id, role, invited_by, created_at, updated_at"
                    " FROM members WHERE workspace_id = :w ORDER BY id"
                ),
                {"w": workspace_a.id},
            )
            return [tuple(r) for r in rows]

    before = await snapshot()
    async with admin_client(app_engine, workspace_a.id, owner) as client:
        assert (await client.get("/v1/members", params={"limit": 100})).status_code == 200
    assert await snapshot() == before


async def test_repository_list_page_cannot_be_asked_for_another_tenant() -> None:
    """Structural layer-1 guarantee: no parameter could name a Workspace."""
    params = set(MemberRepository.list_page.__annotations__)
    assert params == {"limit", "after", "return"}
    assert not {"workspace_id", "workspace", "tenant"} & params


async def test_a_role_change_whose_transaction_fails_leaves_the_old_role(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed request must not half-apply a privilege change.

    The dangerous shape is a promotion the operator is told failed but which actually
    committed — the target silently keeps authority nobody believes they have. The service
    performs no commit of its own, so the UnitOfWork's transaction is the only boundary and
    rolling it back must undo the change.

    Found by mutation: a hidden `commit()` inside `change_member_role` survived the entire
    suite, because nothing here exercised a failure *after* the write. `surface_errors`
    makes ASGITransport return the 500 a real client would see rather than re-raising into
    the test, so the assertion after the call actually executes.
    """
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    target = await seed_member(admin_engine, workspace_a.id, user_id="target", role="member")

    import app.domains.workspaces.service as service_module

    real_change = service_module.MemberService.change_member_role

    async def failing_change(self: Any, member_id: uuid.UUID, role: str) -> Any:
        await real_change(self, member_id, role)
        raise RuntimeError("simulated failure after the role was written")

    monkeypatch.setattr(service_module.MemberService, "change_member_role", failing_change)

    async with AsyncClient(
        transport=ASGITransport(
            app=build_members_app(app_engine, lambda: member_context(workspace_a.id, owner)),
            raise_app_exceptions=False,
        ),
        base_url="http://t",
    ) as client:
        response = await client.patch(f"/v1/members/{target}", json={"role": "owner"})

    assert response.status_code == 500, "a failed role change did not surface as an error"
    assert await role_of(admin_engine, target) == "member", (
        "a rolled-back role change was still applied"
    )


async def test_a_removal_whose_transaction_fails_leaves_the_member_in_place(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The mirror hazard: an operator told "failed" whose removal actually committed."""
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    target = await seed_member(admin_engine, workspace_a.id, user_id="target", role="member")

    import app.domains.workspaces.service as service_module

    real_remove = service_module.MemberService.remove_member

    async def failing_remove(self: Any, member_id: uuid.UUID) -> None:
        await real_remove(self, member_id)
        raise RuntimeError("simulated failure after the row was deleted")

    monkeypatch.setattr(service_module.MemberService, "remove_member", failing_remove)

    async with AsyncClient(
        transport=ASGITransport(
            app=build_members_app(app_engine, lambda: member_context(workspace_a.id, owner)),
            raise_app_exceptions=False,
        ),
        base_url="http://t",
    ) as client:
        response = await client.delete(f"/v1/members/{target}")

    assert response.status_code == 500
    assert await member_exists(admin_engine, target), "a rolled-back removal still deleted"
