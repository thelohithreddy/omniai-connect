"""M1.2 as one system: membership, RBAC and the token lifecycle acting on each other.

Each module suite proved its own module, and M1.2-J proved the token lifecycle end to end.
What no suite owns is the seam between the *membership* half of M1.2 (A–E) and the *token*
half (F–H): a role stored by one module decides what the other module permits, and a
foreign key defined by a third decides what survives when a person leaves.

The properties here fail only when modules disagree:

- A role change written through the member service must change what the token endpoints
  permit, on the next request, with no cache and no restart.
- Removing a Member must clear the provenance on the tokens they issued **without**
  revoking them — the composite FK's `ON DELETE SET NULL` and the credential's continued
  ability to authenticate are two different modules' guarantees meeting.
- The RBAC matrix must hold identically across every token endpoint, not endpoint by
  endpoint.
- Infrastructure probes must not disturb, or be disturbed by, tenant traffic.

The same seam M1.2-J documented applies: management requires a human Member, and production
authentication issues machine identity only (ADR-0002), so management runs against an app
with `get_workspace_context` overridden while authentication runs against the real app.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from app.core.db import UnitOfWork
from app.core.ids import new_id
from app.domains.workspaces.repository import MemberRepository
from app.domains.workspaces.service import MemberService
from tests.conftest import SeededWorkspace
from tests.integration.test_api_token_creation import (
    api_token_context,
    build_token_app,
    member_context,
)
from tests.integration.test_members_tenancy import seed_member

pytestmark = pytest.mark.asyncio

#: SECURITY.md §4.1, transcribed once here and applied to every token endpoint below. The
#: point is not to re-test the policy — M1.2-D does that — but to prove every endpoint is
#: wired to the *same* policy rather than to its own copy.
TOKEN_ENDPOINT_MATRIX = {"owner": True, "admin": True, "member": False, "viewer": False}


def manager(app_engine: AsyncEngine, workspace_id: uuid.UUID, member_id: uuid.UUID) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(
            app=build_token_app(app_engine, lambda: member_context(workspace_id, member_id))
        ),
        base_url="http://t",
    )


async def mint(client: AsyncClient, name: str = "integration") -> tuple[uuid.UUID, str]:
    response = await client.post("/v1/api-tokens", json={"name": name})
    assert response.status_code == 201, response.text
    return uuid.UUID(response.json()["id"]), response.json()["token"]


# =======================================================================================
# Seam 1 — membership decides token authority, and changes take effect immediately
# =======================================================================================


async def test_a_role_change_immediately_changes_what_the_token_endpoints_permit(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Demote an admin through the member service; token management must stop working.

    This is the seam between M1.2-C (role writes), M1.2-D/E (policy and enforcement) and
    M1.2-F/G/H (the endpoints). Each module is correct alone and they could still disagree:
    if authorization cached a role, or read it from the request context captured at login,
    a demoted admin would keep minting credentials until something restarted. The role is
    read from the persisted row on every request, so the change binds the very next call.

    Asserted in both directions — promotion must also take effect — so a test cannot pass
    by authorization simply always denying.
    """
    person = await seed_member(admin_engine, workspace_a.id, user_id="mover", role="admin")

    async with manager(app_engine, workspace_a.id, person) as client:
        assert (await client.post("/v1/api-tokens", json={"name": "as-admin"})).status_code == 201

    factory = async_sessionmaker(app_engine, expire_on_commit=False)
    async with factory() as session, session.begin():
        await UnitOfWork(session=session).bind_workspace(workspace_a.id)
        service = MemberService(MemberRepository(session, api_token_context(workspace_a.id)))
        await service.change_member_role(person, "member")

    async with manager(app_engine, workspace_a.id, person) as client:
        demoted = await client.post("/v1/api-tokens", json={"name": "as-member"})
        assert demoted.status_code == 403, "a demoted admin still minted a credential"
        assert (await client.get("/v1/api-tokens")).status_code == 403

    async with factory() as session, session.begin():
        await UnitOfWork(session=session).bind_workspace(workspace_a.id)
        service = MemberService(MemberRepository(session, api_token_context(workspace_a.id)))
        await service.change_member_role(person, "owner")

    async with manager(app_engine, workspace_a.id, person) as client:
        assert (await client.post("/v1/api-tokens", json={"name": "as-owner"})).status_code == 201


async def test_removing_a_member_clears_provenance_without_revoking_their_tokens(
    client: AsyncClient,
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """Offboarding a person must not silently break production.

    Three modules meet here. M1.2-A's composite FK carries
    `ON DELETE SET NULL (created_by_member_id)`; M1.2-F records the creator; M1.1's resolver
    decides whether the credential still authenticates. If the FK had been written as a
    plain `ON DELETE CASCADE` — the obvious choice — removing an employee would delete the
    tokens they issued, and every deploy pipeline they had ever set up would fail at the
    moment HR processed their departure.

    Asserted through the real authentication path, not by reading a column: the credential
    must still work, and only its attribution must be gone.
    """
    leaver = await seed_member(admin_engine, workspace_a.id, user_id="leaver", role="owner")
    async with manager(app_engine, workspace_a.id, leaver) as admin:
        token_id, plaintext = await mint(admin, name="their-ci-token")

    headers = {"Authorization": f"Bearer {plaintext}"}
    assert (await client.get("/v1/workspaces/me", headers=headers)).status_code == 200

    factory = async_sessionmaker(app_engine, expire_on_commit=False)
    async with factory() as session, session.begin():
        await UnitOfWork(session=session).bind_workspace(workspace_a.id)
        service = MemberService(MemberRepository(session, api_token_context(workspace_a.id)))
        await service.remove_member(leaver)

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

    assert row["created_by_member_id"] is None, "provenance survived the member's removal"
    assert row["revoked_at"] is None, "offboarding a member revoked their tokens"
    assert (await client.get("/v1/workspaces/me", headers=headers)).status_code == 200, (
        "offboarding a member broke a live credential"
    )


# =======================================================================================
# Seam 2 — one RBAC policy, applied identically by every endpoint
# =======================================================================================


@pytest.mark.parametrize("role", ["owner", "admin", "member", "viewer"])
async def test_every_token_endpoint_agrees_with_the_same_role_matrix(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, role: str
) -> None:
    """The full matrix swept across all three token endpoints at once.

    Testing endpoints one at a time cannot catch divergence: each module's suite would pass
    while one endpoint quietly required a different capability. Sweeping the same role
    across create, list and revoke in a single test makes disagreement the failure.
    """
    person = await seed_member(admin_engine, workspace_a.id, user_id=f"m-{role}", role=role)
    seeded, _ = await _seed_token(admin_engine, workspace_a.id)
    allowed = TOKEN_ENDPOINT_MATRIX[role]

    async with manager(app_engine, workspace_a.id, person) as client:
        outcomes = {
            "create": (await client.post("/v1/api-tokens", json={"name": "x"})).status_code,
            "list": (await client.get("/v1/api-tokens")).status_code,
            "revoke": (await client.delete(f"/v1/api-tokens/{seeded}")).status_code,
        }

    if allowed:
        assert outcomes == {"create": 201, "list": 200, "revoke": 204}, outcomes
    else:
        assert set(outcomes.values()) == {403}, f"{role} was not denied uniformly: {outcomes}"


async def test_no_role_or_permission_can_be_supplied_by_the_caller(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """A denied member cannot talk their way in through any request surface.

    Every escalation vector at once: query parameters, body fields, and headers, against
    each endpoint. Authority is read from the persisted membership row; nothing a client
    sends participates in the decision.
    """
    person = await seed_member(admin_engine, workspace_a.id, user_id="plain", role="member")
    seeded, _ = await _seed_token(admin_engine, workspace_a.id)
    escalations: list[dict[str, Any]] = [
        {"params": {"role": "owner"}},
        {"params": {"permission": "api_tokens:manage"}},
        {"params": {"workspace_id": str(uuid.uuid4())}},
        {"headers": {"X-Role": "owner", "X-Permission": "api_tokens:manage"}},
        {"headers": {"X-Workspace-Id": str(uuid.uuid4())}},
    ]

    async with manager(app_engine, workspace_a.id, person) as client:
        for attempt in escalations:
            assert (await client.get("/v1/api-tokens", **attempt)).status_code == 403
            assert (await client.delete(f"/v1/api-tokens/{seeded}", **attempt)).status_code == 403
        for body in ({"name": "x", "role": "owner"}, {"name": "x", "scopes": ["*"]}):
            created = await client.post("/v1/api-tokens", json=body, params={"role": "owner"})
            assert created.status_code in (400, 403), created.text

    async with admin_engine.begin() as conn:
        revoked = await conn.scalar(
            text("SELECT revoked_at FROM api_tokens WHERE id = :i"), {"i": seeded}
        )
    assert revoked is None, "an escalation attempt still mutated state"


# =======================================================================================
# Seam 3 — two tenants, members and tokens, every operation
# =======================================================================================


async def test_two_workspaces_remain_isolated_across_members_and_tokens(
    client: AsyncClient,
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """A full cross-tenant sweep with real members and real credentials on both sides.

    Both tenants are populated identically so that a leak in either direction fails, and
    every answer is checked to be `not_found` rather than `forbidden` — SECURITY.md §3
    requires cross-tenant access to be indistinguishable from absence, or the API becomes
    an oracle for which ids exist elsewhere.
    """
    a_owner = await seed_member(admin_engine, workspace_a.id, user_id="a-own", role="owner")
    b_owner = await seed_member(admin_engine, workspace_b.id, user_id="b-own", role="owner")

    async with manager(app_engine, workspace_a.id, a_owner) as a_client:
        a_token, a_secret = await mint(a_client, name="a-token")
    async with manager(app_engine, workspace_b.id, b_owner) as b_client:
        b_token, b_secret = await mint(b_client, name="b-token")

    # Credentials resolve only into their own tenant.
    for secret, expected in ((a_secret, workspace_a.id), (b_secret, workspace_b.id)):
        resolved = await client.get(
            "/v1/workspaces/me", headers={"Authorization": f"Bearer {secret}"}
        )
        assert resolved.json()["id"] == str(expected)

    # Neither side can see, or revoke, the other's token — in both directions.
    for viewer_ws, viewer_member, foreign_token in (
        (workspace_a.id, a_owner, b_token),
        (workspace_b.id, b_owner, a_token),
    ):
        async with manager(app_engine, viewer_ws, viewer_member) as viewer:
            listed = (await viewer.get("/v1/api-tokens", params={"limit": 100})).json()
            assert str(foreign_token) not in {i["id"] for i in listed["data"]}

            attempt = await viewer.delete(f"/v1/api-tokens/{foreign_token}")
            assert attempt.status_code == 404
            assert attempt.json()["error"]["code"] == "not_found"

    # Neither token was touched by the attempts.
    async with admin_engine.begin() as conn:
        for token_id in (a_token, b_token):
            assert (
                await conn.scalar(
                    text("SELECT revoked_at FROM api_tokens WHERE id = :i"), {"i": token_id}
                )
                is None
            )


async def test_membership_in_one_workspace_grants_nothing_in_another(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """The same human, owner in B, holds nothing in A.

    Roles are per-workspace by construction: the membership row is unreachable from the
    other tenant's context, so no comparison in the authorization code is doing this work —
    which is precisely why it keeps holding as modules change.
    """
    b_owner = await seed_member(admin_engine, workspace_b.id, user_id="shared", role="owner")

    async with manager(app_engine, workspace_a.id, b_owner) as impostor:
        assert (await impostor.get("/v1/api-tokens")).status_code == 403
        assert (await impostor.post("/v1/api-tokens", json={"name": "x"})).status_code == 403


# =======================================================================================
# Seam 4 — machine identity stays machine identity across the whole surface
# =======================================================================================


async def test_a_machine_credential_can_do_exactly_one_thing(
    client: AsyncClient,
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """The complete machine-plane capability surface, enumerated.

    A token authenticates and reads its own Workspace. It cannot mint a successor, cannot
    enumerate the workspace's credentials, and cannot revoke anything — including itself.
    Together those prevent a stolen credential from surviving revocation of the original,
    performing reconnaissance, or cutting off the operator's own tokens mid-incident.
    """
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    async with manager(app_engine, workspace_a.id, owner) as admin:
        token_id, plaintext = await mint(admin)

    headers = {"Authorization": f"Bearer {plaintext}"}
    assert (await client.get("/v1/workspaces/me", headers=headers)).status_code == 200

    denied = {
        "list": (await client.get("/v1/api-tokens", headers=headers)).status_code,
        "create": (
            await client.post("/v1/api-tokens", json={"name": "successor"}, headers=headers)
        ).status_code,
        "revoke_self": (
            await client.delete(f"/v1/api-tokens/{token_id}", headers=headers)
        ).status_code,
        "revoke_other": (
            await client.delete(f"/v1/api-tokens/{new_id()}", headers=headers)
        ).status_code,
    }
    assert set(denied.values()) == {403}, denied


# =======================================================================================
# Seam 5 — infrastructure probes and tenant traffic coexist
# =======================================================================================


async def test_readiness_probes_do_not_disturb_concurrent_tenant_traffic(
    client: AsyncClient,
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Probes hammer the same pool tenant requests use; neither may affect the other.

    Readiness borrows connections from the application pool. If a probe left a transaction
    open or a tenant bound, the damage would appear here — as a tenant request resolving
    into the wrong workspace, or blocking. Both tenants' traffic is interleaved with probes
    and every answer is checked to be its own workspace's.
    """
    a_owner = await seed_member(admin_engine, workspace_a.id, user_id="a-own", role="owner")
    b_owner = await seed_member(admin_engine, workspace_b.id, user_id="b-own", role="owner")
    async with manager(app_engine, workspace_a.id, a_owner) as a_client:
        _, a_secret = await mint(a_client, name="a")
    async with manager(app_engine, workspace_b.id, b_owner) as b_client:
        _, b_secret = await mint(b_client, name="b")

    async def tenant_call(secret: str, expected: uuid.UUID) -> bool:
        response = await client.get(
            "/v1/workspaces/me", headers={"Authorization": f"Bearer {secret}"}
        )
        return response.status_code == 200 and response.json()["id"] == str(expected)

    async def probe() -> int:
        return (await client.get("/health/ready")).status_code

    results = await asyncio.gather(
        *(tenant_call(a_secret, workspace_a.id) for _ in range(5)),
        *(tenant_call(b_secret, workspace_b.id) for _ in range(5)),
        *(probe() for _ in range(10)),
    )

    tenant_results, probe_results = results[:10], results[10:]
    assert all(tenant_results), "a tenant request resolved into the wrong workspace under load"
    assert set(probe_results) == {200}

    factory = async_sessionmaker(app_engine, expire_on_commit=False)
    async with factory() as session, session.begin():
        inherited = await session.scalar(text("SELECT current_setting('app.workspace_id', true)"))
    assert not inherited, f"a tenant binding survived on a pooled connection: {inherited!r}"


async def test_liveness_and_readiness_require_no_credential_while_the_api_does(
    client: AsyncClient, workspace_a: SeededWorkspace
) -> None:
    """The operational surface and the tenant surface have opposite authentication rules."""
    assert (await client.get("/health")).status_code == 200
    assert (await client.get("/health/ready")).status_code == 200
    assert (await client.get("/v1/workspaces/me")).status_code == 401
    assert (await client.get("/v1/api-tokens")).status_code == 401


async def _seed_token(engine: AsyncEngine, workspace_id: uuid.UUID) -> tuple[uuid.UUID, str]:
    """A token inserted out-of-band, for cases that need one to exist without minting it."""
    from app.core.security import generate_token

    token_id = new_id()
    generated = generate_token()
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO api_tokens (id, workspace_id, name, token_hash, token_prefix, scopes)"
                " VALUES (:i, :w, 'seeded', :h, :p, '[]'::jsonb)"
            ),
            {
                "i": token_id,
                "w": workspace_id,
                "h": generated.token_hash,
                "p": generated.token_prefix,
            },
        )
    return token_id, generated.plaintext
