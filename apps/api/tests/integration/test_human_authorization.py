"""Human authorization across every protected endpoint, through the real chain (M1.3-E).

M1.3-C proved the JWT → X-Workspace-Id → membership → role → RBAC → RLS chain on
`/v1/members`. The api-token endpoints share the same `require_permission` dependency but
were **unreachable** before M1.3-B/C (only machine tokens existed, and machines resolve to
no membership → always denied), so their human authorization path had never executed. The
tests that do exist for them build a *fabricated* `WorkspaceContext` and thereby skip the
very chain that produces it.

This file closes that gap: every protected endpoint is driven with a REAL human JWT and a
REAL `X-Workspace-Id`, over real Postgres with RLS armed and the real centralized RBAC. No
fabricated contexts. The matrix is (endpoint × role) plus machine/human separation,
cross-tenant, request-spoofing, and provenance.

The authorization contract under test (ADR-0009, SECURITY.md §4.1) — `members:manage` and
`api_tokens:manage` are both held by owner and admin only:

    endpoint group     owner  admin  member  viewer  machine
    members:manage      ✓      ✓      ✗       ✗       ✗
    api_tokens:manage   ✓      ✓      ✗       ✗       ✗
    workspaces/me       any authenticated caller (its own workspace)
    GET /v1/workspaces  any human (own memberships); machine → 401
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.human_auth import HUMAN_AUTH_FAILED
from tests.conftest import FakeJWKSEndpoint, SeededWorkspace, SigningAuthority, bearer
from tests.integration.test_human_auth import seed_member
from tests.integration.test_human_auth_e2e import real_human


def hx(token: str, workspace_id: uuid.UUID) -> dict[str, str]:
    return {**bearer(token), "X-Workspace-Id": str(workspace_id)}


@dataclass(frozen=True)
class Endpoint:
    """A protected endpoint and the outcome an *authorized* (owner/admin) caller gets.

    `authorized_status` is what a caller who HOLDS the permission sees. For list/create
    that is a real success; for mutation against a non-existent target it is 404 — which is
    itself the proof that authorization passed (the handler ran and looked the target up),
    cleanly distinct from the 403 an unauthorized caller gets before the handler ever runs.
    """

    label: str
    method: str
    path: str
    body: dict[str, str] | None
    authorized_status: int


# A random-but-valid uuid as the mutation target: owner/admin pass authorization and then
# 404 (no such member/token); member/viewer are refused at the dependency with 403.
_ABSENT = "00000000-0000-0000-0000-0000000000ff"

MANAGE_ENDPOINTS = [
    Endpoint("GET /v1/members", "GET", "/v1/members", None, 200),
    Endpoint("PATCH /v1/members/{id}", "PATCH", f"/v1/members/{_ABSENT}", {"role": "admin"}, 404),
    Endpoint("DELETE /v1/members/{id}", "DELETE", f"/v1/members/{_ABSENT}", None, 404),
    Endpoint("GET /v1/api-tokens", "GET", "/v1/api-tokens", None, 200),
    Endpoint("POST /v1/api-tokens", "POST", "/v1/api-tokens", {"name": "authz-test"}, 201),
    Endpoint("DELETE /v1/api-tokens/{id}", "DELETE", f"/v1/api-tokens/{_ABSENT}", None, 404),
]

# owner/admin hold both manage permissions; member/viewer hold neither (ADR-0009).
ROLE_AUTHORIZED = {"owner": True, "admin": True, "member": False, "viewer": False}


async def call(client: AsyncClient, ep: Endpoint, headers: dict[str, str]) -> int:
    response = await client.request(ep.method, ep.path, headers=headers, json=ep.body)
    return response.status_code


# ---------------------------------------------------------------------------------------
# The core matrix: every manage endpoint × every role, via the real human chain
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("endpoint", MANAGE_ENDPOINTS, ids=lambda e: e.label)
@pytest.mark.parametrize("role", ["owner", "admin", "member", "viewer"])
async def test_manage_endpoint_authorization_matrix(
    role: str,
    endpoint: Endpoint,
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """A real human of `role`, selecting their workspace, hits `endpoint`.

    owner/admin reach the handler (`authorized_status`); member/viewer are refused with 403
    by `require_permission` before the handler runs. The role is the ONLY thing that varies
    — the JWT, the endpoint, and the selection are otherwise identical — so nothing but the
    persisted role can be producing the difference.
    """
    client, _ = human_client
    user = f"{role}-{endpoint.method}"
    await seed_member(admin_engine, workspace_a.id, user_id=user, role=role)

    status = await call(client, endpoint, hx(authority.sign(user), workspace_a.id))

    if ROLE_AUTHORIZED[role]:
        assert status == endpoint.authorized_status, (
            f"{role} should be authorized for {endpoint.label}"
        )
    else:
        assert status == 403, f"{role} must be forbidden on {endpoint.label}"


async def test_workspaces_me_is_readable_by_any_member_role(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """`/v1/workspaces/me` gates on authentication only — every member role may read the
    workspace they belong to. It carries no `require_permission`, and that is correct: no
    canonical permission governs 'see your own workspace'."""
    client, _ = human_client
    for role in ("owner", "admin", "member", "viewer"):
        await seed_member(admin_engine, workspace_a.id, user_id=f"me-{role}", role=role)
        r = await client.get(
            "/v1/workspaces/me", headers=hx(authority.sign(f"me-{role}"), workspace_a.id)
        )
        assert r.status_code == 200
        assert r.json()["id"] == str(workspace_a.id)


# ---------------------------------------------------------------------------------------
# Machine / human separation on the authorization layer
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("endpoint", MANAGE_ENDPOINTS, ids=lambda e: e.label)
async def test_machine_tokens_are_denied_on_every_manage_endpoint(
    endpoint: Endpoint,
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    workspace_a: SeededWorkspace,
) -> None:
    """A machine token resolves to no membership, so `require_permission` denies it on every
    RBAC-gated endpoint — the M1.2 design, still holding now that humans can pass. 403, not
    a fallthrough to some machine-role shortcut."""
    client, endpoint_jwks = human_client
    status = await call(
        client,
        endpoint,
        {**bearer(workspace_a.token.plaintext), "X-Workspace-Id": str(workspace_a.id)},
    )
    assert status == 403
    assert endpoint_jwks.calls == 0, "a machine token must never hit the human verifier"


async def test_machine_token_ignores_workspace_header_for_authorization(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """A machine token for A, sent `X-Workspace-Id: B` where a B-owner exists, still acts as
    A's machine identity (403 on manage, no membership) — the header never moves a machine
    token's workspace or grants it a role."""
    client, _ = human_client
    await seed_member(admin_engine, workspace_b.id, user_id="b-owner", role="owner")
    r = await client.get(
        "/v1/members",
        headers={**bearer(workspace_a.token.plaintext), "X-Workspace-Id": str(workspace_b.id)},
    )
    assert r.status_code == 403  # no membership anywhere; the B-owner's role is not borrowed


# ---------------------------------------------------------------------------------------
# Cross-tenant: authorization never crosses the selected-workspace boundary
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("endpoint", MANAGE_ENDPOINTS, ids=lambda e: e.label)
async def test_owner_of_a_cannot_authorize_against_foreign_workspace(
    endpoint: Endpoint,
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """An owner of A selecting B (where they have no membership) is refused before any role
    is resolved — fail closed at the uniform 401, no existence oracle for B's endpoints."""
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="xt-owner", role="owner")
    await seed_member(admin_engine, workspace_b.id, user_id="b-native", role="owner")

    status = await call(client, endpoint, hx(authority.sign("xt-owner"), workspace_b.id))
    assert status == 401


# ---------------------------------------------------------------------------------------
# Multi-workspace: the same human authorizes by the SELECTED workspace's role
# ---------------------------------------------------------------------------------------


async def test_same_human_authorizes_by_selected_workspace_role(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """USER C: owner in A, viewer in B. ONE JWT. Managing api-tokens is allowed when C
    selects A (owner) and forbidden when C selects B (viewer). Then swap the roles and prove
    the outcome swaps — authorization follows the selected persisted membership, never the
    identity or a cached role."""
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="user-c", role="owner")
    b_member = await seed_member(admin_engine, workspace_b.id, user_id="user-c", role="viewer")
    token = authority.sign("user-c")

    assert (
        await client.get("/v1/api-tokens", headers=hx(token, workspace_a.id))
    ).status_code == 200
    assert (
        await client.get("/v1/api-tokens", headers=hx(token, workspace_b.id))
    ).status_code == 403

    # Swap: promote C in B to admin; the SAME token now manages tokens in B.
    async with admin_engine.begin() as conn:
        await conn.execute(text("UPDATE members SET role='admin' WHERE id=:i"), {"i": b_member})
    assert (
        await client.get("/v1/api-tokens", headers=hx(token, workspace_b.id))
    ).status_code == 200


# ---------------------------------------------------------------------------------------
# Request-spoofing: nothing the client sends can grant a permission
# ---------------------------------------------------------------------------------------


async def test_no_request_channel_can_elevate_a_viewer(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """A viewer floods every request channel with owner/admin-shaped authority — JWT claims,
    headers, query, body — and still gets 403. The persisted viewer role is the only input
    `authz.is_allowed` ever sees."""
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="spoofer", role="viewer")
    token = authority.sign(
        "spoofer",
        role="owner",
        roles=["owner"],
        permissions=["members:manage", "api_tokens:manage"],
        is_admin=True,
    )

    spoofed = await client.get(
        "/v1/members",
        params={"role": "owner", "permission": "members:manage"},
        headers={
            **hx(token, workspace_a.id),
            "X-Role": "owner",
            "X-Permission": "members:manage",
            "X-Member-Id": str(uuid.uuid4()),
            "X-User-Id": "someone-else",
        },
    )
    # The query params are unknown → 400; the point is that NOTHING yields 200. Re-check
    # with only header/JWT spoofing (no unknown query param) to pin the 403 precisely.
    assert spoofed.status_code in (400, 403)

    clean = await client.get(
        "/v1/members",
        headers={**hx(token, workspace_a.id), "X-Role": "owner", "X-Permission": "members:manage"},
    )
    assert clean.status_code == 403, "header/JWT-claimed authority must not elevate a viewer"


# ---------------------------------------------------------------------------------------
# Provenance: a human-created token records the human's real member_id
# ---------------------------------------------------------------------------------------


async def test_human_created_token_records_the_creators_member_id(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """The provenance the endpoint promises: `created_by_member_id` is the caller's verified
    member row, taken from the context, not the request — and it satisfies the composite FK
    `(workspace_id, created_by_member_id) → members`, which only holds because the bound
    member really belongs to the bound workspace."""
    client, _ = human_client
    member_id = await seed_member(admin_engine, workspace_a.id, user_id="creator", role="owner")

    r = await client.post(
        "/v1/api-tokens",
        headers=hx(authority.sign("creator"), workspace_a.id),
        json={"name": "provenance"},
    )
    assert r.status_code == 201
    assert r.json()["created_by_member_id"] == str(member_id)
    assert r.headers["cache-control"] == "no-store"


# ---------------------------------------------------------------------------------------
# GET /v1/workspaces is human-only at the authorization layer too
# ---------------------------------------------------------------------------------------


async def test_my_workspaces_rejects_machine_tokens(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    workspace_a: SeededWorkspace,
) -> None:
    client, _ = human_client
    r = await client.get("/v1/workspaces", headers=bearer(workspace_a.token.plaintext))
    assert r.status_code == 401
    assert r.json()["error"]["message"] == HUMAN_AUTH_FAILED


async def test_unauthenticated_requests_are_401_on_every_endpoint(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    workspace_a: SeededWorkspace,
) -> None:
    """No credential at all → 401 everywhere, before any authorization is considered."""
    client, _ = human_client
    for ep in MANAGE_ENDPOINTS:
        r = await client.request(ep.method, ep.path, json=ep.body)
        assert r.status_code == 401, f"{ep.label} must be 401 without a credential"
    assert (await client.get("/v1/workspaces/me")).status_code == 401
    assert (await client.get("/v1/workspaces")).status_code == 401


# ---------------------------------------------------------------------------------------
# Real-provider E2E: the primary authorization proof, no doubles (directive §23)
# ---------------------------------------------------------------------------------------


async def test_e2e_real_human_authorization_on_api_tokens(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """A real Better Auth human, owner in A and viewer in B, manages api-tokens by the whole
    real chain (live JWKS, no doubles): authorized when selecting A, forbidden when selecting
    B, and the created token carries their real A-member provenance. Fails (not skips) if the
    provider is down."""
    token, sub = await real_human("authz")
    a_member = await seed_member(admin_engine, workspace_a.id, user_id=sub, role="owner")
    await seed_member(admin_engine, workspace_b.id, user_id=sub, role="viewer")

    created = await client.post(
        "/v1/api-tokens", headers=hx(token, workspace_a.id), json={"name": "e2e"}
    )
    assert created.status_code == 201
    assert created.json()["created_by_member_id"] == str(a_member)

    # Same JWT, selecting B (viewer) → forbidden.
    assert (
        await client.get("/v1/api-tokens", headers=hx(token, workspace_b.id))
    ).status_code == 403
    # Foreign workspace → fail closed at authentication, before authorization.
    assert (await client.get("/v1/api-tokens", headers=hx(token, uuid.uuid4()))).status_code == 401
