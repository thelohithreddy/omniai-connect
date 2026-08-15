"""Human multi-workspace selection through the real application (M1.3-C, ADR-0016).

The security model in one line: the JWT proves WHO, `X-Workspace-Id` states WHERE the human
wants to act, the server proves membership, the persisted row proves ROLE, RBAC proves WHAT,
RLS is the final boundary — and the client never declares its own authority.

Every test drives real HTTP against the real app, real Postgres with RLS armed, the real
bootstrap functions, and the real RBAC chain. The only double is the JWKS endpoint (the
`human_client` seam), because the tests must mint tokens for arbitrary subjects.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.human_auth import HUMAN_AUTH_FAILED
from tests.conftest import FakeJWKSEndpoint, SeededWorkspace, SigningAuthority, bearer
from tests.integration.test_human_auth import seed_member
from tests.integration.test_human_auth_e2e import real_human


def ws_headers(token: str, workspace_id: uuid.UUID | str) -> dict[str, str]:
    return {**bearer(token), "X-Workspace-Id": str(workspace_id)}


# ---------------------------------------------------------------------------------------
# The cross-tenant matrix: users A, B, C across workspaces A and B
# ---------------------------------------------------------------------------------------


@pytest.fixture
async def two_tenant_world(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> dict[str, object]:
    """USER A owner@A · USER B admin@B · USER C member@A + viewer@B.

    USER C is the point of the module: one identity, two workspaces, two roles.
    """
    await seed_member(admin_engine, workspace_a.id, user_id="user-a", role="owner")
    await seed_member(admin_engine, workspace_b.id, user_id="user-b", role="admin")
    await seed_member(admin_engine, workspace_a.id, user_id="user-c", role="member")
    await seed_member(admin_engine, workspace_b.id, user_id="user-c", role="viewer")
    return {"a": workspace_a.id, "b": workspace_b.id}


async def test_user_a_reaches_only_workspace_a(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    two_tenant_world: dict[str, object],
) -> None:
    client, _ = human_client
    wsa, wsb = two_tenant_world["a"], two_tenant_world["b"]
    token = authority.sign("user-a")

    ok = await client.get("/v1/members", headers=ws_headers(token, wsa))
    assert ok.status_code == 200
    assert {m["user_id"] for m in ok.json()["data"]} == {"user-a", "user-c"}

    denied = await client.get("/v1/members", headers=ws_headers(token, wsb))
    assert denied.status_code == 401
    assert denied.json()["error"]["message"] == HUMAN_AUTH_FAILED


async def test_user_b_reaches_only_workspace_b(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    two_tenant_world: dict[str, object],
) -> None:
    client, _ = human_client
    wsa, wsb = two_tenant_world["a"], two_tenant_world["b"]
    token = authority.sign("user-b")

    assert (await client.get("/v1/members", headers=ws_headers(token, wsb))).status_code == 200
    assert (await client.get("/v1/members", headers=ws_headers(token, wsa))).status_code == 401


async def test_user_c_role_depends_on_the_selected_workspace(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    two_tenant_world: dict[str, object],
) -> None:
    """The core M1.3-C proof: ONE JWT, the header decides the role.

    C is `member` in A and `viewer` in B. `members:manage` needs admin+; member and viewer
    both lack it. So both selections authenticate (not 401) and both are forbidden (403) at
    THIS endpoint — but the important part is that the *role* resolved differently per
    selection, proven next by an endpoint C's A-role can reach.
    """
    client, _ = human_client
    wsa, wsb = two_tenant_world["a"], two_tenant_world["b"]
    token = authority.sign("user-c")

    # Both are authenticated humans (not 401) but neither role holds members:manage → 403.
    for ws in (wsa, wsb):
        r = await client.get("/v1/members", headers=ws_headers(token, ws))
        assert r.status_code == 403, "authenticated, but role lacks the permission"
        assert r.json()["error"]["code"] == "forbidden"


async def test_selection_changes_the_resolved_role_observably(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """C is owner in A, viewer in B. Same JWT: selecting A authorizes members:manage (200),
    selecting B does not (403). The header, and only the header, moved the outcome — and it
    moved it by resolving a different persisted role, never by carrying one."""
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="c2", role="owner")
    await seed_member(admin_engine, workspace_b.id, user_id="c2", role="viewer")
    token = authority.sign("c2")

    a = await client.get("/v1/members", headers=ws_headers(token, workspace_a.id))
    b = await client.get("/v1/members", headers=ws_headers(token, workspace_b.id))
    assert a.status_code == 200
    assert b.status_code == 403


# ---------------------------------------------------------------------------------------
# Foreign / malformed / missing selection
# ---------------------------------------------------------------------------------------


async def test_foreign_random_and_malformed_selectors_all_fail_closed_identically(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    two_tenant_world: dict[str, object],
) -> None:
    """No existence oracle: a foreign workspace, a random UUID, a malformed value, and an
    outright invalid JWT all return the byte-identical 401 body (modulo request_id)."""
    client, _ = human_client
    token = authority.sign("user-a")

    bodies = []
    for headers in (
        ws_headers(token, two_tenant_world["b"]),  # real, but foreign to user-a
        ws_headers(token, uuid.uuid4()),  # random nonexistent
        {**bearer(token), "X-Workspace-Id": "not-a-uuid"},  # malformed
        {**bearer(token), "X-Workspace-Id": ""},  # empty
        bearer("garbage.jwt.value"),  # invalid credential entirely
    ):
        r = await client.get("/v1/members", headers=headers)
        assert r.status_code == 401
        body = r.json()
        body["error"].pop("request_id")
        bodies.append(body)

    assert all(b == bodies[0] for b in bodies), "failure responses must be indistinguishable"


async def test_duplicate_workspace_headers_are_ambiguous_and_denied(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    two_tenant_world: dict[str, object],
) -> None:
    """Two `X-Workspace-Id` headers must never let one tenant be silently chosen.

    Starlette's `Headers.get()` returns only the FIRST repeated value, so a naive resolver
    would bind `wsa` and ignore `wsb` entirely — the forbidden "silently reconciled" case.
    The resolver reads the full list and rejects anything that is not exactly one value.
    Sent as a raw header list so both values are genuinely on the wire.
    """
    client, _ = human_client
    token = authority.sign("user-c")
    wsa, wsb = two_tenant_world["a"], two_tenant_world["b"]

    response = await client.get(
        "/v1/members",
        headers=[
            ("authorization", f"Bearer {token}"),
            ("x-workspace-id", str(wsa)),
            ("x-workspace-id", str(wsb)),
        ],
    )
    assert response.status_code == 401
    assert response.json()["error"]["message"] == HUMAN_AUTH_FAILED


async def test_a_padded_but_valid_uuid_selector_is_accepted(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """Surrounding whitespace is stripped; the id still has to match a membership."""
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="padded", role="owner")
    token = authority.sign("padded")

    r = await client.get(
        "/v1/members", headers={**bearer(token), "X-Workspace-Id": f"  {workspace_a.id}  "}
    )
    assert r.status_code == 200


# ---------------------------------------------------------------------------------------
# Switching, revocation, role change — same JWT throughout
# ---------------------------------------------------------------------------------------


async def test_switching_back_and_forth_tracks_the_persisted_role(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="switcher", role="owner")
    await seed_member(admin_engine, workspace_b.id, user_id="switcher", role="viewer")
    token = authority.sign("switcher")

    # A(owner)=200, B(viewer)=403, back to A(owner)=200 — no state carries between requests.
    assert (
        await client.get("/v1/members", headers=ws_headers(token, workspace_a.id))
    ).status_code == 200
    assert (
        await client.get("/v1/members", headers=ws_headers(token, workspace_b.id))
    ).status_code == 403
    assert (
        await client.get("/v1/members", headers=ws_headers(token, workspace_a.id))
    ).status_code == 200

    # And a foreign selection in the middle changes nothing about the next legitimate one.
    assert (
        await client.get("/v1/members", headers=ws_headers(token, uuid.uuid4()))
    ).status_code == 401
    assert (
        await client.get("/v1/members", headers=ws_headers(token, workspace_a.id))
    ).status_code == 200


async def test_revoking_the_selected_membership_denies_the_next_request(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """C works in B, its B-membership is removed, the SAME JWT + `X-Workspace-Id: B` now
    fails closed — authorization is the membership row, not the token (ADR-0016 §3)."""
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="revoked-c", role="owner")
    b_member = await seed_member(admin_engine, workspace_b.id, user_id="revoked-c", role="admin")
    token = authority.sign("revoked-c")

    assert (
        await client.get("/v1/members", headers=ws_headers(token, workspace_b.id))
    ).status_code == 200

    async with admin_engine.begin() as conn:
        await conn.execute(text("DELETE FROM members WHERE id = :id"), {"id": b_member})

    gone = await client.get("/v1/members", headers=ws_headers(token, workspace_b.id))
    assert gone.status_code == 401
    assert gone.json()["error"]["message"] == HUMAN_AUTH_FAILED
    # A-membership is untouched, so A still works with the same token.
    assert (
        await client.get("/v1/members", headers=ws_headers(token, workspace_a.id))
    ).status_code == 200


async def test_changing_the_persisted_role_changes_authorization_on_the_next_request(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_b: SeededWorkspace,
) -> None:
    """C is viewer in B (403), promoted to admin (200), demoted back to viewer (403) — the
    same JWT and header throughout, no stale role cached."""
    client, _ = human_client
    member = await seed_member(admin_engine, workspace_b.id, user_id="promoted", role="viewer")
    token = authority.sign("promoted")
    headers = ws_headers(token, workspace_b.id)

    assert (await client.get("/v1/members", headers=headers)).status_code == 403

    async with admin_engine.begin() as conn:
        await conn.execute(text("UPDATE members SET role='admin' WHERE id=:i"), {"i": member})
    assert (await client.get("/v1/members", headers=headers)).status_code == 200

    async with admin_engine.begin() as conn:
        await conn.execute(text("UPDATE members SET role='viewer' WHERE id=:i"), {"i": member})
    assert (await client.get("/v1/members", headers=headers)).status_code == 403


# ---------------------------------------------------------------------------------------
# Attacker-controlled identity — only the JWT and the verified membership are authority
# ---------------------------------------------------------------------------------------


async def test_request_supplied_role_and_identity_are_inert(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_b: SeededWorkspace,
) -> None:
    """A viewer stuffs owner-shaped identity into headers, query, and a claim-laden JWT.

    Nothing moves: role stays viewer (403). The header selects a workspace; it never sets a
    role, member_id, user_id, or kind.
    """
    client, _ = human_client
    await seed_member(admin_engine, workspace_b.id, user_id="sneaky", role="viewer")
    token = authority.sign("sneaky", role="owner", permissions=["members:manage"], kind="api_token")

    r = await client.get(
        "/v1/members",
        params={"role": "owner"},
        headers={
            **ws_headers(token, workspace_b.id),
            "X-Role": "owner",
            "X-Member-Id": str(uuid.uuid4()),
            "X-User-Id": "someone-else",
        },
    )
    # The query param `role` is an unknown param → 400; even without it the role is viewer.
    assert r.status_code in (400, 403)
    clean = await client.get(
        "/v1/members", headers={**ws_headers(token, workspace_b.id), "X-Role": "owner"}
    )
    assert clean.status_code == 403


# ---------------------------------------------------------------------------------------
# Machine / human separation
# ---------------------------------------------------------------------------------------


async def test_machine_token_ignores_the_workspace_header(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """A machine token for workspace A, sent with `X-Workspace-Id: B`, stays bound to A.

    The machine plane never reads the selection header — its workspace is the token's. Proven
    by an endpoint the token's workspace can reach: /v1/workspaces/me returns A, not B.
    """
    client, endpoint = human_client
    me = await client.get(
        "/v1/workspaces/me",
        headers=ws_headers(workspace_a.token.plaintext, workspace_b.id),
    )
    assert me.status_code == 200
    assert me.json()["id"] == str(workspace_a.id)
    assert endpoint.calls == 0, "machine auth must not consult the JWKS"


async def test_my_workspaces_is_human_only(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    workspace_a: SeededWorkspace,
) -> None:
    """A machine token on the human discovery endpoint fails as a non-human credential,
    uniformly, with no fallthrough to the machine plane."""
    client, _ = human_client
    r = await client.get("/v1/workspaces", headers=bearer(workspace_a.token.plaintext))
    assert r.status_code == 401
    assert r.json()["error"]["message"] == HUMAN_AUTH_FAILED


# ---------------------------------------------------------------------------------------
# GET /v1/workspaces — the my-workspaces listing
# ---------------------------------------------------------------------------------------


async def test_my_workspaces_lists_only_the_callers_memberships_with_roles(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    two_tenant_world: dict[str, object],
) -> None:
    """C sees A(member) and B(viewer) and nothing else. A sees only A. Ground truth for the
    'nothing else' is the admin-engine seeding: A and B both have multiple members, but each
    caller's list is exactly their own."""
    client, _ = human_client
    wsa, wsb = two_tenant_world["a"], two_tenant_world["b"]

    c = await client.get("/v1/workspaces", headers=bearer(authority.sign("user-c")))
    assert c.status_code == 200
    assert {(m["id"], m["role"]) for m in c.json()["data"]} == {
        (str(wsa), "member"),
        (str(wsb), "viewer"),
    }

    a = await client.get("/v1/workspaces", headers=bearer(authority.sign("user-a")))
    assert {(m["id"], m["role"]) for m in a.json()["data"]} == {(str(wsa), "owner")}
    assert str(wsb) not in {m["id"] for m in a.json()["data"]}


async def test_my_workspaces_is_empty_for_a_membershipless_human(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
) -> None:
    """Zero memberships → an empty list, not an error and not a fabricated workspace."""
    client, _ = human_client
    r = await client.get("/v1/workspaces", headers=bearer(authority.sign("orphan")))
    assert r.status_code == 200
    assert r.json()["data"] == []


async def test_my_workspaces_never_exposes_workspace_names_or_foreign_data(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    two_tenant_world: dict[str, object],
) -> None:
    """The listing discloses id + the caller's own role only — no name, slug, plan, member
    count, or any field belonging to a workspace the caller is not in."""
    client, _ = human_client
    r = await client.get("/v1/workspaces", headers=bearer(authority.sign("user-c")))
    for item in r.json()["data"]:
        assert set(item.keys()) == {"id", "role"}


# ---------------------------------------------------------------------------------------
# Connection / GUC safety and concurrency
# ---------------------------------------------------------------------------------------


async def test_tenant_guc_does_not_survive_a_request(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    app_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """After a bound human request commits, a fresh transaction on the pool sees no
    workspace GUC — the binding is transaction-local (SET LOCAL), never leaked to the next
    checkout of that pooled connection."""
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="guc", role="owner")

    assert (
        await client.get("/v1/members", headers=ws_headers(authority.sign("guc"), workspace_a.id))
    ).status_code == 200

    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(app_engine, expire_on_commit=False)
    async with factory() as session, session.begin():
        leaked = await session.scalar(text("SELECT current_setting('app.workspace_id', true)"))
    assert not leaked, "workspace GUC leaked past its request/transaction boundary"


async def test_interleaved_multi_tenant_requests_never_cross(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    two_tenant_world: dict[str, object],
) -> None:
    """Fire A→A, B→B, C→A, C→B concurrently, many times: each response reflects only its own
    selection. A crossover (pooled-connection contamination, shared mutable state, async
    leakage) would show up as A seeing B's members or C's role bleeding between workspaces."""
    client, _ = human_client
    wsa, wsb = two_tenant_world["a"], two_tenant_world["b"]
    a_tok, b_tok, c_tok = (authority.sign(u) for u in ("user-a", "user-b", "user-c"))

    async def a_sees_a() -> None:
        r = await client.get("/v1/members", headers=ws_headers(a_tok, wsa))
        assert r.status_code == 200
        assert {m["user_id"] for m in r.json()["data"]} == {"user-a", "user-c"}

    async def b_sees_b() -> None:
        r = await client.get("/v1/members", headers=ws_headers(b_tok, wsb))
        assert r.status_code == 200
        assert {m["user_id"] for m in r.json()["data"]} == {"user-b", "user-c"}

    async def a_denied_b() -> None:
        assert (await client.get("/v1/members", headers=ws_headers(a_tok, wsb))).status_code == 401

    async def c_forbidden_either() -> None:
        # member@A and viewer@B both lack members:manage → 403, never a leak or a 200.
        for ws in (wsa, wsb):
            assert (
                await client.get("/v1/members", headers=ws_headers(c_tok, ws))
            ).status_code == 403

    await asyncio.gather(
        *(coro() for _ in range(8) for coro in (a_sees_a, b_sees_b, a_denied_b, c_forbidden_either))
    )


# ---------------------------------------------------------------------------------------
# Log audit
# ---------------------------------------------------------------------------------------


async def test_selection_logs_carry_reasons_but_no_tenant_or_credential_material(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Drive the interesting selection failures under captured stdout, prove the capture is
    non-empty, and prove it leaks neither the JWT/cookie nor the *foreign* workspace id a
    caller tried to reach (only reason codes and the caller's own bound ids may appear)."""
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="log-c", role="owner")
    await seed_member(admin_engine, workspace_b.id, user_id="log-c", role="viewer")
    token = authority.sign("log-c")
    foreign = uuid.uuid4()

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        await client.get("/v1/members", headers=bearer(token))  # multi, no selector
        await client.get("/v1/members", headers=ws_headers(token, foreign))  # foreign
        await client.get(
            "/v1/members", headers={**bearer(token), "X-Workspace-Id": "xxx"}
        )  # malformed
    emitted = buffer.getvalue()

    assert "human_auth.workspace_selection_rejected" in emitted, "reasons must be observable"
    assert token not in emitted, "the JWT must never be logged"
    assert token.split(".")[1] not in emitted, "the JWT payload must never be logged"
    assert str(foreign) not in emitted, "a foreign workspace id must not be logged"


# ---------------------------------------------------------------------------------------
# Real-provider end-to-end (no doubles): login → JWT → X-Workspace-Id → RBAC → RLS
# ---------------------------------------------------------------------------------------


async def test_e2e_real_login_selects_a_workspace_and_resolves_its_role(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """The whole M1.3-C chain against real components: a real Better Auth human, member of
    two real workspaces with different roles, selects each via `X-Workspace-Id` and gets the
    role resolved for THAT workspace — verified against the live JWKS, no doubles.

    Fails (not skips) if the provider is down, exactly like the M1.3-B E2E suite.
    """
    token, sub = await real_human("selector")
    await seed_member(admin_engine, workspace_a.id, user_id=sub, role="owner")
    await seed_member(admin_engine, workspace_b.id, user_id=sub, role="viewer")

    # Discovery: the real human sees exactly their two memberships with roles.
    listing = await client.get("/v1/workspaces", headers=bearer(token))
    assert listing.status_code == 200
    assert {(m["id"], m["role"]) for m in listing.json()["data"]} == {
        (str(workspace_a.id), "owner"),
        (str(workspace_b.id), "viewer"),
    }

    # Selecting A (owner) authorizes members:manage; selecting B (viewer) does not.
    assert (
        await client.get("/v1/members", headers=ws_headers(token, workspace_a.id))
    ).status_code == 200
    assert (
        await client.get("/v1/members", headers=ws_headers(token, workspace_b.id))
    ).status_code == 403

    # No selector with two memberships → fail closed; a foreign selection → fail closed.
    assert (await client.get("/v1/members", headers=bearer(token))).status_code == 401
    assert (
        await client.get("/v1/members", headers=ws_headers(token, uuid.uuid4()))
    ).status_code == 401
