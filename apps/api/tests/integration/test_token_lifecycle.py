"""The API token lifecycle as one system: create → authenticate → list → revoke → denied.

M1.2-F, -G and -H each proved their own module. This file exists because a lifecycle can
break while every module test still passes: creation can succeed and mint a credential the
resolver will not accept, revocation can update a column the resolver does not read, a
transaction can roll back after the plaintext has already reached the client. Those defects
live *between* modules, so they are invisible to any one module's suite.

Two rules shape everything here.

**Real boundaries, or it proves nothing.** Every token is minted through `POST
/v1/api-tokens` and authenticated by presenting that exact plaintext to the real
application — the real resolver, the real `auth.resolve_api_token`, the real RLS binding.
No test in this file asserts on a database column *instead of* on behaviour; where a column
is checked it is in addition to driving the credential through the authentication path.

**The one unavoidable seam.** Token management requires `api_tokens:manage`, which only a
human Member holds, and production authentication currently issues machine identity only
(ADR-0002, M1.2-E). So the *management* half of each lifecycle runs against an app whose
`get_workspace_context` is overridden to yield a human context — the M1.2-E technique,
where the permission dependency, membership lookup, policy, services and repositories are
all untouched production code — while the *authentication* half runs against the real,
unmodified application. That seam is a property of the system, not of the tests: until
human authentication lands, no single process can perform both halves.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import uuid
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from app.core.ids import new_id
from app.core.security import PREFIX_DISPLAY_LEN, TOKEN_PREFIX
from app.domains.workspaces.repository import ApiTokenRepository, RevocationOutcome
from tests.conftest import SeededWorkspace
from tests.integration.test_api_token_creation import (
    api_token_context,
    build_token_app,
    member_context,
)
from tests.integration.test_members_tenancy import seed_member

pytestmark = pytest.mark.asyncio


def manager(
    app_engine: AsyncEngine,
    workspace_id: uuid.UUID,
    member_id: uuid.UUID,
    *,
    surface_errors: bool = False,
) -> AsyncClient:
    """A client that may manage tokens in `workspace_id`, via the real authorization path.

    `surface_errors=True` sets `raise_app_exceptions=False`, which is what makes the
    failure-injection tests honest. ASGITransport's default is to re-raise an unhandled
    server exception into the caller, so an assertion about the *response* placed after such
    a call never executes — it is dead code inside whatever suppresses the exception.
    Production runs behind uvicorn, which turns that exception into a 500; this flag
    reproduces that, so the tests assert on what a real client would actually receive.
    """
    return AsyncClient(
        transport=ASGITransport(
            app=build_token_app(app_engine, lambda: member_context(workspace_id, member_id)),
            raise_app_exceptions=not surface_errors,
        ),
        base_url="http://t",
    )


async def owner_of(engine: AsyncEngine, workspace_id: uuid.UUID, label: str = "owner") -> uuid.UUID:
    return await seed_member(
        engine, workspace_id, user_id=f"{label}-{uuid.uuid4().hex[:8]}", role="owner"
    )


async def mint(client: AsyncClient, name: str = "lifecycle") -> tuple[uuid.UUID, str, str]:
    """Create a token through the real endpoint. Returns `(id, plaintext, prefix)`."""
    response = await client.post("/v1/api-tokens", json={"name": name})
    assert response.status_code == 201, response.text
    body = response.json()
    return uuid.UUID(body["id"]), body["token"], body["token_prefix"]


async def db_row(engine: AsyncEngine, token_id: uuid.UUID) -> dict[str, Any]:
    async with engine.begin() as conn:
        result = await conn.execute(text("SELECT * FROM api_tokens WHERE id = :i"), {"i": token_id})
        row = result.mappings().first()
    return dict(row) if row else {}


# =======================================================================================
# LIFECYCLE A — create → authenticate
# =======================================================================================


async def test_a_token_minted_through_the_api_authenticates_against_the_real_resolver(
    client: AsyncClient,
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """The single most important cross-module property: what creation returns actually works.

    M1.2-F proved the *service* produces a usable credential; this proves the **endpoint**
    does. The two can diverge — a router that returned `token_prefix` as `token`, or
    serialized the wrong field, would pass every creation test (the response shape is
    valid, the row is correct) and hand every client a credential that cannot authenticate.
    Only presenting the response's `token` value to the real resolver catches that.
    """
    owner = await owner_of(admin_engine, workspace_a.id)
    async with manager(app_engine, workspace_a.id, owner) as admin:
        token_id, plaintext, prefix = await mint(admin)

    authenticated = await client.get(
        "/v1/workspaces/me", headers={"Authorization": f"Bearer {plaintext}"}
    )

    assert authenticated.status_code == 200, authenticated.text
    assert authenticated.json()["id"] == str(workspace_a.id), "authenticated into the wrong tenant"

    row = await db_row(admin_engine, token_id)
    assert row["workspace_id"] == workspace_a.id
    assert row["revoked_at"] is None
    assert row["token_prefix"] == prefix == plaintext[:PREFIX_DISPLAY_LEN]
    for column, value in row.items():
        assert plaintext not in str(value), f"plaintext persisted in api_tokens.{column}"


async def test_the_plaintext_is_obtainable_exactly_once(
    client: AsyncClient,
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """ "Shown once" across every surface that exists, not just the one that returned it.

    Checked against the raw bytes of each response rather than parsed fields, so a secret
    smuggled into a nested object or a message string would still be caught.
    """
    owner = await owner_of(admin_engine, workspace_a.id)
    async with manager(app_engine, workspace_a.id, owner) as admin:
        token_id, plaintext, _ = await mint(admin)

        surfaces = {
            "list": await admin.get("/v1/api-tokens", params={"limit": 100}),
            "second_create": await admin.post("/v1/api-tokens", json={"name": "other"}),
            "revoke": await admin.delete(f"/v1/api-tokens/{token_id}"),
            "list_after_revoke": await admin.get("/v1/api-tokens", params={"limit": 100}),
        }
    authenticated = await client.get(
        "/v1/workspaces/me", headers={"Authorization": f"Bearer {plaintext}"}
    )

    body = plaintext.removeprefix(TOKEN_PREFIX)
    for label, response in surfaces.items():
        assert plaintext not in response.text, f"plaintext re-emitted by {label}"
        assert body not in response.text, f"secret body re-emitted by {label}"
    assert plaintext not in authenticated.text


# =======================================================================================
# LIFECYCLE B — create → list
# =======================================================================================


async def test_a_minted_token_appears_in_the_listing_with_matching_metadata(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Creation and listing must agree about the same row.

    The prefix is the field an operator uses to recognise a credential in a revocation UI,
    so the value shown at creation and the value shown in the list have to be the same
    string — otherwise the operator revokes by matching a prefix that never appears again.
    """
    owner = await owner_of(admin_engine, workspace_a.id)
    async with manager(app_engine, workspace_a.id, owner) as admin:
        token_id, plaintext, prefix = await mint(admin, name="ci-deploy")
        listing = await admin.get("/v1/api-tokens", params={"limit": 100})

    entry = next(i for i in listing.json()["data"] if i["id"] == str(token_id))
    assert entry["name"] == "ci-deploy"
    assert entry["token_prefix"] == prefix
    assert entry["revoked_at"] is None
    assert entry["scopes"] == []
    assert set(entry) == {
        "id",
        "name",
        "token_prefix",
        "scopes",
        "last_used_at",
        "expires_at",
        "revoked_at",
        "created_at",
    }
    row = await db_row(admin_engine, token_id)
    assert entry["token_prefix"] == row["token_prefix"], "listing disagrees with storage"


async def test_listing_reflects_every_token_the_workspace_minted(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Create several through the API, then page through and account for all of them.

    Catches an interaction the module suites cannot: creation ordering versus the listing's
    keyset cursor. Tokens minted in rapid succession share a `created_at` to the microsecond
    on fast machines, and if the cursor's tie-break disagreed with the insert order the
    listing would silently drop one of the credentials an operator needs to revoke.
    """
    owner = await owner_of(admin_engine, workspace_a.id)
    minted: list[uuid.UUID] = []
    async with manager(app_engine, workspace_a.id, owner) as admin:
        for index in range(7):
            token_id, _, _ = await mint(admin, name=f"t{index}")
            minted.append(token_id)

        seen: list[str] = []
        cursor: str | None = None
        for _ in range(20):
            params: dict[str, Any] = {"limit": 2} | ({"cursor": cursor} if cursor else {})
            page = (await admin.get("/v1/api-tokens", params=params)).json()
            seen.extend(i["id"] for i in page["data"])
            cursor = page["next_cursor"]
            if not page["has_more"]:
                break

    assert cursor is None, "pagination did not terminate"
    assert {str(t) for t in minted} <= set(seen), "a minted token was missing from the listing"
    assert len(seen) == len(set(seen)), "a token was served on more than one page"


# =======================================================================================
# LIFECYCLE C / J — create → revoke → authentication and authorization both fail
# =======================================================================================


async def test_the_full_arc_create_authenticate_revoke_denied(
    client: AsyncClient,
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """The headline lifecycle, end to end, with the same secret used throughout.

    Each step is asserted through behaviour: the credential works, then it does not. The
    401 body is checked to carry no hint that the token was *revoked* rather than never
    valid — distinguishing them would tell an attacker that a guessed or stolen value was
    once real, which is why the resolver uses one message for unknown, revoked and expired.
    """
    owner = await owner_of(admin_engine, workspace_a.id)
    headers: dict[str, str]

    async with manager(app_engine, workspace_a.id, owner) as admin:
        token_id, plaintext, _ = await mint(admin)
        headers = {"Authorization": f"Bearer {plaintext}"}

        assert (await client.get("/v1/workspaces/me", headers=headers)).status_code == 200

        revoked = await admin.delete(f"/v1/api-tokens/{token_id}")
        assert revoked.status_code == 204
        assert revoked.content == b""

    denied = await client.get("/v1/workspaces/me", headers=headers)
    never_existed = await client.get(
        "/v1/workspaces/me", headers={"Authorization": f"Bearer {TOKEN_PREFIX}neverexisted"}
    )

    assert denied.status_code == never_existed.status_code == 401
    error = denied.json()["error"]
    assert error["code"] == "unauthorized"
    # The real property, asserted by comparison rather than by inspecting wording: a revoked
    # credential is indistinguishable from one that never existed. Any difference would tell
    # an attacker that a stolen or guessed value was once real.
    assert error["message"] == never_existed.json()["error"]["message"]
    assert str(token_id) not in denied.text
    assert error["request_id"] == denied.headers["X-Request-Id"]

    row = await db_row(admin_engine, token_id)
    assert row["revoked_at"] is not None


async def test_a_revoked_credential_is_inert_on_every_surface(
    client: AsyncClient,
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """Revocation must cut the credential off everywhere, not only where it was cut.

    A revoked token that still passed authentication on an endpoint the resolver guards
    differently would be the worst kind of partial revocation: the operator sees 204 and
    believes the credential is dead. Every route reachable with a bearer token is checked.
    """
    owner = await owner_of(admin_engine, workspace_a.id)
    async with manager(app_engine, workspace_a.id, owner) as admin:
        token_id, plaintext, _ = await mint(admin)
        assert (await admin.delete(f"/v1/api-tokens/{token_id}")).status_code == 204

    headers = {"Authorization": f"Bearer {plaintext}"}
    for method, path, kwargs in (
        ("GET", "/v1/workspaces/me", {}),
        ("GET", "/v1/api-tokens", {}),
        ("POST", "/v1/api-tokens", {"json": {"name": "x"}}),
        ("DELETE", f"/v1/api-tokens/{token_id}", {}),
        ("DELETE", f"/v1/api-tokens/{new_id()}", {}),
    ):
        response = await client.request(method, path, headers=headers, **kwargs)
        assert response.status_code == 401, f"{method} {path} accepted a revoked credential"
        assert response.json()["error"]["code"] == "unauthorized"


# =======================================================================================
# LIFECYCLE D / E — revoke → list, and revoke twice
# =======================================================================================


async def test_the_listing_shows_the_revoked_token_with_its_timestamp(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Derived from the implementation, not chosen: revocation is a state transition.

    `revoked_at` exists on `ApiTokenRead` (M1.1) and the repository sets rather than deletes
    (ADR-0012), so a revoked token *remains* listed and is distinguishable. This asserts the
    two halves agree — a revocation that hid the row would leave an operator unable to
    confirm the credential was cut off.
    """
    owner = await owner_of(admin_engine, workspace_a.id)
    async with manager(app_engine, workspace_a.id, owner) as admin:
        live_id, _, _ = await mint(admin, name="stays-live")
        revoked_id, _, _ = await mint(admin, name="gets-revoked")
        before = (await admin.get("/v1/api-tokens", params={"limit": 100})).json()
        await admin.delete(f"/v1/api-tokens/{revoked_id}")
        after = (await admin.get("/v1/api-tokens", params={"limit": 100})).json()

    assert {i["id"] for i in before["data"]} == {i["id"] for i in after["data"]}, (
        "revocation changed which tokens are listed"
    )
    entries = {i["id"]: i for i in after["data"]}
    assert entries[str(revoked_id)]["revoked_at"] is not None
    assert entries[str(live_id)]["revoked_at"] is None


async def test_repeated_revocation_is_idempotent_and_leaves_one_transition(
    client: AsyncClient,
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """Three revocations, one recorded moment, and the credential dead throughout.

    The preserved timestamp is the part a naive implementation loses: an unconditional
    `SET revoked_at = now()` answers 204 every time and looks correct while rewriting the
    audit record to the moment of the last retry.
    """
    owner = await owner_of(admin_engine, workspace_a.id)
    async with manager(app_engine, workspace_a.id, owner) as admin:
        token_id, plaintext, _ = await mint(admin)
        first = await admin.delete(f"/v1/api-tokens/{token_id}")
        first_at = (await db_row(admin_engine, token_id))["revoked_at"]
        await asyncio.sleep(0.05)
        second = await admin.delete(f"/v1/api-tokens/{token_id}")
        third = await admin.delete(f"/v1/api-tokens/{token_id}")
        listing = (await admin.get("/v1/api-tokens", params={"limit": 100})).json()

    assert [first.status_code, second.status_code, third.status_code] == [204, 204, 204]
    assert (await db_row(admin_engine, token_id))["revoked_at"] == first_at
    assert len([i for i in listing["data"] if i["id"] == str(token_id)]) == 1
    assert (
        await client.get("/v1/workspaces/me", headers={"Authorization": f"Bearer {plaintext}"})
    ).status_code == 401


# =======================================================================================
# LIFECYCLE F — transaction rollback
# =======================================================================================


async def test_a_creation_whose_transaction_fails_leaves_no_usable_credential(
    client: AsyncClient,
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The dangerous half-state: a client holding a plaintext for a row that was rolled back.

    Creation flushes inside the request transaction and the commit happens when the
    UnitOfWork dependency exits. This injects a failure after the row is flushed and asserts
    the two things that must both hold: the client does **not** receive a 201 carrying a
    credential, and no row survives — so there is no plaintext in the world that maps to a
    persisted token.
    """
    owner = await owner_of(admin_engine, workspace_a.id)
    import app.domains.workspaces.service as service_module

    real_issue = service_module.ApiTokenService.issue

    async def failing_issue(self: Any, **kwargs: Any) -> Any:
        # Call through first: the row must be flushed before the failure, or this proves
        # nothing about rollback — only that an exception prevents work from starting.
        await real_issue(self, **kwargs)
        raise RuntimeError("simulated failure after the row was flushed")

    monkeypatch.setattr(service_module.ApiTokenService, "issue", failing_issue)

    async with manager(app_engine, workspace_a.id, owner, surface_errors=True) as admin:
        response = await admin.post("/v1/api-tokens", json={"name": "doomed"})

    assert response.status_code == 500, "a failed creation did not surface as an error"
    assert "doomed" not in response.text or "token" not in response.json().get("error", {})
    assert "omc_" not in response.text, "a failure response carried credential material"

    async with admin_engine.begin() as conn:
        count = await conn.scalar(
            text("SELECT count(*) FROM api_tokens WHERE workspace_id = :w AND name = 'doomed'"),
            {"w": workspace_a.id},
        )
    assert count == 0, "a rolled-back creation left a persisted token"


async def test_a_revocation_whose_transaction_fails_leaves_the_credential_live(
    client: AsyncClient,
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The mirror hazard: an operator told "revoked" whose transaction rolled back.

    Asserted through authentication rather than the column — the question that matters is
    whether the credential still works, and it must, because the operator will be told the
    revocation failed and will retry.
    """
    owner = await owner_of(admin_engine, workspace_a.id)
    async with manager(app_engine, workspace_a.id, owner) as admin:
        token_id, plaintext, _ = await mint(admin)

    import app.domains.workspaces.service as service_module

    real_revoke = service_module.ApiTokenService.revoke

    async def failing_revoke(self: Any, target: uuid.UUID) -> None:
        await real_revoke(self, target)
        raise RuntimeError("simulated failure after the state transition")

    monkeypatch.setattr(service_module.ApiTokenService, "revoke", failing_revoke)

    async with manager(app_engine, workspace_a.id, owner, surface_errors=True) as admin:
        response = await admin.delete(f"/v1/api-tokens/{token_id}")

    assert response.status_code == 500, "a failed revocation did not surface as an error"

    assert (await db_row(admin_engine, token_id))["revoked_at"] is None
    assert (
        await client.get("/v1/workspaces/me", headers={"Authorization": f"Bearer {plaintext}"})
    ).status_code == 200, "a rolled-back revocation killed a live credential"


# =======================================================================================
# LIFECYCLE G / H — pooled connections and cross-tenant attacks
# =======================================================================================


async def test_tenant_context_does_not_leak_across_pooled_lifecycle_requests(
    client: AsyncClient,
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Interleave two tenants' full lifecycles over the same pool, repeatedly.

    `SET LOCAL` dies with its transaction, so a connection returned to the pool carries no
    tenant into the next request. A session-scoped binding would survive, and the failure
    would look exactly like this test's B-listing containing A's tokens. Interleaving —
    rather than running A fully then B — is what forces connection reuse between tenants.
    """
    a_owner = await owner_of(admin_engine, workspace_a.id, "a")
    b_owner = await owner_of(admin_engine, workspace_b.id, "b")
    a_ids: list[str] = []
    b_ids: list[str] = []

    for round_index in range(3):
        async with manager(app_engine, workspace_a.id, a_owner) as a_admin:
            token_id, a_plain, _ = await mint(a_admin, name=f"a{round_index}")
            a_ids.append(str(token_id))
        async with manager(app_engine, workspace_b.id, b_owner) as b_admin:
            token_id, b_plain, _ = await mint(b_admin, name=f"b{round_index}")
            b_ids.append(str(token_id))

        assert (
            await client.get("/v1/workspaces/me", headers={"Authorization": f"Bearer {a_plain}"})
        ).json()["id"] == str(workspace_a.id)
        assert (
            await client.get("/v1/workspaces/me", headers={"Authorization": f"Bearer {b_plain}"})
        ).json()["id"] == str(workspace_b.id)

    async with manager(app_engine, workspace_a.id, a_owner) as a_admin:
        a_list = {
            i["id"]
            for i in (await a_admin.get("/v1/api-tokens", params={"limit": 100})).json()["data"]
        }
    async with manager(app_engine, workspace_b.id, b_owner) as b_admin:
        b_list = {
            i["id"]
            for i in (await b_admin.get("/v1/api-tokens", params={"limit": 100})).json()["data"]
        }

    assert set(a_ids) <= a_list and set(b_ids) <= b_list
    assert a_list & b_list == set(), "a token appeared in both tenants' listings"
    assert not (set(b_ids) & a_list), "workspace B's tokens leaked into A's listing"


async def test_a_token_and_its_identifiers_are_useless_in_another_tenant(
    client: AsyncClient,
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Every cross-tenant move available to an attacker holding A's credential and ids.

    Each leg is a real attempt with genuine material — a real token, a real id, a real
    cursor — so nothing passes merely because the attacker's input was malformed.
    """
    a_owner = await owner_of(admin_engine, workspace_a.id, "a")
    b_owner = await owner_of(admin_engine, workspace_b.id, "b")

    async with manager(app_engine, workspace_a.id, a_owner) as a_admin:
        a_token_id, a_plaintext, _ = await mint(a_admin, name="a-secret")
        a_cursor = (await a_admin.get("/v1/api-tokens", params={"limit": 1})).json()["next_cursor"]

    # 1. A's credential authenticates only into A.
    resolved = await client.get(
        "/v1/workspaces/me", headers={"Authorization": f"Bearer {a_plaintext}"}
    )
    assert resolved.json()["id"] == str(workspace_a.id) != str(workspace_b.id)

    async with manager(app_engine, workspace_b.id, b_owner) as b_admin:
        # 2. B cannot see A's token.
        b_listing = (await b_admin.get("/v1/api-tokens", params={"limit": 100})).json()
        assert str(a_token_id) not in {i["id"] for i in b_listing["data"]}

        # 3. B cannot revoke A's token — and learns nothing from trying.
        attempt = await b_admin.delete(f"/v1/api-tokens/{a_token_id}")
        assert attempt.status_code == 404
        assert attempt.json()["error"]["code"] == "not_found"

        # 4. A cursor minted inside A does not carry authority into B.
        if a_cursor:
            crossed = await b_admin.get("/v1/api-tokens", params={"cursor": a_cursor, "limit": 100})
            assert crossed.status_code == 200
            assert str(a_token_id) not in {i["id"] for i in crossed.json()["data"]}

    # 5. After all of that, A's credential is untouched and still live.
    assert (await db_row(admin_engine, a_token_id))["revoked_at"] is None
    assert (
        await client.get("/v1/workspaces/me", headers={"Authorization": f"Bearer {a_plaintext}"})
    ).status_code == 200


# =======================================================================================
# LIFECYCLE I — human/machine identity separation across the whole lifecycle
# =======================================================================================


async def test_a_minted_credential_inherits_nothing_from_the_owner_who_minted_it(
    client: AsyncClient,
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """An owner mints a token; the token is still not an owner.

    This is the confused-deputy boundary at lifecycle scale. The token records
    `created_by_member_id` pointing at an owner, authenticates successfully, and is still
    refused every management operation — so a leaked credential cannot enumerate the
    workspace's other tokens, mint a successor that outlives revoking the stolen one, or
    revoke the operator's tokens mid-incident.
    """
    owner = await owner_of(admin_engine, workspace_a.id)
    async with manager(app_engine, workspace_a.id, owner) as admin:
        token_id, plaintext, _ = await mint(admin)

    row = await db_row(admin_engine, token_id)
    assert row["created_by_member_id"] == owner, "provenance was not recorded"

    headers = {"Authorization": f"Bearer {plaintext}"}
    assert (await client.get("/v1/workspaces/me", headers=headers)).status_code == 200

    for method, path, kwargs in (
        ("GET", "/v1/api-tokens", {}),
        ("POST", "/v1/api-tokens", {"json": {"name": "successor"}}),
        ("DELETE", f"/v1/api-tokens/{token_id}", {}),
    ):
        response = await client.request(method, path, headers=headers, **kwargs)
        assert response.status_code == 403, f"{method} {path} let a machine token manage tokens"
        assert response.json()["error"]["code"] == "forbidden"

    assert (await db_row(admin_engine, token_id))["revoked_at"] is None


# =======================================================================================
# Concurrency across the lifecycle
# =======================================================================================


async def test_concurrent_creation_produces_distinct_working_credentials(
    client: AsyncClient,
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """Eight simultaneous mints: eight distinct secrets, eight rows, all usable.

    Guards the entropy and uniqueness properties under contention specifically — a
    generator seeded per-process or a hash collision would show up here and nowhere else,
    and the `token_hash` unique constraint would turn it into a 500 rather than silent
    credential sharing.
    """
    owner = await owner_of(admin_engine, workspace_a.id)

    async def mint_one(index: int) -> tuple[uuid.UUID, str]:
        async with manager(app_engine, workspace_a.id, owner) as admin:
            token_id, plaintext, _ = await mint(admin, name=f"concurrent-{index}")
            return token_id, plaintext

    results = await asyncio.gather(*(mint_one(i) for i in range(8)))

    ids = {token_id for token_id, _ in results}
    secrets = {plaintext for _, plaintext in results}
    assert len(ids) == len(secrets) == 8, "concurrent creation collided"

    for _, plaintext in results:
        response = await client.get(
            "/v1/workspaces/me", headers={"Authorization": f"Bearer {plaintext}"}
        )
        assert response.status_code == 200
        assert response.json()["id"] == str(workspace_a.id)


async def test_authentication_racing_revocation_never_yields_a_torn_state(
    client: AsyncClient,
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """Authenticate and revoke the same credential simultaneously, repeatedly.

    The only outcomes Postgres permits are "authenticated before the revocation committed"
    (200) and "after" (401). This asserts the observed set is exactly that — never a 500,
    never a partially applied state — and that once the dust settles the credential is
    dead and was revoked exactly once.
    """
    owner = await owner_of(admin_engine, workspace_a.id)
    async with manager(app_engine, workspace_a.id, owner) as admin:
        token_id, plaintext, _ = await mint(admin)
    headers = {"Authorization": f"Bearer {plaintext}"}

    async def authenticate() -> int:
        return (await client.get("/v1/workspaces/me", headers=headers)).status_code

    async def revoke() -> int:
        async with manager(app_engine, workspace_a.id, owner) as admin:
            return (await admin.delete(f"/v1/api-tokens/{token_id}")).status_code

    outcomes = await asyncio.gather(
        authenticate(), revoke(), authenticate(), revoke(), authenticate()
    )

    auth_results = {outcomes[0], outcomes[2], outcomes[4]}
    revoke_results = {outcomes[1], outcomes[3]}
    assert auth_results <= {200, 401}, f"unexpected authentication outcome: {auth_results}"
    assert revoke_results == {204}

    async with admin_engine.begin() as conn:
        distinct = await conn.scalar(
            text("SELECT count(DISTINCT revoked_at) FROM api_tokens WHERE id = :i"),
            {"i": token_id},
        )
    assert distinct == 1, "the token transitioned more than once"
    assert (await client.get("/v1/workspaces/me", headers=headers)).status_code == 401


# =======================================================================================
# LIFECYCLE K — one secret audit across the entire lifecycle
# =======================================================================================


async def test_no_secret_reaches_the_log_stream_across_the_whole_lifecycle(
    client: AsyncClient,
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """Capture every log line emitted by create → authenticate → list → revoke → denied.

    A per-module log test can miss a leak that only occurs when one module hands a value to
    another. This drives the whole arc inside one stdout capture and searches the emitted
    text for the plaintext, the secret body, the stored digest, and the raw Authorization
    header value.

    `assert emitted` runs first and is doing real work: `configure_logging` installs
    `PrintLoggerFactory`, so `caplog` sees nothing, and structlog freezes a logger's level
    filter on first use — which is why the level is pinned session-wide in `conftest.py`
    rather than here. Without that guard this test would pass against an empty buffer,
    exactly as M1.2-F's did until CI caught it.
    """
    owner = await owner_of(admin_engine, workspace_a.id)
    buffer = io.StringIO()

    with contextlib.redirect_stdout(buffer):
        async with manager(app_engine, workspace_a.id, owner) as admin:
            token_id, plaintext, _ = await mint(admin, name="audited")
            headers = {"Authorization": f"Bearer {plaintext}"}
            await client.get("/v1/workspaces/me", headers=headers)
            await admin.get("/v1/api-tokens", params={"limit": 100})
            await admin.delete(f"/v1/api-tokens/{token_id}")
            await client.get("/v1/workspaces/me", headers=headers)

    emitted = buffer.getvalue()
    assert emitted, "nothing was logged — every assertion below would be vacuous"
    assert "http.request" in emitted, "request logging did not run; the capture is not the app's"

    row = await db_row(admin_engine, token_id)
    assert plaintext not in emitted, "the plaintext reached the log stream"
    assert plaintext.removeprefix(TOKEN_PREFIX) not in emitted
    assert row["token_hash"] not in emitted, "the stored digest reached the log stream"
    assert f"Bearer {plaintext}" not in emitted


async def test_lifecycle_tenant_isolation_holds_with_rls_bypassed(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """The lifecycle's isolation claim, re-checked with Postgres's net removed.

    Every other test in this file goes through HTTP with RLS armed, which means none of them
    can tell whether isolation came from the application's `workspace_id` predicate or from
    the database policy. That is not a theoretical distinction: deleting the predicate from
    the listing query, or from the revoking UPDATE, leaves this entire file green because
    RLS silently does the work — verified by mutation, and the reason this test exists.

    Both tokens are minted through the real endpoint, then the repositories are driven on a
    **superuser** session where RLS does not apply, so the application predicate is the only
    control left standing.
    """
    a_owner = await owner_of(admin_engine, workspace_a.id, "a")
    b_owner = await owner_of(admin_engine, workspace_b.id, "b")
    async with manager(app_engine, workspace_a.id, a_owner) as a_admin:
        a_token, _, _ = await mint(a_admin, name="a-token")
    async with manager(app_engine, workspace_b.id, b_owner) as b_admin:
        b_token, _, _ = await mint(b_admin, name="b-token")

    factory = async_sessionmaker(admin_engine, expire_on_commit=False)
    async with factory() as session, session.begin():
        assert await session.scalar(
            text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
        ), "this test proves nothing unless RLS is genuinely bypassed"

        a_repo = ApiTokenRepository(session, api_token_context(workspace_a.id))
        visible = {token.id for token in await a_repo.list_page(limit=100)}
        outcome = await a_repo.revoke(b_token)

    assert a_token in visible, "the workspace's own token was not listed"
    assert b_token not in visible, "another tenant's token was listed with RLS bypassed"
    assert outcome is RevocationOutcome.NOT_FOUND, "another tenant's token was revocable"
    assert (await db_row(admin_engine, b_token))["revoked_at"] is None


async def test_a_pooled_connection_carries_no_tenant_into_the_next_transaction(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Observe the GUC itself, rather than inferring it from request results.

    The interleaved lifecycle test above cannot prove transaction-locality: every request
    binds its own workspace, so a *session*-scoped binding would be overwritten each time
    and the results would look identical. Verified by mutation — switching `set_config`'s
    `is_local` flag to false leaves that test green.

    This reads `app.workspace_id` at the start of a fresh transaction on the same pool after
    a lifecycle request has run. Empty is the only safe answer: a value surviving here is a
    tenant inherited by whichever request picks up the connection next, and any request that
    then failed to bind would silently read the previous tenant's rows.
    """
    owner = await owner_of(admin_engine, workspace_a.id)
    async with manager(app_engine, workspace_a.id, owner) as admin:
        token_id, _, _ = await mint(admin)
        await admin.get("/v1/api-tokens", params={"limit": 10})
        await admin.delete(f"/v1/api-tokens/{token_id}")

    factory = async_sessionmaker(app_engine, expire_on_commit=False)
    for _ in range(3):
        async with factory() as session, session.begin():
            inherited = await session.scalar(
                text("SELECT current_setting('app.workspace_id', true)")
            )
            assert not inherited, f"a pooled connection inherited a tenant: {inherited!r}"
            # And with nothing bound, the tenant tables must be empty rather than open.
            assert await session.scalar(text("SELECT count(*) FROM api_tokens")) == 0
