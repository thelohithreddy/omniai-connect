"""API token listing: an inventory of credentials that never discloses one.

Listing is an information-disclosure boundary, so the properties under test are mostly
about what the endpoint *refuses* to do:

1. **It cannot emit a secret.** Not "it filters one out" — there is no stored plaintext and
   no field on the read model able to carry one, and that is asserted against every byte of
   the response rather than against the fields we expect.
2. **It cannot be pointed at another tenant.** No query, path, body, or header field names
   a Workspace; the cursor carries a position, not an authority; and a hand-forged cursor
   is proven not to cross a tenant boundary.
3. **It requires human membership holding `api_tokens:manage`.** A machine token cannot
   enumerate the Workspace's credentials, exactly as it cannot mint one.
4. **Pagination is stable under concurrent writes**, which is the property offset
   pagination fails and the reason API_GUIDELINES.md §3 forbids it.
"""

from __future__ import annotations

import base64
import contextlib
import io
import uuid
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.core.exceptions import ValidationFailedError
from app.core.ids import new_id
from app.core.pagination import CursorPosition, decode_cursor, encode_cursor
from app.core.security import generate_token
from app.domains.workspaces.repository import ApiTokenRepository
from tests.conftest import SeededWorkspace
from tests.integration.test_api_token_creation import (
    api_token_context,
    bound_service,
    build_token_app,
    member_context,
)
from tests.integration.test_members_tenancy import seed_member

pytestmark = pytest.mark.asyncio


async def seed_tokens(engine: AsyncEngine, workspace_id: uuid.UUID, count: int) -> list[uuid.UUID]:
    """Insert `count` tokens out-of-band, oldest first, as the superuser.

    Seeded directly rather than through the service because these are *preconditions*, and
    several tests need rows in another Workspace — something no application code is allowed
    to do. `created_at` is set explicitly and monotonically so ordering assertions test the
    query's ORDER BY rather than accidental insertion timing.
    """
    ids: list[uuid.UUID] = []
    async with engine.begin() as conn:
        for index in range(count):
            token_id = new_id()
            generated = generate_token()
            await conn.execute(
                text(
                    "INSERT INTO api_tokens"
                    " (id, workspace_id, name, token_hash, token_prefix, scopes, created_at)"
                    " VALUES (:i, :w, :n, :h, :p, '[]'::jsonb,"
                    "         now() - make_interval(secs => :offset))"
                ),
                {
                    "i": token_id,
                    "w": workspace_id,
                    "n": f"token-{index}",
                    "h": generated.token_hash,
                    "p": generated.token_prefix,
                    "offset": float(count - index),
                },
            )
            ids.append(token_id)
    return ids


async def listing_client(app_engine: AsyncEngine, context_factory: Any) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=build_token_app(app_engine, context_factory)),
        base_url="http://t",
    )


# =======================================================================================
# A–D. Listing, ordering, and pagination
# =======================================================================================


async def test_lists_the_workspaces_tokens_newest_first(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    await seed_tokens(admin_engine, workspace_a.id, 3)
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")

    async with await listing_client(
        app_engine, lambda: member_context(workspace_a.id, owner)
    ) as client:
        response = await client.get("/v1/api-tokens")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["has_more"] is False
    assert body["next_cursor"] is None
    # 3 seeded + the 1 the workspace fixture creates.
    names = [item["name"] for item in body["data"]]
    assert names == ["a-token", "token-2", "token-1", "token-0"], names


async def test_an_empty_workspace_returns_an_empty_page_not_an_error(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Absence of tokens is a valid answer, not a 404.

    A 404 here would be wrong twice: the collection exists, and conflating "you have no
    tokens" with "no such resource" would make the endpoint's own existence depend on its
    contents.
    """
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    async with admin_engine.begin() as conn:
        await conn.execute(
            text("DELETE FROM api_tokens WHERE workspace_id = :w"), {"w": workspace_a.id}
        )

    async with await listing_client(
        app_engine, lambda: member_context(workspace_a.id, owner)
    ) as client:
        response = await client.get("/v1/api-tokens")

    assert response.status_code == 200
    assert response.json() == {"data": [], "next_cursor": None, "has_more": False}


async def test_pages_through_every_token_exactly_once(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """The core pagination property: complete coverage, no repeats.

    Walks the whole collection two rows at a time and asserts the union is exactly the
    tenant's tokens with no duplicates — which is what catches an off-by-one in the
    over-fetch (`limit + 1`) that would either skip a row at every boundary or serve one
    twice.
    """
    await seed_tokens(admin_engine, workspace_a.id, 6)
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")

    seen: list[str] = []
    cursor: str | None = None
    async with await listing_client(
        app_engine, lambda: member_context(workspace_a.id, owner)
    ) as client:
        for _ in range(10):  # bounded so a broken cursor loops finitely, not forever
            params = {"limit": 2} | ({"cursor": cursor} if cursor else {})
            body = (await client.get("/v1/api-tokens", params=params)).json()
            seen.extend(item["id"] for item in body["data"])
            cursor = body["next_cursor"]
            if not body["has_more"]:
                break

    assert cursor is None
    assert len(seen) == 7, seen  # 6 seeded + 1 from the workspace fixture
    assert len(set(seen)) == len(seen), "a token was served on more than one page"


async def test_has_more_and_next_cursor_agree(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """§3: `next_cursor` is null exactly when `has_more` is false.

    A client loops until the cursor is null, so the two fields disagreeing is either an
    infinite loop or a truncated listing.
    """
    await seed_tokens(admin_engine, workspace_a.id, 3)
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")

    async with await listing_client(
        app_engine, lambda: member_context(workspace_a.id, owner)
    ) as client:
        first = (await client.get("/v1/api-tokens", params={"limit": 2})).json()
        last = (await client.get("/v1/api-tokens", params={"limit": 100})).json()

    assert first["has_more"] is True and first["next_cursor"] is not None
    assert last["has_more"] is False and last["next_cursor"] is None


async def test_a_page_is_stable_when_a_token_is_created_mid_pagination(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """The exact failure offset pagination has, and the reason §3 forbids it.

    A row inserted between two page requests shifts every subsequent offset by one, so the
    client re-reads a row it already saw and never sees another. A keyset cursor asks for
    "rows after *this row*", so the second page is unaffected by anything inserted at the
    front — and the neighbouring endpoint's whole job is inserting at the front.
    """
    await seed_tokens(admin_engine, workspace_a.id, 4)
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")

    async with await listing_client(
        app_engine, lambda: member_context(workspace_a.id, owner)
    ) as client:
        first = (await client.get("/v1/api-tokens", params={"limit": 2})).json()
        await seed_tokens(admin_engine, workspace_a.id, 1)  # concurrent issuance
        second = (
            await client.get("/v1/api-tokens", params={"limit": 2, "cursor": first["next_cursor"]})
        ).json()

    first_ids = {item["id"] for item in first["data"]}
    second_ids = {item["id"] for item in second["data"]}
    assert first_ids & second_ids == set(), "a row was served twice across a concurrent insert"


async def test_ordering_is_deterministic_when_timestamps_tie(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """`created_at` alone is not a unique sort key.

    Tokens minted in the same microsecond tie, and a keyset predicate over a non-unique key
    either skips rows or serves one forever. This forces an exact tie and asserts the page
    is still complete and duplicate-free, which only holds because `id` breaks it.
    """
    async with admin_engine.begin() as conn:
        for index in range(4):
            generated = generate_token()
            await conn.execute(
                text(
                    "INSERT INTO api_tokens"
                    " (id, workspace_id, name, token_hash, token_prefix, scopes, created_at)"
                    " VALUES (:i, :w, :n, :h, :p, '[]'::jsonb,"
                    "         timestamptz '2026-08-14 00:00:00+00')"
                ),
                {
                    "i": new_id(),
                    "w": workspace_a.id,
                    "n": f"tied-{index}",
                    "h": generated.token_hash,
                    "p": generated.token_prefix,
                },
            )

    collected: list[uuid.UUID] = []
    cursor = None
    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        for _ in range(10):
            page = await service.list_tokens(limit=2, cursor=cursor)
            collected.extend(token.id for token in page.tokens)
            cursor = page.next_cursor
            if not page.has_more:
                break

    assert len(collected) == 5, collected  # 4 tied + the fixture's token
    assert len(set(collected)) == len(collected), "a tied row repeated across pages"


# =======================================================================================
# E–H. Authentication and authorization
# =======================================================================================


async def test_listing_requires_authentication(
    client: AsyncClient, workspace_a: SeededWorkspace
) -> None:
    response = await client.get("/v1/api-tokens")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


@pytest.mark.parametrize(
    ("role", "expected"), [("owner", 200), ("admin", 200), ("member", 403), ("viewer", 403)]
)
async def test_admits_exactly_the_roles_holding_api_tokens_manage(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    role: str,
    expected: int,
) -> None:
    """Mirrors SECURITY.md §4.1, asserted through HTTP so it tests the *wiring*.

    A policy unit test would pass even if the route forgot the dependency entirely.
    """
    member = await seed_member(admin_engine, workspace_a.id, user_id=f"u-{role}", role=role)
    async with await listing_client(
        app_engine, lambda: member_context(workspace_a.id, member)
    ) as client:
        response = await client.get("/v1/api-tokens")

    assert response.status_code == expected, response.text
    if expected == 403:
        assert response.json()["error"]["code"] == "forbidden"


async def test_a_machine_token_cannot_enumerate_the_workspaces_credentials(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """A leaked token must not be able to inventory its Workspace's other credentials.

    Reconnaissance is the first step of using a stolen credential well: knowing how many
    tokens exist, what they are named, and which are already revoked tells an attacker
    which one to impersonate and when they are likely to be noticed. Machine identity
    resolves to no membership (ADR-0002), so the same boundary that stops it minting a
    token stops it reading the list.
    """
    await seed_tokens(admin_engine, workspace_a.id, 2)
    async with await listing_client(
        app_engine, lambda: api_token_context(workspace_a.id)
    ) as client:
        response = await client.get("/v1/api-tokens")

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


async def test_a_confused_deputy_token_naming_a_real_owner_is_still_denied(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """A machine context that also carries a real, privileged member id must not inherit it."""
    from app.core.security import CallerIdentity, WorkspaceContext

    owner = await seed_member(admin_engine, workspace_a.id, user_id="real-owner", role="owner")
    deputy = WorkspaceContext(
        workspace_id=workspace_a.id,
        caller=CallerIdentity(kind="api_token", api_token_id=uuid.uuid4(), member_id=owner),
        request_id="req_test",
    )

    async with await listing_client(app_engine, lambda: deputy) as client:
        response = await client.get("/v1/api-tokens")

    assert response.status_code == 403


# =======================================================================================
# I–K. Tenant isolation
# =======================================================================================


async def test_another_workspaces_tokens_are_never_listed(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    await seed_tokens(admin_engine, workspace_b.id, 5)
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")

    async with await listing_client(
        app_engine, lambda: member_context(workspace_a.id, owner)
    ) as client:
        body = (await client.get("/v1/api-tokens", params={"limit": 100})).json()

    assert all(item["name"] == "a-token" for item in body["data"]), body["data"]
    assert len(body["data"]) == 1
    assert body["has_more"] is False


async def test_the_same_user_sees_only_the_workspace_they_authenticated_against(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Owner of A and owner of B, authenticated against A. Roles are per-Workspace.

    The isolation holds without any comparison in the listing code: B's membership row is
    simply unreachable from A's context, and B's tokens fail both the repository predicate
    and the RLS policy.
    """
    await seed_tokens(admin_engine, workspace_b.id, 3)
    a_member = await seed_member(admin_engine, workspace_a.id, user_id="dual", role="owner")
    await seed_member(admin_engine, workspace_b.id, user_id="dual", role="owner")

    async with await listing_client(
        app_engine, lambda: member_context(workspace_a.id, a_member)
    ) as client:
        body = (await client.get("/v1/api-tokens", params={"limit": 100})).json()

    assert len(body["data"]) == 1
    assert body["data"][0]["name"] == "a-token"


@pytest.mark.parametrize(
    "params",
    [
        {"workspace_id": "11111111-1111-1111-1111-111111111111"},
        {"workspace": "11111111-1111-1111-1111-111111111111"},
        {"role": "owner"},
        {"permission": "api_tokens:manage"},
        {"member_id": "11111111-1111-1111-1111-111111111111"},
        {"sort": "-created_at"},
        {"revoked": "false"},
        {"limlt": "5"},
    ],
)
async def test_caller_supplied_control_parameters_are_refused_not_ignored(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    params: dict[str, str],
) -> None:
    """§4: unknown parameters are a `validation_error`, never silently dropped.

    Two different dangers in one assertion. A caller must not be able to *name* a tenant,
    a role, or a permission — those come from the authenticated context and nowhere else.
    And a caller who misspells a filter (`limlt`) or asks for one this endpoint does not
    support (`revoked`) must not receive a cheerful 200 containing everything while
    believing the result was filtered.
    """
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    async with await listing_client(
        app_engine, lambda: member_context(workspace_a.id, owner)
    ) as client:
        response = await client.get("/v1/api-tokens", params=params)

    assert response.status_code == 400, response.text
    assert response.json()["error"]["code"] == "validation_error"


async def test_a_forged_cursor_cannot_reach_another_tenant(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """The cursor is a position, not an authority.

    Hand-builds a cursor from a row that genuinely exists in Workspace B and replays it
    against Workspace A. It is accepted as a *position* — it is well-formed — and still
    yields only A's rows, because the tenant predicate comes from the authenticated context
    and is applied independently of anything the cursor says. This is the property that
    makes leaving the cursor unsigned safe.
    """
    b_tokens = await seed_tokens(admin_engine, workspace_b.id, 3)
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    async with admin_engine.begin() as conn:
        created_at = await conn.scalar(
            text("SELECT created_at FROM api_tokens WHERE id = :i"), {"i": b_tokens[0]}
        )
    forged = encode_cursor(CursorPosition(created_at=created_at, id=b_tokens[0]))

    async with await listing_client(
        app_engine, lambda: member_context(workspace_a.id, owner)
    ) as client:
        response = await client.get("/v1/api-tokens", params={"cursor": forged, "limit": 100})

    assert response.status_code == 200
    for item in response.json()["data"]:
        assert uuid.UUID(item["id"]) not in b_tokens


async def test_application_scoping_holds_even_with_rls_bypassed(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    """Layer 1 in isolation, with layer 2 removed.

    Runs the repository on a **superuser** session where RLS does not apply, so the only
    remaining control is the `workspace_id` predicate in the query. Without this, every
    tenancy assertion in this file would still pass if someone deleted that predicate —
    RLS would quietly do the work and the application-level guarantee would rot unnoticed.
    """
    await seed_tokens(admin_engine, workspace_b.id, 4)
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(admin_engine, expire_on_commit=False)
    async with factory() as session, session.begin():
        is_superuser = await session.scalar(
            text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
        )
        assert is_superuser, "this test proves nothing unless RLS is genuinely bypassed"

        repository = ApiTokenRepository(session, api_token_context(workspace_a.id))
        rows = await repository.list_page(limit=100)

    assert rows, "expected the workspace's own tokens"
    assert all(token.workspace_id == workspace_a.id for token in rows)


# =======================================================================================
# N–P. Secret and metadata disclosure
# =======================================================================================


async def test_the_listing_never_discloses_a_secret_or_a_hash(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Asserted against the raw response bytes, not against the fields we expect.

    Comparing the parsed keys would miss a secret smuggled inside a nested object or a
    message string. The stored hashes are read back out-of-band and searched for in the
    response text, which is the assertion that fails if anyone ever adds `token_hash` to
    the read model for debugging.
    """
    await seed_tokens(admin_engine, workspace_a.id, 3)
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    async with admin_engine.begin() as conn:
        hashes = list(
            (
                await conn.execute(
                    text("SELECT token_hash FROM api_tokens WHERE workspace_id = :w"),
                    {"w": workspace_a.id},
                )
            ).scalars()
        )

    async with await listing_client(
        app_engine, lambda: member_context(workspace_a.id, owner)
    ) as client:
        response = await client.get("/v1/api-tokens", params={"limit": 100})

    raw = response.text
    assert hashes
    for token_hash in hashes:
        assert token_hash not in raw, "a token hash was disclosed by the listing"
    for item in response.json()["data"]:
        assert set(item) == {
            "id",
            "name",
            "token_prefix",
            "scopes",
            "last_used_at",
            "expires_at",
            "revoked_at",
            "created_at",
        }


async def test_an_issued_token_is_not_recoverable_through_the_listing(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """End to end across both endpoints: mint, then try to read the secret back.

    The strongest form of "shown once" — the plaintext is captured at issuance and then
    searched for in the listing that follows. Only the public display prefix survives, and
    the prefix is asserted to be a fragment rather than the secret.
    """
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    async with await listing_client(
        app_engine, lambda: member_context(workspace_a.id, owner)
    ) as client:
        created = await client.post("/v1/api-tokens", json={"name": "ci"})
        assert created.status_code == 201
        plaintext = created.json()["token"]

        listed = await client.get("/v1/api-tokens", params={"limit": 100})

    assert listed.status_code == 200
    assert plaintext not in listed.text
    assert plaintext.removeprefix("omc_") not in listed.text
    prefixes = [item["token_prefix"] for item in listed.json()["data"]]
    assert created.json()["token_prefix"] in prefixes


async def test_a_denied_caller_learns_nothing_about_the_workspace(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """A 403 body must not become a side channel.

    No token count, no ids, no prefixes, no names, no workspace id, and not even the name
    of the permission required — that last one would tell a prober exactly which capability
    to go acquire, and enumerating "which permission does this endpoint want" across an API
    maps its whole authorization surface.
    """
    await seed_tokens(admin_engine, workspace_a.id, 3)
    member = await seed_member(admin_engine, workspace_a.id, user_id="plain", role="member")

    async with await listing_client(
        app_engine, lambda: member_context(workspace_a.id, member)
    ) as client:
        response = await client.get("/v1/api-tokens")

    assert response.status_code == 403
    raw = response.text
    assert str(workspace_a.id) not in raw
    assert "api_tokens" not in raw
    assert "token" not in raw.lower().replace("api-tokens", "")
    assert response.json()["error"].get("details") is None


# =======================================================================================
# Q–T. Contract, transactions, and layering
# =======================================================================================


async def test_errors_use_the_canonical_envelope_with_a_request_id(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """§6: one envelope, always, and `request_id` matches `X-Request-Id`."""
    member = await seed_member(admin_engine, workspace_a.id, user_id="plain", role="member")
    async with await listing_client(
        app_engine, lambda: member_context(workspace_a.id, member)
    ) as client:
        response = await client.get("/v1/api-tokens")

    error = response.json()["error"]
    assert set(error) >= {"code", "message", "request_id"}
    assert error["code"] == "forbidden"
    assert error["request_id"]
    assert error["request_id"] == response.headers["X-Request-Id"]


@pytest.mark.parametrize(
    "cursor", ["not-base64", "", "!!!!", base64.urlsafe_b64encode(b"x|y").decode()]
)
async def test_an_unusable_cursor_is_a_validation_error_not_an_empty_page(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    cursor: str,
) -> None:
    """§3: an expired or malformed cursor yields `validation_error`.

    Silently serving page one for a bad cursor would be worse than an error: a client
    paginating through an inventory would loop forever, or believe it had reached the end
    of a list it had barely started.
    """
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    async with await listing_client(
        app_engine, lambda: member_context(workspace_a.id, owner)
    ) as client:
        response = await client.get("/v1/api-tokens", params={"cursor": cursor})

    assert response.status_code == 400, response.text
    assert response.json()["error"]["code"] == "validation_error"


@pytest.mark.parametrize("limit", [0, -1, 101, 1000])
async def test_limit_is_bounded(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, limit: int
) -> None:
    """§3 caps the page at 100. Without a ceiling, `?limit=10000000` is a table read."""
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    async with await listing_client(
        app_engine, lambda: member_context(workspace_a.id, owner)
    ) as client:
        response = await client.get("/v1/api-tokens", params={"limit": limit})

    assert response.status_code == 400, response.text


async def test_the_service_rejects_an_unbounded_limit_from_a_non_http_caller(
    app_session: AsyncSession, workspace_a: SeededWorkspace
) -> None:
    """The HTTP ceiling is not the only one.

    A Celery task or MCP adapter calls the service directly (BACKEND_SPEC.md §2), bypassing
    FastAPI's `Query(le=100)` entirely. The bound is enforced in the service too, so the
    limit is a property of the operation rather than of one transport.
    """
    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        with pytest.raises(ValidationFailedError):
            await service.list_tokens(limit=100_000)


async def test_listing_writes_nothing(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """A read must stay a read.

    Compares the full table state before and after, so a stray `flush`, an accidental
    attribute mutation flushed by autoflush, or a `last_used_at` "touch" added later would
    be caught. `xact_commit` is not asserted — the UnitOfWork legitimately commits an empty
    transaction — but no *row* may change.
    """
    await seed_tokens(admin_engine, workspace_a.id, 3)
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")

    async def snapshot() -> list[tuple[Any, ...]]:
        async with admin_engine.begin() as conn:
            rows = await conn.execute(
                text(
                    "SELECT id, name, token_hash, token_prefix, scopes, last_used_at,"
                    " expires_at, revoked_at, created_at, updated_at"
                    " FROM api_tokens WHERE workspace_id = :w ORDER BY id"
                ),
                {"w": workspace_a.id},
            )
            return [tuple(row) for row in rows]

    before = await snapshot()
    async with await listing_client(
        app_engine, lambda: member_context(workspace_a.id, owner)
    ) as client:
        assert (await client.get("/v1/api-tokens", params={"limit": 100})).status_code == 200
    assert await snapshot() == before


async def test_repository_list_page_cannot_be_asked_for_another_tenant() -> None:
    """Layer 1, structurally: there is no parameter through which a tenant could be named."""
    params = set(ApiTokenRepository.list_page.__annotations__)

    assert params == {"limit", "after", "return"}
    assert "workspace_id" not in params


async def test_the_cursor_round_trips_exactly(workspace_a: SeededWorkspace) -> None:
    """Encoding is lossless, including microseconds.

    A truncated timestamp would make the keyset predicate straddle a row boundary and
    silently drop or repeat rows minted in the same second.
    """
    from datetime import UTC, datetime

    position = CursorPosition(
        created_at=datetime(2026, 8, 14, 10, 30, 15, 123456, tzinfo=UTC), id=new_id()
    )
    decoded = decode_cursor(encode_cursor(position))

    assert decoded == position
    assert decoded.created_at.microsecond == 123456


async def test_the_uow_is_shared_between_authorization_and_the_query(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """One transaction per request, or the tenant binding does not apply to the query.

    `bind_workspace` sets `app.workspace_id` with `SET LOCAL`, which lives and dies with a
    single transaction. If the authorization dependency and the repository ran on different
    sessions, the listing query would execute with no workspace bound and RLS would return
    nothing — so a successful, non-empty response is itself the proof they share one.
    """
    await seed_tokens(admin_engine, workspace_a.id, 2)
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")

    async with await listing_client(
        app_engine, lambda: member_context(workspace_a.id, owner)
    ) as client:
        body = (await client.get("/v1/api-tokens", params={"limit": 100})).json()

    assert len(body["data"]) == 3


async def test_workspace_context_does_not_leak_across_pooled_requests(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Consecutive requests for different tenants on a reused connection.

    `SET LOCAL` is transaction-scoped precisely so a returned connection carries no tenant
    into the next request. A session-scoped `SET` would pass this test's first half and
    leak on the second — A's rows appearing in B's response.
    """
    await seed_tokens(admin_engine, workspace_a.id, 2)
    await seed_tokens(admin_engine, workspace_b.id, 3)
    a_owner = await seed_member(admin_engine, workspace_a.id, user_id="a-owner", role="owner")
    b_owner = await seed_member(admin_engine, workspace_b.id, user_id="b-owner", role="owner")

    async with await listing_client(
        app_engine, lambda: member_context(workspace_a.id, a_owner)
    ) as client:
        first = (await client.get("/v1/api-tokens", params={"limit": 100})).json()
        second = (await client.get("/v1/api-tokens", params={"limit": 100})).json()
    async with await listing_client(
        app_engine, lambda: member_context(workspace_b.id, b_owner)
    ) as client:
        third = (await client.get("/v1/api-tokens", params={"limit": 100})).json()

    assert len(first["data"]) == len(second["data"]) == 3
    assert len(third["data"]) == 4
    assert {i["id"] for i in first["data"]} & {i["id"] for i in third["data"]} == set()


async def test_no_log_output_discloses_credential_material(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """A listing request must not write credential material into the log stream.

    The listing path has no logger of its own — the only emitter during the request is the
    middleware, which records method, path, status and duration. That is precisely why this
    test drives a real request through the middleware stack and captures stdout rather than
    asserting against the service in isolation: a check that observed nothing would pass
    while proving nothing, which is the failure M1.2-F's CI run exposed.

    `assert emitted` is the guard that keeps it honest, and the level is pinned session-wide
    by `_pin_log_level` because structlog freezes a logger's level filter on first use.
    """
    await seed_tokens(admin_engine, workspace_a.id, 2)
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    async with admin_engine.begin() as conn:
        hashes = list(
            (
                await conn.execute(
                    text("SELECT token_hash FROM api_tokens WHERE workspace_id = :w"),
                    {"w": workspace_a.id},
                )
            ).scalars()
        )

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        async with await listing_client(
            app_engine, lambda: member_context(workspace_a.id, owner)
        ) as client:
            response = await client.get("/v1/api-tokens", params={"limit": 100})

    assert response.status_code == 200
    emitted = buffer.getvalue()
    assert emitted, "nothing was logged — this assertion would pass vacuously"
    assert hashes
    for token_hash in hashes:
        assert token_hash not in emitted, "a token hash reached the log stream"
    # Display prefixes are deliberately not asserted absent: they are public by design
    # (SECURITY.md §4.3), so requiring them to stay out of logs would be a false property.
