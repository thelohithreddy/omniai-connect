"""The workspace notification destination at the HTTP edge. Real Postgres, real RLS, real auth.

The destination is PII a human typed, and it is the one input that decides where mail goes. So the
questions here are not "does the field persist" but: who may set it, who may read it, can it be
aimed at another tenant, and can it leak to a caller who should not see it.

The last one has its own test for a reason. `GET /v1/workspaces/me` authenticates with
`CurrentWorkspace`, which every **machine token** satisfies — a token has no membership and
therefore no permissions (ADR-0002). Putting `notification_email` on that response would hand the
address to every MCP client holding a workspace token, which is why it lives on a separate
`workspace:manage` endpoint instead.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.conftest import FakeJWKSEndpoint, SeededWorkspace, SigningAuthority, bearer
from tests.integration.test_human_auth import seed_member

WS_HEADER = "X-Workspace-Id"
SETTINGS = "/v1/workspaces/me/notification-settings"
PATCH = "/v1/workspaces/me"

#: Distinct from any other canary in the suite so a leak can be attributed to this feature.
DESTINATION = "m210-owner-canary@example.com"


async def human_headers(
    engine: AsyncEngine,
    workspace: SeededWorkspace,
    authority: SigningAuthority,
    role: str,
    subject: str,
) -> dict[str, str]:
    await seed_member(engine, workspace.id, user_id=subject, role=role)
    return {**bearer(authority.sign(subject)), WS_HEADER: str(workspace.id)}


async def stored_destination(engine: AsyncEngine, workspace_id: uuid.UUID) -> str | None:
    """Read the column as the superuser — the database is the authority, not the response body."""
    async with engine.connect() as conn:
        return (
            await conn.execute(
                text("SELECT notification_email FROM workspaces WHERE id = :i"),
                {"i": workspace_id},
            )
        ).scalar()


async def owner(
    engine: AsyncEngine, workspace: SeededWorkspace, authority: SigningAuthority
) -> dict[str, str]:
    return await human_headers(
        engine, workspace, authority, "owner", f"m210-owner-{uuid.uuid4().hex[:8]}"
    )


# --------------------------------------------------------------------------- setting and clearing


@pytest.mark.asyncio
async def test_an_owner_sets_the_destination_and_it_reaches_the_database(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
) -> None:
    http, _ = human_client
    headers = await owner(admin_engine, workspace_a, authority)

    response = await http.patch(PATCH, json={"notification_email": DESTINATION}, headers=headers)

    assert response.status_code == 200, response.text
    assert response.json()["notification_email"] == DESTINATION
    assert await stored_destination(admin_engine, workspace_a.id) == DESTINATION


@pytest.mark.asyncio
async def test_the_destination_is_normalized_exactly_like_an_invitation(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
) -> None:
    """`strip().lower()` — the same treatment `invited_email` gets (ADR-0017), so the two email
    columns cannot disagree about what the "same" address is."""
    http, _ = human_client
    headers = await owner(admin_engine, workspace_a, authority)

    response = await http.patch(
        PATCH, json={"notification_email": "  M210-Owner-CANARY@Example.COM  "}, headers=headers
    )

    assert response.status_code == 200, response.text
    assert await stored_destination(admin_engine, workspace_a.id) == DESTINATION


@pytest.mark.asyncio
@pytest.mark.parametrize("cleared", [None, "", "   "])
async def test_an_owner_can_disable_notifications(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
    cleared: str | None,
) -> None:
    """Null and an emptied form field both mean "off". Turning notifications off must not require
    inventing a sentinel address."""
    http, _ = human_client
    headers = await owner(admin_engine, workspace_a, authority)
    await http.patch(PATCH, json={"notification_email": DESTINATION}, headers=headers)

    response = await http.patch(PATCH, json={"notification_email": cleared}, headers=headers)

    assert response.status_code == 200, response.text
    assert response.json()["notification_email"] is None
    assert await stored_destination(admin_engine, workspace_a.id) is None


@pytest.mark.asyncio
async def test_an_unset_destination_reads_as_null_rather_than_failing(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
) -> None:
    """Every Workspace that existed before migration 0015 is in exactly this state."""
    http, _ = human_client
    headers = await owner(admin_engine, workspace_a, authority)

    response = await http.get(SETTINGS, headers=headers)

    assert response.status_code == 200, response.text
    assert response.json() == {"notification_email": None}


@pytest.mark.asyncio
async def test_the_destination_round_trips_through_the_read_endpoint(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
) -> None:
    http, _ = human_client
    headers = await owner(admin_engine, workspace_a, authority)
    await http.patch(PATCH, json={"notification_email": DESTINATION}, headers=headers)

    response = await http.get(SETTINGS, headers=headers)

    assert response.status_code == 200, response.text
    assert response.json()["notification_email"] == DESTINATION


# ------------------------------------------------------------------------------------ validation


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad", ["not-an-email", "@example.com", "user@", "user@localhost", "a b@example.com"]
)
async def test_a_malformed_destination_is_refused(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
    bad: str,
) -> None:
    http, _ = human_client
    headers = await owner(admin_engine, workspace_a, authority)

    response = await http.patch(PATCH, json={"notification_email": bad}, headers=headers)

    assert response.status_code == 400, response.text
    assert await stored_destination(admin_engine, workspace_a.id) is None


@pytest.mark.asyncio
async def test_the_endpoint_refuses_to_become_a_general_workspace_mutator(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
) -> None:
    """`extra="forbid"`. Accepting-and-ignoring a `plan` field would look to the caller like a
    working billing change; the slug is the workspace's public identity and is not editable here."""
    http, _ = human_client
    headers = await owner(admin_engine, workspace_a, authority)

    response = await http.patch(
        PATCH,
        json={"notification_email": DESTINATION, "plan": "enterprise", "slug": "hijacked"},
        headers=headers,
    )

    assert response.status_code == 400, response.text
    async with admin_engine.connect() as conn:
        row = (
            await conn.execute(
                text("SELECT plan, slug FROM workspaces WHERE id = :i"), {"i": workspace_a.id}
            )
        ).first()
    assert row is not None
    assert row[0] == "free"
    assert row[1] == workspace_a.slug


@pytest.mark.asyncio
async def test_an_over_long_destination_cannot_reach_the_column(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
) -> None:
    """A 320-character column plus an unbounded input is a 500 waiting to happen."""
    http, _ = human_client
    headers = await owner(admin_engine, workspace_a, authority)
    huge = ("a" * 400) + "@example.com"

    response = await http.patch(PATCH, json={"notification_email": huge}, headers=headers)

    assert response.status_code == 400, response.text
    assert await stored_destination(admin_engine, workspace_a.id) is None


# ------------------------------------------------------------------------------------------ RBAC


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["admin", "member", "viewer"])
async def test_only_an_owner_may_set_the_destination(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
    role: str,
) -> None:
    """`workspace:manage` is OWNER-only in the canonical matrix, and ADR-0041 ratified it for this
    endpoint. ADMIN is denied deliberately — it holds `connections:manage`, which is custody of
    credentials, not authority over where the Workspace's mail goes."""
    http, _ = human_client
    headers = await human_headers(
        admin_engine, workspace_a, authority, role, f"m210-{role}-{uuid.uuid4().hex[:8]}"
    )

    response = await http.patch(PATCH, json={"notification_email": DESTINATION}, headers=headers)

    assert response.status_code == 403, response.text
    assert await stored_destination(admin_engine, workspace_a.id) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["admin", "member", "viewer"])
async def test_only_an_owner_may_read_the_destination(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
    role: str,
) -> None:
    http, _ = human_client
    headers = await human_headers(
        admin_engine, workspace_a, authority, role, f"m210-r-{role}-{uuid.uuid4().hex[:8]}"
    )

    response = await http.get(SETTINGS, headers=headers)

    assert response.status_code == 403, response.text


@pytest.mark.asyncio
async def test_an_unauthenticated_caller_is_refused(client: AsyncClient) -> None:
    assert (await client.patch(PATCH, json={"notification_email": DESTINATION})).status_code == 401
    assert (await client.get(SETTINGS)).status_code == 401


@pytest.mark.asyncio
async def test_a_machine_token_holds_no_permissions_and_is_refused(
    client: AsyncClient, workspace_a: SeededWorkspace, admin_engine: AsyncEngine
) -> None:
    """A workspace token authenticates but has no membership, so it has no role and no
    permissions (ADR-0002). Treating it as its workspace's owner is the confused-deputy pattern
    the authorization boundary exists to prevent."""
    headers = bearer(workspace_a.token.plaintext)

    response = await client.patch(PATCH, json={"notification_email": DESTINATION}, headers=headers)

    assert response.status_code == 403, response.text
    assert await stored_destination(admin_engine, workspace_a.id) is None


# ------------------------------------------------------------------------- PII / tenant boundary


@pytest.mark.asyncio
async def test_the_destination_never_appears_on_the_token_readable_workspace_read(
    client: AsyncClient,
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
) -> None:
    """The PII boundary, asserted on the response body rather than argued in a docstring."""
    http, _ = human_client
    headers = await owner(admin_engine, workspace_a, authority)
    await http.patch(PATCH, json={"notification_email": DESTINATION}, headers=headers)

    response = await client.get("/v1/workspaces/me", headers=bearer(workspace_a.token.plaintext))

    assert response.status_code == 200, response.text
    assert "notification_email" not in response.json()
    assert DESTINATION not in response.text


@pytest.mark.asyncio
async def test_one_workspace_cannot_set_anothers_destination(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    authority: SigningAuthority,
) -> None:
    """The endpoint takes no workspace id at all, so the only lever a caller has is the workspace
    they authenticated against — and an owner of A is nobody in B."""
    http, _ = human_client
    subject = f"m210-cross-{uuid.uuid4().hex[:8]}"
    await seed_member(admin_engine, workspace_a.id, user_id=subject, role="owner")
    forged = {**bearer(authority.sign(subject)), WS_HEADER: str(workspace_b.id)}

    response = await http.patch(PATCH, json={"notification_email": DESTINATION}, headers=forged)

    assert response.status_code in (401, 403), response.text
    assert await stored_destination(admin_engine, workspace_b.id) is None


@pytest.mark.asyncio
async def test_setting_one_workspaces_destination_leaves_the_other_untouched(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    authority: SigningAuthority,
) -> None:
    """An UPDATE whose tenant predicate was dropped would write every row in the table."""
    http, _ = human_client
    headers = await owner(admin_engine, workspace_a, authority)

    await http.patch(PATCH, json={"notification_email": DESTINATION}, headers=headers)

    assert await stored_destination(admin_engine, workspace_a.id) == DESTINATION
    assert await stored_destination(admin_engine, workspace_b.id) is None


@pytest.mark.asyncio
async def test_one_workspaces_owner_cannot_read_anothers_destination(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    authority: SigningAuthority,
) -> None:
    http, _ = human_client
    b_owner = await owner(admin_engine, workspace_b, authority)
    await http.patch(PATCH, json={"notification_email": DESTINATION}, headers=b_owner)

    a_owner = await owner(admin_engine, workspace_a, authority)
    response = await http.get(SETTINGS, headers=a_owner)

    assert response.status_code == 200, response.text
    assert response.json()["notification_email"] is None
    assert DESTINATION not in response.text
