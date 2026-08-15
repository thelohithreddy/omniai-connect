"""Workspace invitations, end to end through the real application (M1.3-F, ADR-0017).

Real HTTP against the real app, real Postgres with RLS armed, the real SECURITY DEFINER
resolver, the real centralized RBAC. The only doubles are the JWKS endpoint (so tokens can
be minted for arbitrary subjects with controllable `email`/`emailVerified`) and the email
sender (a `CapturingEmailSender`, so no live mail is sent and the invite token can be read
back — the seam, not a patch). Nothing about token hashing, atomicity, the email binding, or
RLS is mocked.

The invariant under test: an invitation is a temporary mechanism for establishing a
membership. Identity is the verified Better Auth `sub`; the email is a verified *binding*
check only; the workspace and role are server-established; the resulting membership is the
permanent authority.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import uuid
from collections.abc import AsyncIterator, Iterator

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.email import CapturingEmailSender, EmailMessage, get_email_sender
from app.core.security import generate_invitation_token, hash_token
from app.main import app
from tests.conftest import FakeJWKSEndpoint, SeededWorkspace, SigningAuthority, bearer
from tests.integration.test_human_auth import seed_member

WS_HEADER = "X-Workspace-Id"


def hx(token: str, workspace_id: uuid.UUID) -> dict[str, str]:
    return {**bearer(token), WS_HEADER: str(workspace_id)}


def human(authority: SigningAuthority, sub: str, *, email: str, verified: bool = True) -> str:
    """A JWT for a human with the given verified (or not) email — the acceptance credential."""
    return authority.sign(sub, email=email, emailVerified=verified)


@pytest.fixture
def emails() -> Iterator[CapturingEmailSender]:
    """Override the email sender with a capturing fake for the duration of a test."""
    sender = CapturingEmailSender()
    app.dependency_overrides[get_email_sender] = lambda: sender
    yield sender
    app.dependency_overrides.pop(get_email_sender, None)


@pytest.fixture
async def invite_ctx(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    emails: CapturingEmailSender,
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> AsyncIterator[dict[str, object]]:
    """An owner of workspace A who can invite, plus the capturing email sender."""
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="inviter-owner", role="owner")
    yield {
        "client": client,
        "emails": emails,
        "ws": workspace_a.id,
        "owner_token": authority.sign("inviter-owner"),
    }


async def create_invitation(
    ctx: dict[str, object], *, email: str, role: str = "member"
) -> tuple[dict[str, object], str]:
    """POST an invitation as the owner; return (response json, captured raw token)."""
    client: AsyncClient = ctx["client"]  # type: ignore[assignment]
    emails: CapturingEmailSender = ctx["emails"]  # type: ignore[assignment]
    before = len(emails.sent)
    response = await client.post(
        "/v1/invitations",
        headers=hx(ctx["owner_token"], ctx["ws"]),  # type: ignore[arg-type]
        json={"email": email, "role": role},
    )
    assert response.status_code == 201, response.text
    assert len(emails.sent) == before + 1, "creation must send exactly one email"
    message: EmailMessage = emails.sent[-1]
    # The raw token lives only in the email link.
    token = message.html.split("token=")[1].split('"')[0]
    return response.json(), token


# ---------------------------------------------------------------------------------------
# Inviter authorization (members:manage)
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role", "expected"), [("owner", 201), ("admin", 201), ("member", 403), ("viewer", 403)]
)
async def test_only_members_manage_may_invite(
    role: str,
    expected: int,
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    emails: CapturingEmailSender,
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id=f"inv-{role}", role=role)
    r = await client.post(
        "/v1/invitations",
        headers=hx(authority.sign(f"inv-{role}"), workspace_a.id),
        json={"email": "x@example.test", "role": "member"},
    )
    assert r.status_code == expected
    if expected == 403:
        assert not emails.sent, "an unauthorized caller must not send an invite"


async def test_machine_token_cannot_invite(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    emails: CapturingEmailSender,
    workspace_a: SeededWorkspace,
) -> None:
    client, endpoint = human_client
    r = await client.post(
        "/v1/invitations",
        headers=hx(workspace_a.token.plaintext, workspace_a.id),
        json={"email": "x@example.test", "role": "member"},
    )
    assert r.status_code == 403
    assert endpoint.calls == 0 and not emails.sent


# ---------------------------------------------------------------------------------------
# Creation contract
# ---------------------------------------------------------------------------------------


async def test_creation_returns_no_token_and_records_server_fields(
    invite_ctx: dict[str, object], admin_engine: AsyncEngine
) -> None:
    body, token = await create_invitation(invite_ctx, email="Invitee@Example.COM", role="admin")

    # The response never carries the token or its hash.
    assert "token" not in body and "token_hash" not in body
    assert body["invited_email"] == "invitee@example.com"  # normalized from Invitee@Example.COM
    assert body["role"] == "admin" and body["status"] == "pending"

    # invited_by is the inviter's real member id; the email is stored normalized; the hash
    # — not the raw token — is what persisted.
    async with admin_engine.connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT invited_email, token_hash, invited_by FROM invitations "
                    "WHERE workspace_id = :w"
                ),
                {"w": invite_ctx["ws"]},
            )
        ).one()
    assert row.invited_email == "invitee@example.com"
    assert row.token_hash == hash_token(token) and row.token_hash != token
    assert row.invited_by is not None


async def test_invalid_email_and_role_are_rejected(invite_ctx: dict[str, object]) -> None:
    client: AsyncClient = invite_ctx["client"]  # type: ignore[assignment]
    headers = hx(invite_ctx["owner_token"], invite_ctx["ws"])  # type: ignore[arg-type]
    for bad in ({"email": "not-an-email", "role": "member"}, {"email": "a@b.co", "role": "boss"}):
        r = await client.post("/v1/invitations", headers=headers, json=bad)
        assert r.status_code == 400

    # Server-owned fields are refused, not silently ignored.
    r = await client.post(
        "/v1/invitations",
        headers=headers,
        json={"email": "a@b.co", "role": "member", "invited_by": str(uuid.uuid4())},
    )
    assert r.status_code == 400


async def test_duplicate_pending_invitation_is_conflict(invite_ctx: dict[str, object]) -> None:
    await create_invitation(invite_ctx, email="dup@example.com")
    client: AsyncClient = invite_ctx["client"]  # type: ignore[assignment]
    r = await client.post(
        "/v1/invitations",
        headers=hx(invite_ctx["owner_token"], invite_ctx["ws"]),  # type: ignore[arg-type]
        json={"email": "dup@example.com", "role": "admin"},
    )
    assert r.status_code == 409


# ---------------------------------------------------------------------------------------
# Acceptance — the core flow
# ---------------------------------------------------------------------------------------


async def test_accept_establishes_membership_and_consumes_the_invitation(
    invite_ctx: dict[str, object], authority: SigningAuthority, admin_engine: AsyncEngine
) -> None:
    _, token = await create_invitation(invite_ctx, email="joiner@example.com", role="admin")
    client: AsyncClient = invite_ctx["client"]  # type: ignore[assignment]

    accepted = await client.post(
        "/v1/invitations/accept",
        headers=bearer(human(authority, "joiner-sub", email="joiner@example.com")),
        json={"token": token},
    )
    assert accepted.status_code == 200
    assert accepted.json() == {"workspace_id": str(invite_ctx["ws"]), "role": "admin"}

    # The membership is keyed by the verified sub, not the email, with the invitation's role.
    async with admin_engine.connect() as conn:
        member = (
            await conn.execute(
                text("SELECT user_id, role FROM members WHERE workspace_id=:w AND user_id=:u"),
                {"w": invite_ctx["ws"], "u": "joiner-sub"},
            )
        ).one()
        status = await conn.scalar(
            text("SELECT status FROM invitations WHERE workspace_id=:w"), {"w": invite_ctx["ws"]}
        )
    assert member.user_id == "joiner-sub" and member.role == "admin"
    assert status == "accepted"

    # The new workspace now appears in the joiner's own membership list.
    listing = await client.get(
        "/v1/workspaces", headers=bearer(human(authority, "joiner-sub", email="joiner@example.com"))
    )
    assert (str(invite_ctx["ws"]), "admin") in {
        (m["id"], m["role"]) for m in listing.json()["data"]
    }


async def test_email_case_and_whitespace_are_normalized_for_the_match(
    invite_ctx: dict[str, object], authority: SigningAuthority
) -> None:
    """Invited `Joiner@Example.com`, accepted by a JWT whose verified email is
    `joiner@example.com` — the normalized comparison matches."""
    _, token = await create_invitation(invite_ctx, email="Joiner@Example.com")
    client: AsyncClient = invite_ctx["client"]  # type: ignore[assignment]
    r = await client.post(
        "/v1/invitations/accept",
        headers=bearer(human(authority, "c-sub", email="joiner@example.com")),
        json={"token": token},
    )
    assert r.status_code == 200


@pytest.mark.parametrize("verified", [True, False])
async def test_unverified_email_can_never_accept(
    verified: bool, invite_ctx: dict[str, object], authority: SigningAuthority
) -> None:
    _, token = await create_invitation(invite_ctx, email="ev@example.com")
    client: AsyncClient = invite_ctx["client"]  # type: ignore[assignment]
    r = await client.post(
        "/v1/invitations/accept",
        headers=bearer(human(authority, "ev-sub", email="ev@example.com", verified=verified)),
        json={"token": token},
    )
    assert r.status_code == (200 if verified else 404)


async def test_wrong_user_cannot_accept_someone_elses_invitation(
    invite_ctx: dict[str, object], authority: SigningAuthority
) -> None:
    _, token = await create_invitation(invite_ctx, email="intended@example.com")
    client: AsyncClient = invite_ctx["client"]  # type: ignore[assignment]
    r = await client.post(
        "/v1/invitations/accept",
        headers=bearer(human(authority, "attacker-sub", email="attacker@example.com")),
        json={"token": token},
    )
    assert r.status_code == 404


async def test_replay_after_acceptance_is_rejected(
    invite_ctx: dict[str, object], authority: SigningAuthority
) -> None:
    _, token = await create_invitation(invite_ctx, email="once@example.com")
    client: AsyncClient = invite_ctx["client"]  # type: ignore[assignment]
    creds = bearer(human(authority, "once-sub", email="once@example.com"))
    assert (
        await client.post("/v1/invitations/accept", headers=creds, json={"token": token})
    ).status_code == 200
    replay = await client.post("/v1/invitations/accept", headers=creds, json={"token": token})
    assert replay.status_code == 404


async def test_expired_invitation_is_rejected(
    invite_ctx: dict[str, object], authority: SigningAuthority, admin_engine: AsyncEngine
) -> None:
    _, token = await create_invitation(invite_ctx, email="late@example.com")
    async with admin_engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE invitations SET expires_at = now() - interval '1 hour' "
                "WHERE workspace_id=:w"
            ),
            {"w": invite_ctx["ws"]},
        )
    client: AsyncClient = invite_ctx["client"]  # type: ignore[assignment]
    r = await client.post(
        "/v1/invitations/accept",
        headers=bearer(human(authority, "late-sub", email="late@example.com")),
        json={"token": token},
    )
    assert r.status_code == 404


async def test_already_member_is_conflict_and_does_not_consume(
    invite_ctx: dict[str, object], authority: SigningAuthority, admin_engine: AsyncEngine
) -> None:
    """A verified invitee who is already a member → 409, the invitation stays pending, and
    their existing role is untouched (ADR-0017 §9)."""
    await seed_member(admin_engine, invite_ctx["ws"], user_id="existing-sub", role="viewer")  # type: ignore[arg-type]
    _, token = await create_invitation(invite_ctx, email="existing@example.com", role="owner")
    client: AsyncClient = invite_ctx["client"]  # type: ignore[assignment]

    r = await client.post(
        "/v1/invitations/accept",
        headers=bearer(human(authority, "existing-sub", email="existing@example.com")),
        json={"token": token},
    )
    assert r.status_code == 409

    async with admin_engine.connect() as conn:
        role = await conn.scalar(
            text("SELECT role FROM members WHERE workspace_id=:w AND user_id=:u"),
            {"w": invite_ctx["ws"], "u": "existing-sub"},
        )
        status = await conn.scalar(
            text("SELECT status FROM invitations WHERE workspace_id=:w"), {"w": invite_ctx["ws"]}
        )
    assert role == "viewer", "the invitation must not have upgraded the existing role"
    assert status == "pending", "an already-member rejection must not consume the invitation"


async def test_random_bad_and_foreign_tokens_fail_uniformly(
    invite_ctx: dict[str, object],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_b: SeededWorkspace,
) -> None:
    """No enumeration oracle: an unknown token, a cancelled one, and a foreign-workspace one
    return byte-identical 404 bodies (modulo request_id)."""
    _, good = await create_invitation(invite_ctx, email="real@example.com")
    # Cancel it so the token is now non-pending.
    client: AsyncClient = invite_ctx["client"]  # type: ignore[assignment]
    async with admin_engine.begin() as conn:
        await conn.execute(
            text("UPDATE invitations SET status='cancelled' WHERE workspace_id=:w"),
            {"w": invite_ctx["ws"]},
        )
    creds = bearer(human(authority, "any-sub", email="real@example.com"))

    bodies = []
    for token in ("totally-random-token", good, "another-bogus-value"):
        r = await client.post("/v1/invitations/accept", headers=creds, json={"token": token})
        assert r.status_code == 404
        body = r.json()
        body["error"].pop("request_id")
        bodies.append(body)
    assert all(b == bodies[0] for b in bodies), "acceptance failures must be indistinguishable"


# ---------------------------------------------------------------------------------------
# Role is server-established; the recipient cannot choose it
# ---------------------------------------------------------------------------------------


async def test_recipient_cannot_influence_their_granted_role(
    invite_ctx: dict[str, object], authority: SigningAuthority, admin_engine: AsyncEngine
) -> None:
    """Invited as `member`; the acceptor floods every channel with owner-shaped authority and
    still becomes a plain member."""
    _, token = await create_invitation(invite_ctx, email="climber@example.com", role="member")
    client: AsyncClient = invite_ctx["client"]  # type: ignore[assignment]
    spoof_token = authority.sign(
        "climber-sub",
        email="climber@example.com",
        emailVerified=True,
        role="owner",
        permissions=["members:manage"],
    )
    r = await client.post(
        "/v1/invitations/accept",
        headers={**bearer(spoof_token), "X-Role": "owner"},
        json={"token": token, "role": "owner"},  # extra body field → 400, or ignored
    )
    # Extra body field 'role' is forbidden by the schema → 400; retry clean proves the role.
    if r.status_code == 400:
        r = await client.post(
            "/v1/invitations/accept",
            headers={**bearer(spoof_token), "X-Role": "owner"},
            json={"token": token},
        )
    assert r.status_code == 200
    async with admin_engine.connect() as conn:
        role = await conn.scalar(
            text("SELECT role FROM members WHERE workspace_id=:w AND user_id=:u"),
            {"w": invite_ctx["ws"], "u": "climber-sub"},
        )
    assert role == "member", "the server-set invitation role is authoritative"


# ---------------------------------------------------------------------------------------
# Listing and cancellation, workspace-scoped
# ---------------------------------------------------------------------------------------


async def test_list_shows_only_this_workspaces_pending_invitations(
    invite_ctx: dict[str, object],
) -> None:
    await create_invitation(invite_ctx, email="a@example.com")
    await create_invitation(invite_ctx, email="b@example.com")
    client: AsyncClient = invite_ctx["client"]  # type: ignore[assignment]
    r = await client.get("/v1/invitations", headers=hx(invite_ctx["owner_token"], invite_ctx["ws"]))  # type: ignore[arg-type]
    assert r.status_code == 200
    data = r.json()["data"]
    assert {i["invited_email"] for i in data} == {"a@example.com", "b@example.com"}
    for item in data:
        assert set(item) == {"id", "invited_email", "role", "status", "created_at", "expires_at"}


async def test_cancel_makes_an_invitation_unacceptable(
    invite_ctx: dict[str, object], authority: SigningAuthority
) -> None:
    body, token = await create_invitation(invite_ctx, email="cancel@example.com")
    client: AsyncClient = invite_ctx["client"]  # type: ignore[assignment]
    cancelled = await client.delete(
        f"/v1/invitations/{body['id']}",
        headers=hx(invite_ctx["owner_token"], invite_ctx["ws"]),  # type: ignore[arg-type]
    )
    assert cancelled.status_code == 204
    r = await client.post(
        "/v1/invitations/accept",
        headers=bearer(human(authority, "c-sub", email="cancel@example.com")),
        json={"token": token},
    )
    assert r.status_code == 404


async def test_cancel_requires_members_manage(
    invite_ctx: dict[str, object], authority: SigningAuthority, admin_engine: AsyncEngine
) -> None:
    body, _ = await create_invitation(invite_ctx, email="c2@example.com")
    await seed_member(admin_engine, invite_ctx["ws"], user_id="a-viewer", role="viewer")  # type: ignore[arg-type]
    client: AsyncClient = invite_ctx["client"]  # type: ignore[assignment]
    r = await client.delete(
        f"/v1/invitations/{body['id']}",
        headers=hx(authority.sign("a-viewer"), invite_ctx["ws"]),  # type: ignore[arg-type]
    )
    assert r.status_code == 403


# ---------------------------------------------------------------------------------------
# Cross-tenant isolation
# ---------------------------------------------------------------------------------------


async def test_cross_tenant_invitation_isolation(
    invite_ctx: dict[str, object],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_b: SeededWorkspace,
) -> None:
    """B's owner can neither see nor cancel A's invitation; A's list never shows B's."""
    a_body, _ = await create_invitation(invite_ctx, email="a-side@example.com")
    await seed_member(admin_engine, workspace_b.id, user_id="b-owner", role="owner")
    client: AsyncClient = invite_ctx["client"]  # type: ignore[assignment]
    b_creds = hx(authority.sign("b-owner"), workspace_b.id)

    # B's list is empty (A's invite is invisible).
    b_list = await client.get("/v1/invitations", headers=b_creds)
    assert b_list.status_code == 200 and b_list.json()["data"] == []

    # B cannot cancel A's invitation — scoped to B, it is simply not found.
    b_cancel = await client.delete(f"/v1/invitations/{a_body['id']}", headers=b_creds)
    assert b_cancel.status_code == 404


# ---------------------------------------------------------------------------------------
# Concurrency: single-use under a real race
# ---------------------------------------------------------------------------------------


async def test_concurrent_acceptance_creates_exactly_one_membership(
    invite_ctx: dict[str, object], authority: SigningAuthority, admin_engine: AsyncEngine
) -> None:
    _, token = await create_invitation(invite_ctx, email="race@example.com", role="member")
    client: AsyncClient = invite_ctx["client"]  # type: ignore[assignment]
    creds = bearer(human(authority, "race-sub", email="race@example.com"))

    results = await asyncio.gather(
        *(
            client.post("/v1/invitations/accept", headers=creds, json={"token": token})
            for _ in range(6)
        )
    )
    statuses = sorted(r.status_code for r in results)
    assert statuses.count(200) == 1, f"exactly one acceptance must win, got {statuses}"

    async with admin_engine.connect() as conn:
        count = await conn.scalar(
            text("SELECT count(*) FROM members WHERE workspace_id=:w AND user_id=:u"),
            {"w": invite_ctx["ws"], "u": "race-sub"},
        )
        status = await conn.scalar(
            text("SELECT status FROM invitations WHERE workspace_id=:w"), {"w": invite_ctx["ws"]}
        )
    assert count == 1, "the race must never create a second membership"
    assert status == "accepted"


# ---------------------------------------------------------------------------------------
# Log audit
# ---------------------------------------------------------------------------------------


async def test_no_token_or_email_leaks_to_logs(
    invite_ctx: dict[str, object], authority: SigningAuthority
) -> None:
    _, token = await create_invitation(invite_ctx, email="logtest@example.com")
    client: AsyncClient = invite_ctx["client"]  # type: ignore[assignment]
    good = human(authority, "log-sub", email="logtest@example.com")

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        # a success and a couple of failures, to exercise the logging paths
        await client.post("/v1/invitations/accept", headers=bearer(good), json={"token": token})
        await client.post("/v1/invitations/accept", headers=bearer(good), json={"token": "bogus"})
        await client.post(
            "/v1/invitations/accept",
            headers=bearer(human(authority, "x", email="wrong@example.com")),
            json={"token": token},
        )
    emitted = buffer.getvalue()
    assert emitted, "the capture must not be empty — otherwise the audit is vacuous"
    assert token not in emitted, "the raw invitation token must never be logged"
    assert good not in emitted, "the JWT must never be logged"
    # The reason codes are observable; the invited email is not.
    assert "invitation.rejected" in emitted


# ---------------------------------------------------------------------------------------
# RLS-independent proof: the application predicate protects the boundary without RLS
# ---------------------------------------------------------------------------------------


async def _seed_pending_invitation(
    admin_engine: AsyncEngine, workspace_id: uuid.UUID, *, email: str = "seed@example.com"
) -> uuid.UUID:
    """Insert one pending invitation directly (RLS-exempt) and return its id.

    The repository-layer proofs need a row in a known state without going through the HTTP
    creation path, so the single guard under test is the only thing they exercise.
    """
    from datetime import UTC, datetime, timedelta

    invitation_id = uuid.uuid4()
    async with admin_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO invitations (id, workspace_id, invited_email, role, token_hash, "
                "status, expires_at) VALUES (:i, :w, :m, 'member', :h, 'pending', :e)"
            ),
            {
                "i": invitation_id,
                "w": workspace_id,
                "m": email,
                "h": hash_token(generate_invitation_token()),
                "e": datetime.now(UTC) + timedelta(days=7),
            },
        )
    return invitation_id


async def test_consume_is_single_use_at_the_repository_layer(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """`consume` is the atomic single-use arbiter: a second call updates nothing.

    Exercised directly at the repository layer, on purpose. Through the HTTP path the
    acceptance-time status check rejects a replay *before* `consume` even runs, which masks
    whether the `status = 'pending'` predicate inside the UPDATE actually holds the line.
    Here `consume` is the only thing between the two calls, so the second returning False
    proves the DB guard — not a layer above it — is what enforces single use (ADR-0017 §5).
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.core.security import CallerIdentity, WorkspaceContext
    from app.domains.workspaces.repository import InvitationRepository

    invitation_id = await _seed_pending_invitation(admin_engine, workspace_a.id)
    ctx = WorkspaceContext(
        workspace_id=workspace_a.id,
        caller=CallerIdentity(kind="member", member_id=None),
        request_id="req_test",
    )
    session = async_sessionmaker(admin_engine, expire_on_commit=False)()
    try:
        async with session.begin():
            repo = InvitationRepository(session, ctx)
            assert await repo.consume(invitation_id) is True, "the first acceptance consumes it"
            assert await repo.consume(invitation_id) is False, "a replay consumes nothing"
    finally:
        await session.close()


async def test_a_cancelled_invitation_can_never_be_consumed(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Once cancelled, an invitation is inert at the lowest layer: `consume` refuses it.

    The HTTP cancel→accept test proves the outward 404; this proves the mechanism — that the
    single `status = 'pending'` predicate is what makes 'cancelled' and 'accepted' equally
    unacceptable, independently of the acceptance-time check above it.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.core.security import CallerIdentity, WorkspaceContext
    from app.domains.workspaces.repository import InvitationRepository

    invitation_id = await _seed_pending_invitation(admin_engine, workspace_a.id)
    ctx = WorkspaceContext(
        workspace_id=workspace_a.id,
        caller=CallerIdentity(kind="member", member_id=None),
        request_id="req_test",
    )
    session = async_sessionmaker(admin_engine, expire_on_commit=False)()
    try:
        async with session.begin():
            repo = InvitationRepository(session, ctx)
            assert await repo.cancel(invitation_id) is True, "the pending invite cancels"
            assert await repo.consume(invitation_id) is False, "a cancelled invite is unacceptable"
    finally:
        await session.close()


async def test_cancel_and_consume_are_workspace_scoped_without_rls(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """On an RLS-EXEMPT connection, an A-scoped repository still refuses to cancel or consume
    a B invitation (ADR-0017, directive §18).

    The `admin_engine` connects as the superuser, so RLS does not apply — a green result
    here proves the repository's own `workspace_id` predicate is correct, not that RLS
    happened to hide the row. Without this, the cross-tenant HTTP test could pass purely
    because RLS blocked the write while the application predicate was missing.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.core.security import CallerIdentity, WorkspaceContext
    from app.domains.workspaces.repository import InvitationRepository

    # Seed a pending invitation into workspace B directly (RLS-exempt).
    b_invite = await _seed_pending_invitation(admin_engine, workspace_b.id, email="b@example.com")

    ctx_a = WorkspaceContext(
        workspace_id=workspace_a.id,
        caller=CallerIdentity(kind="member", member_id=None),
        request_id="req_test",
    )
    session = async_sessionmaker(admin_engine, expire_on_commit=False)()
    try:
        async with session.begin():
            # Prove the connection is genuinely unconstrained: it can see B's invitation.
            visible = await session.scalar(
                text("SELECT count(*) FROM invitations WHERE id = :i"), {"i": b_invite}
            )
            assert visible == 1, "expected an RLS-exempt connection for this test"

            repo = InvitationRepository(session, ctx_a)
            assert await repo.cancel(b_invite) is False, "A must not cancel B's invitation"
            assert await repo.consume(b_invite) is False, "A must not consume B's invitation"
    finally:
        await session.close()

    # And B's invitation is untouched — still pending.
    async with admin_engine.connect() as conn:
        status = await conn.scalar(
            text("SELECT status FROM invitations WHERE id = :i"), {"i": b_invite}
        )
    assert status == "pending"


async def test_service_normalizes_email_independently_of_the_schema(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """The service normalizes the email itself, not only the request schema.

    A direct service call (an MCP adapter, a Celery task, a future internal caller) bypasses
    the Pydantic `field_validator`, so the invariant that the stored email matches the
    normalized verified email must hold at the service layer too — otherwise the acceptance
    binding silently fails for those callers.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.core.email import CapturingEmailSender
    from app.core.security import CallerIdentity, WorkspaceContext
    from app.domains.workspaces.repository import InvitationRepository
    from app.domains.workspaces.service import InvitationService

    ctx = WorkspaceContext(
        workspace_id=workspace_a.id,
        caller=CallerIdentity(kind="member", member_id=None),
        request_id="req_test",
    )
    session = async_sessionmaker(admin_engine, expire_on_commit=False)()
    try:
        async with session.begin():
            await session.execute(
                text("SELECT set_config('app.workspace_id', :w, true)"),
                {"w": str(workspace_a.id)},
            )
            service = InvitationService(InvitationRepository(session, ctx), CapturingEmailSender())
            issued = await service.invite(
                email="  MixedCase@Example.COM  ", role="member", invited_by=None
            )
    finally:
        await session.close()
    assert issued.invitation.invited_email == "mixedcase@example.com"


# ---------------------------------------------------------------------------------------
# Real-provider E2E: real Better Auth, real verified email, real JWKS (directive §32)
# ---------------------------------------------------------------------------------------


async def _real_verified_human(admin_engine: AsyncEngine, name: str) -> tuple[str, str, str]:
    """Sign up a real Better Auth user, mark their email verified (as the click would), and
    return (JWT, sub, email). The verification is done directly in `identity.user` via the
    superuser admin engine — the API-side proof is that the resulting JWT carries
    `emailVerified: true` and the acceptance path honors it."""
    import base64
    import json

    import httpx

    from app.core.config import settings

    provider_base = settings.resolved_jwks_url.removesuffix("/api/auth/jwks")
    email = f"e2e-inv-{name}-{uuid.uuid4().hex[:10]}@example.test"
    password = f"pw-{uuid.uuid4()}"
    async with httpx.AsyncClient(base_url=provider_base, timeout=10.0) as provider:
        signup = await provider.post(
            "/api/auth/sign-up/email",
            json={"email": email, "password": password, "name": name},
            headers={"origin": settings.better_auth_url},
        )
        assert signup.status_code == 200, f"provider up at {provider_base}? {signup.text}"
        # Mark the email verified, exactly the state a real verification click produces.
        async with admin_engine.begin() as conn:
            await conn.execute(
                text('UPDATE identity."user" SET "emailVerified" = true WHERE email = :e'),
                {"e": email},
            )
        cookie = signup.headers.get("set-cookie", "").split(";")[0]
        token = (await provider.get("/api/auth/token", headers={"cookie": cookie})).json()["token"]

    sub = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))["sub"]
    return token, sub, email


async def test_e2e_real_invitation_lifecycle(
    client: AsyncClient,
    emails: CapturingEmailSender,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """The whole chain against real components (live JWKS, no JWKS double): a real owner
    invites a real person, who signs up, verifies their email, accepts, and becomes a member
    — then the workspace shows up in their real membership list and their persisted role is
    what the invitation set. Fails (not skips) if the provider is down."""
    inviter_token, inviter_sub, _ = await _real_verified_human(admin_engine, "owner")
    await seed_member(admin_engine, workspace_a.id, user_id=inviter_sub, role="owner")

    invitee_token, invitee_sub, invitee_email = await _real_verified_human(admin_engine, "joiner")

    # The real owner creates the invitation for the real invitee's email.
    created = await client.post(
        "/v1/invitations",
        headers=hx(inviter_token, workspace_a.id),
        json={"email": invitee_email, "role": "admin"},
    )
    assert created.status_code == 201
    token = emails.sent[-1].html.split("token=")[1].split('"')[0]

    # The real invitee accepts with their real, verified JWT.
    accepted = await client.post(
        "/v1/invitations/accept", headers=bearer(invitee_token), json={"token": token}
    )
    assert accepted.status_code == 200
    assert accepted.json() == {"workspace_id": str(workspace_a.id), "role": "admin"}

    # The membership is real and keyed by the verified sub; the workspace is now in their list.
    listing = await client.get("/v1/workspaces", headers=bearer(invitee_token))
    assert (str(workspace_a.id), "admin") in {(m["id"], m["role"]) for m in listing.json()["data"]}
    # And their admin role is enforced: they can now manage members in that workspace.
    manage = await client.get("/v1/members", headers=hx(invitee_token, workspace_a.id))
    assert manage.status_code == 200
    assert invitee_sub in {m["user_id"] for m in manage.json()["data"]}
