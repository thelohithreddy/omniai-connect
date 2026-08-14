"""API token revocation: the credential stops working, and the record survives.

Revocation is only real if the revoked credential can no longer authenticate, so the
central tests drive a genuine token through the **real** authentication path before and
after revocation rather than asserting on a database column. Four properties:

1. **A revoked token cannot authenticate**, immediately, with no cache to wait for.
2. **Revocation is idempotent** (API_GUIDELINES.md §2) and preserves the *first*
   `revoked_at`, so the audit trail records when the credential actually stopped working
   rather than when someone retried the request.
3. **It is tenant-scoped**, proven both with RLS active and with RLS bypassed — the second
   is what stops Postgres masking a missing application predicate.
4. **A foreign token is not an existence oracle**: absent and not-yours are the same 404.
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
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.core.db import UnitOfWork
from app.core.exceptions import NotFoundError
from app.core.ids import new_id
from app.core.security import CallerIdentity, WorkspaceContext, generate_token
from app.domains.workspaces.repository import ApiTokenRepository, RevocationOutcome
from tests.conftest import SeededWorkspace
from tests.integration.test_api_token_creation import (
    api_token_context,
    bound_service,
    build_token_app,
    member_context,
)
from tests.integration.test_members_tenancy import seed_member

pytestmark = pytest.mark.asyncio


async def seed_live_token(engine: AsyncEngine, workspace_id: uuid.UUID) -> tuple[uuid.UUID, str]:
    """Insert a genuine, usable token and return `(id, plaintext)`.

    The plaintext is kept only so the tests can present it to the real authentication path;
    it is never stored anywhere but this local variable.
    """
    token_id = new_id()
    generated = generate_token()
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO api_tokens (id, workspace_id, name, token_hash, token_prefix, scopes)"
                " VALUES (:i, :w, 'revocable', :h, :p, '[]'::jsonb)"
            ),
            {
                "i": token_id,
                "w": workspace_id,
                "h": generated.token_hash,
                "p": generated.token_prefix,
            },
        )
    return token_id, generated.plaintext


async def revoked_at_of(engine: AsyncEngine, token_id: uuid.UUID) -> Any:
    async with engine.begin() as conn:
        return await conn.scalar(
            text("SELECT revoked_at FROM api_tokens WHERE id = :i"), {"i": token_id}
        )


def token_client(app_engine: AsyncEngine, context_factory: Any) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=build_token_app(app_engine, context_factory)),
        base_url="http://t",
    )


# =======================================================================================
# The point of the module: a revoked credential stops working
# =======================================================================================


async def test_a_token_authenticates_before_revocation_and_not_after(
    client: AsyncClient,
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """The whole module in one test, through the real authentication path both times.

    Asserting that `revoked_at` is set would prove a column was written, not that the
    credential stopped working. This presents the same genuine secret to the real resolver
    before and after, so it fails if revocation writes the wrong column, if authentication
    stops consulting it, or if anything caches the token's validity.
    """
    token_id, plaintext = await seed_live_token(admin_engine, workspace_a.id)
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    headers = {"Authorization": f"Bearer {plaintext}"}

    before = await client.get("/v1/workspaces/me", headers=headers)
    assert before.status_code == 200, before.text
    assert before.json()["id"] == str(workspace_a.id)

    async with token_client(app_engine, lambda: member_context(workspace_a.id, owner)) as admin:
        revoked = await admin.delete(f"/v1/api-tokens/{token_id}")
    assert revoked.status_code == 204
    assert revoked.content == b""

    after = await client.get("/v1/workspaces/me", headers=headers)
    assert after.status_code == 401
    assert after.json()["error"]["code"] == "unauthorized"


async def test_revocation_does_not_delete_the_row(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """State transition, not deletion — the record is the audit trail.

    If revocation removed the row, an incident review could not answer "did this credential
    exist, and when was it cut off?". The token therefore stays listed with `revoked_at`
    populated, which is exactly why `ApiTokenRead` carries that field.
    """
    token_id, _ = await seed_live_token(admin_engine, workspace_a.id)
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")

    async with token_client(app_engine, lambda: member_context(workspace_a.id, owner)) as admin:
        assert (await admin.delete(f"/v1/api-tokens/{token_id}")).status_code == 204
        listed = (await admin.get("/v1/api-tokens", params={"limit": 100})).json()

    row = [item for item in listed["data"] if item["id"] == str(token_id)]
    assert row, "the revoked token disappeared from the listing"
    assert row[0]["revoked_at"] is not None
    assert await revoked_at_of(admin_engine, token_id) is not None


async def test_revocation_is_idempotent_and_preserves_the_first_timestamp(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """§2: *"Idempotent: deleting a deleted resource is 204."*

    The preserved timestamp is the part that matters and the part a naive implementation
    gets wrong. An unconditional `SET revoked_at = now()` would answer 204 both times and
    look correct, while quietly rewriting the audit record to the moment of the *retry* —
    so an incident review would report the credential was live hours longer than it was.
    """
    token_id, _ = await seed_live_token(admin_engine, workspace_a.id)
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")

    async with token_client(app_engine, lambda: member_context(workspace_a.id, owner)) as admin:
        first = await admin.delete(f"/v1/api-tokens/{token_id}")
        first_at = await revoked_at_of(admin_engine, token_id)
        await asyncio.sleep(0.05)
        second = await admin.delete(f"/v1/api-tokens/{token_id}")
        third = await admin.delete(f"/v1/api-tokens/{token_id}")

    assert first.status_code == second.status_code == third.status_code == 204
    assert await revoked_at_of(admin_engine, token_id) == first_at


async def test_concurrent_revocation_transitions_once(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Five simultaneous revocations of the same token, on real Postgres.

    The `WHERE revoked_at IS NULL` predicate is what makes this safe: the requests serialise
    on the row lock, and every loser re-evaluates the predicate after the winner commits,
    matches nothing, and leaves the timestamp alone. All five report success — none of them
    is wrong, the credential is revoked — while exactly one transition is recorded.
    """
    token_id, _ = await seed_live_token(admin_engine, workspace_a.id)
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")

    async def revoke_once() -> int:
        async with token_client(app_engine, lambda: member_context(workspace_a.id, owner)) as c:
            return (await c.delete(f"/v1/api-tokens/{token_id}")).status_code

    statuses = await asyncio.gather(*(revoke_once() for _ in range(5)))

    assert statuses == [204] * 5
    async with admin_engine.begin() as conn:
        distinct = await conn.scalar(
            text("SELECT count(DISTINCT revoked_at) FROM api_tokens WHERE id = :i"), {"i": token_id}
        )
    assert distinct == 1


async def test_a_revoked_token_cannot_be_resurrected_by_a_concurrent_write(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Revocation is one-way: the repository exposes no operation that clears `revoked_at`.

    Asserted structurally as well as behaviourally, because "there is no un-revoke endpoint"
    is only true while nobody adds a generic update helper to the repository.
    """
    token_id, plaintext = await seed_live_token(admin_engine, workspace_a.id)

    async with async_sessionmaker(app_engine, expire_on_commit=False)() as session, session.begin():
        await UnitOfWork(session=session).bind_workspace(workspace_a.id)
        repository = ApiTokenRepository(session, api_token_context(workspace_a.id))
        assert await repository.revoke(token_id) is RevocationOutcome.REVOKED
        assert await repository.revoke(token_id) is RevocationOutcome.ALREADY_REVOKED

    public = {name for name in dir(ApiTokenRepository) if not name.startswith("_")}
    assert public == {"create", "get", "list_for_workspace", "list_page", "revoke"}, public
    assert await revoked_at_of(admin_engine, token_id) is not None
    del plaintext


# =======================================================================================
# Authorization and identity
# =======================================================================================


async def test_revocation_requires_authentication(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    token_id, _ = await seed_live_token(admin_engine, workspace_a.id)
    response = await client.delete(f"/v1/api-tokens/{token_id}")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


@pytest.mark.parametrize(
    ("role", "expected"), [("owner", 204), ("admin", 204), ("member", 403), ("viewer", 403)]
)
async def test_admits_exactly_the_roles_holding_api_tokens_manage(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    role: str,
    expected: int,
) -> None:
    token_id, _ = await seed_live_token(admin_engine, workspace_a.id)
    member = await seed_member(admin_engine, workspace_a.id, user_id=f"u-{role}", role=role)

    async with token_client(app_engine, lambda: member_context(workspace_a.id, member)) as c:
        response = await c.delete(f"/v1/api-tokens/{token_id}")

    assert response.status_code == expected, response.text
    if expected == 403:
        assert response.json()["error"]["code"] == "forbidden"
        assert await revoked_at_of(admin_engine, token_id) is None, "a denied call still revoked"


async def test_a_machine_token_cannot_revoke_anything_including_itself(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """A stolen credential must not be able to revoke the tokens used to respond to it.

    If a machine token could revoke, an attacker holding one could cut off every *other*
    credential in the workspace — including the operator's — turning a compromise into a
    denial of service during the incident response. It also cannot revoke itself, which is
    a lesser but real property: self-revocation would let an attacker destroy the evidence
    of which credential was used.
    """
    token_id, _ = await seed_live_token(admin_engine, workspace_a.id)

    async with token_client(app_engine, lambda: api_token_context(workspace_a.id)) as c:
        response = await c.delete(f"/v1/api-tokens/{token_id}")

    assert response.status_code == 403
    assert await revoked_at_of(admin_engine, token_id) is None


async def test_a_confused_deputy_token_naming_a_real_owner_is_still_denied(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """A machine context carrying a real owner's member id must not inherit that authority."""
    token_id, _ = await seed_live_token(admin_engine, workspace_a.id)
    owner = await seed_member(admin_engine, workspace_a.id, user_id="real-owner", role="owner")
    deputy = WorkspaceContext(
        workspace_id=workspace_a.id,
        caller=CallerIdentity(kind="api_token", api_token_id=uuid.uuid4(), member_id=owner),
        request_id="req_test",
    )

    async with token_client(app_engine, lambda: deputy) as c:
        assert (await c.delete(f"/v1/api-tokens/{token_id}")).status_code == 403
    assert await revoked_at_of(admin_engine, token_id) is None


async def test_the_creator_of_a_token_gains_no_special_authority_over_it(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """`created_by_member_id` is provenance, not a capability.

    A plain member who issued a token still cannot revoke it — authority comes from the role
    matrix alone. Treating creation as ownership would be a quiet second authorization
    system living in a foreign key.
    """
    creator = await seed_member(admin_engine, workspace_a.id, user_id="creator", role="member")
    token_id, _ = await seed_live_token(admin_engine, workspace_a.id)
    async with admin_engine.begin() as conn:
        await conn.execute(
            text("UPDATE api_tokens SET created_by_member_id = :m WHERE id = :i"),
            {"m": creator, "i": token_id},
        )

    async with token_client(app_engine, lambda: member_context(workspace_a.id, creator)) as c:
        assert (await c.delete(f"/v1/api-tokens/{token_id}")).status_code == 403
    assert await revoked_at_of(admin_engine, token_id) is None


# =======================================================================================
# Tenant isolation and information disclosure
# =======================================================================================


async def test_another_workspaces_token_cannot_be_revoked(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """The id is real and the caller is an owner — of the wrong Workspace.

    404, not 403: SECURITY.md §3 requires cross-tenant access to answer `not_found`, because
    `forbidden` would confirm the id names something real and let an attacker enumerate
    other tenants' tokens by response code alone.
    """
    b_token, b_plaintext = await seed_live_token(admin_engine, workspace_b.id)
    a_owner = await seed_member(admin_engine, workspace_a.id, user_id="a-owner", role="owner")

    async with token_client(app_engine, lambda: member_context(workspace_a.id, a_owner)) as c:
        response = await c.delete(f"/v1/api-tokens/{b_token}")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"
    assert await revoked_at_of(admin_engine, b_token) is None, "cross-tenant revocation succeeded"
    del b_plaintext


async def test_a_foreign_token_is_indistinguishable_from_a_nonexistent_one(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Byte-identical responses, or the endpoint is an existence oracle.

    Comparing the two bodies field by field — rather than just both status codes — is what
    catches a well-meant `details: {"workspace": ...}` added to one path later.
    """
    b_token, _ = await seed_live_token(admin_engine, workspace_b.id)
    absent = new_id()
    a_owner = await seed_member(admin_engine, workspace_a.id, user_id="a-owner", role="owner")

    async with token_client(app_engine, lambda: member_context(workspace_a.id, a_owner)) as c:
        foreign = await c.delete(f"/v1/api-tokens/{b_token}")
        missing = await c.delete(f"/v1/api-tokens/{absent}")

    assert foreign.status_code == missing.status_code == 404
    foreign_error = foreign.json()["error"]
    missing_error = missing.json()["error"]
    assert foreign_error["code"] == missing_error["code"]
    assert foreign_error["message"] == missing_error["message"]
    assert foreign_error.get("details") == missing_error.get("details")


async def test_application_scoping_holds_with_rls_bypassed(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    """Layer 1 alone, with layer 2 removed.

    Runs the repository on a **superuser** session where RLS does not apply, so the
    `workspace_id` predicate in the UPDATE is the only remaining control. Without this,
    deleting that predicate would leave every other tenancy test in this file passing —
    Postgres would silently do the work and the application guarantee would rot unnoticed.
    """
    b_token, _ = await seed_live_token(admin_engine, workspace_b.id)

    factory = async_sessionmaker(admin_engine, expire_on_commit=False)
    async with factory() as session, session.begin():
        assert await session.scalar(
            text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
        ), "this test proves nothing unless RLS is genuinely bypassed"

        repository = ApiTokenRepository(session, api_token_context(workspace_a.id))
        outcome = await repository.revoke(b_token)

    assert outcome is RevocationOutcome.NOT_FOUND
    assert await revoked_at_of(admin_engine, b_token) is None


async def test_the_same_user_in_two_workspaces_cannot_reach_across(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Owner of both, authenticated against A, targeting B's token."""
    b_token, _ = await seed_live_token(admin_engine, workspace_b.id)
    a_member = await seed_member(admin_engine, workspace_a.id, user_id="dual", role="owner")
    await seed_member(admin_engine, workspace_b.id, user_id="dual", role="owner")

    async with token_client(app_engine, lambda: member_context(workspace_a.id, a_member)) as c:
        assert (await c.delete(f"/v1/api-tokens/{b_token}")).status_code == 404
    assert await revoked_at_of(admin_engine, b_token) is None


async def test_a_nonexistent_token_is_not_found(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    async with token_client(app_engine, lambda: member_context(workspace_a.id, owner)) as c:
        response = await c.delete(f"/v1/api-tokens/{new_id()}")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


@pytest.mark.parametrize("bad_id", ["not-a-uuid", "123", "' OR 1=1 --", "00000000"])
async def test_a_malformed_token_id_is_a_validation_error(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, bad_id: str
) -> None:
    """Rejected at the path-parameter boundary, before any query is built."""
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    async with token_client(app_engine, lambda: member_context(workspace_a.id, owner)) as c:
        response = await c.delete(f"/v1/api-tokens/{bad_id}")

    assert response.status_code == 400, response.text
    assert response.json()["error"]["code"] == "validation_error"


@pytest.mark.parametrize(
    "params",
    [
        {"workspace_id": "11111111-1111-1111-1111-111111111111"},
        {"role": "owner"},
        {"permission": "api_tokens:manage"},
        {"member_id": "11111111-1111-1111-1111-111111111111"},
    ],
)
async def test_caller_supplied_control_parameters_have_no_effect(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    params: dict[str, str],
) -> None:
    """Injecting a workspace, role, permission, or member cannot redirect the operation.

    The target stays B's token and the answer stays 404 — the authenticated context decides
    the tenant, and no query parameter is read by this endpoint at all.
    """
    b_token, _ = await seed_live_token(admin_engine, workspace_b.id)
    a_owner = await seed_member(admin_engine, workspace_a.id, user_id="a-owner", role="owner")

    async with token_client(app_engine, lambda: member_context(workspace_a.id, a_owner)) as c:
        response = await c.delete(f"/v1/api-tokens/{b_token}", params=params)

    assert response.status_code == 404
    assert await revoked_at_of(admin_engine, b_token) is None


# =======================================================================================
# Transactions, secrets, and the error contract
# =======================================================================================


async def test_a_failed_transaction_leaves_the_token_live(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Rollback must un-revoke: a half-applied revocation is worse than none.

    An operator told "revoked" whose transaction then rolled back would believe a live
    credential was dead. The service performs no commit of its own, so the UnitOfWork's
    transaction boundary is the only one — and rolling it back undoes the transition.
    """
    token_id, _ = await seed_live_token(admin_engine, workspace_a.id)

    with contextlib.suppress(RuntimeError):
        async with app_session.begin():
            service = await bound_service(app_session, workspace_a.id)
            await service.revoke(token_id)
            assert await revoked_at_of(admin_engine, token_id) is None, "uncommitted write visible"
            raise RuntimeError("simulated failure after revocation")

    assert await revoked_at_of(admin_engine, token_id) is None


async def test_the_service_raises_not_found_for_a_foreign_token(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """The domain error, independent of HTTP."""
    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        with pytest.raises(NotFoundError):
            await service.revoke(new_id())


async def test_the_error_envelope_and_request_id_are_preserved(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    async with token_client(app_engine, lambda: member_context(workspace_a.id, owner)) as c:
        response = await c.delete(f"/v1/api-tokens/{new_id()}")

    error = response.json()["error"]
    assert set(error) >= {"code", "message", "request_id"}
    assert error["request_id"] == response.headers["X-Request-Id"]


async def test_revocation_discloses_no_credential_material(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Neither the response nor the log stream may carry the secret or its digest.

    Revocation needs neither: it is addressed by token id, so no code path has a reason to
    read `token_hash` at all. The log capture asserts `emitted` first — a check against an
    empty buffer would prove nothing, which is the failure M1.2-F's CI run exposed.
    """
    token_id, plaintext = await seed_live_token(admin_engine, workspace_a.id)
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    async with admin_engine.begin() as conn:
        token_hash = await conn.scalar(
            text("SELECT token_hash FROM api_tokens WHERE id = :i"), {"i": token_id}
        )

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        async with token_client(app_engine, lambda: member_context(workspace_a.id, owner)) as c:
            response = await c.delete(f"/v1/api-tokens/{token_id}")

    assert response.status_code == 204
    emitted = buffer.getvalue()
    assert emitted, "nothing was logged — this assertion would pass vacuously"
    assert token_hash and token_hash not in emitted
    assert plaintext not in emitted
    assert response.content == b""


async def test_revocation_touches_only_the_targeted_token(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """A missing `id` predicate would revoke the whole Workspace's credentials at once.

    That mistake produces a perfectly successful 204 and is invisible to every test that
    only inspects the target row — so this asserts the *other* tokens are still live.
    """
    target, _ = await seed_live_token(admin_engine, workspace_a.id)
    bystander_one, _ = await seed_live_token(admin_engine, workspace_a.id)
    bystander_two, _ = await seed_live_token(admin_engine, workspace_a.id)
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")

    async with token_client(app_engine, lambda: member_context(workspace_a.id, owner)) as c:
        assert (await c.delete(f"/v1/api-tokens/{target}")).status_code == 204

    assert await revoked_at_of(admin_engine, target) is not None
    assert await revoked_at_of(admin_engine, bystander_one) is None
    assert await revoked_at_of(admin_engine, bystander_two) is None


async def test_revoking_one_token_does_not_disturb_another_workspace(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    a_token, _ = await seed_live_token(admin_engine, workspace_a.id)
    b_token, _ = await seed_live_token(admin_engine, workspace_b.id)
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")

    async with token_client(app_engine, lambda: member_context(workspace_a.id, owner)) as c:
        assert (await c.delete(f"/v1/api-tokens/{a_token}")).status_code == 204

    assert await revoked_at_of(admin_engine, a_token) is not None
    assert await revoked_at_of(admin_engine, b_token) is None


async def test_workspace_context_does_not_leak_across_pooled_revocations(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Consecutive revocations for different tenants over reused connections.

    `SET LOCAL` dies with its transaction, so a returned connection carries no tenant into
    the next request. A session-scoped binding would let B's request inherit A's workspace.
    """
    a_token, _ = await seed_live_token(admin_engine, workspace_a.id)
    b_token, _ = await seed_live_token(admin_engine, workspace_b.id)
    a_owner = await seed_member(admin_engine, workspace_a.id, user_id="a-owner", role="owner")
    b_owner = await seed_member(admin_engine, workspace_b.id, user_id="b-owner", role="owner")

    async with token_client(app_engine, lambda: member_context(workspace_a.id, a_owner)) as c:
        assert (await c.delete(f"/v1/api-tokens/{a_token}")).status_code == 204
        assert (await c.delete(f"/v1/api-tokens/{b_token}")).status_code == 404
    async with token_client(app_engine, lambda: member_context(workspace_b.id, b_owner)) as c:
        assert (await c.delete(f"/v1/api-tokens/{b_token}")).status_code == 204

    assert await revoked_at_of(admin_engine, a_token) is not None
    assert await revoked_at_of(admin_engine, b_token) is not None


async def test_a_revoked_token_cannot_revoke_or_authenticate_afterwards(
    client: AsyncClient,
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """End state: the credential is inert on every surface, not just the one it was cut on."""
    token_id, plaintext = await seed_live_token(admin_engine, workspace_a.id)
    owner = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    headers = {"Authorization": f"Bearer {plaintext}"}

    async with token_client(app_engine, lambda: member_context(workspace_a.id, owner)) as admin:
        assert (await admin.delete(f"/v1/api-tokens/{token_id}")).status_code == 204

    assert (await client.get("/v1/workspaces/me", headers=headers)).status_code == 401
    assert (await client.get("/v1/api-tokens", headers=headers)).status_code == 401
    assert (
        await client.post("/v1/api-tokens", json={"name": "x"}, headers=headers)
    ).status_code == 401
    assert (await client.delete(f"/v1/api-tokens/{token_id}", headers=headers)).status_code == 401


async def test_revoke_cannot_be_asked_to_target_another_tenant() -> None:
    """Structural layer-1 guarantee: there is no parameter that could name a Workspace.

    The behavioural tests above prove the *current* query is scoped. This proves the
    stronger property the architecture actually claims — that scoping is not something a
    caller can influence, because the argument does not exist. It mirrors the same guard on
    `list_page`; its absence let a mutation that widens this signature pass unnoticed.
    """
    params = set(ApiTokenRepository.revoke.__annotations__)

    assert params == {"token_id", "return"}
    assert not {"workspace_id", "workspace", "tenant"} & params
