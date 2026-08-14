"""API token issuance: the secret exists once, provenance cannot be forged, tenants hold.

Four properties are under test, and each is asserted *behaviourally* rather than by
reading the implementation:

1. **The plaintext is unrecoverable after the response.** Not "we did not store it" — the
   row is dumped column by column and searched, the log stream is captured and searched,
   and the resolver is asked to prove the hash round-trips while the secret does not.
2. **Provenance comes from the authenticated member.** A client cannot supply it, and the
   database refuses a creator belonging to another tenant even though the application
   would have written it.
3. **Only a human-plane member holding `api_tokens:manage` can mint.** A machine token
   cannot mint another token — no credential self-propagation.
4. **A token issued in workspace A is a workspace A credential**, end to end through real
   authentication.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import uuid
from collections.abc import AsyncIterator
from typing import Annotated, Any

import pytest
import structlog
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

import app.domains.workspaces.service as service_module
from app.core.db import UnitOfWork, get_uow
from app.core.exceptions import ValidationFailedError
from app.core.middleware import RequestContextMiddleware
from app.core.security import (
    PREFIX_DISPLAY_LEN,
    TOKEN_PREFIX,
    CallerIdentity,
    WorkspaceContext,
    get_workspace_context,
)
from app.domains.workspaces.repository import ApiTokenRepository
from app.domains.workspaces.router import api_tokens_router
from app.domains.workspaces.service import ApiTokenService
from app.main import app as real_app
from tests.conftest import SeededWorkspace
from tests.integration.test_members_tenancy import seed_member

pytestmark = pytest.mark.asyncio


def api_token_context(workspace_id: uuid.UUID) -> WorkspaceContext:
    """A machine-plane context, as `get_workspace_context` builds today."""
    return WorkspaceContext(
        workspace_id=workspace_id,
        caller=CallerIdentity(kind="api_token", api_token_id=uuid.uuid4()),
        request_id="req_test",
    )


def member_context(workspace_id: uuid.UUID, member_id: uuid.UUID) -> WorkspaceContext:
    """A human-plane context, as Better Auth will build in M1.2-G."""
    return WorkspaceContext(
        workspace_id=workspace_id,
        caller=CallerIdentity(kind="member", member_id=member_id),
        request_id="req_test",
    )


async def bound_service(session: AsyncSession, workspace_id: uuid.UUID) -> ApiTokenService:
    """Arm both isolation layers, then hand back the service under test.

    `bind_workspace` arms RLS on the transaction; the context arms the repository. A test
    that skips the first proves nothing about layer 2, and one that skips the second is
    not exercising the code path production uses.
    """
    await UnitOfWork(session=session).bind_workspace(workspace_id)
    return ApiTokenService(ApiTokenRepository(session, api_token_context(workspace_id)))


async def dump_token_row(engine: AsyncEngine, token_id: uuid.UUID) -> dict[str, Any]:
    """Every column of a token row, as an admin who is not constrained by RLS.

    Read with the *admin* engine on purpose: proving the plaintext is absent has to look
    everywhere, including places the application role cannot see.
    """
    async with engine.begin() as conn:
        result = await conn.execute(
            text("SELECT * FROM api_tokens WHERE id = :id"), {"id": token_id}
        )
        row = result.mappings().one()
    return dict(row)


# =======================================================================================
# 1. The secret: minted correctly, stored only as a hash, unrecoverable afterwards
# =======================================================================================


async def test_issue_persists_the_token_in_the_bound_workspace(
    app_session: AsyncSession, workspace_a: SeededWorkspace
) -> None:
    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        issued = await service.issue(name="ci-deploy", created_by_member_id=None)

    assert issued.token.workspace_id == workspace_a.id
    assert issued.token.name == "ci-deploy"
    assert issued.token.id is not None


async def test_stored_row_contains_the_hash_and_never_the_plaintext(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """The central guarantee, asserted against every column rather than the ones we expect.

    Searching each value for the secret — instead of asserting `row["token_hash"] !=
    plaintext` — is what makes this test survive a future migration that adds a column.
    A well-meant `token_plaintext` or a `metadata` blob echoing the request would fail
    here without anyone having to remember to update the assertion.
    """
    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        issued = await service.issue(name="ci", created_by_member_id=None)
    plaintext = issued.plaintext

    row = await dump_token_row(admin_engine, issued.token.id)

    assert row["token_hash"] == hashlib.sha256(plaintext.encode()).hexdigest()
    for column, value in row.items():
        assert plaintext not in str(value), f"plaintext leaked into api_tokens.{column}"


async def test_the_secret_cannot_be_reconstructed_from_the_stored_row(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """ "Shown once" only holds if the retained fragment is not the secret.

    `token_prefix` is deliberately persisted in the clear so a revocation UI can name a
    credential. That is safe exactly while it stays a *fragment*: 8 random characters of a
    43-character secret. If a future change widened `PREFIX_DISPLAY_LEN` toward the full
    length, the "shown once" property would erode silently — this asserts the retained
    portion stays a small minority of the whole.
    """
    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        issued = await service.issue(name="ci", created_by_member_id=None)

    row = await dump_token_row(admin_engine, issued.token.id)
    secret_body = issued.plaintext.removeprefix(TOKEN_PREFIX)
    retained = row["token_prefix"].removeprefix(TOKEN_PREFIX)

    assert issued.plaintext.startswith(row["token_prefix"])
    assert retained == secret_body[: PREFIX_DISPLAY_LEN - len(TOKEN_PREFIX)]
    assert len(retained) * 4 < len(secret_body), "retained prefix is no longer a small fragment"
    assert secret_body not in row["token_prefix"]


async def test_every_issuance_mints_a_distinct_secret(
    app_session: AsyncSession, workspace_a: SeededWorkspace
) -> None:
    """No reuse, no derivation from the workspace, no counter."""
    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        first = await service.issue(name="one", created_by_member_id=None)
        second = await service.issue(name="two", created_by_member_id=None)

    assert first.plaintext != second.plaintext
    assert first.token.token_hash != second.token.token_hash
    assert first.token.id != second.token.id


async def test_issued_token_defaults_to_no_scopes(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Tokens are minted unscoped until a scope vocabulary exists (see module docstring
    of `schemas.ApiTokenCreate`). `[]` is the deny-by-default value, not a placeholder for
    "everything"."""
    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        issued = await service.issue(name="ci", created_by_member_id=None)

    row = await dump_token_row(admin_engine, issued.token.id)
    assert row["scopes"] == []


# =======================================================================================
# 2. Round-trip: the returned secret is a working credential for the issuing workspace
# =======================================================================================


async def test_issued_token_authenticates_against_its_own_workspace(
    client: AsyncClient, app_session: AsyncSession, workspace_a: SeededWorkspace
) -> None:
    """The proof that hashing is symmetric with resolution.

    A test that only asserted "we stored sha256(plaintext)" would pass even if the
    resolver hashed differently, and the first real client would be unable to authenticate.
    This drives the freshly minted secret through `auth.resolve_api_token`, RLS binding and
    the real endpoint.
    """
    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        issued = await service.issue(name="ci", created_by_member_id=None)

    response = await client.get(
        "/v1/workspaces/me", headers={"Authorization": f"Bearer {issued.plaintext}"}
    )

    assert response.status_code == 200, response.text
    assert response.json()["id"] == str(workspace_a.id)


async def test_a_token_issued_in_one_workspace_cannot_read_another(
    client: AsyncClient,
    app_session: AsyncSession,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Issuance does not create a cross-tenant credential.

    The token resolves — it is genuine — and still returns only workspace A. There is no
    request field that could point it at B, and RLS is bound from the resolved row.
    """
    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        issued = await service.issue(name="ci", created_by_member_id=None)

    response = await client.get(
        "/v1/workspaces/me", headers={"Authorization": f"Bearer {issued.plaintext}"}
    )

    assert response.status_code == 200
    assert response.json()["id"] == str(workspace_a.id)
    assert response.json()["id"] != str(workspace_b.id)


async def test_a_tampered_token_does_not_authenticate(
    client: AsyncClient, app_session: AsyncSession, workspace_a: SeededWorkspace
) -> None:
    """Knowing the public prefix is not knowing the token."""
    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        issued = await service.issue(name="ci", created_by_member_id=None)

    for candidate in (
        issued.token.token_prefix,
        issued.plaintext[:-1],
        issued.plaintext + "x",
        issued.token.token_hash,
    ):
        response = await client.get(
            "/v1/workspaces/me", headers={"Authorization": f"Bearer {candidate}"}
        )
        assert response.status_code == 401, f"{candidate[:16]}... authenticated"


# =======================================================================================
# 3. Tenancy: a token is written into the bound workspace and nowhere else
# =======================================================================================


async def test_repository_create_cannot_be_asked_to_write_another_tenant(
    app_session: AsyncSession, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    """Layer 1 — the parameter does not exist; layer 2 — RLS refuses anyway.

    Building a repository whose context says B while the transaction is bound to A is the
    strongest cross-tenant write an attacker could reach through this code, and it needs a
    compromised authenticator to even construct. Postgres rejects it: the INSERT fails the
    row-security policy because the row's `workspace_id` is not the bound one.
    """
    assert "workspace_id" not in ApiTokenRepository.create.__annotations__

    async with app_session.begin():
        await UnitOfWork(session=app_session).bind_workspace(workspace_a.id)
        wrong = ApiTokenRepository(app_session, api_token_context(workspace_b.id))
        with pytest.raises(Exception, match="row-level security|violates"):
            await wrong.create(
                name="evil",
                token_hash="0" * 64,
                token_prefix="omc_evil",  # noqa: S106 — a literal, not a credential
            )


# =======================================================================================
# 4. Provenance: attributed to a real member of this workspace, or to nobody
# =======================================================================================


async def test_created_by_records_the_issuing_member(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    member_id = await seed_member(admin_engine, workspace_a.id, user_id="alice")

    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        issued = await service.issue(name="ci", created_by_member_id=member_id)

    row = await dump_token_row(admin_engine, issued.token.id)
    assert row["created_by_member_id"] == member_id


async def test_created_by_may_be_absent_for_bootstrap_tokens(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """The first token of a workspace predates every Member, so the column stays nullable.

    Making it `NOT NULL` would make workspace bootstrap impossible, or force a fabricated
    member row — which is worse than an honest NULL.
    """
    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        issued = await service.issue(name="bootstrap", created_by_member_id=None)

    row = await dump_token_row(admin_engine, issued.token.id)
    assert row["created_by_member_id"] is None


async def test_a_creator_from_another_workspace_is_refused_by_the_database(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """The composite intra-tenant foreign key, doing the job a single-column FK could not.

    Foreign keys are validated with RLS bypassed, so `REFERENCES members(id)` would have
    accepted this row: B's member genuinely exists. Only carrying `workspace_id` into the
    key makes the reference unsatisfiable from A. This test fails if anyone ever
    "simplifies" the constraint back to one column.
    """
    b_member = await seed_member(admin_engine, workspace_b.id, user_id="mallory")

    with pytest.raises(IntegrityError) as exc_info:
        async with app_session.begin():
            service = await bound_service(app_session, workspace_a.id)
            await service.issue(name="cross-tenant", created_by_member_id=b_member)

    assert "fk_api_tokens_created_by_member_id" in str(exc_info.value)


async def test_removing_the_creator_clears_provenance_but_keeps_the_token(
    app_session: AsyncSession,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """`ON DELETE SET NULL (created_by_member_id)`, verified as behaviour.

    Two failure modes are excluded at once. A bare `SET NULL` would also target
    `workspace_id`, which is `NOT NULL`, so removing a member would *fail* — the workspace
    would have an undeletable member. `CASCADE` would silently revoke every token an
    offboarded employee issued, breaking production deploys the moment HR removes them.
    Tokens are workspace-owned; revoking them is a separate, explicit act.
    """
    member_id = await seed_member(admin_engine, workspace_a.id, user_id="departing")
    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        issued = await service.issue(name="their-ci-token", created_by_member_id=member_id)

    async with admin_engine.begin() as conn:
        await conn.execute(text("DELETE FROM members WHERE id = :id"), {"id": member_id})

    row = await dump_token_row(admin_engine, issued.token.id)
    assert row["created_by_member_id"] is None
    assert row["revoked_at"] is None, "offboarding a member must not revoke their tokens"
    assert row["token_hash"] == issued.token.token_hash


# =======================================================================================
# 5. Input validation at the service boundary (not only at the HTTP door)
# =======================================================================================


@pytest.mark.parametrize("name", ["", "   ", "\t\n"])
async def test_issue_rejects_a_nameless_token(
    app_session: AsyncSession, workspace_a: SeededWorkspace, name: str
) -> None:
    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        with pytest.raises(ValidationFailedError):
            await service.issue(name=name, created_by_member_id=None)


async def test_issue_rejects_an_overlong_name(
    app_session: AsyncSession, workspace_a: SeededWorkspace
) -> None:
    """A domain error, not a driver `DataError` leaking through the service (P-50)."""
    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        with pytest.raises(ValidationFailedError):
            await service.issue(name="x" * 121, created_by_member_id=None)


async def test_a_rejected_request_persists_nothing(
    app_session: AsyncSession, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Validation happens before minting, so a failed issuance leaves no row behind."""
    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        with pytest.raises(ValidationFailedError):
            await service.issue(name="  ", created_by_member_id=None)

    async with admin_engine.begin() as conn:
        count = await conn.scalar(
            text("SELECT count(*) FROM api_tokens WHERE workspace_id = :w AND name <> :seeded"),
            {"w": workspace_a.id, "seeded": "a-token"},
        )
    assert count == 0


async def test_issue_trims_surrounding_whitespace(
    app_session: AsyncSession, workspace_a: SeededWorkspace
) -> None:
    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        issued = await service.issue(name="  ci-deploy  ", created_by_member_id=None)
    assert issued.token.name == "ci-deploy"


# =======================================================================================
# 6. The endpoint: authorization, provenance, and the response contract
# =======================================================================================


def build_token_app(app_engine: AsyncEngine, context_factory: Any) -> FastAPI:
    """The real router, mounted with authentication replaced by a chosen identity.

    Only `get_workspace_context` is overridden — the same technique M1.2-E used. The
    permission dependency, the membership lookup, the policy, the service, the repository
    and the error handlers are all untouched production code, so what this exercises is the
    real authorization path and not a re-implementation of it.
    """
    factory = async_sessionmaker(app_engine, expire_on_commit=False, autoflush=False)
    test_app = FastAPI()
    for exc, handler in real_app.exception_handlers.items():
        test_app.add_exception_handler(exc, handler)  # type: ignore[arg-type]
    # Production's middleware stack, not a bare app. It is what emits request logs, so
    # without it the log-leak test observes an empty stream and passes for the wrong
    # reason — and any future middleware that touches the response body would go untested
    # against the one endpoint that returns a credential.
    test_app.add_middleware(RequestContextMiddleware)
    test_app.include_router(api_tokens_router)

    async def override_uow() -> AsyncIterator[UnitOfWork]:
        async with factory() as session, session.begin():
            yield UnitOfWork(session=session)

    async def override_context(uow: Annotated[UnitOfWork, Depends(get_uow)]) -> WorkspaceContext:
        ctx = context_factory()
        await uow.bind_workspace(ctx.workspace_id)
        return ctx

    test_app.dependency_overrides[get_uow] = override_uow
    test_app.dependency_overrides[get_workspace_context] = override_context
    return test_app


@pytest.mark.parametrize(
    ("role", "expected"), [("owner", 201), ("admin", 201), ("member", 403), ("viewer", 403)]
)
async def test_endpoint_admits_exactly_the_roles_holding_api_tokens_manage(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    role: str,
    expected: int,
) -> None:
    """Mirrors SECURITY.md §4.1's "Create/revoke workspace API tokens" row, end to end.

    Asserted through HTTP rather than by calling `is_allowed`, because the question here is
    whether the *endpoint* is wired to the policy — a route that forgot the dependency
    would still pass a policy unit test.
    """
    member_id = await seed_member(admin_engine, workspace_a.id, user_id=f"u-{role}", role=role)
    test_app = build_token_app(app_engine, lambda: member_context(workspace_a.id, member_id))

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://t") as client:
        response = await client.post("/v1/api-tokens", json={"name": "ci"})

    assert response.status_code == expected, response.text
    if expected == 403:
        assert response.json()["error"]["code"] == "forbidden"
        assert "token" not in response.text


async def test_a_machine_token_cannot_mint_another_token(
    app_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """No credential self-propagation.

    A leaked API token must not be able to issue further tokens: that would let an attacker
    mint a credential that survives revocation of the one they stole, converting a
    time-boxed compromise into a permanent one. Machine identity resolves to no membership
    (ADR-0002), so the permission check denies — and this asserts that the *effect* holds,
    not merely that the identity planes are separate somewhere.
    """
    test_app = build_token_app(app_engine, lambda: api_token_context(workspace_a.id))

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://t") as client:
        response = await client.post("/v1/api-tokens", json={"name": "escalation"})

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


async def test_a_confused_deputy_token_carrying_a_member_id_is_still_denied(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """A machine context that also names a real member must not inherit that member's power.

    This is the mutation that M1.2-E's suite originally missed: with a token identity whose
    `member_id` is `None`, removing the identity-plane check changes nothing. Here the
    member id is real and privileged, so only the `kind` test stands between the token and
    an owner's permissions.
    """
    owner_id = await seed_member(admin_engine, workspace_a.id, user_id="real-owner", role="owner")
    deputy = WorkspaceContext(
        workspace_id=workspace_a.id,
        caller=CallerIdentity(kind="api_token", api_token_id=uuid.uuid4(), member_id=owner_id),
        request_id="req_test",
    )
    test_app = build_token_app(app_engine, lambda: deputy)

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://t") as client:
        response = await client.post("/v1/api-tokens", json={"name": "escalation"})

    assert response.status_code == 403


async def test_a_member_of_another_workspace_cannot_mint_here(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Owner in B, nobody in A. Roles are per-workspace, not global."""
    b_owner = await seed_member(admin_engine, workspace_b.id, user_id="b-owner", role="owner")
    test_app = build_token_app(app_engine, lambda: member_context(workspace_a.id, b_owner))

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://t") as client:
        response = await client.post("/v1/api-tokens", json={"name": "ci"})

    assert response.status_code == 403


async def test_successful_creation_returns_the_secret_once_with_correct_provenance(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    owner_id = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    test_app = build_token_app(app_engine, lambda: member_context(workspace_a.id, owner_id))

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://t") as client:
        response = await client.post("/v1/api-tokens", json={"name": "ci-deploy"})

    assert response.status_code == 201
    body = response.json()
    assert body["token"].startswith(TOKEN_PREFIX)
    assert body["token_prefix"] == body["token"][:PREFIX_DISPLAY_LEN]
    assert body["created_by_member_id"] == str(owner_id)
    assert body["scopes"] == []

    row = await dump_token_row(admin_engine, uuid.UUID(body["id"]))
    assert row["workspace_id"] == workspace_a.id
    assert row["created_by_member_id"] == owner_id
    assert row["token_hash"] == hashlib.sha256(body["token"].encode()).hexdigest()
    for column, value in row.items():
        assert body["token"] not in str(value), f"plaintext leaked into api_tokens.{column}"


async def test_the_response_never_carries_the_hash_and_is_not_cacheable(
    app_engine: AsyncEngine, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """`no-store` per RFC 6749 §5.1: this body is a bearer credential in transit."""
    owner_id = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    test_app = build_token_app(app_engine, lambda: member_context(workspace_a.id, owner_id))

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://t") as client:
        response = await client.post("/v1/api-tokens", json={"name": "ci"})

    assert response.headers["cache-control"] == "no-store"
    assert "token_hash" not in response.json()
    assert set(response.json()) == {
        "id",
        "name",
        "token",
        "token_prefix",
        "scopes",
        "created_by_member_id",
        "expires_at",
        "created_at",
    }


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "ci", "created_by_member_id": "11111111-1111-1111-1111-111111111111"},
        {"name": "ci", "workspace_id": "11111111-1111-1111-1111-111111111111"},
        {"name": "ci", "token_hash": "0" * 64},
        {"name": "ci", "token": "omc_attacker-chosen"},
        {"name": "ci", "scopes": ["*"]},
        {"name": "ci", "revoked_at": None},
    ],
)
async def test_server_owned_fields_are_rejected_rather_than_ignored(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    payload: dict[str, Any],
) -> None:
    """Pydantic's default is to *ignore* unknown fields, which is the dangerous behaviour.

    Ignoring would return 201 and leave the client believing their `created_by_member_id`
    or `scopes` were honoured. `extra="forbid"` turns each attempt into a 422. Note the
    `token` case in particular: a caller must never be able to propose their own secret.
    """
    owner_id = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    test_app = build_token_app(app_engine, lambda: member_context(workspace_a.id, owner_id))

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://t") as client:
        response = await client.post("/v1/api-tokens", json=payload)

    assert response.status_code == 400, response.text
    assert response.json()["error"]["code"] == "validation_error"


@pytest.mark.parametrize("payload", [{}, {"name": ""}, {"name": "   "}, {"name": "x" * 121}])
async def test_invalid_names_are_refused_at_the_endpoint(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    payload: dict[str, Any],
) -> None:
    owner_id = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    test_app = build_token_app(app_engine, lambda: member_context(workspace_a.id, owner_id))

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://t") as client:
        response = await client.post("/v1/api-tokens", json=payload)

    assert response.status_code == 400, response.text
    assert response.json()["error"]["code"] == "validation_error"


async def test_creation_requires_authentication(
    client: AsyncClient, workspace_a: SeededWorkspace
) -> None:
    """Through the *real* app, with no context override: no header, no token."""
    response = await client.post("/v1/api-tokens", json={"name": "ci"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


async def test_a_denied_request_creates_no_token(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """403 must mean nothing happened, not "it happened and we hid the response".

    The permission dependency is resolved before the service is constructed, so a denial
    cannot have written a row. Asserted by counting, because "the handler returns early" is
    an implementation claim and this is the observable one.
    """
    member_id = await seed_member(admin_engine, workspace_a.id, user_id="plain", role="member")
    test_app = build_token_app(app_engine, lambda: member_context(workspace_a.id, member_id))

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://t") as client:
        assert (await client.post("/v1/api-tokens", json={"name": "ci"})).status_code == 403

    async with admin_engine.begin() as conn:
        count = await conn.scalar(
            text("SELECT count(*) FROM api_tokens WHERE workspace_id = :w AND name = 'ci'"),
            {"w": workspace_a.id},
        )
    assert count == 0


# =======================================================================================
# 7. The secret does not escape through observability
# =======================================================================================


async def test_no_log_output_contains_the_plaintext(
    app_engine: AsyncEngine,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """Capture the real log stream for a successful issuance and search it.

    `caplog` is useless here and using it would make this test *look* like a security check
    while asserting against an empty buffer: `configure_logging` installs
    `structlog.PrintLoggerFactory`, which writes to stdout and never reaches stdlib logging.
    Redirecting stdout is what actually observes what the process emits.

    The log level is pinned session-wide by `_pin_log_level` in `conftest.py`, **not** here.
    Setting it inside this test does not work and looks like it does: structlog freezes a
    logger's level filter on first use (`cache_logger_on_first_use=True`), so by the time
    this test runs, the middleware's module-level logger has already been frozen by whatever
    earlier test first made a request. Reconfiguring afterwards changes the configuration and
    not that logger. See the fixture's docstring for the full mechanism.

    `assert emitted` is what keeps this test honest, and it is doing real work: it is the
    assertion that failed in CI when the level filter silently suppressed everything, turning
    "the secret is absent" into a statement about an empty string.
    """
    owner_id = await seed_member(admin_engine, workspace_a.id, user_id="owner", role="owner")
    test_app = build_token_app(app_engine, lambda: member_context(workspace_a.id, owner_id))

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://t"
        ) as client:
            response = await client.post("/v1/api-tokens", json={"name": "ci"})

    assert response.status_code == 201
    emitted = buffer.getvalue()
    assert emitted, "nothing was logged — this assertion would pass vacuously"

    plaintext = response.json()["token"]
    assert plaintext not in emitted
    assert plaintext.removeprefix(TOKEN_PREFIX) not in emitted


async def test_a_failed_request_mints_no_secret_at_all(
    app_session: AsyncSession, workspace_a: SeededWorkspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Validation runs *before* generation, so a doomed request never creates a credential.

    "No row was written" is not the same property and would still hold if the order were
    reversed. What matters is that no high-entropy secret ever exists for a request that is
    about to fail: a generated-then-discarded token lives in a stack frame that a traceback
    renderer, an APM agent capturing locals, or a `repr()` of the frame can walk. Counting
    calls to `generate_token` is the only way to observe the ordering from outside.
    """
    calls = 0
    real = service_module.generate_token

    def counting_generate_token() -> Any:
        nonlocal calls
        calls += 1
        return real()

    monkeypatch.setattr(service_module, "generate_token", counting_generate_token)

    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        with pytest.raises(ValidationFailedError):
            await service.issue(name="   ", created_by_member_id=None)
        assert calls == 0, "a secret was minted for a request that was rejected"

        await service.issue(name="valid", created_by_member_id=None)
        assert calls == 1


async def test_structlog_rendering_of_the_service_result_omits_the_secret(
    app_session: AsyncSession, workspace_a: SeededWorkspace
) -> None:
    """`IssuedApiToken` and `GeneratedToken` must be safe to hand to a logger by accident.

    structlog calls `repr()` on non-primitive values, so a dataclass with a default repr
    turns `log.info("issued", result=issued)` into a credential disclosure. Asserted by
    actually rendering through structlog rather than by reading the decorator.
    """
    async with app_session.begin():
        service = await bound_service(app_session, workspace_a.id)
        issued = await service.issue(name="ci", created_by_member_id=None)

    rendered = structlog.processors.KeyValueRenderer()(
        None, "info", {"event": "issued", "result": issued, "token": issued.token}
    )

    assert issued.plaintext not in str(rendered)
    assert issued.plaintext not in repr(issued)
    assert issued.plaintext not in str(issued)
