"""Human authentication through the real application (M1.3-B).

Where `tests/unit/test_human_jwt_verifier.py` proves the *verifier* rejects what it must,
this file proves the *system* composes correctly: real HTTP requests against the real app,
real Postgres with RLS armed, the real membership bootstrap function from migration 0004,
and the real RBAC chain. The only double is the JWKS endpoint (MockTransport through the
`get_jwks_cache` dependency override — BACKEND_SPEC §3's prescribed seam), because these
tests must control key material to prove what happens when it is wrong.

Until this module, nothing could pass `require_permission` over real HTTP — every prior
test fabricated the WorkspaceContext. These are the first tests in the repository where
authentication, tenancy binding, membership resolution, and RBAC all execute end-to-end
in one request.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import uuid
from collections.abc import AsyncIterator

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.human_auth import HUMAN_AUTH_FAILED, JWKSCache, get_jwks_cache
from app.core.ids import new_id
from app.main import app
from tests.conftest import FakeJWKSEndpoint, SeededWorkspace, SigningAuthority

MACHINE_AUTH_FAILED = "Invalid or revoked API token."


async def seed_member(
    engine: AsyncEngine,
    workspace_id: uuid.UUID,
    *,
    user_id: str,
    role: str,
) -> uuid.UUID:
    member_id = new_id()
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO members (id, workspace_id, user_id, role)"
                " VALUES (:id, :ws, :uid, :role)"
            ),
            {"id": member_id, "ws": workspace_id, "uid": user_id, "role": role},
        )
    return member_id


@pytest.fixture
async def human_client(
    client: AsyncClient, jwks_endpoint: FakeJWKSEndpoint
) -> AsyncIterator[tuple[AsyncClient, FakeJWKSEndpoint]]:
    """The app client with the JWKS dependency pointing at the in-process endpoint.

    One cache instance for the whole test — the override returns the same object on every
    request, exactly like production's module singleton. Returning a fresh cache per
    request would silently reset the fetch counter and make every amplification assertion
    vacuous.
    """
    cache: JWKSCache = jwks_endpoint.cache()
    app.dependency_overrides[get_jwks_cache] = lambda: cache
    # `client`'s teardown clears ALL overrides, including this one.
    yield client, jwks_endpoint


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------------------
# The chain: JWT → membership → workspace → RBAC → endpoint
# ---------------------------------------------------------------------------------------


async def test_an_owner_jwt_authenticates_and_lists_members(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """The positive control: sign-in-shaped JWT → 200 through the full stack."""
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="human-owner", role="owner")

    response = await client.get("/v1/members", headers=bearer(authority.sign("human-owner")))

    assert response.status_code == 200
    body = response.json()
    assert [item["user_id"] for item in body["data"]] == ["human-owner"]


async def test_a_subject_with_no_membership_is_uniformly_unauthorized(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
) -> None:
    """A cryptographically valid JWT for a user in no workspace must not authenticate —
    and must be indistinguishable from a forged one."""
    client, _ = human_client
    response = await client.get("/v1/members", headers=bearer(authority.sign("nobody")))

    assert response.status_code == 401
    error = response.json()["error"]
    assert error["code"] == "unauthorized"
    assert error["message"] == HUMAN_AUTH_FAILED


async def test_multi_workspace_membership_fails_closed(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Two memberships, no canonical selection mechanism → deny, not guess (ADR-0015 §8).

    The alternative — picking the first, the newest, or the alphabetically lowest — would
    silently bind a human to a workspace they did not choose, which is a tenancy bug with
    a login screen in front of it.
    """
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="two-homes", role="owner")
    await seed_member(admin_engine, workspace_b.id, user_id="two-homes", role="owner")

    response = await client.get("/v1/members", headers=bearer(authority.sign("two-homes")))

    assert response.status_code == 401
    assert response.json()["error"]["message"] == HUMAN_AUTH_FAILED


@pytest.mark.parametrize(
    ("role", "expected_status"),
    [("owner", 200), ("admin", 200), ("member", 403), ("viewer", 403)],
)
async def test_rbac_executes_on_the_persisted_role(
    role: str,
    expected_status: int,
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """Same valid JWT, four different persisted roles, four policy outcomes.

    This is the proof that authorization comes from the members row and the static matrix
    (ADR-0009) — the token is identical in all four cases, so nothing in it can be what
    grants or denies. It is also the 401/403 distinction: authentication succeeded here.
    """
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id=f"role-{role}", role=role)

    response = await client.get("/v1/members", headers=bearer(authority.sign(f"role-{role}")))

    assert response.status_code == expected_status
    if expected_status == 403:
        assert response.json()["error"]["code"] == "forbidden"


async def test_a_role_change_binds_on_the_next_request(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """Demote an owner between two requests with the SAME JWT: second request loses.

    The JWT outlives the role because the role was never in it.
    """
    client, _ = human_client
    member_id = await seed_member(admin_engine, workspace_a.id, user_id="demoted", role="owner")
    token = authority.sign("demoted")

    assert (await client.get("/v1/members", headers=bearer(token))).status_code == 200

    async with admin_engine.begin() as conn:
        await conn.execute(
            text("UPDATE members SET role = 'viewer' WHERE id = :id"), {"id": member_id}
        )

    assert (await client.get("/v1/members", headers=bearer(token))).status_code == 403


async def test_membership_removal_revokes_access_immediately(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """The honest revocation story (ADR-0015): the JWT stays valid until exp, but the
    membership row is what authorizes — deleting it locks the subject out on the very
    next request, no token expiry required."""
    client, _ = human_client
    member_id = await seed_member(admin_engine, workspace_a.id, user_id="fired", role="owner")
    token = authority.sign("fired")

    assert (await client.get("/v1/members", headers=bearer(token))).status_code == 200

    async with admin_engine.begin() as conn:
        await conn.execute(text("DELETE FROM members WHERE id = :id"), {"id": member_id})

    response = await client.get("/v1/members", headers=bearer(token))
    assert response.status_code == 401
    assert response.json()["error"]["message"] == HUMAN_AUTH_FAILED


# ---------------------------------------------------------------------------------------
# Tenancy
# ---------------------------------------------------------------------------------------


async def test_a_human_sees_only_their_workspace(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Workspace B's members exist (proven via the admin engine, so the assertion is not
    vacuous) and are absent from A's response."""
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="a-owner", role="owner")
    await seed_member(admin_engine, workspace_b.id, user_id="b-owner", role="owner")
    await seed_member(admin_engine, workspace_b.id, user_id="b-second", role="member")

    async with admin_engine.connect() as conn:
        b_rows = await conn.scalar(
            text("SELECT count(*) FROM members WHERE workspace_id = :ws"),
            {"ws": workspace_b.id},
        )
    assert b_rows == 2, "precondition: workspace B really has members"

    response = await client.get("/v1/members", headers=bearer(authority.sign("a-owner")))
    assert response.status_code == 200
    assert {item["user_id"] for item in response.json()["data"]} == {"a-owner"}


async def test_request_supplied_workspace_identity_is_inert(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Headers naming workspace B change nothing; a query parameter cannot even be
    expressed (the router rejects unknown parameters)."""
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="a-only", role="owner")
    await seed_member(admin_engine, workspace_b.id, user_id="b-victim", role="owner")
    token = authority.sign("a-only")

    smuggled = await client.get(
        "/v1/members",
        headers={
            **bearer(token),
            "X-Workspace-Id": str(workspace_b.id),
            "X-Member-Id": str(uuid.uuid4()),
            "Workspace-Id": str(workspace_b.id),
        },
    )
    assert smuggled.status_code == 200
    assert {i["user_id"] for i in smuggled.json()["data"]} == {"a-only"}

    as_query = await client.get(
        "/v1/members",
        params={"workspace_id": str(workspace_b.id)},
        headers=bearer(token),
    )
    assert as_query.status_code == 400
    assert as_query.json()["error"]["code"] == "validation_error"


async def test_jwt_claims_confer_no_authorization(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """A validly signed JWT stuffed with authority-shaped claims — role, permissions, a
    workspace id, even an api_token_id — moves nothing: the persisted viewer row decides,
    and the bound workspace is the membership's, not the claim's."""
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="claim-stuffer", role="viewer")

    token = authority.sign(
        "claim-stuffer",
        role="owner",
        permissions=["members:manage", "workspace:manage"],
        workspace_id=str(workspace_b.id),
        api_token_id=str(uuid.uuid4()),
        scopes=["*"],
    )

    response = await client.get("/v1/members", headers=bearer(token))
    assert response.status_code == 403, "the persisted viewer role must win"


# ---------------------------------------------------------------------------------------
# Machine/human separation
# ---------------------------------------------------------------------------------------


async def test_machine_tokens_still_authenticate_and_never_touch_jwks(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    workspace_a: SeededWorkspace,
) -> None:
    """The machine plane is untouched: an API token authenticates exactly as in M1.2, and
    its path never consults the JWKS endpoint (fetch counter stays zero)."""
    client, endpoint = human_client

    response = await client.get("/v1/workspaces/me", headers=bearer(workspace_a.token.plaintext))
    assert response.status_code == 200
    assert response.json()["id"] == str(workspace_a.id)
    assert endpoint.calls == 0, "machine authentication must not involve JWKS"


async def test_a_machine_token_is_not_a_human_and_rbac_denies_it(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """kind='api_token' resolves no membership, so a permission-gated endpoint is 403 —
    the M1.2 deliberate state, unchanged by the human plane's arrival."""
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="unrelated", role="owner")

    response = await client.get("/v1/members", headers=bearer(workspace_a.token.plaintext))
    assert response.status_code == 403


async def test_a_jwt_can_never_take_the_machine_path(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """An omc_-prefixed credential is machine, full stop — even when its suffix is a
    perfectly valid signed JWT for a real owner. The machine resolver hashes it, finds no
    token row, and answers with the MACHINE failure message: no fallback ran, or the
    message would be the human one."""
    client, endpoint = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="prefixed", role="owner")

    disguised = "omc_" + authority.sign("prefixed")
    response = await client.get("/v1/members", headers=bearer(disguised))

    assert response.status_code == 401
    assert response.json()["error"]["message"] == MACHINE_AUTH_FAILED
    assert endpoint.calls == 0, "the human verifier must never have run"


async def test_a_machine_token_never_reaches_the_human_verifier(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    workspace_a: SeededWorkspace,
) -> None:
    """The converse: a *revoked-looking* (unknown) machine token fails with the machine
    message, not the human one — an invalid API token is never retried as a JWT."""
    client, endpoint = human_client

    response = await client.get("/v1/members", headers=bearer("omc_unknown_token_value"))

    assert response.status_code == 401
    assert response.json()["error"]["message"] == MACHINE_AUTH_FAILED
    assert endpoint.calls == 0


async def test_resolved_caller_kind_matches_the_credential_plane(
    jwks_endpoint: FakeJWKSEndpoint,
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    app_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """The CallerIdentity.kind must reflect which credential was presented — asserted
    directly on the resolved WorkspaceContext, not merely inferred from a status code.

    RBAC denies an unknown member_id and an api_token identically (both resolve no role),
    so a mutation that mislabels a machine token as kind='member' — or a human as
    kind='api_token' — is invisible to any status-code assertion. Only inspecting the
    resolved identity catches it. This is that inspection.
    """
    from starlette.requests import Request

    from app.core.db import UnitOfWork
    from app.core.security import get_workspace_context

    member_id = await seed_member(admin_engine, workspace_a.id, user_id="kind-check", role="owner")
    cache: JWKSCache = jwks_endpoint.cache()

    async def resolve(credential: str) -> tuple[str, object]:
        from sqlalchemy.ext.asyncio import async_sessionmaker

        factory = async_sessionmaker(app_engine, expire_on_commit=False, autoflush=False)
        async with factory() as session, session.begin():
            uow = UnitOfWork(session=session)
            scope = {
                "type": "http",
                "headers": [(b"authorization", f"Bearer {credential}".encode())],
                "state": {},
            }
            ctx = await get_workspace_context(Request(scope), uow, cache)
            return ctx.caller.kind, ctx.caller

    human_kind, human_caller = await resolve(authority.sign("kind-check"))
    assert human_kind == "member"
    assert human_caller.member_id == member_id
    assert human_caller.api_token_id is None

    machine_kind, machine_caller = await resolve(workspace_a.token.plaintext)
    assert machine_kind == "api_token"
    assert machine_caller.member_id is None, "a machine token must never carry a member_id"
    assert machine_caller.api_token_id is not None


async def test_non_bearer_schemes_are_rejected_before_any_plane(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
) -> None:
    client, endpoint = human_client
    response = await client.get(
        "/v1/members", headers={"Authorization": f"Basic {authority.sign('x')}"}
    )
    assert response.status_code == 401
    assert endpoint.calls == 0


# ---------------------------------------------------------------------------------------
# Failure behavior and concurrency through the app
# ---------------------------------------------------------------------------------------


async def test_jwks_outage_is_a_401_never_a_500(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """Infrastructure failure fails closed as the canonical envelope, not a traceback."""
    client, endpoint = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="outage", role="owner")
    endpoint.mode = "timeout"

    response = await client.get("/v1/members", headers=bearer(authority.sign("outage")))

    assert response.status_code == 401
    error = response.json()["error"]
    assert error["code"] == "unauthorized"
    assert error["message"] == HUMAN_AUTH_FAILED
    assert "request_id" in error


async def test_concurrent_human_requests_share_one_jwks_fetch(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """Fifteen simultaneous cold-start requests: all succeed, the provider is hit once.

    This is the fetch-storm guard proven through the whole app rather than against the
    cache in isolation — dependency wiring, single-flight, and the shared singleton all
    have to cooperate for the counter to read 1.
    """
    client, endpoint = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="stampede", role="owner")
    token = authority.sign("stampede")

    responses = await asyncio.gather(
        *(client.get("/v1/members", headers=bearer(token)) for _ in range(15))
    )

    assert [r.status_code for r in responses] == [200] * 15
    assert endpoint.calls == 1


# ---------------------------------------------------------------------------------------
# Log audit
# ---------------------------------------------------------------------------------------


async def test_no_credential_material_reaches_the_logs(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """Drive success and every interesting failure while capturing stdout, then prove the
    capture saw the events (non-vacuous) and none of the secret material.

    structlog writes to stdout via PrintLoggerFactory — the M1.2-F lesson: caplog sees
    nothing, so the capture must wrap the stream itself.
    """
    client, endpoint = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="logged", role="owner")

    good = authority.sign("logged")
    forged = SigningAuthority(kid=authority.kid).sign("logged")
    now_expired = authority.sign("logged", iat=1, exp=2)
    unknown_kid = authority.sign("logged", headers={"kid": "who-dis"})
    machine = workspace_a.token.plaintext

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        assert (await client.get("/v1/members", headers=bearer(good))).status_code == 200
        for bad in (forged, now_expired, unknown_kid):
            assert (await client.get("/v1/members", headers=bearer(bad))).status_code == 401
        endpoint.mode = "timeout"
        endpoint.document = {"keys": []}
        # Also exercise a refresh failure path so its warning is in the capture.
        cache_miss = authority.sign("logged", headers={"kid": "force-refresh-miss"})
        assert (await client.get("/v1/members", headers=bearer(cache_miss))).status_code == 401

    emitted = buffer.getvalue()
    assert emitted, "the capture saw nothing — the audit below would be vacuous"
    assert "human_auth.rejected" in emitted, "rejection events should be observable"

    for label, needle in [
        ("the valid JWT", good),
        ("the forged JWT", forged),
        ("the expired JWT", now_expired),
        ("the unknown-kid JWT", unknown_kid),
        ("the machine token plaintext", machine),
        ("an Authorization header", "Bearer "),
        ("the JWT payload marker", good.split(".")[1]),
    ]:
        assert needle not in emitted, f"{label} leaked into the logs"
