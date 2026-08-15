"""The real end-to-end proof (M1.3-B §11): live Better Auth, no doubles anywhere.

Every other auth test controls the key material. This file controls nothing: a human is
created in the real Better Auth (apps/web, `identity` schema), the JWT is minted by the
real provider, the JWKS is fetched from the real endpoint by the real production cache,
and the request flows through the real app into real RLS-guarded Postgres. If any link —
provider config, JWKS publication, EdDSA verification, issuer pinning, the membership
bootstrap function, RBAC — disagrees with any other, this file is where it surfaces.

Deliberately FAILS rather than skips when the provider is unreachable: a missing identity
provider is a broken environment, and a skipped end-to-end proof is indistinguishable
from a passing one in a green CI summary. Locally the provider is the compose `web`
service; in CI the API job builds and starts it before pytest.

Better Auth users created here are left behind by design: the API's database role cannot
reach the `identity` schema (ADR-0014 — that privilege boundary is the point), emails are
random per run, and CI's database is destroyed with the job.
"""

from __future__ import annotations

import uuid

import httpx
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.config import settings
from app.core.human_auth import HUMAN_AUTH_FAILED
from tests.conftest import SeededWorkspace
from tests.integration.test_human_auth import bearer, seed_member

# The provider's base URL is wherever the JWKS actually lives, minus the well-known path.
# One derivation, so the login calls and the verifier's key fetches hit the same instance.
PROVIDER_BASE = settings.resolved_jwks_url.removesuffix("/api/auth/jwks")


async def real_human(name: str) -> tuple[str, str]:
    """Create a real Better Auth user; return (verified-looking JWT, its sub).

    The origin header matches the provider's trusted origin (its own baseURL), which is
    what its CSRF check requires of state-changing requests.
    """
    email = f"e2e-{name}-{uuid.uuid4().hex[:10]}@example.test"
    password = f"pw-{uuid.uuid4()}"
    async with httpx.AsyncClient(base_url=PROVIDER_BASE, timeout=10.0) as provider:
        signup = await provider.post(
            "/api/auth/sign-up/email",
            json={"email": email, "password": password, "name": name},
            headers={"origin": settings.better_auth_url},
        )
        assert signup.status_code == 200, (
            f"Better Auth sign-up failed ({signup.status_code}) — is the provider up at "
            f"{PROVIDER_BASE}? Locally: `docker compose up -d web`."
        )
        cookie = signup.headers.get("set-cookie", "").split(";")[0]
        token_response = await provider.get("/api/auth/token", headers={"cookie": cookie})
        assert token_response.status_code == 200
        token = token_response.json()["token"]

    import base64
    import json

    payload_raw = token.split(".")[1]
    payload = json.loads(base64.urlsafe_b64decode(payload_raw + "=" * (-len(payload_raw) % 4)))
    return token, payload["sub"]


async def test_the_full_chain_from_real_login_to_rls_scoped_data(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """§11's enumerated proof, in one flow, against entirely real components.

    Note what is NOT overridden here: `get_jwks_cache` uses the production singleton,
    which fetches the provider's live JWKS. This is the only test in the repository whose
    keys came from the actual `identity.jwks` row.
    """
    token, sub = await real_human("owner")

    # 12. Missing and invalid credentials are uniform 401s before any membership exists.
    assert (await client.get("/v1/members")).status_code == 401
    garbage = await client.get("/v1/members", headers=bearer("not.a.jwt"))
    assert garbage.status_code == 401
    assert garbage.json()["error"]["message"] == HUMAN_AUTH_FAILED

    # A real, live JWT for a user with no membership must also be the uniform 401.
    no_membership = await client.get("/v1/members", headers=bearer(token))
    assert no_membership.status_code == 401
    assert no_membership.json()["error"]["message"] == HUMAN_AUTH_FAILED

    # 6–10. Membership lands; the same real JWT now authenticates, resolves the member,
    # binds the workspace, passes RBAC (owner → members:manage), and reads RLS-scoped data.
    member_id = await seed_member(admin_engine, workspace_a.id, user_id=sub, role="owner")
    await seed_member(admin_engine, workspace_b.id, user_id="someone-else", role="owner")

    response = await client.get("/v1/members", headers=bearer(token))
    assert response.status_code == 200
    rows = response.json()["data"]
    assert [row["user_id"] for row in rows] == [sub], "sub must map to exactly its member"
    assert rows[0]["id"] == str(member_id)
    assert rows[0]["role"] == "owner"

    # 13. Cross-tenant stays impossible with a real credential: workspace B's rows exist
    # (ground truth via the admin engine) and are absent from the response.
    async with admin_engine.connect() as conn:
        b_count = await conn.scalar(
            text("SELECT count(*) FROM members WHERE workspace_id = :ws"),
            {"ws": workspace_b.id},
        )
    assert b_count == 1, "precondition: workspace B really has a member"
    assert all(row["user_id"] != "someone-else" for row in rows)


async def test_a_real_jwt_for_a_viewer_is_authenticated_but_forbidden(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """§11.11: the unauthorized endpoint answers 403 — authentication succeeded, the
    persisted viewer role holds no permission (ADR-0009), and the distinction between
    401 and 403 survives the human plane."""
    token, sub = await real_human("viewer")
    await seed_member(admin_engine, workspace_a.id, user_id=sub, role="viewer")

    response = await client.get("/v1/members", headers=bearer(token))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


async def test_provider_logout_does_not_invalidate_an_outstanding_jwt(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """The revocation semantics of ADR-0015, proven rather than assumed.

    Signing out destroys the Better Auth *session*; the already-issued JWT remains a
    valid bearer credential until `exp` (≤ 900 s), because the API verifies signatures,
    not sessions, and cannot see the `identity` schema (ADR-0014). This test pins the
    documented behavior so that if it ever changes — either direction — the docs and the
    ADR must change with it. Immediate lockout is achieved by removing the membership,
    which `test_membership_removal_revokes_access_immediately` proves.
    """
    email = f"e2e-logout-{uuid.uuid4().hex[:10]}@example.test"
    password = f"pw-{uuid.uuid4()}"
    async with httpx.AsyncClient(base_url=PROVIDER_BASE, timeout=10.0) as provider:
        signup = await provider.post(
            "/api/auth/sign-up/email",
            json={"email": email, "password": password, "name": "Logout"},
            headers={"origin": settings.better_auth_url},
        )
        assert signup.status_code == 200
        cookie = signup.headers.get("set-cookie", "").split(";")[0]
        token = (await provider.get("/api/auth/token", headers={"cookie": cookie})).json()["token"]

        import base64
        import json

        raw = token.split(".")[1]
        sub = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))["sub"]
        await seed_member(admin_engine, workspace_a.id, user_id=sub, role="owner")

        # Prove the JWT works, sign out at the provider, prove it still works.
        assert (await client.get("/v1/members", headers=bearer(token))).status_code == 200

        signout = await provider.post(
            "/api/auth/sign-out",
            json={},
            headers={"cookie": cookie, "origin": settings.better_auth_url},
        )
        assert signout.status_code == 200
        session_gone = await provider.get("/api/auth/get-session", headers={"cookie": cookie})
        assert session_gone.json() is None, "the provider session must really be dead"

    still_valid = await client.get("/v1/members", headers=bearer(token))
    assert still_valid.status_code == 200, (
        "documented semantics: an outstanding JWT survives logout until exp"
    )


def _session_cookie(response: httpx.Response) -> str:
    """The `better-auth.session_token=<value>` pair from a real Set-Cookie response."""
    for header in response.headers.get_list("set-cookie"):
        if header.startswith("better-auth.session_token="):
            return header.split(";", 1)[0]
    raise AssertionError("no session_token cookie was set")


async def test_the_issued_jwt_lifetime_is_the_documented_bounded_window() -> None:
    """The real provider issues a 900 s (15 min) JWT — the exact window the revocation
    boundary depends on (ADR-0015, SECURITY.md ≤900s). Pinned against the live provider so a
    Better Auth default change that widened the replay window forces the docs to change too.
    """
    import base64
    import json

    token, _sub = await real_human("ttl")
    payload_raw = token.split(".")[1]
    payload = json.loads(base64.urlsafe_b64decode(payload_raw + "=" * (-len(payload_raw) % 4)))
    assert payload["exp"] - payload["iat"] == 900


async def test_logout_kills_the_session_so_no_new_jwt_can_be_minted() -> None:
    """The other half of the revocation boundary: sign-out deletes the session, so the old
    cookie can no longer mint a *fresh* JWT (401). Together with
    `test_provider_logout_does_not_invalidate_an_outstanding_jwt` this fully bounds the model:
    already-issued JWTs live to exp; no new ones are obtainable after logout.
    """
    email = f"e2e-nonew-{uuid.uuid4().hex[:10]}@example.test"
    password = f"pw-{uuid.uuid4()}"
    async with httpx.AsyncClient(base_url=PROVIDER_BASE, timeout=10.0) as provider:
        signup = await provider.post(
            "/api/auth/sign-up/email",
            json={"email": email, "password": password, "name": "NoNew"},
            headers={"origin": settings.better_auth_url},
        )
        assert signup.status_code == 200
        cookie = _session_cookie(signup)

        # The live cookie mints a JWT...
        assert (
            await provider.get("/api/auth/token", headers={"cookie": cookie})
        ).status_code == 200

        signout = await provider.post(
            "/api/auth/sign-out",
            json={},
            headers={"cookie": cookie, "origin": settings.better_auth_url},
        )
        assert signout.status_code == 200

        # ...and after logout the same cookie can no longer obtain one.
        denied = await provider.get("/api/auth/token", headers={"cookie": cookie})
        assert denied.status_code == 401


async def test_each_login_mints_a_fresh_session_token() -> None:
    """Session-fixation resistance: no session cookie exists before authentication, and each
    authentication issues a *new* session token — an attacker-fixed pre-login value can never
    become the authenticated session (owned by Better Auth; pinned here against the live one).
    """
    email = f"e2e-fixation-{uuid.uuid4().hex[:10]}@example.test"
    password = f"pw-{uuid.uuid4()}"
    async with httpx.AsyncClient(base_url=PROVIDER_BASE, timeout=10.0) as provider:
        # No anonymous session cookie is set before login.
        pre = await provider.get(
            "/api/auth/get-session", headers={"origin": settings.better_auth_url}
        )
        assert not pre.headers.get_list("set-cookie"), "no cookie must be set pre-authentication"

        signup = await provider.post(
            "/api/auth/sign-up/email",
            json={"email": email, "password": password, "name": "Fix"},
            headers={"origin": settings.better_auth_url},
        )
        assert signup.status_code == 200
        first = _session_cookie(signup)

        signin = await provider.post(
            "/api/auth/sign-in/email",
            json={"email": email, "password": password},
            headers={"origin": settings.better_auth_url},
        )
        assert signin.status_code == 200
        second = _session_cookie(signin)

    assert first != second, "re-authentication must rotate the session token (no fixation)"


async def test_the_real_jwks_contains_no_private_material(
    client: AsyncClient,
) -> None:
    """Belt over the web suite's braces: the JWKS the VERIFIER trusts, fetched from the
    live provider by this process, exposes only public parameters."""
    async with httpx.AsyncClient(timeout=10.0) as http:
        document = (await http.get(settings.resolved_jwks_url)).json()
    assert document["keys"], "empty JWKS would make this vacuous"
    for key in document["keys"]:
        assert key["kty"] == "OKP" and key["alg"] == "EdDSA"
        for private_param in ("d", "p", "q", "dp", "dq", "qi"):
            assert private_param not in key
