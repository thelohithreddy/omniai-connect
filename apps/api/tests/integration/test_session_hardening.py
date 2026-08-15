"""Session/credential-transport hardening at the API boundary (M1.3-G).

Two properties, proven through the real ASGI app:

1. A duplicate `Authorization` header is rejected, never silently resolved to the first
   value — the fail-closed rule ADR-0016 §3 already applies to `X-Workspace-Id`, now applied
   to the credential header (`extract_bearer_token`). Exercised on both planes because the
   check runs before machine/human dispatch.
2. The API is `Authorization: Bearer`-only. A Better Auth *session cookie* — the browser's
   credential — never authenticates the API, so a stolen cookie is useless against it and the
   two identity planes cannot be confused (ADR-0002/0015).

The M1.3-G scope is to LOCK settled behavior; these tests fail if a future change reopens the
duplicate-header ambiguity or teaches the API to read cookies.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.human_auth import HUMAN_AUTH_FAILED
from tests.conftest import FakeJWKSEndpoint, SeededWorkspace, SigningAuthority, bearer
from tests.integration.test_human_auth import seed_member


def _dup(a: str, b: str) -> list[tuple[str, str]]:
    """Two `Authorization` header lines, preserved as duplicates (httpx keeps list order)."""
    return [("authorization", a), ("authorization", b)]


# --- Duplicate Authorization — machine plane (extract_bearer_token runs before dispatch) ---


async def test_single_machine_credential_is_the_control(
    client: AsyncClient, workspace_a: SeededWorkspace
) -> None:
    """Baseline: one valid token authenticates, so the rejections below are not vacuous."""
    ok = await client.get("/v1/workspaces/me", headers=bearer(workspace_a.token.plaintext))
    assert ok.status_code == 200


async def test_duplicate_authorization_never_binds_the_first_value(
    client: AsyncClient, workspace_a: SeededWorkspace
) -> None:
    """A valid token paired with garbage — in either order — is a uniform 401, not a 200.

    If the endpoint silently took the first header, `[valid, garbage]` would authenticate;
    if it took the last, `[garbage, valid]` would. Both must fail: ambiguity denies.
    """
    valid = f"Bearer {workspace_a.token.plaintext}"
    for pair in (_dup(valid, "Bearer garbage"), _dup("Bearer garbage", valid), _dup(valid, valid)):
        response = await client.get("/v1/workspaces/me", headers=pair)
        assert response.status_code == 401, f"duplicate must fail closed: {pair}"
        assert response.json()["error"]["code"] == "unauthorized"


# --- Duplicate Authorization — human plane (same guard, verified JWT) ---


async def test_duplicate_authorization_is_rejected_on_the_human_plane(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """A live, verifiable human JWT that authenticates alone is still refused when duplicated."""
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="dup-owner", role="owner")
    token = authority.sign("dup-owner")

    solo = await client.get(
        "/v1/members", headers={**bearer(token), "X-Workspace-Id": str(workspace_a.id)}
    )
    assert solo.status_code == 200, "control: the JWT authenticates on its own"

    dup = await client.get(
        "/v1/members",
        headers=[
            *_dup(f"Bearer {token}", "Bearer garbage"),
            ("x-workspace-id", str(workspace_a.id)),
        ],
    )
    assert dup.status_code == 401


# --- The API is Bearer-only: a session cookie is not a credential ---


async def test_a_session_cookie_alone_does_not_authenticate_the_api(
    client: AsyncClient,
) -> None:
    """Presenting only a (well-formed-looking) Better Auth session cookie is 401 — the API
    reads `Authorization`, never `Cookie`, so the browser credential is inert here."""
    response = await client.get(
        "/v1/workspaces/me",
        headers={"cookie": f"better-auth.session_token={uuid.uuid4().hex}.{uuid.uuid4().hex}"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Missing Authorization header."


async def test_a_session_cookie_value_presented_as_a_bearer_is_not_a_credential(
    client: AsyncClient,
) -> None:
    """Even smuggled into the Bearer slot, an opaque session-cookie value is neither an `omc_`
    token nor a JWT, so it fails the same uniform human 401 — no cross-plane confusion."""
    response = await client.get(
        "/v1/workspaces/me", headers=bearer(f"{uuid.uuid4().hex}.{uuid.uuid4().hex}")
    )
    assert response.status_code == 401
    # Not the omc_ prefix → dispatched to the human plane → uniform human failure.
    assert response.json()["error"]["message"] == HUMAN_AUTH_FAILED
