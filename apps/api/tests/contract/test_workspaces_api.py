"""Contract tests for GET /v1/workspaces/me and the error envelope.

These assert the shape of what leaves the API — the part clients build against — rather
than internal behavior. Every error path must produce exactly the envelope in
API_GUIDELINES.md §6, because a client branching on `error.code` breaks silently when one
endpoint invents its own format (P-38).
"""

from __future__ import annotations

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.conftest import SeededWorkspace


def assert_error_envelope(response: httpx.Response, *, code: str) -> None:
    body = response.json()
    assert set(body) == {"error"}, f"unexpected top-level keys: {set(body)}"
    error = body["error"]
    assert error["code"] == code
    assert isinstance(error["message"], str) and error["message"]
    assert error["request_id"], "every error must carry a request_id for support"
    assert response.headers["X-Request-Id"] == error["request_id"]


async def test_health_is_public_and_leaks_no_environment_detail(client: AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
    # Unauthenticated, so every field is public. `env` was removed for that reason.
    assert response.json() == {"status": "ok"}


async def test_valid_token_returns_its_workspace(
    client: AsyncClient, workspace_a: SeededWorkspace
) -> None:
    response = await client.get(
        "/v1/workspaces/me",
        headers={"Authorization": f"Bearer {workspace_a.token.plaintext}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(workspace_a.id)
    assert body["slug"] == workspace_a.slug
    assert body["plan"] == "free"
    assert response.headers["X-Request-Id"].startswith("req_")


async def test_response_never_contains_token_material(
    client: AsyncClient, workspace_a: SeededWorkspace
) -> None:
    response = await client.get(
        "/v1/workspaces/me",
        headers={"Authorization": f"Bearer {workspace_a.token.plaintext}"},
    )
    raw = response.text
    assert workspace_a.token.plaintext not in raw
    assert workspace_a.token.token_hash not in raw


async def test_two_workspaces_each_see_only_themselves(
    client: AsyncClient, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    """The end-to-end statement of the whole milestone."""
    a = await client.get(
        "/v1/workspaces/me", headers={"Authorization": f"Bearer {workspace_a.token.plaintext}"}
    )
    b = await client.get(
        "/v1/workspaces/me", headers={"Authorization": f"Bearer {workspace_b.token.plaintext}"}
    )
    assert a.json()["id"] == str(workspace_a.id)
    assert b.json()["id"] == str(workspace_b.id)
    assert a.json()["id"] != b.json()["id"]


async def test_missing_authorization_header_is_401(client: AsyncClient) -> None:
    response = await client.get("/v1/workspaces/me")
    assert response.status_code == 401
    assert_error_envelope(response, code="unauthorized")


async def test_malformed_authorization_scheme_is_401(client: AsyncClient) -> None:
    response = await client.get(
        "/v1/workspaces/me", headers={"Authorization": "Basic dXNlcjpwYXNz"}
    )
    assert response.status_code == 401
    assert_error_envelope(response, code="unauthorized")


async def test_unknown_token_is_401(client: AsyncClient) -> None:
    response = await client.get(
        "/v1/workspaces/me", headers={"Authorization": "Bearer omc_definitely-not-a-real-token"}
    )
    assert response.status_code == 401
    assert_error_envelope(response, code="unauthorized")


async def test_unknown_and_revoked_tokens_are_indistinguishable(
    client: AsyncClient, workspace_a: SeededWorkspace, admin_engine: AsyncEngine
) -> None:
    """Different failures, identical responses.

    A distinct message for "revoked" would confirm the token was once real, which is a
    useful signal to anyone testing a stolen list (P-17, no existence oracle).
    """
    unknown = await client.get(
        "/v1/workspaces/me", headers={"Authorization": "Bearer omc_never-existed"}
    )
    async with admin_engine.begin() as conn:
        await conn.execute(
            text("UPDATE api_tokens SET revoked_at = now() WHERE workspace_id = :ws"),
            {"ws": workspace_a.id},
        )
    revoked = await client.get(
        "/v1/workspaces/me",
        headers={"Authorization": f"Bearer {workspace_a.token.plaintext}"},
    )

    assert unknown.status_code == revoked.status_code == 401
    assert unknown.json()["error"]["code"] == revoked.json()["error"]["code"]
    assert unknown.json()["error"]["message"] == revoked.json()["error"]["message"]


async def test_inbound_request_id_is_propagated(client: AsyncClient) -> None:
    response = await client.get("/health", headers={"X-Request-Id": "caller-supplied-123"})
    assert response.headers["X-Request-Id"] == "caller-supplied-123"


@pytest.mark.parametrize(
    ("hostile", "note"),
    [
        ("abc\ndef INJECTED-LOG-LINE", "embedded newline"),
        # Regression: `^...$` in Python also matches immediately before a *trailing*
        # newline, so this value passed sanitization and was echoed back into a response
        # header — a textbook response-splitting primitive. `\\Z` is what rejects it.
        ("abc123\n", "trailing newline"),
        ("a" * 65, "over the length cap"),
        ("has spaces", "disallowed charset"),
        ("semi;colon", "header delimiter"),
        ("", "empty"),
    ],
)
async def test_hostile_request_id_is_replaced_not_echoed(
    client: AsyncClient, hostile: str, note: str
) -> None:
    """Log- and header-injection guard: hostile values are replaced, never patched in place."""
    response = await client.get("/health", headers={"X-Request-Id": hostile})
    returned = response.headers["X-Request-Id"]
    assert returned.startswith("req_"), f"{note}: hostile value survived as {returned!r}"
    assert "\n" not in returned and "\r" not in returned
    assert "INJECTED" not in returned


async def test_unrouted_path_uses_the_error_envelope(client: AsyncClient) -> None:
    response = await client.get("/v1/does-not-exist")
    assert response.status_code == 404
    assert_error_envelope(response, code="not_found")
