"""Credential endpoints through the real app (M1-Credentials-v1):
/v1/connections/{connection_id}/credential.

Real HTTP, real Postgres+RLS, real RBAC, real human JWT + machine API-token auth, real vault. Proves
the attach/get/rotate/revoke contract; the Connection lifecycle (pending_auth ↔ active); that
**no secret ever appears in a response** (metadata only); `connections:manage` on every role;
machine/human separation; cross-tenant 404s; server-owned-field rejection; and per-type shapes.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.security import generate_token
from tests.conftest import FakeJWKSEndpoint, SeededWorkspace, SigningAuthority, bearer
from tests.integration.test_human_auth import seed_member

WS_HEADER = "X-Workspace-Id"
SECRET = "sk-live-supersecret-do-not-leak"  # noqa: S105 (test secret)


def hx(token: str, workspace_id: uuid.UUID) -> dict[str, str]:
    return {**bearer(token), WS_HEADER: str(workspace_id)}


@pytest.fixture
async def owner(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> AsyncIterator[dict[str, object]]:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="cr-owner", role="owner")
    yield {"client": client, "ws": workspace_a.id, "token": authority.sign("cr-owner")}


async def _make_connection(owner: dict[str, object], slug: str = "demo") -> str:
    """Create a connector + a connection (pending_auth) and return the connection id."""
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    headers = hx(owner["token"], owner["ws"])  # type: ignore[arg-type]
    connector = await client.post(
        "/v1/connectors",
        headers=headers,
        json={"name": "Demo", "base_url": "https://api.example.com", "slug": slug},
    )
    assert connector.status_code == 201, connector.text
    connection = await client.post(
        "/v1/connections",
        headers=headers,
        json={"connector_id": connector.json()["id"], "name": f"conn-{slug}"},
    )
    assert connection.status_code == 201, connection.text
    return connection.json()["id"]


def _url(conn_id: str) -> str:
    return f"/v1/connections/{conn_id}/credential"


# ------------------------------------------------------------------ happy path / no-echo


async def test_attach_returns_metadata_only_and_activates_the_connection(
    owner: dict[str, object],
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    headers = hx(owner["token"], owner["ws"])  # type: ignore[arg-type]
    conn_id = await _make_connection(owner)

    resp = await client.post(
        _url(conn_id), headers=headers, json={"credential_type": "api_key", "value": SECRET}
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["credential_type"] == "api_key" and body["key_version"] == 1
    assert body["connection_id"] == conn_id and body["rotated_at"] is None
    # No secret, no ciphertext material, no workspace leak — anywhere in the response.
    assert SECRET not in resp.text
    for banned in ("value", "ciphertext", "encrypted_dek", "nonce", "workspace_id"):
        assert banned not in body

    # The connection is now active (§3).
    conn = await client.get(f"/v1/connections/{conn_id}", headers=headers)
    assert conn.json()["status"] == "active"

    # GET metadata: still no secret.
    got = await client.get(_url(conn_id), headers=headers)
    assert got.status_code == 200 and SECRET not in got.text and "value" not in got.json()


async def test_rotate_then_revoke_lifecycle(owner: dict[str, object]) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    headers = hx(owner["token"], owner["ws"])  # type: ignore[arg-type]
    conn_id = await _make_connection(owner)
    await client.post(
        _url(conn_id), headers=headers, json={"credential_type": "bearer", "value": SECRET}
    )

    rotated = await client.put(
        _url(conn_id), headers=headers, json={"credential_type": "bearer", "value": "sk-rotated"}
    )
    assert rotated.status_code == 200 and rotated.json()["rotated_at"] is not None
    assert "sk-rotated" not in rotated.text

    revoked = await client.delete(_url(conn_id), headers=headers)
    assert revoked.status_code == 204
    # The credential is gone (404) and the connection returned to pending_auth.
    assert (await client.get(_url(conn_id), headers=headers)).status_code == 404
    conn = await client.get(f"/v1/connections/{conn_id}", headers=headers)
    assert conn.json()["status"] == "pending_auth" and conn.json()["credential_id"] is None


async def test_basic_and_a_bad_shape(owner: dict[str, object]) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    headers = hx(owner["token"], owner["ws"])  # type: ignore[arg-type]
    conn_id = await _make_connection(owner)
    ok = await client.post(
        _url(conn_id),
        headers=headers,
        json={"credential_type": "basic", "username": "alice", "password": SECRET},
    )
    assert ok.status_code == 201 and SECRET not in ok.text
    assert ok.json()["credential_type"] == "basic"  # the stored type is the one submitted
    # basic without a password is a 400.
    conn2 = await _make_connection(owner, slug="two")
    bad = await client.post(
        _url(conn2), headers=headers, json={"credential_type": "basic", "username": "bob"}
    )
    assert bad.status_code == 400


async def test_a_second_attach_is_409(owner: dict[str, object]) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    headers = hx(owner["token"], owner["ws"])  # type: ignore[arg-type]
    conn_id = await _make_connection(owner)
    await client.post(
        _url(conn_id), headers=headers, json={"credential_type": "api_key", "value": "a"}
    )
    second = await client.post(
        _url(conn_id), headers=headers, json={"credential_type": "api_key", "value": "b"}
    )
    assert second.status_code == 409


# ------------------------------------------------------------------ authorization


@pytest.mark.parametrize(("role", "expected"), [("admin", 201), ("member", 403), ("viewer", 403)])
async def test_attach_permission_matrix(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    owner: dict[str, object],
    role: str,
    expected: int,
) -> None:
    client, _ = human_client
    conn_id = await _make_connection(owner)
    await seed_member(admin_engine, workspace_a.id, user_id=f"cr-{role}", role=role)
    resp = await client.post(
        _url(conn_id),
        headers=hx(authority.sign(f"cr-{role}"), workspace_a.id),
        json={"credential_type": "api_key", "value": SECRET},
    )
    assert resp.status_code == expected, resp.text
    assert SECRET not in resp.text


async def test_machine_token_cannot_manage_credentials(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    owner: dict[str, object],
) -> None:
    client, _ = human_client
    conn_id = await _make_connection(owner)  # connection in workspace A
    generated = generate_token()
    async with admin_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO api_tokens (id, workspace_id, name, token_hash, token_prefix, scopes)"
                " VALUES (:i,:w,'m',:h,:p,'[]'::jsonb)"
            ),
            {
                "i": uuid.uuid4(),
                "w": workspace_b.id,
                "h": generated.token_hash,
                "p": generated.token_prefix,
            },
        )
    # Machine token holds no membership → no connections:manage → 403, X-Workspace-Id inert.
    resp = await client.post(
        _url(conn_id),
        headers={**bearer(generated.plaintext), WS_HEADER: str(workspace_a.id)},
        json={"credential_type": "api_key", "value": SECRET},
    )
    assert resp.status_code == 403


# ------------------------------------------------------------------ untrusted input / cross-tenant


@pytest.mark.parametrize(
    "smuggled",
    [
        {"workspace_id": "00000000-0000-0000-0000-000000000000"},
        {"status": "active"},
        {"credential_id": "00000000-0000-0000-0000-000000000000"},
        {"connection_id": "00000000-0000-0000-0000-000000000000"},
        {"key_version": 99},
        {"id": "00000000-0000-0000-0000-000000000000"},
    ],
)
async def test_smuggled_server_owned_fields_are_rejected(
    owner: dict[str, object], smuggled: dict[str, object]
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    headers = hx(owner["token"], owner["ws"])  # type: ignore[arg-type]
    conn_id = await _make_connection(owner)
    resp = await client.post(
        _url(conn_id),
        headers=headers,
        json={"credential_type": "api_key", "value": SECRET, **smuggled},
    )
    assert resp.status_code == 400


async def test_attach_to_a_foreign_connection_is_404(
    owner: dict[str, object],
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_b: SeededWorkspace,
) -> None:
    client, _ = human_client
    a_conn = await _make_connection(owner)  # in workspace A
    await seed_member(admin_engine, workspace_b.id, user_id="b-owner", role="owner")
    b_headers = hx(authority.sign("b-owner"), workspace_b.id)
    # B cannot attach to / read / revoke A's connection's credential — each a uniform 404.
    assert (
        await client.post(
            _url(a_conn), headers=b_headers, json={"credential_type": "api_key", "value": SECRET}
        )
    ).status_code == 404
    assert (await client.get(_url(a_conn), headers=b_headers)).status_code == 404
    assert (await client.delete(_url(a_conn), headers=b_headers)).status_code == 404


async def test_get_or_revoke_without_a_credential_is_404(owner: dict[str, object]) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    headers = hx(owner["token"], owner["ws"])  # type: ignore[arg-type]
    conn_id = await _make_connection(owner)  # pending_auth, no credential yet
    assert (await client.get(_url(conn_id), headers=headers)).status_code == 404
    assert (await client.delete(_url(conn_id), headers=headers)).status_code == 404
