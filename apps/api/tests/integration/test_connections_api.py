"""Connections endpoints through the real app (M1-Connections-v1): /v1/connections.

Real HTTP, real Postgres with RLS, real centralized RBAC, real human JWT + machine API-token auth,
real Redis idempotency. Nothing in the authorization chain is mocked. Proves the CRUD/lifecycle
contract, `connections:manage` on every role, machine/human separation (a machine token cannot be
redirected by `X-Workspace-Id`), cross-tenant 404s, server-owned-field rejection, SSRF-linted
overrides, and Idempotency-Key replay / mismatch / concurrency.
"""

from __future__ import annotations

import asyncio
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
    await seed_member(admin_engine, workspace_a.id, user_id="cx-owner", role="owner")
    yield {"client": client, "ws": workspace_a.id, "token": authority.sign("cx-owner")}


async def _make_connector(owner: dict[str, object], slug: str = "demo") -> str:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    resp = await client.post(
        "/v1/connectors",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
        json={"name": "Demo", "base_url": "https://api.example.com/v1", "slug": slug},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _create(
    owner: dict[str, object], connector_id: str, name: str, **extra: object
) -> object:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    return await client.post(
        "/v1/connections",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
        json={"connector_id": connector_id, "name": name, **extra},
    )


# ------------------------------------------------------------------ happy path


async def test_create_returns_201_pending_auth_and_is_readable(owner: dict[str, object]) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    cid = await _make_connector(owner)

    resp = await _create(owner, cid, "prod", config_overrides={"base_url": "https://api.x.com"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "pending_auth"
    assert body["connector_id"] == cid
    assert body["credential_id"] is None
    assert "workspace_id" not in body  # never leaked

    got = await client.get(
        f"/v1/connections/{body['id']}",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
    )
    assert got.status_code == 200 and got.json()["id"] == body["id"]
    listed = await client.get("/v1/connections", headers=hx(owner["token"], owner["ws"]))  # type: ignore[arg-type]
    assert [c["name"] for c in listed.json()["data"]] == ["prod"]


async def test_patch_updates_name_and_config_then_revoke(owner: dict[str, object]) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    cid = await _make_connector(owner)
    conn_id = (await _create(owner, cid, "n1")).json()["id"]

    patched = await client.patch(
        f"/v1/connections/{conn_id}",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
        json={"name": "n2", "config_overrides": {"base_url": "https://api.x.com/v2"}},
    )
    assert patched.status_code == 200 and patched.json()["name"] == "n2"

    revoked = await client.delete(
        f"/v1/connections/{conn_id}",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
    )
    assert revoked.status_code == 204
    # Second revoke and a get are both a uniform 404 (soft-deleted → no longer live).
    assert (
        await client.delete(
            f"/v1/connections/{conn_id}",
            headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
        )
    ).status_code == 404
    assert (
        await client.get(
            f"/v1/connections/{conn_id}",
            headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
        )
    ).status_code == 404


# ------------------------------------------------------------------ authorization matrix


async def test_create_admin_allowed_member_and_viewer_denied(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    owner: dict[str, object],
) -> None:
    client, _ = human_client
    cid = await _make_connector(owner)
    # admin holds connections:manage → allowed.
    await seed_member(admin_engine, workspace_a.id, user_id="cx-admin", role="admin")
    admin_resp = await client.post(
        "/v1/connections",
        headers=hx(authority.sign("cx-admin"), workspace_a.id),
        json={"connector_id": cid, "name": "by-admin"},
    )
    assert admin_resp.status_code == 201, admin_resp.text
    # member and viewer do not → 403.
    for role in ("member", "viewer"):
        await seed_member(admin_engine, workspace_a.id, user_id=f"cx-{role}", role=role)
        denied = await client.post(
            "/v1/connections",
            headers=hx(authority.sign(f"cx-{role}"), workspace_a.id),
            json={"connector_id": cid, "name": f"by-{role}"},
        )
        assert denied.status_code == 403, f"{role}: {denied.text}"


async def test_machine_token_cannot_manage_connections_even_with_x_workspace_id(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    owner: dict[str, object],
) -> None:
    client, _ = human_client
    cid = await _make_connector(owner)  # a connector in workspace A
    # Mint a machine token bound to workspace B.
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
    # The machine token holds no membership → no `connections:manage` → 403, and `X-Workspace-Id`
    # is inert for machine callers (they bind to the token's own workspace). It cannot act in A.
    resp = await client.post(
        "/v1/connections",
        headers={**bearer(generated.plaintext), WS_HEADER: str(workspace_a.id)},
        json={"connector_id": cid, "name": "by-machine"},
    )
    assert resp.status_code == 403
    async with admin_engine.connect() as c:
        count = await c.scalar(text("SELECT count(*) FROM connections WHERE name='by-machine'"))
    assert count == 0  # nothing created in A (or anywhere)


# ------------------------------------------------------------------ untrusted input / cross-tenant


@pytest.mark.parametrize(
    "smuggled",
    [
        {"workspace_id": "00000000-0000-0000-0000-000000000000"},
        {"status": "active"},
        {"credential_id": "00000000-0000-0000-0000-000000000000"},
        {"role": "owner"},
        {"member_id": "00000000-0000-0000-0000-000000000000"},
        {"kind": "member"},
        {"id": "00000000-0000-0000-0000-000000000000"},
    ],
)
async def test_smuggled_server_owned_fields_are_rejected(
    owner: dict[str, object], smuggled: dict[str, str]
) -> None:
    cid = await _make_connector(owner)
    resp = await _create(owner, cid, "smuggle", **smuggled)
    assert resp.status_code == 400  # extra="forbid"


async def test_create_against_a_foreign_connector_is_404(
    owner: dict[str, object], admin_engine: AsyncEngine, workspace_b: SeededWorkspace
) -> None:
    # A connector that exists, but in workspace B — the owner acting in A cannot bind it.
    b_cid = uuid.uuid4()
    async with admin_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO connectors"
                " (id, workspace_id, name, slug, source_type, base_url, status)"
                " VALUES (:i,:w,'b','b','manual','https://api.b.com','active')"
            ),
            {"i": b_cid, "w": workspace_b.id},
        )
    resp = await _create(owner, str(b_cid), "x")
    assert resp.status_code == 404


async def test_an_unsafe_base_url_override_is_400(owner: dict[str, object]) -> None:
    cid = await _make_connector(owner)
    resp = await _create(owner, cid, "bad", config_overrides={"base_url": "http://169.254.169.254"})
    assert resp.status_code == 400


async def test_unknown_query_param_is_400(owner: dict[str, object]) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    resp = await client.get(
        "/v1/connections?sort=name",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
    )
    assert resp.status_code == 400


async def test_a_foreign_workspaces_connection_is_a_uniform_404(
    owner: dict[str, object],
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_b: SeededWorkspace,
) -> None:
    client, _ = human_client
    cid = await _make_connector(owner)
    a_conn_id = (await _create(owner, cid, "a-only")).json()["id"]
    # An owner of B cannot get / patch / delete A's connection — each a uniform 404.
    await seed_member(admin_engine, workspace_b.id, user_id="b-owner", role="owner")
    b_headers = hx(authority.sign("b-owner"), workspace_b.id)
    assert (await client.get(f"/v1/connections/{a_conn_id}", headers=b_headers)).status_code == 404
    assert (
        await client.patch(
            f"/v1/connections/{a_conn_id}", headers=b_headers, json={"name": "hijack"}
        )
    ).status_code == 404
    assert (
        await client.delete(f"/v1/connections/{a_conn_id}", headers=b_headers)
    ).status_code == 404


# ------------------------------------------------------------------ idempotency


async def test_idempotent_retry_replays_the_same_connection(owner: dict[str, object]) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    cid = await _make_connector(owner)
    key = str(uuid.uuid4())
    headers = {**hx(owner["token"], owner["ws"]), "Idempotency-Key": key}  # type: ignore[arg-type]
    body = {"connector_id": cid, "name": "idem"}

    first = await client.post("/v1/connections", headers=headers, json=body)
    second = await client.post("/v1/connections", headers=headers, json=body)
    assert first.status_code == 201 and second.status_code == 201
    assert first.json()["id"] == second.json()["id"]  # replayed, not re-created
    listed = await client.get("/v1/connections", headers=hx(owner["token"], owner["ws"]))  # type: ignore[arg-type]
    assert [c["name"] for c in listed.json()["data"]] == ["idem"]  # exactly one row


async def test_idempotency_key_reuse_with_a_different_body_is_409(owner: dict[str, object]) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    cid = await _make_connector(owner)
    key = str(uuid.uuid4())
    headers = {**hx(owner["token"], owner["ws"]), "Idempotency-Key": key}  # type: ignore[arg-type]

    first = await client.post(
        "/v1/connections", headers=headers, json={"connector_id": cid, "name": "one"}
    )
    assert first.status_code == 201
    clash = await client.post(
        "/v1/connections", headers=headers, json={"connector_id": cid, "name": "two"}
    )
    assert clash.status_code == 409


async def test_a_bad_idempotency_key_is_400(owner: dict[str, object]) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    cid = await _make_connector(owner)
    resp = await client.post(
        "/v1/connections",
        headers={**hx(owner["token"], owner["ws"]), "Idempotency-Key": "not-a-uuid"},  # type: ignore[arg-type]
        json={"connector_id": cid, "name": "x"},
    )
    assert resp.status_code == 400


async def test_concurrent_same_key_creates_no_duplicate(owner: dict[str, object]) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    cid = await _make_connector(owner)
    key = str(uuid.uuid4())
    headers = {**hx(owner["token"], owner["ws"]), "Idempotency-Key": key}  # type: ignore[arg-type]
    body = {"connector_id": cid, "name": "concurrent"}

    r1, r2 = await asyncio.gather(
        client.post("/v1/connections", headers=headers, json=body),
        client.post("/v1/connections", headers=headers, json=body),
    )
    statuses = sorted([r1.status_code, r2.status_code])
    # No duplicate: one succeeds; the concurrent twin either replays (201) or sees the reservation
    # in-flight (409). Never two distinct rows.
    assert 201 in statuses and set(statuses) <= {201, 409}
    listed = await client.get("/v1/connections", headers=hx(owner["token"], owner["ws"]))  # type: ignore[arg-type]
    assert len([c for c in listed.json()["data"] if c["name"] == "concurrent"]) == 1
