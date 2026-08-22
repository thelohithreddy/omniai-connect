"""Execution Runtime end to end — `/v1/tool-calls` through the real app (M1, AI_RUNTIME.md).

Real HTTP, real Postgres with RLS, real machine-token auth, real credential decrypt + injection,
audit row + Idempotency-Key. The ONLY thing mocked is the final socket: `app.core.net.request` is
replaced so no test performs real egress, while everything up to and including credential decryption
and request construction runs for real. Proves: successful execution with correct credential
injection, the failure taxonomy (upstream error, timeout, SSRF, bad args, missing credential), the
mandatory audit row on every audited outcome, cross-tenant 404s, and idempotent replay.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core import net
from app.core.events import event_bus
from app.domains.credentials.vault import seal
from app.domains.runtime.events import TOOL_CALL_COMPLETED
from tests.conftest import FakeJWKSEndpoint, SeededWorkspace, SigningAuthority, bearer
from tests.integration.test_human_auth import seed_member

WS_HEADER = "X-Workspace-Id"

_DEFAULT_ENDPOINT = {
    "method": "GET",
    "url": "/get",
    "binding": {"q": {"location": "query"}},
    "body_style": "none",
}
_DEFAULT_INPUT_SCHEMA = {"type": "object", "properties": {"q": {"type": "string"}}, "required": []}


@dataclass
class _Sent:
    method: str
    url: str
    headers: dict[str, str]
    allowed_hosts: frozenset[str] | None


class _Egress:
    """A stand-in for the guarded outbound call. Records what the runtime tried to send (so tests
    can assert the injected credential) and returns a canned response, or raises a canned error."""

    def __init__(self) -> None:
        self.calls: list[_Sent] = []
        self.response = net.GuardedResponse(
            status_code=200,
            headers=httpx.Headers({"content-type": "application/json"}),
            body=b'{"ok":true}',
            truncated=False,
        )
        self.exc: Exception | None = None

    async def __call__(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        allowed_hosts: frozenset[str] | None = None,
        max_bytes: int = 0,
        **_: object,
    ) -> net.GuardedResponse:
        self.calls.append(_Sent(method, url, dict(headers or {}), allowed_hosts))
        if self.exc is not None:
            raise self.exc
        return self.response


@pytest.fixture
def egress(monkeypatch: pytest.MonkeyPatch) -> _Egress:
    fake = _Egress()
    monkeypatch.setattr("app.core.net.request", fake)
    return fake


async def seed_tool(
    engine: AsyncEngine,
    workspace_id: uuid.UUID,
    *,
    credential_type: str = "bearer",
    secret: dict[str, str] | None = None,
    auth_config: dict[str, object] | None = None,
    endpoint: dict[str, object] | None = None,
    input_schema: dict[str, object] | None = None,
    status: str = "active",
    with_credential: bool = True,
    tool_name: str = "demo_op",
    base_url: str = "https://api.example.com",
    connection_name: str = "Demo conn",
) -> dict[str, uuid.UUID]:
    """Seed a full executable Tool (connector → version → tool → connection → credential) as the
    superuser admin engine, bypassing RLS. Returns the ids the test needs."""
    endpoint = endpoint or _DEFAULT_ENDPOINT
    input_schema = input_schema or _DEFAULT_INPUT_SCHEMA
    secret = secret or {"value": "sk-live-demo"}
    auth_config = auth_config if auth_config is not None else {}

    connector_id = uuid.uuid4()
    version_id = uuid.uuid4()
    tool_id = uuid.uuid4()
    connection_id = uuid.uuid4()
    credential_id = uuid.uuid4()
    slug = f"demo-{connector_id.hex[:8]}"
    normalized = {
        "tools": [{"name": tool_name, "endpoint": endpoint, "input_schema": input_schema}]
    }

    async with engine.begin() as conn:
        # Cyclic FK connectors ↔ connector_versions: connector first (no version pointer), then the
        # version (references the connector), then point the connector at it.
        await conn.execute(
            text(
                "INSERT INTO connectors (id, workspace_id, name, slug, source_type, base_url, "
                "auth_config, status) VALUES (:id, :ws, 'Demo', :slug, 'manual', :base_url, "
                ":auth, 'active')"
            ),
            {
                "id": connector_id,
                "ws": workspace_id,
                "slug": slug,
                "base_url": base_url,
                "auth": json.dumps(auth_config),
            },
        )
        await conn.execute(
            text(
                "INSERT INTO connector_versions (id, workspace_id, connector_id, version, "
                "spec_hash, normalized_schema) VALUES (:id, :ws, :cid, 1, 'hash', :schema)"
            ),
            {
                "id": version_id,
                "ws": workspace_id,
                "cid": connector_id,
                "schema": json.dumps(normalized),
            },
        )
        await conn.execute(
            text("UPDATE connectors SET current_version_id = :ver WHERE id = :id"),
            {"ver": version_id, "id": connector_id},
        )
        await conn.execute(
            text(
                "INSERT INTO tools (id, workspace_id, connector_id, connector_version_id, name, "
                "description, input_schema) VALUES (:id, :ws, :cid, :ver, :name, 'op', :schema)"
            ),
            {
                "id": tool_id,
                "ws": workspace_id,
                "cid": connector_id,
                "ver": version_id,
                "name": tool_name,
                "schema": json.dumps(input_schema),
            },
        )
        await conn.execute(
            text(
                "INSERT INTO connections (id, workspace_id, connector_id, name, status, "
                "config_overrides) VALUES (:id, :ws, :cid, :name, :status, '{}')"
            ),
            {
                "id": connection_id,
                "ws": workspace_id,
                "cid": connector_id,
                # Overridable because `(workspace_id, name)` is unique: a scenario seeding two
                # Connectors into one Workspace (EC1) needs distinct Connection names.
                "name": connection_name,
                "status": status,
            },
        )
        if with_credential:
            sealed = seal(
                json.dumps(secret).encode("utf-8"),
                workspace_id=workspace_id,
                connection_id=connection_id,
            )
            await conn.execute(
                text(
                    "INSERT INTO credentials (id, workspace_id, connection_id, credential_type, "
                    "ciphertext, encrypted_dek, key_version, nonce) VALUES (:id, :ws, :conn, :ct, "
                    ":ct_b, :dek, :kv, :nonce)"
                ),
                {
                    "id": credential_id,
                    "ws": workspace_id,
                    "conn": connection_id,
                    "ct": credential_type,
                    "ct_b": sealed.ciphertext,
                    "dek": sealed.encrypted_dek,
                    "kv": sealed.key_version,
                    "nonce": sealed.nonce,
                },
            )
            await conn.execute(
                text("UPDATE connections SET credential_id = :cred WHERE id = :id"),
                {"cred": credential_id, "id": connection_id},
            )

    return {
        "connector_id": connector_id,
        "connection_id": connection_id,
        "tool_id": tool_id,
        "credential_id": credential_id,
    }


def _auth(ws: SeededWorkspace) -> dict[str, str]:
    return bearer(ws.token.plaintext)


async def _call(
    client: httpx.AsyncClient, ws: SeededWorkspace, body: dict[str, object]
) -> httpx.Response:
    return await client.post("/v1/tool-calls", headers=_auth(ws), json=body)


# --------------------------------------------------------------------------- success paths


async def test_successful_bearer_call_injects_authorization_and_audits(
    client: httpx.AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
) -> None:
    await seed_tool(
        admin_engine, workspace_a.id, credential_type="bearer", secret={"value": "tok-xyz"}
    )
    resp = await _call(client, workspace_a, {"tool_name": "demo_op", "arguments": {"q": "hi"}})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "succeeded"
    assert body["content"] == {"type": "json", "json": {"ok": True}, "truncated": False}

    # The runtime decrypted the credential and injected the Authorization header for real.
    assert egress.calls[0].headers.get("Authorization") == "Bearer tok-xyz"
    assert egress.calls[0].allowed_hosts == frozenset({"api.example.com"})

    # The audit row exists and reads back as succeeded.
    got = await client.get(f"/v1/tool-calls/{body['id']}", headers=_auth(workspace_a))
    assert got.status_code == 200
    assert got.json()["status"] == "succeeded"
    assert got.json()["error_code"] is None


async def test_api_key_header_injection(
    client: httpx.AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
) -> None:
    await seed_tool(
        admin_engine,
        workspace_a.id,
        credential_type="api_key",
        secret={"value": "sk-123"},
        auth_config={"type": "api_key", "key_name": "X-API-Key", "location": "header"},
    )
    resp = await _call(client, workspace_a, {"tool_name": "demo_op", "arguments": {}})
    assert resp.status_code == 200, resp.text
    assert egress.calls[0].headers.get("X-API-Key") == "sk-123"


async def test_basic_auth_injection(
    client: httpx.AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
) -> None:
    await seed_tool(
        admin_engine,
        workspace_a.id,
        credential_type="basic",
        secret={"username": "user", "password": "pass"},
    )
    resp = await _call(client, workspace_a, {"tool_name": "demo_op", "arguments": {}})
    assert resp.status_code == 200, resp.text
    assert egress.calls[0].headers["Authorization"].startswith("Basic ")


# --------------------------------------------------------------------------- failure taxonomy


async def test_upstream_error_maps_to_connector_error_and_audits_failed(
    client: httpx.AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
) -> None:
    await seed_tool(admin_engine, workspace_a.id)
    egress.response = net.GuardedResponse(
        503, httpx.Headers({"content-type": "text/plain"}), b"down", False
    )
    resp = await _call(client, workspace_a, {"tool_name": "demo_op", "arguments": {}})
    assert resp.status_code == 502
    assert resp.json()["error"]["code"] == "connector_error"
    tool_call_id = resp.json()["error"]["details"]["tool_call_id"]
    got = await client.get(f"/v1/tool-calls/{tool_call_id}", headers=_auth(workspace_a))
    assert got.json()["status"] == "failed"
    assert got.json()["error_code"] == "connector_error"
    assert got.json()["output_summary"]["status_code"] == 503


async def test_timeout_maps_to_504(
    client: httpx.AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
) -> None:
    await seed_tool(admin_engine, workspace_a.id)
    egress.exc = httpx.TimeoutException("slow")
    resp = await _call(client, workspace_a, {"tool_name": "demo_op", "arguments": {}})
    assert resp.status_code == 504
    assert resp.json()["error"]["code"] == "upstream_timeout"
    got = await client.get(
        f"/v1/tool-calls/{resp.json()['error']['details']['tool_call_id']}",
        headers=_auth(workspace_a),
    )
    assert got.json()["status"] == "timeout"


async def test_ssrf_block_maps_to_ssrf_blocked_403(
    client: httpx.AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
) -> None:
    await seed_tool(admin_engine, workspace_a.id)
    egress.exc = net.SSRFError("blocked-private")
    resp = await _call(client, workspace_a, {"tool_name": "demo_op", "arguments": {}})
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "ssrf_blocked"
    # The safe message must not carry the raw reason/URL/address.
    assert "blocked-private" not in resp.text
    got = await client.get(
        f"/v1/tool-calls/{resp.json()['error']['details']['tool_call_id']}",
        headers=_auth(workspace_a),
    )
    assert got.json()["status"] == "denied"


async def test_bad_arguments_are_400_and_audited(
    client: httpx.AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
) -> None:
    await seed_tool(admin_engine, workspace_a.id)
    resp = await _call(client, workspace_a, {"tool_name": "demo_op", "arguments": {"unknown": 1}})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "validation_error"
    assert not egress.calls  # never reached the wire
    got = await client.get(
        f"/v1/tool-calls/{resp.json()['error']['details']['tool_call_id']}",
        headers=_auth(workspace_a),
    )
    assert got.json()["status"] == "failed"


async def test_connection_without_credential_is_409(
    client: httpx.AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
) -> None:
    await seed_tool(admin_engine, workspace_a.id, with_credential=False)
    resp = await _call(client, workspace_a, {"tool_name": "demo_op", "arguments": {}})
    assert resp.status_code == 409
    assert not egress.calls


async def test_unknown_tool_is_404_with_no_audit_row(
    client: httpx.AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
) -> None:
    resp = await _call(client, workspace_a, {"tool_name": "does_not_exist", "arguments": {}})
    assert resp.status_code == 404
    assert "details" not in resp.json()["error"]  # no tool_call_id — nothing was audited


async def test_no_active_connection_is_404(
    client: httpx.AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
) -> None:
    await seed_tool(admin_engine, workspace_a.id, status="pending_auth")
    resp = await _call(client, workspace_a, {"tool_name": "demo_op", "arguments": {}})
    assert resp.status_code == 404


# ------------------------------------------------------------------ isolation + idempotency


async def test_cross_tenant_tool_is_not_visible(
    client: httpx.AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    egress: _Egress,
) -> None:
    await seed_tool(admin_engine, workspace_a.id)
    # Workspace B's token cannot see or execute A's tool — a uniform 404.
    resp = await _call(client, workspace_b, {"tool_name": "demo_op", "arguments": {}})
    assert resp.status_code == 404
    assert not egress.calls


async def test_get_tool_call_is_cross_tenant_404(
    client: httpx.AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    egress: _Egress,
) -> None:
    await seed_tool(admin_engine, workspace_a.id)
    made = await _call(client, workspace_a, {"tool_name": "demo_op", "arguments": {}})
    call_id = made.json()["id"]
    # A's audit row is invisible to B.
    resp = await client.get(f"/v1/tool-calls/{call_id}", headers=_auth(workspace_b))
    assert resp.status_code == 404


async def test_idempotency_key_replays_without_re_executing(
    client: httpx.AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
) -> None:
    await seed_tool(admin_engine, workspace_a.id)
    key = str(uuid.uuid4())
    headers = {**_auth(workspace_a), "Idempotency-Key": key}
    body = {"tool_name": "demo_op", "arguments": {"q": "one"}}
    first = await client.post("/v1/tool-calls", headers=headers, json=body)
    second = await client.post("/v1/tool-calls", headers=headers, json=body)
    assert first.status_code == 200 and second.status_code == 200
    assert first.json()["id"] == second.json()["id"]  # same audit row replayed
    assert len(egress.calls) == 1  # executed exactly once


async def test_idempotency_key_mismatched_body_is_409(
    client: httpx.AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
) -> None:
    await seed_tool(admin_engine, workspace_a.id)
    key = str(uuid.uuid4())
    headers = {**_auth(workspace_a), "Idempotency-Key": key}
    await client.post(
        "/v1/tool-calls", headers=headers, json={"tool_name": "demo_op", "arguments": {"q": "a"}}
    )
    clash = await client.post(
        "/v1/tool-calls", headers=headers, json={"tool_name": "demo_op", "arguments": {"q": "b"}}
    )
    assert clash.status_code == 409


# --------------------------------------------------------------------- human plane + events


async def test_human_owner_can_execute(
    human_client: tuple[httpx.AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
) -> None:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="rt-owner", role="owner")
    await seed_tool(admin_engine, workspace_a.id)
    headers = {**bearer(authority.sign("rt-owner")), WS_HEADER: str(workspace_a.id)}
    resp = await client.post(
        "/v1/tool-calls", headers=headers, json={"tool_name": "demo_op", "arguments": {}}
    )
    assert resp.status_code == 200, resp.text


async def test_human_viewer_is_denied(
    human_client: tuple[httpx.AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
) -> None:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="rt-viewer", role="viewer")
    await seed_tool(admin_engine, workspace_a.id)
    headers = {**bearer(authority.sign("rt-viewer")), WS_HEADER: str(workspace_a.id)}
    resp = await client.post(
        "/v1/tool-calls", headers=headers, json={"tool_name": "demo_op", "arguments": {}}
    )
    assert resp.status_code == 403
    assert not egress.calls  # VIEWER never reaches execution


async def test_explicit_inactive_connection_is_denied(
    client: httpx.AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
) -> None:
    ids = await seed_tool(admin_engine, workspace_a.id, status="error")
    resp = await _call(
        client,
        workspace_a,
        {"tool_name": "demo_op", "connection_id": str(ids["connection_id"]), "arguments": {}},
    )
    assert resp.status_code == 409  # a non-active connection cannot execute
    assert not egress.calls


@pytest.fixture
def bus_recorder() -> list[object]:
    saved = {k: list(v) for k, v in event_bus._handlers.items()}
    seen: list[object] = []
    event_bus.subscribe(TOOL_CALL_COMPLETED, lambda e: seen.append(e))
    try:
        yield seen
    finally:
        event_bus._handlers.clear()
        event_bus._handlers.update(saved)


async def test_tool_call_completed_event_is_published(
    client: httpx.AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    bus_recorder: list[object],
) -> None:
    await seed_tool(admin_engine, workspace_a.id, secret={"value": "evt-secret"})
    resp = await _call(client, workspace_a, {"tool_name": "demo_op", "arguments": {}})
    assert resp.status_code == 200
    assert len(bus_recorder) == 1
    event = bus_recorder[0]
    assert event.event_type == "tool_call.completed"  # type: ignore[attr-defined]
    assert event.workspace_id == workspace_a.id  # type: ignore[attr-defined]
    assert event.payload["status"] == "succeeded"  # type: ignore[attr-defined]
    assert "evt-secret" not in str(event.payload)  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_an_explicit_connection_from_another_connector_is_refused(
    client: httpx.AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
) -> None:
    """A Connection may only be bound to a Tool of its **own** Connector.

    Found by the EC1 mutation audit: deleting the connector-match check from `_bind_connection`
    broke no test. It should have broken this one. Without it, a caller who legitimately owns two
    Connectors can name Tool X and pass Connector Y's `connection_id`, and the Runtime will send
    **Y's credential to X's provider** — a same-tenant credential disclosure to the wrong third
    party, entirely inside the caller's own Workspace, so no tenant boundary is crossed to catch it.

    The refusal is also a uniform 404: a mismatched Connection is indistinguishable from a missing
    one, so this cannot be used to enumerate which Connections exist.
    """
    alpha = await seed_tool(
        admin_engine,
        workspace_a.id,
        tool_name="alpha_only_op",
        secret={"value": "alpha-secret"},
        auth_config={"type": "api_key", "key_name": "X-Alpha", "location": "header"},
        base_url="https://alpha.example.com",
        connection_name="Mismatch Alpha",
    )
    beta = await seed_tool(
        admin_engine,
        workspace_a.id,
        tool_name="beta_only_op",
        secret={"value": "beta-secret"},
        auth_config={"type": "api_key", "key_name": "X-Beta", "location": "header"},
        base_url="https://beta.example.com",
        connection_name="Mismatch Beta",
    )
    egress.calls.clear()

    # Alpha's Tool, Beta's Connection — both owned by this Workspace.
    response = await client.post(
        "/v1/tool-calls",
        headers={"Authorization": f"Bearer {workspace_a.token.plaintext}"},
        json={"tool_name": "alpha_only_op", "connection_id": str(beta["connection_id"])},
    )
    assert response.status_code == 404, response.text
    assert response.json()["error"]["code"] == "not_found"

    # Nothing was sent, so no credential reached the wrong provider.
    assert egress.calls == [], "a mismatched Connection produced an outbound call"
    assert "beta-secret" not in response.text

    # Uniform with a Connection that does not exist at all — no existence oracle.
    missing = await client.post(
        "/v1/tool-calls",
        headers={"Authorization": f"Bearer {workspace_a.token.plaintext}"},
        json={"tool_name": "alpha_only_op", "connection_id": str(uuid.uuid4())},
    )
    assert missing.json()["error"] == response.json()["error"] | {
        "request_id": missing.json()["error"]["request_id"]
    }

    # And the correct pairing still works, so the check filters rather than simply blocking.
    ok = await client.post(
        "/v1/tool-calls",
        headers={"Authorization": f"Bearer {workspace_a.token.plaintext}"},
        json={"tool_name": "alpha_only_op", "connection_id": str(alpha["connection_id"])},
    )
    assert ok.status_code == 200, ok.text
