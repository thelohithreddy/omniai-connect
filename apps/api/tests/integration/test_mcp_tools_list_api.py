"""MCP tools/list end to end — the M2.2 discovery surface (ADR-0035).

Real HTTP through the real ASGI app, real Postgres + RLS, real machine-token auth, real Redis,
and the real event bus with the real MCP eviction subscribers. Nothing at an architectural
boundary is mocked (the single exception: the Redis-outage test replaces the client factory
with one that fails, to prove degradation to the authoritative database).

Layers per the M2.2 directive: protocol (initialize/ping/tools/list/errors), authentication
(machine-only, uniform 401s, token/slug binding), tenant isolation (A never sees B — DB or
cache), visibility (enabled × live × active-connection), event eviction (all six triggers,
duplicates, wrong-workspace), TTL backstop, Redis failure, concurrency, and secret exclusion.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.events import event_bus
from app.core.ids import new_id
from app.domains.connections.events import (
    connection_activated,
    connection_deactivated,
    connection_revoked,
)
from app.domains.connectors.events import connector_ingested
from app.domains.tools.events import tool_disabled, tool_enabled
from app.interfaces.mcp.cache import cache_key
from app.workers.context import worker_tenant_uow
from tests.conftest import SeededWorkspace
from tests.integration.test_tools_api import seed_tools

VERSION = "2025-11-25"
SECRET_MARKER = "sk-live-mcp-secret-marker"  # noqa: S105 (test secret)


def _headers(ws: SeededWorkspace, *, version: str | None = VERSION) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {ws.token.plaintext}"}
    if version is not None:
        headers["MCP-Protocol-Version"] = version
    return headers


def _url(slug: str) -> str:
    return f"/mcp/v1/{slug}"


def _list_req(msg_id: int = 1, params: dict[str, Any] | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"jsonrpc": "2.0", "id": msg_id, "method": "tools/list"}
    if params is not None:
        body["params"] = params
    return body


async def _tools(client: AsyncClient, ws: SeededWorkspace) -> list[dict[str, Any]]:
    resp = await client.post(_url(ws.slug), headers=_headers(ws), json=_list_req())
    assert resp.status_code == 200, resp.text
    return resp.json()["result"]["tools"]


async def _seed_connection(
    engine: AsyncEngine, ws: uuid.UUID, connector_id: uuid.UUID, *, status: str = "active"
) -> uuid.UUID:
    connection_id = new_id()
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO connections (id, workspace_id, connector_id, name, status)"
                " VALUES (:i, :w, :c, :n, :s)"
            ),
            {
                "i": connection_id,
                "w": ws,
                "c": connector_id,
                # UUIDv7 leads with a timestamp, so the FIRST hex chars collide within a test —
                # the random TAIL keeps (workspace_id, name) unique across seeded connections.
                "n": f"c-{connection_id.hex[-12:]}",
                "s": status,
            },
        )
    return connection_id


async def _evict(ws: uuid.UUID) -> None:
    """Reset the workspace's cache directly (test hygiene between phases)."""
    from app.interfaces.mcp.cache import evict_tools_cache

    await evict_tools_cache(ws)


@pytest.fixture(autouse=True)
async def _clean_cache(workspace_a: SeededWorkspace) -> Any:
    await _evict(workspace_a.id)
    yield
    await _evict(workspace_a.id)


# ------------------------------------------------------------------------ protocol handshake


async def test_initialize_ping_and_unknown_method(
    client: AsyncClient, workspace_a: SeededWorkspace
) -> None:
    init = await client.post(
        _url(workspace_a.slug),
        headers=_headers(workspace_a, version=None),
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
        },
    )
    assert init.status_code == 200
    result = init.json()["result"]
    assert result["protocolVersion"] == "2025-06-18"  # supported → echoed
    assert result["capabilities"] == {"tools": {"listChanged": False}}

    note = await client.post(
        _url(workspace_a.slug),
        headers=_headers(workspace_a, version=None),
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    assert note.status_code == 202 and note.content == b""

    ping = await client.post(
        _url(workspace_a.slug),
        headers=_headers(workspace_a),
        json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
    )
    assert ping.status_code == 200 and ping.json()["result"] == {}

    # An unimplemented method (resources are out of scope for this server) → method-not-found.
    unknown = await client.post(
        _url(workspace_a.slug),
        headers=_headers(workspace_a),
        json={"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}},
    )
    assert unknown.json()["error"]["code"] == -32601


async def test_unsupported_version_negotiates_down_and_header_is_enforced(
    client: AsyncClient, workspace_a: SeededWorkspace
) -> None:
    init = await client.post(
        _url(workspace_a.slug),
        headers=_headers(workspace_a, version=None),
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2026-07-28"},
        },
    )
    assert init.json()["result"]["protocolVersion"] == VERSION  # advertised, not the request

    for bad_version in (None, "2026-07-28", "2025-03-26", "garbage"):
        resp = await client.post(
            _url(workspace_a.slug),
            headers=_headers(workspace_a, version=bad_version),
            json=_list_req(),
        )
        assert resp.status_code == 400, bad_version
        assert resp.json()["error"]["code"] == -32600


async def test_malformed_payloads(client: AsyncClient, workspace_a: SeededWorkspace) -> None:
    url, hx = _url(workspace_a.slug), _headers(workspace_a)
    raw = await client.post(
        url, headers={**hx, "Content-Type": "application/json"}, content=b"{nope"
    )
    assert raw.status_code == 400 and raw.json()["error"]["code"] == -32700
    batch = await client.post(url, headers=hx, json=[_list_req()])
    assert batch.status_code == 400 and batch.json()["error"]["code"] == -32600
    cursor = await client.post(url, headers=hx, json=_list_req(params={"cursor": "x"}))
    assert cursor.json()["error"]["code"] == -32602


# ---------------------------------------------------------------------------- authentication


async def test_authentication_is_machine_only_and_uniform(
    client: AsyncClient, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    url = _url(workspace_a.slug)
    body = _list_req()

    assert (await client.post(url, json=body)).status_code == 401  # no token
    assert (
        await client.post(url, headers={"Authorization": "Bearer omc_forged"}, json=body)
    ).status_code == 401  # invalid token
    # Workspace B's valid token against A's slug: uniform 401 — the slug is not an oracle.
    assert (await client.post(url, headers=_headers(workspace_b), json=body)).status_code == 401
    # A's own token against a nonexistent slug: same uniform 401.
    assert (
        await client.post(_url("no-such-slug"), headers=_headers(workspace_a), json=body)
    ).status_code == 401


async def test_human_jwt_is_rejected_mcp_is_machine_only(
    human_client: Any,
    authority: Any,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """MCP is machine identity only (ADR-0002 via MCP_RUNTIME §2): even a workspace OWNER's
    valid human session is refused with the uniform 401 — never a listing."""
    from tests.conftest import bearer
    from tests.integration.test_human_auth import seed_member

    hclient, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="mcp-human", role="owner")
    resp = await hclient.post(
        _url(workspace_a.slug),
        headers={
            **bearer(authority.sign("mcp-human")),
            "X-Workspace-Id": str(workspace_a.id),
            "MCP-Protocol-Version": VERSION,
        },
        json=_list_req(),
    )
    assert resp.status_code == 401


async def test_browser_origin_is_refused(client: AsyncClient, workspace_a: SeededWorkspace) -> None:
    resp = await client.post(
        _url(workspace_a.slug),
        headers={**_headers(workspace_a), "Origin": "https://evil.example"},
        json=_list_req(),
    )
    assert resp.status_code == 403


# ------------------------------------------------------------------- visibility + isolation


async def test_discovery_lists_exactly_the_runtime_callable_set(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Enabled × live × active-connection — and nothing else. Also proves ordering and the
    metadata-only shape end to end."""
    ids = await seed_tools(
        admin_engine,
        workspace_a.id,
        [("vis_enabled", True, False), ("vis_disabled", False, False), ("vis_deleted", True, True)],
    )
    await _seed_connection(admin_engine, workspace_a.id, ids["__connector__"], status="active")
    # A second connector with tools but NO active connection: nothing from it may appear.
    orphan = await seed_tools(admin_engine, workspace_a.id, [("vis_orphan", True, False)])
    await _seed_connection(
        admin_engine, workspace_a.id, orphan["__connector__"], status="pending_auth"
    )

    tools = await _tools(client, workspace_a)
    names = [t["name"] for t in tools]
    assert names == ["vis_enabled"], names  # not disabled, not deleted, not unbound
    entry = tools[0]
    assert set(entry) <= {"name", "description", "inputSchema", "annotations"}
    assert "workspace_id" not in json.dumps(tools) and str(workspace_a.id) not in json.dumps(tools)


async def test_ordering_is_deterministic_created_at_id_desc(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    ids = await seed_tools(
        admin_engine,
        workspace_a.id,
        [("ord_a", True, False), ("ord_b", True, False), ("ord_c", True, False)],
    )
    await _seed_connection(admin_engine, workspace_a.id, ids["__connector__"], status="active")
    async with admin_engine.begin() as conn:
        expected = [
            row.name
            for row in await conn.execute(
                text(
                    "SELECT name FROM tools WHERE workspace_id = :w AND deleted_at IS NULL"
                    " ORDER BY created_at DESC, id DESC"
                ),
                {"w": workspace_a.id},
            )
        ]
    assert [t["name"] for t in await _tools(client, workspace_a)] == expected


async def test_annotations_map_and_internal_metadata_never_crosses(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    ids = await seed_tools(admin_engine, workspace_a.id, [("ann_tool", True, False)])
    await _seed_connection(admin_engine, workspace_a.id, ids["__connector__"], status="active")
    async with admin_engine.begin() as conn:
        await conn.execute(
            text("UPDATE tools SET annotations = :a WHERE id = :i"),
            {
                "a": json.dumps(
                    {
                        "readonly": True,
                        "destructive": False,
                        "idempotent": True,
                        "tags": ["internal-tag"],
                        "rate_hints": {"requests_per_minute": 9},
                    }
                ),
                "i": ids["ann_tool"],
            },
        )
    tools = await _tools(client, workspace_a)
    assert tools[0]["annotations"] == {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
    }
    wire = json.dumps(tools)
    assert "internal-tag" not in wire and "rate_hints" not in wire


async def test_tenant_isolation_database_and_cache(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    a_ids = await seed_tools(admin_engine, workspace_a.id, [("iso_a_tool", True, False)])
    await _seed_connection(admin_engine, workspace_a.id, a_ids["__connector__"], status="active")
    b_ids = await seed_tools(admin_engine, workspace_b.id, [("iso_b_tool", True, False)])
    await _seed_connection(admin_engine, workspace_b.id, b_ids["__connector__"], status="active")
    await _evict(workspace_b.id)

    a_names = {t["name"] for t in await _tools(client, workspace_a)}  # populates A's cache
    b_names = {t["name"] for t in await _tools(client, workspace_b)}  # must NOT read A's cache
    assert a_names == {"iso_a_tool"} and b_names == {"iso_b_tool"}

    # The cache namespace is per-workspace and server-derived.
    from app.core.redis import redis_client

    async with redis_client() as redis:
        a_raw, b_raw = (
            await redis.get(cache_key(workspace_a.id)),
            await redis.get(cache_key(workspace_b.id)),
        )
    assert a_raw and b_raw and "iso_b_tool" not in a_raw and "iso_a_tool" not in b_raw
    await _evict(workspace_b.id)


# ------------------------------------------------------------------------- cache + eviction


async def test_cache_serves_until_evicted_and_every_event_evicts(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """The core cache-aside + eviction contract, end to end against the real bus + subscribers:
    a DB change WITHOUT an event stays invisible (cache hit — proves the cache is really
    serving), then each of the six canonical events evicts and the next read is authoritative."""
    ids = await seed_tools(
        admin_engine, workspace_a.id, [("ev_keep", True, False), ("ev_flip", True, False)]
    )
    connector_id = ids["__connector__"]
    connection_id = await _seed_connection(
        admin_engine, workspace_a.id, connector_id, status="active"
    )

    assert {t["name"] for t in await _tools(client, workspace_a)} == {"ev_keep", "ev_flip"}

    # Silent DB flip (no event): the cached listing must still be served — the cache is real.
    async with admin_engine.begin() as conn:
        await conn.execute(
            text("UPDATE tools SET enabled = false WHERE id = :i"), {"i": ids["ev_flip"]}
        )
    assert {t["name"] for t in await _tools(client, workspace_a)} == {"ev_keep", "ev_flip"}

    # Each canonical event, published through the REAL bus inside a REAL committed transaction,
    # must evict `ws:{A}:mcp:tools` via the startup-registered subscriber.
    events = [
        connector_ingested(workspace_a.id, connector_id, 1, "hash"),
        connection_activated(
            workspace_a.id, connection_id=connection_id, connector_id=connector_id
        ),
        connection_deactivated(
            workspace_a.id,
            connection_id=connection_id,
            connector_id=connector_id,
            status="pending_auth",
        ),
        connection_revoked(workspace_a.id, connection_id=connection_id, connector_id=connector_id),
        tool_enabled(workspace_a.id, tool_id=ids["ev_keep"], connector_id=connector_id),
        tool_disabled(workspace_a.id, tool_id=ids["ev_flip"], connector_id=connector_id),
    ]
    from app.core.redis import redis_client

    for event in events:
        await _tools(client, workspace_a)  # (re)populate
        async with redis_client() as redis:
            assert await redis.get(cache_key(workspace_a.id)) is not None
        async with worker_tenant_uow(str(workspace_a.id)):
            event_bus.publish(event)
        async with redis_client() as redis:
            assert await redis.get(cache_key(workspace_a.id)) is None, event.event_type

    # After eviction the next read is authoritative: the silent flip is now visible.
    assert {t["name"] for t in await _tools(client, workspace_a)} == {"ev_keep"}


async def test_duplicate_and_foreign_workspace_evictions_are_safe(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    ids = await seed_tools(admin_engine, workspace_a.id, [("dup_tool", True, False)])
    await _seed_connection(admin_engine, workspace_a.id, ids["__connector__"], status="active")
    await _tools(client, workspace_a)

    # B's event must never evict A's namespace (the envelope tenant is the namespace).
    async with worker_tenant_uow(str(workspace_b.id)):
        event_bus.publish(
            tool_disabled(workspace_b.id, tool_id=uuid.uuid4(), connector_id=uuid.uuid4())
        )
    from app.core.redis import redis_client

    async with redis_client() as redis:
        assert await redis.get(cache_key(workspace_a.id)) is not None

    # Duplicate delivery of the same eviction is an idempotent no-op.
    event = tool_disabled(
        workspace_a.id, tool_id=ids["dup_tool"], connector_id=ids["__connector__"]
    )
    for _ in range(3):
        async with worker_tenant_uow(str(workspace_a.id)):
            event_bus.publish(event.model_copy(deep=True))
    assert {t["name"] for t in await _tools(client, workspace_a)} == {"dup_tool"}


async def test_lifecycle_actions_end_to_end_refresh_discovery(
    client: AsyncClient,
    human_client: Any,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: Any,
) -> None:
    """The full production path with no synthetic events: a human admin disables a Tool via
    REST → M2.1 emits → the MCP subscriber evicts → the next MCP listing reflects it."""
    from tests.conftest import bearer
    from tests.integration.test_human_auth import seed_member

    hclient, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="mcp-owner", role="owner")
    hx = {**bearer(authority.sign("mcp-owner")), "X-Workspace-Id": str(workspace_a.id)}

    ids = await seed_tools(admin_engine, workspace_a.id, [("e2e_tool", True, False)])
    await _seed_connection(admin_engine, workspace_a.id, ids["__connector__"], status="active")
    assert [t["name"] for t in await _tools(client, workspace_a)] == ["e2e_tool"]

    disable = await hclient.patch(
        f"/v1/tools/{ids['e2e_tool']}", headers=hx, json={"enabled": False}
    )
    assert disable.status_code == 200
    assert await _tools(client, workspace_a) == []  # evicted + authoritative reload

    enable = await hclient.patch(f"/v1/tools/{ids['e2e_tool']}", headers=hx, json={"enabled": True})
    assert enable.status_code == 200
    assert [t["name"] for t in await _tools(client, workspace_a)] == ["e2e_tool"]


# ------------------------------------------------------------------------------ TTL backstop


async def test_ttl_is_bounded_and_expiry_reloads_authoritatively(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import settings
    from app.core.redis import redis_client

    ids = await seed_tools(admin_engine, workspace_a.id, [("ttl_tool", True, False)])
    await _seed_connection(admin_engine, workspace_a.id, ids["__connector__"], status="active")

    # Default population carries the founder-ratified bound.
    await _tools(client, workspace_a)
    async with redis_client() as redis:
        ttl = await redis.ttl(cache_key(workspace_a.id))
    assert 0 < ttl <= 300

    # With a 1-second TTL, an entry that outlives a LOST eviction event expires and the next
    # read reloads from the authoritative database — the recovery path for at-most-once loss.
    monkeypatch.setattr(settings, "mcp_tools_cache_ttl_seconds", 1)
    await _evict(workspace_a.id)
    await _tools(client, workspace_a)
    async with admin_engine.begin() as conn:  # silent change; imagine its event was lost
        await conn.execute(
            text("UPDATE tools SET enabled = false WHERE id = :i"), {"i": ids["ttl_tool"]}
        )
    await asyncio.sleep(1.2)
    async with redis_client() as redis:
        assert await redis.get(cache_key(workspace_a.id)) is None  # expired
    assert await _tools(client, workspace_a) == []  # authoritative truth after recovery


# ------------------------------------------------------------------------------ Redis failure


async def test_redis_outage_degrades_to_authoritative_db(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = await seed_tools(admin_engine, workspace_a.id, [("outage_tool", True, False)])
    await _seed_connection(admin_engine, workspace_a.id, ids["__connector__"], status="active")

    class _Down:
        async def __aenter__(self) -> Any:
            raise ConnectionError("redis unavailable")

        async def __aexit__(self, *exc: object) -> None:
            return None

    import app.interfaces.mcp.cache as cache_module

    monkeypatch.setattr(cache_module, "redis_client", lambda: _Down())
    # Serving must fall back to Postgres — a Redis outage is never "the workspace has no tools".
    assert [t["name"] for t in await _tools(client, workspace_a)] == ["outage_tool"]


async def test_poisoned_or_drifted_cache_entry_reads_as_miss(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    ids = await seed_tools(admin_engine, workspace_a.id, [("shape_tool", True, False)])
    await _seed_connection(admin_engine, workspace_a.id, ids["__connector__"], status="active")
    from app.core.redis import redis_client

    for junk in ("not-json", json.dumps({"v": 99, "tools": [{"name": "evil"}]}), json.dumps([])):
        async with redis_client() as redis:
            await redis.set(cache_key(workspace_a.id), junk)
        assert [t["name"] for t in await _tools(client, workspace_a)] == ["shape_tool"], junk


# ------------------------------------------------------------------------------- concurrency


async def test_concurrent_cold_listings_agree(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    ids = await seed_tools(admin_engine, workspace_a.id, [("race_tool", True, False)])
    await _seed_connection(admin_engine, workspace_a.id, ids["__connector__"], status="active")
    results = await asyncio.gather(*(_tools(client, workspace_a) for _ in range(5)))
    assert all(r == results[0] for r in results)
    assert [t["name"] for t in results[0]] == ["race_tool"]


# ----------------------------------------------------------------------------- secret safety


async def test_no_credential_material_in_response_or_cache(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """A workspace with an attached credential: the MCP wire response and the Redis entry carry
    no ciphertext, key material, or the secret itself — the projection is metadata-only by
    construction, proven here against the real stored bytes."""
    ids = await seed_tools(admin_engine, workspace_a.id, [("sec_tool", True, False)])
    connection_id = await _seed_connection(admin_engine, workspace_a.id, ids["__connector__"])
    async with admin_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO credentials (id, workspace_id, connection_id, credential_type,"
                " ciphertext, encrypted_dek, nonce, key_version)"
                " VALUES (:i, :w, :c, 'api_key', :ct, :dek, :n, 1)"
            ),
            {
                "i": new_id(),
                "w": workspace_a.id,
                "c": connection_id,
                "ct": SECRET_MARKER.encode(),
                "dek": b"dek-bytes",
                "n": b"nonce-bytes!",
            },
        )
    resp = await client.post(
        _url(workspace_a.slug), headers=_headers(workspace_a), json=_list_req()
    )
    assert resp.status_code == 200
    assert SECRET_MARKER not in resp.text and "ciphertext" not in resp.text
    from app.core.redis import redis_client

    async with redis_client() as redis:
        raw = await redis.get(cache_key(workspace_a.id))
    assert raw is not None and SECRET_MARKER not in raw and "encrypted_dek" not in raw
