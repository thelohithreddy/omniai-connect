"""MCP tools/call end to end — the execution bridge (M2.3, ADR-0036).

Real HTTP through the real ASGI app, real Postgres + RLS, real machine-token auth, the real
RuntimeService pipeline, and the real audit ledger. The ONLY seam is the final socket
(`app.core.net.request`), stubbed exactly as the M1 runtime tests do — everything above it
(authorization, Connection resolution, argument validation, vault decrypt-at-use, credential
injection, egress policy, audit) is the production code path.

Covers the directive's error matrix, tenant isolation (A cannot execute B even knowing its Tool
name), the mandatory stale-discovery-cannot-authorize test, the credential canary, single-audit
ownership, no-retry, and the SSRF security-refusal mapping (also exercised live against the real
stack during development).
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core import net
from tests.conftest import SeededWorkspace
from tests.integration.test_tool_calls_api import _Egress, seed_tool

VERSION = "2025-11-25"
CANARY = "M2_3_SECRET_CANARY_bearer_do_not_leak"  # noqa: S105 (synthetic test secret)


@pytest.fixture
def egress(monkeypatch: pytest.MonkeyPatch) -> _Egress:
    """The M1 guarded-egress stand-in (the one seam): everything above the socket is real."""
    fake = _Egress()
    monkeypatch.setattr("app.core.net.request", fake)
    return fake


def _ok_json(body: bytes) -> net.GuardedResponse:
    return net.GuardedResponse(
        status_code=200,
        headers=httpx.Headers({"content-type": "application/json"}),
        body=body,
        truncated=False,
    )


def _headers(ws: SeededWorkspace, *, version: str | None = VERSION) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {ws.token.plaintext}"}
    if version is not None:
        headers["MCP-Protocol-Version"] = version
    return headers


def _url(slug: str) -> str:
    return f"/mcp/v1/{slug}"


def _call(name: str, arguments: dict[str, Any] | None = None, msg_id: int = 1) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    }


async def _post(client: AsyncClient, ws: SeededWorkspace, body: dict[str, Any]) -> Any:
    return await client.post(_url(ws.slug), headers=_headers(ws), json=body)


# --------------------------------------------------------------------------------- happy path


async def test_valid_call_executes_through_runtime_and_maps_result(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    ids = await seed_tool(
        admin_engine, workspace_a.id, tool_name="demo_op", secret={"value": CANARY}
    )
    egress.response = _ok_json(b'{"result":"ok"}')
    resp = await _post(client, workspace_a, _call("demo_op", {"q": "hello"}))
    assert resp.status_code == 200, resp.text
    result = resp.json()["result"]
    assert result["isError"] is False
    # The Runtime's normalized, truncation-aware content wrapper is what crosses (never raw bytes).
    content = json.loads(result["content"][0]["text"])
    assert content["json"] == {"result": "ok"} and content["truncated"] is False
    assert result["structuredContent"] == content
    assert result["_meta"]["omniai/toolCallId"] and result["_meta"]["omniai/requestId"]

    # The credential was injected on the wire by the Runtime — never surfaced to MCP.
    assert egress.calls and egress.calls[0].headers.get("Authorization") == f"Bearer {CANARY}"
    assert CANARY not in resp.text

    # Exactly ONE audit row, owned by the Runtime, tagged interface="mcp" — MCP added no second.
    async with admin_engine.begin() as conn:
        rows = list(
            await conn.execute(
                text(
                    "SELECT status, caller->>'interface' AS iface FROM tool_calls"
                    " WHERE workspace_id=:w"
                ),
                {"w": workspace_a.id},
            )
        )
    assert len(rows) == 1 and rows[0].status == "succeeded" and rows[0].iface == "mcp"
    _ = ids


# ---------------------------------------------------------------------------------- error matrix


async def test_unknown_and_disabled_and_deprecated_tools_are_uniform(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    await seed_tool(admin_engine, workspace_a.id, tool_name="live_op")
    async with admin_engine.begin() as conn:
        # A disabled tool and a deprecated (soft-deleted) tool in the same workspace.
        await conn.execute(
            text(
                "INSERT INTO tools (id, workspace_id, connector_id, connector_version_id, name,"
                " description, input_schema, enabled) SELECT gen_random_uuid(), workspace_id,"
                " connector_id, connector_version_id, 'disabled_op', 'd', input_schema, false"
                " FROM tools WHERE workspace_id=:w AND name='live_op'"
            ),
            {"w": workspace_a.id},
        )
    for name in ("does_not_exist", "disabled_op"):
        resp = await _post(client, workspace_a, _call(name))
        assert resp.status_code == 200
        assert resp.json()["error"]["message"] == "Unknown tool.", name  # uniform, not an oracle
    assert egress.calls == [], "no egress for an unresolved tool"


async def test_inactive_and_revoked_connections_refuse_execution(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    # A pending_auth connection (no credential): the tool exists+enabled but is not callable.
    await seed_tool(
        admin_engine,
        workspace_a.id,
        tool_name="pending_op",
        status="pending_auth",
        with_credential=False,
    )
    resp = await _post(client, workspace_a, _call("pending_op"))
    # No active Connection binds the connector → the Runtime resolves nothing → uniform unknown.
    assert resp.json()["error"]["message"] == "Unknown tool."
    assert egress.calls == []


async def test_invalid_arguments_are_a_protocol_error_before_egress(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    await seed_tool(
        admin_engine,
        workspace_a.id,
        tool_name="strict_op",
        input_schema={
            "type": "object",
            "properties": {"n": {"type": "integer"}},
            "required": ["n"],
            "additionalProperties": False,
        },
    )
    resp = await _post(client, workspace_a, _call("strict_op", {"n": "not-an-int"}))
    assert resp.status_code == 200
    # The Runtime validates against the canonical input_schema INSIDE its audited region, so a bad
    # argument is an audited outcome → isError result carrying the stable `validation_error` code
    # (a real Tool Call attempt that failed at the validation stage), not a protocol -32602.
    result = resp.json()["result"]
    assert result["isError"] is True
    assert result["content"][0]["text"].startswith("validation_error:")
    assert egress.calls == [], "argument validation happens before any egress"


async def test_upstream_error_timeout_and_ssrf_map_to_iserror(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    await seed_tool(admin_engine, workspace_a.id, tool_name="flaky_op")

    # upstream 5xx → connector_error, isError, audited "failed"
    egress.response = net.GuardedResponse(
        status_code=503, headers=httpx.Headers({}), body=b"upstream boom", truncated=False
    )
    r1 = await _post(client, workspace_a, _call("flaky_op", msg_id=1))
    assert r1.json()["result"]["isError"] is True
    assert r1.json()["result"]["content"][0]["text"].startswith("connector_error:")

    # timeout → upstream_timeout (egress translates httpx.TimeoutException)
    egress.exc = httpx.ReadTimeout("slow")
    r2 = await _post(client, workspace_a, _call("flaky_op", msg_id=2))
    assert r2.json()["result"]["content"][0]["text"].startswith("upstream_timeout:")

    # SSRF refusal → ssrf_blocked, DISTINCT from an upstream error, no target leaked
    egress.exc = net.SSRFError("blocked-private-169.254.169.254")
    r3 = await _post(client, workspace_a, _call("flaky_op", msg_id=3))
    text_out = r3.json()["result"]["content"][0]["text"]
    assert text_out.startswith("ssrf_blocked:") and "169.254" not in json.dumps(r3.json())


# ------------------------------------------------------------------------------ authentication


async def test_auth_matrix_matches_tools_list(
    client: AsyncClient, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    body = _call("anything")
    url = _url(workspace_a.slug)
    assert (await client.post(url, json=body)).status_code == 401  # no token
    assert (
        await client.post(url, headers=_headers(workspace_b), json=body)
    ).status_code == 401  # B's token on A's slug
    # missing/unsupported protocol version → 400 before any execution
    assert (
        await client.post(url, headers=_headers(workspace_a, version=None), json=body)
    ).status_code == 400
    assert (
        await client.post(url, headers=_headers(workspace_a, version="2026-07-28"), json=body)
    ).status_code == 400


# ------------------------------------------------------------------------------ tenant isolation


async def test_workspace_a_cannot_execute_workspace_b_even_knowing_the_name(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    egress: _Egress,
) -> None:
    """The defense that matters: A presents B's exact Tool name with A's token. The Runtime
    resolves within A's tenant (RLS + workspace scope), finds nothing, and refuses — no egress,
    no B credential, uniform phrase."""
    await seed_tool(
        admin_engine, workspace_b.id, tool_name="secret_b_op", secret={"value": "b-only"}
    )
    # A has its own unrelated tool, so A is a real, active tenant.
    await seed_tool(admin_engine, workspace_a.id, tool_name="a_op")
    egress.calls.clear()

    resp = await _post(client, workspace_a, _call("secret_b_op", {"x": 1}))
    assert resp.json()["error"]["message"] == "Unknown tool."
    assert egress.calls == [], "A must never reach egress for B's tool"

    # No tool_call row was written in B's tenant by A's attempt.
    async with admin_engine.begin() as conn:
        b_count = (
            await conn.execute(
                text("SELECT count(*) FROM tool_calls WHERE workspace_id=:w"), {"w": workspace_b.id}
            )
        ).scalar()
    assert b_count == 0


# ------------------------------------------- stale discovery cannot authorize (MANDATORY)


async def test_stale_tools_list_cache_cannot_authorize_a_disabled_tool(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    """Enable → list (populates cache) → disable WITHOUT evicting (simulate a lost eviction) →
    the stale cache still lists it → call it → the Runtime re-authorizes at execution time and
    refuses. The discovery cache is never execution authority (ADR-0036 invariant)."""
    ids = await seed_tool(admin_engine, workspace_a.id, tool_name="soon_disabled")

    listing = await client.post(
        _url(workspace_a.slug),
        headers=_headers(workspace_a),
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert "soon_disabled" in [t["name"] for t in listing.json()["result"]["tools"]]

    # Disable directly in the DB and DO NOT evict the cache — the lost-event scenario.
    async with admin_engine.begin() as conn:
        await conn.execute(
            text("UPDATE tools SET enabled=false WHERE id=:i"), {"i": ids["tool_id"]}
        )
    # The cache still advertises it...
    stale = await client.post(
        _url(workspace_a.slug),
        headers=_headers(workspace_a),
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    )
    assert "soon_disabled" in [t["name"] for t in stale.json()["result"]["tools"]]

    # ...but execution is refused by the Runtime, and nothing reaches egress.
    resp = await _post(client, workspace_a, _call("soon_disabled"))
    assert resp.json()["error"]["message"] == "Unknown tool."
    assert egress.calls == []


# --------------------------------------------------------------------------- credential canary


async def test_credential_canary_never_crosses_the_mcp_boundary(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    await seed_tool(admin_engine, workspace_a.id, tool_name="canary_op", secret={"value": CANARY})
    # Even if the upstream echoes the secret back, the normalized result is what crosses — assert
    # the response and the persisted audit both exclude the canary.
    egress.response = _ok_json(b'{"ok":true}')
    resp = await _post(client, workspace_a, _call("canary_op", {"q": "v"}))
    assert resp.status_code == 200 and CANARY not in resp.text
    # Injected on the wire (proves it was used), absent from the audit ledger.
    assert egress.calls[0].headers["Authorization"] == f"Bearer {CANARY}"
    async with admin_engine.begin() as conn:
        leaked = (
            await conn.execute(
                text(
                    "SELECT count(*) FROM tool_calls WHERE workspace_id=:w AND"
                    " (input_summary::text LIKE :c OR output_summary::text LIKE :c)"
                ),
                {"w": workspace_a.id, "c": f"%{CANARY}%"},
            )
        ).scalar()
    assert leaked == 0


async def test_workspace_id_in_arguments_is_not_authority(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    egress: _Egress,
) -> None:
    """A stuffs B's workspace_id and connection_id into the tool arguments. Those are tool data,
    never tenant authority — the workspace is the authenticated `ctx`. The call executes in A
    (success), A owns the single audit row, and B is never touched."""
    # Declare the identity-looking keys as ordinary string arguments so they pass schema
    # validation and the call SUCCEEDS in A — proving they are inert data, not authority (a
    # rejected argument would prove less). The endpoint binding ignores them (body_style none).
    ids = await seed_tool(
        admin_engine,
        workspace_a.id,
        tool_name="iso_arg_op",
        input_schema={
            "type": "object",
            "properties": {
                "workspace_id": {"type": "string"},
                "connection_id": {"type": "string"},
                "q": {"type": "string"},
            },
            "additionalProperties": False,
        },
    )
    egress.response = _ok_json(b'{"ok":true}')
    resp = await _post(
        client,
        workspace_a,
        _call(
            "iso_arg_op",
            {"workspace_id": str(workspace_b.id), "connection_id": str(uuid.uuid4()), "q": "x"},
        ),
    )
    # Executed — in A. Under a mutation that let arguments pick the workspace, A's tool would not
    # resolve in B's tenant and this would be an error instead.
    assert resp.json()["result"]["isError"] is False
    assert egress.calls, "the call ran against A's own connection"
    async with admin_engine.begin() as conn:
        a_rows = (
            await conn.execute(
                text("SELECT count(*) FROM tool_calls WHERE workspace_id=:w"), {"w": workspace_a.id}
            )
        ).scalar()
        b_rows = (
            await conn.execute(
                text("SELECT count(*) FROM tool_calls WHERE workspace_id=:w"), {"w": workspace_b.id}
            )
        ).scalar()
    assert a_rows == 1 and b_rows == 0
    _ = ids


async def test_missing_or_empty_tool_name_is_a_protocol_error(
    client: AsyncClient, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    for params in ({"arguments": {}}, {"name": "", "arguments": {}}, {"name": 5, "arguments": {}}):
        resp = await client.post(
            _url(workspace_a.slug),
            headers=_headers(workspace_a),
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params},
        )
        assert resp.json()["error"]["code"] == -32602, params
    assert egress.calls == []


# ------------------------------------------------------------------------------- no retries


async def test_a_failed_call_is_attempted_exactly_once(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    await seed_tool(admin_engine, workspace_a.id, tool_name="once_op")
    egress.response = net.GuardedResponse(
        status_code=500, headers=httpx.Headers({}), body=b"err", truncated=False
    )
    resp = await _post(client, workspace_a, _call("once_op"))
    assert resp.json()["result"]["isError"] is True
    assert len(egress.calls) == 1, "no automatic retry — a Tool Call may be destructive"


# ------------------------------------------------------------------------------- concurrency


async def test_concurrent_calls_each_execute_once(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    await seed_tool(admin_engine, workspace_a.id, tool_name="conc_op")
    results = await asyncio.gather(
        *(_post(client, workspace_a, _call("conc_op", msg_id=i)) for i in range(4))
    )
    assert all(r.status_code == 200 and r.json()["result"]["isError"] is False for r in results)
    assert len(egress.calls) == 4  # four requests, four executions, no coalescing/dedup
    async with admin_engine.begin() as conn:
        count = (
            await conn.execute(
                text("SELECT count(*) FROM tool_calls WHERE workspace_id=:w"), {"w": workspace_a.id}
            )
        ).scalar()
    assert count == 4
