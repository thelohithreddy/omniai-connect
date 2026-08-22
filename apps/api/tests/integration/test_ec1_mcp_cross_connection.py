"""EC1 — the M2 acceptance criterion, executed literally (ROADMAP §63).

> "Claude Desktop (or any MCP client) lists and successfully calls Tools from two different
> Connections — one API-key, one OAuth — in one Workspace."

Every component of that sentence has been tested somewhere in M2.2–M2.7. None of it had ever been
executed as **one scenario**, which is the only thing EC1 actually asserts: that a real MCP client
can discover and drive two differently-authenticated Connections side by side in a single
Workspace, with the credentials staying separate and nothing crossing the boundary.

This file is deliberately not a composition of existing helpers-as-assertions. It stands one
Workspace up with two Connectors — one `api_key`, one `oauth2` — speaks real JSON-RPC over the real
MCP transport, and then verifies the *consequences* in the database and at the egress seam:
distinct Connections, distinct injected credentials, one audit row apiece, and no secret anywhere
it should not be.

The only seam is the outbound socket. Authorization, discovery, the tools/list cache, Connection
binding, argument validation, rate limits and quota, vault decrypt-at-use, credential injection,
egress policy, RLS and the audit write are all the production path.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.conftest import SeededWorkspace
from tests.integration.test_tool_calls_api import _Egress, seed_tool

VERSION = "2025-11-25"

#: Distinct canaries per credential type. Distinct on purpose: a single shared canary could not
#: tell "the right credential reached the right provider" from "one credential reached both".
API_KEY_CANARY = "EC1_APIKEY_CANARY_do_not_leak"  # noqa: S105 (synthetic test secret)
OAUTH_CANARY = "EC1_OAUTH_CANARY_do_not_leak"  # noqa: S105 (synthetic test secret)

ALPHA_TOOL = "alpha_list_items"  # Connector A, api_key
BETA_TOOL = "beta_list_items"  # Connector B, oauth2


@pytest.fixture
def egress(monkeypatch: pytest.MonkeyPatch) -> _Egress:
    fake = _Egress()
    monkeypatch.setattr("app.core.net.request", fake)
    return fake


def _headers(ws: SeededWorkspace) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {ws.token.plaintext}",
        "MCP-Protocol-Version": VERSION,
    }


async def _rpc(
    client: AsyncClient, ws: SeededWorkspace, method: str, params: dict[str, Any] | None = None
) -> Any:
    body: dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    return await client.post(f"/mcp/v1/{ws.slug}", headers=_headers(ws), json=body)


async def seed_both_connectors(
    engine: AsyncEngine, workspace_id: uuid.UUID
) -> dict[str, dict[str, uuid.UUID]]:
    """One Workspace, two Connectors: A authenticated by api_key, B by oauth2.

    Two Connectors rather than two Connections on one Connector, because the Runtime binds an
    implicit Connection per Connector and would call a second one ambiguous. Tool names are
    deliberately distinct — canonical names are resolved workspace-wide, so reusing a name across
    Connectors would make the scenario about name collision instead of about EC1.
    """
    alpha = await seed_tool(
        engine,
        workspace_id,
        credential_type="api_key",
        secret={"value": API_KEY_CANARY},
        auth_config={"type": "api_key", "key_name": "X-Alpha-Key", "location": "header"},
        tool_name=ALPHA_TOOL,
        base_url="https://alpha.example.com",
        connection_name="EC1 Alpha (api_key)",
    )
    beta = await seed_tool(
        engine,
        workspace_id,
        credential_type="oauth2",
        secret={"access_token": OAUTH_CANARY, "token_type": "Bearer"},
        auth_config={"type": "oauth2"},
        tool_name=BETA_TOOL,
        base_url="https://beta.example.com",
        connection_name="EC1 Beta (oauth2)",
    )
    return {"alpha": alpha, "beta": beta}


async def audit_rows(engine: AsyncEngine, workspace_id: uuid.UUID) -> list[Any]:
    async with engine.connect() as conn:
        return (
            await conn.execute(
                text(
                    "SELECT tc.status, tc.connection_id, tc.tool_id, t.name AS tool_name"
                    " FROM tool_calls tc JOIN tools t ON t.id = tc.tool_id"
                    " WHERE tc.workspace_id = :w ORDER BY tc.created_at"
                ),
                {"w": workspace_id},
            )
        ).all()


# ===================================================================== EC1, one literal scenario


@pytest.mark.asyncio
async def test_ec1_an_mcp_client_lists_and_calls_an_api_key_and_an_oauth_connection(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    """The M2 exit criterion, start to finish, in one test."""
    ids = await seed_both_connectors(admin_engine, workspace_a.id)

    # --- 1. initialize -------------------------------------------------------------------
    init = await _rpc(client, workspace_a, "initialize", {"protocolVersion": VERSION})
    assert init.status_code == 200, init.text
    assert init.json()["result"]["protocolVersion"] == VERSION

    # --- 2. tools/list must surface BOTH Connectors' Tools --------------------------------
    listed = await _rpc(client, workspace_a, "tools/list")
    assert listed.status_code == 200, listed.text
    names = {tool["name"] for tool in listed.json()["result"]["tools"]}
    assert {ALPHA_TOOL, BETA_TOOL} <= names, (
        f"discovery hid a Connector's Tool: saw {sorted(names)}"
    )

    # --- 3. tools/call the API-key-backed Tool --------------------------------------------
    alpha = await _rpc(client, workspace_a, "tools/call", {"name": ALPHA_TOOL, "arguments": {}})
    assert alpha.status_code == 200, alpha.text
    alpha_result = alpha.json()["result"]
    assert alpha_result.get("isError") is not True, alpha_result

    # --- 4. tools/call the OAuth-backed Tool ----------------------------------------------
    beta = await _rpc(client, workspace_a, "tools/call", {"name": BETA_TOOL, "arguments": {}})
    assert beta.status_code == 200, beta.text
    beta_result = beta.json()["result"]
    assert beta_result.get("isError") is not True, beta_result

    # --- 5. two calls, two distinct Connections, one audit row each ------------------------
    rows = await audit_rows(admin_engine, workspace_a.id)
    assert len(rows) == 2, f"expected exactly one audit row per call, got {len(rows)}"
    assert [r.status for r in rows] == ["succeeded", "succeeded"]
    assert {r.tool_name for r in rows} == {ALPHA_TOOL, BETA_TOOL}
    connection_ids = {r.connection_id for r in rows}
    assert len(connection_ids) == 2, "both calls resolved to the same Connection"
    assert connection_ids == {ids["alpha"]["connection_id"], ids["beta"]["connection_id"]}

    # --- 6. the credentials are different, and each reached only its own provider ----------
    assert len(egress.calls) == 2, f"expected one outbound call each, got {len(egress.calls)}"
    by_host = {call.url: call for call in egress.calls}
    alpha_sent = next(c for url, c in by_host.items() if "alpha.example.com" in url)
    beta_sent = next(c for url, c in by_host.items() if "beta.example.com" in url)

    # The api_key Connector's own scheme, and only there.
    assert alpha_sent.headers.get("X-Alpha-Key") == API_KEY_CANARY
    assert "Authorization" not in alpha_sent.headers
    # The OAuth Connector gets a bearer, and only there.
    assert beta_sent.headers.get("Authorization") == f"Bearer {OAUTH_CANARY}"
    assert "X-Alpha-Key" not in beta_sent.headers

    # Neither credential may appear at the other provider — the isolation EC1 is really about.
    assert OAUTH_CANARY not in json.dumps(dict(alpha_sent.headers))
    assert API_KEY_CANARY not in json.dumps(dict(beta_sent.headers))

    # --- 7. no credential crossed the MCP boundary ----------------------------------------
    for response in (init, listed, alpha, beta):
        assert API_KEY_CANARY not in response.text
        assert OAUTH_CANARY not in response.text

    # --- 8. no credential reached the audit ledger ----------------------------------------
    async with admin_engine.connect() as conn:
        dumped = (
            await conn.execute(
                text(
                    "SELECT coalesce(string_agg(tc::text, ' '), '') FROM tool_calls tc"
                    " WHERE tc.workspace_id = :w"
                ),
                {"w": workspace_a.id},
            )
        ).scalar_one()
    assert API_KEY_CANARY not in dumped
    assert OAUTH_CANARY not in dumped


@pytest.mark.asyncio
async def test_ec1_scenario_is_workspace_scoped_and_another_tenant_sees_nothing(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    egress: _Egress,
) -> None:
    """The same scenario, from the wrong tenant. EC1 is only meaningful if it is scoped.

    Workspace B holds a valid token for *its own* Workspace and knows both Tool names. It must
    neither discover them nor execute them, and must produce no egress and no audit row against
    workspace A.
    """
    await seed_both_connectors(admin_engine, workspace_a.id)

    listed = await _rpc(client, workspace_b, "tools/list")
    assert listed.status_code == 200
    names = {tool["name"] for tool in listed.json()["result"]["tools"]}
    assert ALPHA_TOOL not in names and BETA_TOOL not in names, "cross-tenant discovery leaked"

    for tool_name in (ALPHA_TOOL, BETA_TOOL):
        called = await _rpc(client, workspace_b, "tools/call", {"name": tool_name, "arguments": {}})
        # The canonical M2.3 shape: an unresolved Tool is a JSON-RPC *protocol* error carrying a
        # uniform phrase, not an executed call that failed.
        assert called.json()["error"]["message"] == "Unknown tool.", called.text

    # ...and knowing another tenant's Tool name yields no oracle: the response is byte-identical
    # to one for a name that never existed anywhere.
    unknown = await _rpc(
        client, workspace_b, "tools/call", {"name": "definitely_not_a_tool", "arguments": {}}
    )
    assert unknown.json()["error"] == called.json()["error"]

    assert egress.calls == [], "a cross-tenant MCP call reached the network"
    assert await audit_rows(admin_engine, workspace_a.id) == []


@pytest.mark.asyncio
async def test_ec1_calls_use_workspace_bs_token_against_workspace_as_slug(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    egress: _Egress,
) -> None:
    """The confused-deputy shape: B's token, A's slug in the path.

    The MCP transport binds the token to the slug, so this must be refused at the transport
    boundary rather than resolved to either Workspace.
    """
    await seed_both_connectors(admin_engine, workspace_a.id)
    response = await client.post(
        f"/mcp/v1/{workspace_a.slug}",
        headers=_headers(workspace_b),
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert response.status_code in (401, 403), response.text
    assert egress.calls == []


@pytest.mark.asyncio
async def test_runtime_repository_scoping_holds_without_rls(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    """Isolates the Runtime repository's own workspace predicates from RLS (P-14).

    The EC1 cross-tenant test above passes on RLS alone — deleting `Tool.workspace_id == …` or
    `Connection.workspace_id == …` from the Runtime repository does not fail it, which a mutation
    audit confirmed. Defense in depth is only two defenses if each is tested with the other
    absent, so this runs the same lookups on an RLS-exempt connection, leaving the application
    predicates as the only thing standing.
    """
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.core.security import CallerIdentity, WorkspaceContext
    from app.domains.runtime.repository import RuntimeRepository

    ids = await seed_both_connectors(admin_engine, workspace_b.id)

    def context(workspace_id: uuid.UUID) -> WorkspaceContext:
        return WorkspaceContext(
            workspace_id=workspace_id,
            caller=CallerIdentity(kind="api_token", api_token_id=None),
            request_id="ec1-audit",
        )

    async with AsyncSession(admin_engine) as session:
        # Premise: this connection really can see workspace B's rows, or the assertions below
        # would pass for the wrong reason.
        visible = (
            await session.execute(
                text("SELECT count(*) FROM tools WHERE workspace_id = :w"), {"w": workspace_b.id}
            )
        ).scalar_one()
        assert visible >= 2, "premise failed: the admin connection is subject to RLS here"

        foreign = RuntimeRepository(session, context(workspace_a.id))
        assert await foreign.resolve_tool(ALPHA_TOOL) is None, (
            "Tool resolution returned another workspace's Tool"
        )
        assert await foreign.get_connection(ids["beta"]["connection_id"]) is None, (
            "Connection lookup returned another workspace's Connection"
        )

        # And the same repository, correctly scoped, does find them — so the predicates are
        # filtering by tenant rather than simply returning nothing.
        own = RuntimeRepository(session, context(workspace_b.id))
        assert await own.resolve_tool(ALPHA_TOOL) is not None
        assert await own.get_connection(ids["beta"]["connection_id"]) is not None
