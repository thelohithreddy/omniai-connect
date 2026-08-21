"""M2.4-pre — DNS-gap remediation, end to end (real resolver, no egress stub).

Before this fix, a Tool Call against an unresolvable host raised a raw `socket.gaierror` that
escaped the egress taxonomy as an `internal` 500 with **no audit row** — on REST and MCP alike.
Now it is an egress-policy refusal like any other: `ssrf_blocked`, audited `denied`, no OS
detail or hostname leaked. The `.invalid` TLD is RFC 6761-reserved (always NXDOMAIN), so the
real resolver fails deterministically and no network egress can occur.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.conftest import SeededWorkspace
from tests.integration.test_tool_calls_api import seed_tool

VERSION = "2025-11-25"


async def test_unresolvable_host_is_an_audited_ssrf_denial_on_rest_and_mcp(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    base_url = f"https://nxdomain-{uuid.uuid4().hex[:10]}.invalid"
    await seed_tool(admin_engine, workspace_a.id, tool_name="dns_op", base_url=base_url)

    # REST: a policy denial through the canonical envelope — 403 ssrf_blocked, never a 500.
    rest = await client.post(
        "/v1/tool-calls",
        headers={"Authorization": f"Bearer {workspace_a.token.plaintext}"},
        json={"tool_name": "dns_op", "arguments": {}},
    )
    assert rest.status_code == 403, rest.text
    assert rest.json()["error"]["code"] == "ssrf_blocked"
    assert ".invalid" not in rest.text and "gaierror" not in rest.text

    # MCP: the audited denial maps through the M2.3 contract — isError, stable code.
    mcp = await client.post(
        f"/mcp/v1/{workspace_a.slug}",
        headers={
            "Authorization": f"Bearer {workspace_a.token.plaintext}",
            "MCP-Protocol-Version": VERSION,
        },
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "dns_op"}},
    )
    result = mcp.json()["result"]
    assert result["isError"] is True
    assert result["content"][0]["text"].startswith("ssrf_blocked:")
    assert ".invalid" not in mcp.text

    # Both attempts are audited: two `denied` rows with the stable code — no silent 500s.
    async with admin_engine.begin() as conn:
        rows = list(
            await conn.execute(
                text(
                    "SELECT status, error_code, caller->>'interface' AS iface FROM tool_calls"
                    " WHERE workspace_id=:w ORDER BY created_at"
                ),
                {"w": workspace_a.id},
            )
        )
    assert [(r.status, r.error_code) for r in rows] == [
        ("denied", "ssrf_blocked"),
        ("denied", "ssrf_blocked"),
    ]
    assert {r.iface for r in rows} == {"rest", "mcp"}
