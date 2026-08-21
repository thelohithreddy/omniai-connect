"""Independent M2.5 release-audit gates (added by the promotion audit, not the implementation).

The implementation suite proved the OAuth flow itself. These are the gates an independent
auditor asks for that it did **not** cover:

- refresh concurrency at the directive's full fan-out (2 / 4 / 8 workers), not just 4;
- **M2.4 regression**: an OAuth-backed Tool Call must still be rate-limited and must still fail
  closed when Redis is unavailable — OAuth must not have opened a bypass around the limiter;
- cross-tenant refresh and execution refusal proved from the *attacker's* side;
- Celery task payloads statically proven to be identifier-only.
"""

from __future__ import annotations

import asyncio
import inspect
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core import net
from app.core.config import settings
from app.domains.oauth.refresh import RefreshOutcome, refresh_connection
from app.workers.context import worker_tenant_uow
from tests.conftest import SeededWorkspace
from tests.integration.fake_oauth_provider import FakeOAuthProvider
from tests.integration.test_oauth_refresh_api import REFRESH, seed_oauth_tool

MCP_VERSION = "2025-11-25"


@pytest.fixture
def fake_provider(monkeypatch: pytest.MonkeyPatch) -> FakeOAuthProvider:
    provider = FakeOAuthProvider()
    monkeypatch.setattr("app.core.net.request", provider)
    return provider


# ------------------------------------------------------ refresh concurrency at full fan-out


@pytest.mark.parametrize("workers", [2, 4, 8])
async def test_refresh_is_serialized_at_every_fan_out(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    fake_provider: FakeOAuthProvider,
    workers: int,
) -> None:
    """The `FOR UPDATE` claim plus the in-lock re-check must hold at 2, 4 and 8 workers: one
    exchange, and every loser observes the refreshed state rather than redeeming a refresh token
    the provider has already invalidated."""
    ids = await seed_oauth_tool(
        admin_engine, workspace_a.id, expires_at=datetime.now(UTC) + timedelta(seconds=30)
    )
    fake_provider.valid_refresh_tokens.add(REFRESH)

    async def one() -> RefreshOutcome:
        async with worker_tenant_uow(str(workspace_a.id)) as uow:
            result = await refresh_connection(
                uow, workspace_id=workspace_a.id, connection_id=ids["connection_id"]
            )
        return result.outcome

    outcomes = await asyncio.gather(*(one() for _ in range(workers)))
    refreshed = [o for o in outcomes if o is RefreshOutcome.REFRESHED]
    exchanges = [g for g, _ in fake_provider.exchanges if g == "refresh_token"]
    assert len(refreshed) == 1, outcomes
    assert len(exchanges) == 1, f"{workers} workers produced {len(exchanges)} exchanges"
    assert all(o is RefreshOutcome.NOT_DUE for o in outcomes if o is not RefreshOutcome.REFRESHED)


# --------------------------------------------------------------- M2.4 regression under OAuth


async def test_oauth_tool_calls_remain_rate_limited(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OAuth must not open a bypass around the M2.4 limiter: an OAuth-backed Tool Call consumes
    the same workspace bucket as any other, on REST and MCP alike."""
    await seed_oauth_tool(admin_engine, workspace_a.id, tool_name="rl_oauth_op")
    monkeypatch.setattr(settings, "free_workspace_burst", 2)

    async def ok_egress(method: str, url: str, **kwargs: Any) -> net.GuardedResponse:
        return net.GuardedResponse(
            status_code=200,
            headers=httpx.Headers({"content-type": "application/json"}),
            body=b'{"ok":true}',
            truncated=False,
        )

    monkeypatch.setattr("app.core.net.request", ok_egress)
    headers = {"Authorization": f"Bearer {workspace_a.token.plaintext}"}
    body = {"tool_name": "rl_oauth_op", "arguments": {}}

    assert (await client.post("/v1/tool-calls", headers=headers, json=body)).status_code == 200
    assert (await client.post("/v1/tool-calls", headers=headers, json=body)).status_code == 200
    denied = await client.post("/v1/tool-calls", headers=headers, json=body)
    assert denied.status_code == 429, "an OAuth Tool Call escaped the M2.4 rate limiter"
    assert denied.json()["error"]["code"] == "rate_limited"

    # MCP drains the SAME bucket — no per-interface budget was introduced.
    mcp = await client.post(
        f"/mcp/v1/{workspace_a.slug}",
        headers={**headers, "MCP-Protocol-Version": MCP_VERSION},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "rl_oauth_op"}},
    )
    result = mcp.json()["result"]
    assert result["isError"] is True
    assert result["content"][0]["text"].startswith("rate_limited:")


async def test_oauth_tool_call_fails_closed_when_redis_is_unavailable(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M2.4's D3 fail-closed policy must still govern OAuth-backed calls: limits unverifiable
    means the call does not execute, and no credential is touched."""
    await seed_oauth_tool(admin_engine, workspace_a.id, tool_name="ro_oauth_op")
    egressed: list[str] = []

    async def spy_egress(method: str, url: str, **kwargs: Any) -> net.GuardedResponse:
        egressed.append(url)
        return net.GuardedResponse(
            status_code=200, headers=httpx.Headers({}), body=b"{}", truncated=False
        )

    class _Down:
        async def __aenter__(self) -> Any:
            raise ConnectionError("redis down")

        async def __aexit__(self, *exc: object) -> None:
            return None

    monkeypatch.setattr("app.core.net.request", spy_egress)
    monkeypatch.setattr("app.domains.runtime.limits.redis_client", lambda: _Down())

    resp = await client.post(
        "/v1/tool-calls",
        headers={"Authorization": f"Bearer {workspace_a.token.plaintext}"},
        json={"tool_name": "ro_oauth_op", "arguments": {}},
    )
    assert resp.status_code == 429
    assert egressed == [], "an OAuth call executed while rate limits were unverifiable"


# ------------------------------------------------------------------ cross-tenant, attacker side


async def test_workspace_b_can_neither_refresh_nor_execute_workspace_a_oauth(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    fake_provider: FakeOAuthProvider,
) -> None:
    """B holds a valid token for its own workspace and knows A's tool name and connection id.
    Neither the refresh worker nor the execution path may act on A's credential."""
    ids = await seed_oauth_tool(
        admin_engine,
        workspace_a.id,
        tool_name="a_only_oauth",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    fake_provider.valid_refresh_tokens.add(REFRESH)

    # Refresh bound to B cannot see A's connection.
    async with worker_tenant_uow(str(workspace_b.id)) as uow:
        result = await refresh_connection(
            uow, workspace_id=workspace_b.id, connection_id=ids["connection_id"]
        )
    assert result.outcome is RefreshOutcome.SKIPPED
    assert fake_provider.exchanges == []

    # Execution with B's token, naming A's tool, is a uniform not-found — no egress, no rows.
    resp = await client.post(
        "/v1/tool-calls",
        headers={"Authorization": f"Bearer {workspace_b.token.plaintext}"},
        json={"tool_name": "a_only_oauth", "arguments": {}},
    )
    assert resp.status_code == 404
    async with admin_engine.begin() as conn:
        b_rows = (
            await conn.execute(
                text("SELECT count(*) FROM tool_calls WHERE workspace_id=:w"),
                {"w": workspace_b.id},
            )
        ).scalar()
        a_status = (
            await conn.execute(
                text("SELECT status FROM connections WHERE id=:i"), {"i": ids["connection_id"]}
            )
        ).scalar()
    assert b_rows == 0
    assert a_status == "active", "A's connection was mutated by B's attempt"


# ------------------------------------------------------------------ Celery payload discipline


def test_celery_task_signatures_accept_only_identifiers() -> None:
    """Task arguments are JSON at rest in the broker, so a token in a signature would be a
    plaintext secret in Redis. Asserted structurally, not by inspection of one call site."""
    from app.workers import oauth_tasks

    # `__wrapped__` is the undecorated function; Celery's bind=True `self` is not part of it.
    params = list(inspect.signature(oauth_tasks.refresh_oauth_credential.__wrapped__).parameters)
    assert params == ["workspace_id", "connection_id"], params

    source = inspect.getsource(oauth_tasks)
    for forbidden in ("access_token=", "refresh_token=", "code_verifier=", "client_secret="):
        assert forbidden not in source, f"{forbidden} appears in a task module"


# ------------------------------------------------ gaps found by the independent mutation audit


async def test_state_single_use_is_enforced_independently_of_the_provider(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    fake_provider: FakeOAuthProvider,
    human_client: Any,
    authority: Any,
) -> None:
    """Replay must be refused by OUR state row, not by the provider's single-use code.

    The implementation suite's replay test reused the same authorization code, which the
    provider also rejects — so it passed even with `consumed_at IS NULL` removed from the
    consume. This isolates the control: replay the consumed state with a **fresh, valid** code
    the provider would happily honour. If state single-use were gone, a second token exchange
    would occur; it must not.
    """
    from tests.conftest import bearer
    from tests.integration.test_human_auth import seed_member
    from tests.integration.test_oauth_flow_api import _seed_oauth_connection

    hclient, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="audit-owner", role="owner")
    headers = {
        **bearer(authority.sign("audit-owner")),
        "X-Workspace-Id": str(workspace_a.id),
    }
    connection_id = await _seed_oauth_connection(admin_engine, workspace_a.id)
    start = (
        await hclient.post(f"/v1/connections/{connection_id}/oauth/authorize", headers=headers)
    ).json()
    state = FakeOAuthProvider.state_from(start["authorize_url"])

    first = await hclient.get(
        "/v1/oauth/callback",
        params={"code": fake_provider.issue_code(start["authorize_url"]), "state": state},
    )
    assert first.status_code == 200
    exchanges_after_first = len(fake_provider.exchanges)

    # A brand-new code bound to the same challenge: only the consumed state can stop this.
    replay = await hclient.get(
        "/v1/oauth/callback",
        params={"code": fake_provider.issue_code(start["authorize_url"]), "state": state},
    )
    assert replay.status_code == 400
    assert len(fake_provider.exchanges) == exchanges_after_first, (
        "a replayed state reached the token endpoint — single-use is not enforced"
    )


async def test_oauth_kill_switch_disables_authorize_and_refresh(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    fake_provider: FakeOAuthProvider,
    human_client: Any,
    authority: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`OAUTH_ENABLED=false` is the operational rollback lever, so both halves must honour it —
    the refresh half had no test, which let a mutation removing its guard survive."""
    from tests.conftest import bearer
    from tests.integration.test_human_auth import seed_member
    from tests.integration.test_oauth_flow_api import _seed_oauth_connection

    hclient, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="ks-owner", role="owner")
    headers = {**bearer(authority.sign("ks-owner")), "X-Workspace-Id": str(workspace_a.id)}
    connection_id = await _seed_oauth_connection(admin_engine, workspace_a.id)
    ids = await seed_oauth_tool(
        admin_engine,
        workspace_a.id,
        tool_name="ks_oauth_op",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    fake_provider.valid_refresh_tokens.add(REFRESH)

    monkeypatch.setattr(settings, "oauth_enabled", False)

    denied = await hclient.post(f"/v1/connections/{connection_id}/oauth/authorize", headers=headers)
    assert denied.status_code == 409, "the kill switch did not disable the authorize endpoint"

    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        result = await refresh_connection(
            uow, workspace_id=workspace_a.id, connection_id=ids["connection_id"]
        )
    assert result.outcome is RefreshOutcome.SKIPPED
    assert fake_provider.exchanges == [], "refresh ran while the kill switch was off"
