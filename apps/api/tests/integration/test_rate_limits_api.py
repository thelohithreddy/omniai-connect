"""M2.4 rate limits & quotas end to end — real Redis, real Postgres+RLS, real auth (ADR-0037).

The one enforcement point is the Runtime's stage-3 policy check, so REST and MCP are exercised
against the SAME workspace budget; the only stubbed seam is the final egress socket (the M1
pattern). Limits are shrunk per test via settings monkeypatching; every test gets fresh
workspaces (fresh buckets/counters), and keys are asserted directly in Redis where the contract
is about state (TTL, consumption, isolation).
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core import net
from app.core.config import settings
from app.core.redis import redis_client
from app.domains.runtime.limits import _quota_key, _workspace_bucket_key
from tests.conftest import SeededWorkspace
from tests.integration.test_tool_calls_api import _Egress, seed_tool

VERSION = "2025-11-25"


@pytest.fixture
def egress(monkeypatch: pytest.MonkeyPatch) -> _Egress:
    fake = _Egress()
    monkeypatch.setattr("app.core.net.request", fake)
    return fake


@pytest.fixture
def small_limits(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Shrink the Free-plan limits so boundaries are reachable in a test."""
    monkeypatch.setattr(settings, "free_workspace_rate_per_minute", 60)
    monkeypatch.setattr(settings, "free_workspace_burst", 2)
    monkeypatch.setattr(settings, "free_weekly_quota", 1000)
    return monkeypatch


def _rest_headers(ws: SeededWorkspace) -> dict[str, str]:
    return {"Authorization": f"Bearer {ws.token.plaintext}"}


def _mcp_headers(ws: SeededWorkspace) -> dict[str, str]:
    return {**_rest_headers(ws), "MCP-Protocol-Version": VERSION}


async def _rest_call(client: AsyncClient, ws: SeededWorkspace, tool: str = "demo_op") -> Any:
    return await client.post(
        "/v1/tool-calls", headers=_rest_headers(ws), json={"tool_name": tool, "arguments": {}}
    )


async def _mcp_call(client: AsyncClient, ws: SeededWorkspace, tool: str = "demo_op") -> Any:
    return await client.post(
        f"/mcp/v1/{ws.slug}",
        headers=_mcp_headers(ws),
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool}},
    )


async def _quota_used(ws_id: uuid.UUID) -> int:
    from datetime import UTC, datetime

    async with redis_client() as redis:
        raw = await redis.get(_quota_key(ws_id, datetime.now(UTC)))
    return int(raw) if raw is not None else 0


# ------------------------------------------------------------------ workspace rate limit (REST)


async def test_workspace_rate_limit_boundary_on_rest(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    small_limits: pytest.MonkeyPatch,
) -> None:
    await seed_tool(admin_engine, workspace_a.id)
    ok1, ok2 = await _rest_call(client, workspace_a), await _rest_call(client, workspace_a)
    assert ok1.status_code == 200 and ok2.status_code == 200

    denied = await _rest_call(client, workspace_a)
    assert denied.status_code == 429, denied.text
    body = denied.json()["error"]
    assert body["code"] == "rate_limited"
    assert isinstance(body["details"]["retry_after_seconds"], int)
    assert denied.headers.get("Retry-After") == str(body["details"]["retry_after_seconds"])
    assert "redis" not in denied.text.lower() and "Traceback" not in denied.text

    # The denial is audited: status denied, stable code, interface metadata intact.
    async with admin_engine.begin() as conn:
        rows = list(
            await conn.execute(
                text(
                    "SELECT status, error_code FROM tool_calls WHERE workspace_id=:w"
                    " ORDER BY created_at"
                ),
                {"w": workspace_a.id},
            )
        )
    assert [(r.status, r.error_code) for r in rows] == [
        ("succeeded", None),
        ("succeeded", None),
        ("denied", "rate_limited"),
    ]


async def test_rest_and_mcp_share_one_workspace_budget(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    small_limits: pytest.MonkeyPatch,
) -> None:
    """The core cross-surface invariant: alternating REST/MCP calls drain ONE bucket."""
    await seed_tool(admin_engine, workspace_a.id)
    assert (await _rest_call(client, workspace_a)).status_code == 200
    mcp_ok = await _mcp_call(client, workspace_a)
    assert mcp_ok.json()["result"]["isError"] is False  # token 2 of 2

    rest_denied = await _rest_call(client, workspace_a)
    assert rest_denied.status_code == 429  # bucket empty — REST sees it

    mcp_denied = await _mcp_call(client, workspace_a)
    result = mcp_denied.json()["result"]
    assert result["isError"] is True  # …and MCP sees the SAME empty bucket
    assert result["content"][0]["text"].startswith("rate_limited:")


async def test_cross_tenant_isolation_of_buckets(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    egress: _Egress,
    small_limits: pytest.MonkeyPatch,
) -> None:
    small_limits.setattr(settings, "free_workspace_burst", 1)
    await seed_tool(admin_engine, workspace_a.id)
    await seed_tool(admin_engine, workspace_b.id)
    assert (await _rest_call(client, workspace_a)).status_code == 200
    assert (await _rest_call(client, workspace_a)).status_code == 429  # A exhausted
    assert (await _rest_call(client, workspace_b)).status_code == 200  # B unaffected
    async with redis_client() as redis:
        assert await redis.exists(_workspace_bucket_key(workspace_a.id))
        assert await redis.exists(_workspace_bucket_key(workspace_b.id))


async def test_concurrent_calls_admit_exactly_the_burst(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    small_limits: pytest.MonkeyPatch,
) -> None:
    small_limits.setattr(settings, "free_workspace_burst", 3)
    await seed_tool(admin_engine, workspace_a.id)
    responses = await asyncio.gather(*(_rest_call(client, workspace_a) for _ in range(8)))
    codes = sorted(r.status_code for r in responses)
    assert codes == [200, 200, 200, 429, 429, 429, 429, 429]  # no race-based over-admission


async def test_bucket_refills_at_the_sustained_rate(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    small_limits: pytest.MonkeyPatch,
) -> None:
    small_limits.setattr(settings, "free_workspace_burst", 1)  # rate stays 60/min = 1 token/s
    await seed_tool(admin_engine, workspace_a.id)
    assert (await _rest_call(client, workspace_a)).status_code == 200
    assert (await _rest_call(client, workspace_a)).status_code == 429
    await asyncio.sleep(1.2)  # one refill interval
    assert (await _rest_call(client, workspace_a)).status_code == 200


# -------------------------------------------------------------------- connection rate hints


async def test_connection_hint_bucket_narrows_within_the_workspace_limit(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    small_limits: pytest.MonkeyPatch,
) -> None:
    ids = await seed_tool(admin_engine, workspace_a.id, tool_name="hinted_op")
    async with admin_engine.begin() as conn:
        await conn.execute(
            text("UPDATE tools SET annotations = :a WHERE id = :i"),
            {"a": '{"rate_hints": {"requests_per_minute": 60, "burst": 1}}', "i": ids["tool_id"]},
        )
    # Workspace burst is 2, but the Connection hint allows only 1 — the narrower bound wins.
    assert (await _rest_call(client, workspace_a, "hinted_op")).status_code == 200
    denied = await _rest_call(client, workspace_a, "hinted_op")
    assert denied.status_code == 429
    assert "connection" in denied.json()["error"]["message"].lower()


# ----------------------------------------------------------------------------------- quota


async def test_quota_consumption_boundary_and_semantics(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    small_limits: pytest.MonkeyPatch,
) -> None:
    """D2 end to end: executed successes AND executed failures consume; the quota denial is
    `quota_exceeded` (distinct code, D4) with reset details; denied calls consume nothing;
    pre-audit failures consume nothing."""
    small_limits.setattr(settings, "free_workspace_burst", 100)  # rate limit must not bind here
    small_limits.setattr(settings, "free_weekly_quota", 2)
    await seed_tool(admin_engine, workspace_a.id)

    assert (await _rest_call(client, workspace_a)).status_code == 200  # quota 1 (succeeded)
    egress.response = net.GuardedResponse(
        status_code=503, headers=httpx.Headers({}), body=b"boom", truncated=False
    )
    failed = await _rest_call(client, workspace_a)  # executed upstream failure → quota 2
    assert failed.status_code == 502
    assert await _quota_used(workspace_a.id) == 2

    denied = await _rest_call(client, workspace_a)
    assert denied.status_code == 429
    body = denied.json()["error"]
    assert body["code"] == "quota_exceeded"
    assert body["details"]["quota"] == 2 and body["details"]["used"] == 2
    assert body["details"]["quota_resets_at"].endswith("Z")
    assert denied.headers.get("Retry-After") is not None

    # The quota-denied call did NOT consume quota…
    assert await _quota_used(workspace_a.id) == 2
    # …nor does a pre-audit failure (unknown tool).
    missing = await _rest_call(client, workspace_a, "no_such_tool")
    assert missing.status_code == 404
    assert await _quota_used(workspace_a.id) == 2

    # MCP maps the same denial through the M2.3 contract.
    mcp = await _mcp_call(client, workspace_a)
    assert mcp.json()["result"]["isError"] is True
    assert mcp.json()["result"]["content"][0]["text"].startswith("quota_exceeded:")

    # The audit trail tells the same story.
    async with admin_engine.begin() as conn:
        rows = list(
            await conn.execute(
                text(
                    "SELECT status, error_code FROM tool_calls WHERE workspace_id=:w"
                    " ORDER BY created_at"
                ),
                {"w": workspace_a.id},
            )
        )
    assert [(r.status, r.error_code) for r in rows] == [
        ("succeeded", None),
        ("failed", "connector_error"),
        ("denied", "quota_exceeded"),
        ("denied", "quota_exceeded"),
    ]


async def test_timeout_consumes_quota_and_rate_denial_does_not(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    small_limits: pytest.MonkeyPatch,
) -> None:
    small_limits.setattr(settings, "free_workspace_burst", 2)
    await seed_tool(admin_engine, workspace_a.id)
    egress.exc = httpx.ReadTimeout("slow")
    timeout = await _rest_call(client, workspace_a)
    assert timeout.status_code == 504  # executed timeout
    assert await _quota_used(workspace_a.id) == 1  # D2: timeouts consume

    egress.exc = None
    assert (await _rest_call(client, workspace_a)).status_code == 200  # quota 2, bucket empty
    assert (await _rest_call(client, workspace_a)).status_code == 429  # rate-limited
    assert await _quota_used(workspace_a.id) == 2  # the denial consumed nothing


async def test_quota_key_carries_period_scoped_expiry(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    small_limits: pytest.MonkeyPatch,
) -> None:
    from datetime import UTC, datetime

    await seed_tool(admin_engine, workspace_a.id)
    assert (await _rest_call(client, workspace_a)).status_code == 200
    async with redis_client() as redis:
        ttl = await redis.ttl(_quota_key(workspace_a.id, datetime.now(UTC)))
    assert 0 < ttl <= 8 * 24 * 3600  # expires within the period + one day of slack


# ------------------------------------------------------------------------------ plan gating


async def test_paid_plans_are_unenforced_until_m3(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    small_limits: pytest.MonkeyPatch,
) -> None:
    small_limits.setattr(settings, "free_workspace_burst", 1)
    await seed_tool(admin_engine, workspace_a.id)
    async with admin_engine.begin() as conn:
        await conn.execute(
            text("UPDATE workspaces SET plan='pro' WHERE id=:w"), {"w": workspace_a.id}
        )
    for _ in range(4):  # far past the free burst — no limiter, no quota key
        assert (await _rest_call(client, workspace_a)).status_code == 200
    assert await _quota_used(workspace_a.id) == 0


# ------------------------------------------------------------------------------ Redis outage


async def test_redis_outage_fails_closed_on_both_surfaces(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    small_limits: pytest.MonkeyPatch,
) -> None:
    """D3: the limiter cannot reach Redis → the call is DENIED (never silently unlimited),
    audited, retryable, and leaks nothing."""
    await seed_tool(admin_engine, workspace_a.id)

    class _Down:
        async def __aenter__(self) -> Any:
            raise ConnectionError("redis down")

        async def __aexit__(self, *exc: object) -> None:
            return None

    small_limits.setattr("app.domains.runtime.limits.redis_client", lambda: _Down())
    rest = await _rest_call(client, workspace_a)
    assert rest.status_code == 429
    assert rest.json()["error"]["code"] == "rate_limited"
    assert "redis" not in rest.text.lower() and "ConnectionError" not in rest.text

    mcp = await _mcp_call(client, workspace_a)
    assert mcp.json()["result"]["isError"] is True

    assert egress.calls == [], "no execution may happen while limits are unverifiable"
    async with admin_engine.begin() as conn:
        statuses = [
            r.status
            for r in await conn.execute(
                text("SELECT status FROM tool_calls WHERE workspace_id=:w"),
                {"w": workspace_a.id},
            )
        ]
    assert statuses == ["denied", "denied"]


async def test_partial_redis_failure_on_the_quota_read_still_fails_closed(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    small_limits: pytest.MonkeyPatch,
) -> None:
    """D3 on the quota path in isolation: the rate bucket is HEALTHY (real Redis) but the quota
    read fails — a partial outage (dropped connection, eviction, OOM on the second command).

    The whole-outage test above can never reach this branch: it kills the bucket first. Without
    this case, a quota-read fail-open would be indistinguishable from correct behavior, so a
    workspace over its quota could execute whenever Redis half-failed.
    """
    await seed_tool(admin_engine, workspace_a.id)
    real_client = redis_client

    class _Proxy:
        """Delegates every command to the real client except the quota GET."""

        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

        async def get(self, *args: Any, **kwargs: Any) -> Any:
            raise ConnectionError("quota read unavailable")

    class _QuotaReadFails:
        def __init__(self) -> None:
            self._client = real_client()

        async def __aenter__(self) -> Any:
            return _Proxy(await self._client.__aenter__())

        async def __aexit__(self, *exc: object) -> Any:
            return await self._client.__aexit__(*exc)

    small_limits.setattr("app.domains.runtime.limits.redis_client", lambda: _QuotaReadFails())
    resp = await _rest_call(client, workspace_a)
    assert resp.status_code == 429, resp.text
    assert resp.json()["error"]["code"] == "rate_limited"
    assert "redis" not in resp.text.lower() and "ConnectionError" not in resp.text
    assert egress.calls == [], "quota must never be skipped when it cannot be verified"


# ------------------------------------------------------------------------------- kill switch


async def test_kill_switch_restores_pre_m24_behavior(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    small_limits: pytest.MonkeyPatch,
) -> None:
    small_limits.setattr(settings, "free_workspace_burst", 1)
    small_limits.setattr(settings, "rate_limiting_enabled", False)
    await seed_tool(admin_engine, workspace_a.id)
    for _ in range(4):  # no checks…
        assert (await _rest_call(client, workspace_a)).status_code == 200
    assert await _quota_used(workspace_a.id) == 0  # …and no counting: exact M2.3 behavior
    async with redis_client() as redis:
        assert not await redis.exists(_workspace_bucket_key(workspace_a.id))


# ------------------------------------------------------------------------------- idempotency


async def test_idempotent_replay_consumes_no_token_and_no_quota(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    small_limits: pytest.MonkeyPatch,
) -> None:
    await seed_tool(admin_engine, workspace_a.id)
    key = str(uuid.uuid4())
    headers = {**_rest_headers(workspace_a), "Idempotency-Key": key}
    body = {"tool_name": "demo_op", "arguments": {}}

    first = await client.post("/v1/tool-calls", headers=headers, json=body)
    assert first.status_code == 200
    async with redis_client() as redis:
        tokens_after_first = await redis.hget(_workspace_bucket_key(workspace_a.id), "tokens")
    quota_after_first = await _quota_used(workspace_a.id)

    replay = await client.post("/v1/tool-calls", headers=headers, json=body)
    assert replay.status_code == 200 and replay.json() == first.json()
    async with redis_client() as redis:
        tokens_after_replay = await redis.hget(_workspace_bucket_key(workspace_a.id), "tokens")
    assert tokens_after_replay == tokens_after_first  # replay never reached execute()
    assert await _quota_used(workspace_a.id) == quota_after_first
    assert len(egress.calls) == 1
