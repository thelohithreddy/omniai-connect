"""OAuth refresh worker + OAuth-backed execution end to end (M2.5, ADR-0038).

Real Postgres + RLS, the real vault, the real worker tenant context, the real Runtime, and the
real MCP adapter. The only mocked boundary is the outermost socket (the fake provider).

Proves the parts that only real infrastructure can: the `FOR UPDATE` claim serializes concurrent
refreshes to exactly one token exchange, refresh-token **rotation** is persisted (losing it would
orphan the Connection forever), terminal failure transitions to `error` + emits
`connection.deactivated`, `needs_reauth` derives from state rather than a stored column (D5), and
an OAuth credential executes identically through REST and MCP with no adapter-specific logic.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core import net
from app.core.events import Event, event_bus
from app.domains.credentials import vault
from app.domains.oauth.refresh import RefreshOutcome, is_due, refresh_connection
from app.workers.context import worker_tenant_uow
from tests.conftest import SeededWorkspace
from tests.integration.fake_oauth_provider import FakeOAuthProvider

MCP_VERSION = "2025-11-25"
ACCESS = "M2_5_REFRESH_CANARY_access"  # noqa: S105 (synthetic test secret)
REFRESH = "M2_5_REFRESH_CANARY_refresh"  # noqa: S105 (synthetic test secret)

AUTH_CONFIG = {
    "type": "oauth2",
    "authorization_url": "https://provider.example.com/authorize",
    "token_url": "https://provider.example.com/token",
    "scopes": ["read"],
    "client_id": "test-client",
}
_ENDPOINT = {"method": "GET", "url": "/get", "binding": {}, "body_style": "none"}
_SCHEMA: dict[str, Any] = {"type": "object", "additionalProperties": True}


@pytest.fixture
def fake_provider(monkeypatch: pytest.MonkeyPatch) -> FakeOAuthProvider:
    provider = FakeOAuthProvider()
    monkeypatch.setattr("app.core.net.request", provider)
    return provider


async def seed_oauth_tool(
    engine: AsyncEngine,
    workspace_id: uuid.UUID,
    *,
    tool_name: str = "oauth_op",
    access_token: str = ACCESS,
    refresh_token: str | None = REFRESH,
    expires_at: datetime | None = None,
) -> dict[str, uuid.UUID]:
    """A fully executable OAuth Connection: connector + version + tool + connection + a sealed
    oauth2 credential, written as the superuser (bypassing RLS) exactly like the M1 helpers."""
    connector_id, version_id, tool_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    connection_id, credential_id = uuid.uuid4(), uuid.uuid4()
    secret: dict[str, str] = {"access_token": access_token, "token_type": "Bearer"}
    if refresh_token is not None:
        secret["refresh_token"] = refresh_token
    sealed = vault.seal(
        json.dumps(secret).encode(), workspace_id=workspace_id, connection_id=connection_id
    )
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO connectors (id, workspace_id, name, slug, source_type, base_url,"
                " auth_config, status) VALUES (:i,:w,'P',:s,'manual','https://api.example.com',"
                " :a,'active')"
            ),
            {
                "i": connector_id,
                "w": workspace_id,
                "s": f"o-{connector_id.hex[:8]}",
                "a": json.dumps(AUTH_CONFIG),
            },
        )
        await conn.execute(
            text(
                "INSERT INTO connector_versions (id, workspace_id, connector_id, version,"
                " spec_hash, normalized_schema) VALUES (:i,:w,:c,1,'h',:n)"
            ),
            {
                "i": version_id,
                "w": workspace_id,
                "c": connector_id,
                "n": json.dumps(
                    {"tools": [{"name": tool_name, "endpoint": _ENDPOINT, "input_schema": _SCHEMA}]}
                ),
            },
        )
        await conn.execute(
            text("UPDATE connectors SET current_version_id=:v WHERE id=:i"),
            {"v": version_id, "i": connector_id},
        )
        await conn.execute(
            text(
                "INSERT INTO tools (id, workspace_id, connector_id, connector_version_id, name,"
                " description, input_schema) VALUES (:i,:w,:c,:v,:n,'op',:s)"
            ),
            {
                "i": tool_id,
                "w": workspace_id,
                "c": connector_id,
                "v": version_id,
                "n": tool_name,
                "s": json.dumps(_SCHEMA),
            },
        )
        await conn.execute(
            text(
                "INSERT INTO connections (id, workspace_id, connector_id, name, status)"
                " VALUES (:i,:w,:c,:n,'active')"
            ),
            {
                "i": connection_id,
                "w": workspace_id,
                "c": connector_id,
                "n": f"c-{connection_id.hex[-12:]}",
            },
        )
        await conn.execute(
            text(
                "INSERT INTO credentials (id, workspace_id, connection_id, credential_type,"
                " ciphertext, encrypted_dek, nonce, key_version, expires_at)"
                " VALUES (:i,:w,:c,'oauth2',:ct,:d,:n,:kv,:e)"
            ),
            {
                "i": credential_id,
                "w": workspace_id,
                "c": connection_id,
                "ct": sealed.ciphertext,
                "d": sealed.encrypted_dek,
                "n": sealed.nonce,
                "kv": sealed.key_version,
                "e": expires_at or datetime.now(UTC) + timedelta(hours=1),
            },
        )
        await conn.execute(
            text("UPDATE connections SET credential_id=:cr WHERE id=:i"),
            {"cr": credential_id, "i": connection_id},
        )
    return {"connection_id": connection_id, "tool_id": tool_id, "credential_id": credential_id}


async def _credential_row(engine: AsyncEngine, connection_id: uuid.UUID) -> Any:
    async with engine.begin() as conn:
        return (
            await conn.execute(
                text(
                    "SELECT cr.expires_at, cr.rotated_at, cr.ciphertext, c.status"
                    " FROM credentials cr JOIN connections c ON c.id = cr.connection_id"
                    " WHERE cr.connection_id = :i"
                ),
                {"i": connection_id},
            )
        ).first()


# --------------------------------------------------------------------------- due calculation


def test_is_due_boundaries() -> None:
    now = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
    assert is_due(None, now=now) is False  # no expiry → never refreshed
    assert is_due(now - timedelta(seconds=1), now=now) is True  # already expired
    assert is_due(now + timedelta(seconds=60), now=now) is True  # inside the threshold
    assert is_due(now + timedelta(hours=5), now=now) is False  # plenty of life left


# -------------------------------------------------------------------------------- refresh


async def test_refresh_renews_the_token_and_extends_expiry(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, fake_provider: FakeOAuthProvider
) -> None:
    ids = await seed_oauth_tool(
        admin_engine, workspace_a.id, expires_at=datetime.now(UTC) + timedelta(seconds=30)
    )
    fake_provider.valid_refresh_tokens.add(REFRESH)
    before = await _credential_row(admin_engine, ids["connection_id"])

    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        result = await refresh_connection(
            uow, workspace_id=workspace_a.id, connection_id=ids["connection_id"]
        )
    assert result.outcome is RefreshOutcome.REFRESHED

    after = await _credential_row(admin_engine, ids["connection_id"])
    assert after.expires_at > before.expires_at
    assert after.rotated_at is not None
    assert after.status == "active"
    # The task arguments and the stored row never contain plaintext.
    assert ACCESS.encode() not in bytes(after.ciphertext)


async def test_refresh_persists_a_rotated_refresh_token(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, fake_provider: FakeOAuthProvider
) -> None:
    """Rotation is the dangerous case: dropping the new refresh token orphans the Connection
    permanently. After a rotating refresh, a SECOND refresh must still succeed."""
    ids = await seed_oauth_tool(
        admin_engine, workspace_a.id, expires_at=datetime.now(UTC) + timedelta(seconds=30)
    )
    fake_provider.valid_refresh_tokens.add(REFRESH)
    fake_provider.rotate_refresh_tokens = True

    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        first = await refresh_connection(
            uow, workspace_id=workspace_a.id, connection_id=ids["connection_id"]
        )
    assert first.outcome is RefreshOutcome.REFRESHED
    assert REFRESH not in fake_provider.valid_refresh_tokens  # the old one died on rotation

    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        second = await refresh_connection(
            uow, workspace_id=workspace_a.id, connection_id=ids["connection_id"], force=True
        )
    assert second.outcome is RefreshOutcome.REFRESHED, "the rotated refresh token was not stored"


async def test_concurrent_refreshes_perform_exactly_one_exchange(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, fake_provider: FakeOAuthProvider
) -> None:
    """The `FOR UPDATE` claim plus the in-lock re-check: four workers, one token exchange."""
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

    outcomes = await asyncio.gather(*(one() for _ in range(4)))
    assert sum(1 for o in outcomes if o is RefreshOutcome.REFRESHED) == 1, outcomes
    assert sum(1 for o in outcomes if o is RefreshOutcome.NOT_DUE) == 3, outcomes
    exchanges = [g for g, _ in fake_provider.exchanges if g == "refresh_token"]
    assert len(exchanges) == 1, "the row lock did not serialize the refresh"


async def test_terminal_failure_transitions_to_error_and_emits_deactivated(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, fake_provider: FakeOAuthProvider
) -> None:
    """A credential with no refresh token cannot be renewed: `error` + `connection.deactivated`,
    and `needs_reauth` derives from that state — no fifth status, no `error_reason` (D5)."""
    ids = await seed_oauth_tool(
        admin_engine,
        workspace_a.id,
        refresh_token=None,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    saved = {k: list(v) for k, v in event_bus._handlers.items()}
    event_bus._handlers.clear()
    seen: list[Event] = []
    event_bus.subscribe("connection.deactivated", lambda e: seen.append(e))
    try:
        async with worker_tenant_uow(str(workspace_a.id)) as uow:
            result = await refresh_connection(
                uow, workspace_id=workspace_a.id, connection_id=ids["connection_id"]
            )
    finally:
        event_bus._handlers.clear()
        event_bus._handlers.update(saved)

    assert result.outcome is RefreshOutcome.TERMINAL
    row = await _credential_row(admin_engine, ids["connection_id"])
    assert row.status == "error"
    assert len(seen) == 1 and seen[0].payload["status"] == "error"

    # D5: needs_reauth is DERIVED — status == error AND an oauth2 credential exists.
    async with admin_engine.begin() as conn:
        derived = (
            await conn.execute(
                text(
                    "SELECT c.status='error' AND cr.credential_type='oauth2' AS needs_reauth"
                    " FROM connections c JOIN credentials cr ON cr.connection_id=c.id"
                    " WHERE c.id=:i"
                ),
                {"i": ids["connection_id"]},
            )
        ).scalar()
    assert derived is True
    # And no fifth status was invented.
    async with admin_engine.begin() as conn:
        statuses = (
            await conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint"
                    " WHERE conname='status_valid'"
                )
            )
        ).scalar()
    assert "needs_reauth" not in str(statuses)


async def test_provider_outage_is_retryable_not_terminal(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, fake_provider: FakeOAuthProvider
) -> None:
    """An outage must not burn the Connection on the first failure."""
    ids = await seed_oauth_tool(
        admin_engine, workspace_a.id, expires_at=datetime.now(UTC) + timedelta(seconds=30)
    )
    fake_provider.valid_refresh_tokens.add(REFRESH)
    fake_provider.raise_error = net.SSRFError("provider unreachable")

    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        result = await refresh_connection(
            uow, workspace_id=workspace_a.id, connection_id=ids["connection_id"]
        )
    assert result.outcome is RefreshOutcome.RETRYABLE
    assert (await _credential_row(admin_engine, ids["connection_id"])).status == "active"


async def test_refresh_is_tenant_scoped(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    fake_provider: FakeOAuthProvider,
) -> None:
    """Bound to B, A's connection is invisible — RLS governs the worker exactly as it does a
    request, so a mis-routed task cannot touch another tenant's credential."""
    ids = await seed_oauth_tool(
        admin_engine, workspace_a.id, expires_at=datetime.now(UTC) - timedelta(seconds=1)
    )
    fake_provider.valid_refresh_tokens.add(REFRESH)
    async with worker_tenant_uow(str(workspace_b.id)) as uow:
        result = await refresh_connection(
            uow, workspace_id=workspace_b.id, connection_id=ids["connection_id"]
        )
    assert result.outcome is RefreshOutcome.SKIPPED
    assert fake_provider.exchanges == []
    assert (await _credential_row(admin_engine, ids["connection_id"])).status == "active"


# ------------------------------------------------------- OAuth-backed execution: REST + MCP


async def test_oauth_credential_executes_through_rest_and_mcp(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The point of the whole module: an OAuth Connection is callable, identically, from both
    surfaces — one Runtime injection branch, no adapter-specific credential logic."""
    await seed_oauth_tool(admin_engine, workspace_a.id, tool_name="oauth_call")
    sent: list[dict[str, str]] = []

    async def fake_egress(method: str, url: str, **kwargs: Any) -> net.GuardedResponse:
        sent.append(dict(kwargs.get("headers") or {}))
        import httpx

        return net.GuardedResponse(
            status_code=200,
            headers=httpx.Headers({"content-type": "application/json"}),
            body=b'{"ok":true}',
            truncated=False,
        )

    monkeypatch.setattr("app.core.net.request", fake_egress)
    headers = {"Authorization": f"Bearer {workspace_a.token.plaintext}"}

    rest = await client.post(
        "/v1/tool-calls", headers=headers, json={"tool_name": "oauth_call", "arguments": {}}
    )
    assert rest.status_code == 200, rest.text
    assert ACCESS not in rest.text  # the token never returns to the caller

    mcp = await client.post(
        f"/mcp/v1/{workspace_a.slug}",
        headers={**headers, "MCP-Protocol-Version": MCP_VERSION},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "oauth_call"}},
    )
    assert mcp.json()["result"]["isError"] is False
    assert ACCESS not in mcp.text

    # Both surfaces injected the SAME bearer token via the one Runtime branch.
    assert len(sent) == 2
    assert all(h.get("Authorization") == f"Bearer {ACCESS}" for h in sent), sent

    # Audit records both interfaces and leaks nothing.
    async with admin_engine.begin() as conn:
        rows = list(
            await conn.execute(
                text(
                    "SELECT status, caller->>'interface' AS iface, input_summary::text AS i,"
                    " output_summary::text AS o FROM tool_calls WHERE workspace_id=:w"
                ),
                {"w": workspace_a.id},
            )
        )
    assert {r.iface for r in rows} == {"rest", "mcp"}
    assert all(r.status == "succeeded" for r in rows)
    assert all(ACCESS not in (r.i or "") and ACCESS not in (r.o or "") for r in rows)
