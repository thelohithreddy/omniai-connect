"""M2.1 lifecycle events end to end — the cache-eviction event foundation (ADR-0034).

Real HTTP through the real ASGI app, real Postgres + RLS, real human JWT auth, and the real
event bus (the recorder subscribes to the shared-kernel `event_bus`; nothing at the event
boundary is mocked). Proves, per event:

- `connection.activated` — emitted exactly once by credential attach, post-commit, with the
  canonical payload; the failed second attach (409) emits nothing; rotate emits nothing.
- `connection.deactivated` — emitted exactly once by credential revoke (`active → pending_auth`,
  the founder-ratified 5th eviction event); a revoke that 404s emits nothing.
- `connection.revoked` — emitted exactly once by connection revoke; the idempotent second
  revoke (404, no row moved) emits nothing.
- `tool.enabled` / `tool.disabled` — emitted exactly once per persisted flip; a no-op PATCH
  (same value) is still a 200 but emits nothing; 404 paths emit nothing.
- Tenant binding: every event's envelope `workspace_id` is the acting workspace; a cross-tenant
  attempt (uniform 404) emits nothing at all — workspace B can never generate an event against
  workspace A's cache namespace.
- No secret ever rides in a payload (the attach secret does not appear anywhere in the event).

Rollback-emits-nothing for the buffering mechanism itself is proven against real Postgres in
tests/integration/test_event_bus.py; here the failure paths (409/404) prove the lifecycle
services never buffer on a request that did not transition state.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Iterator

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.events import Event, event_bus
from tests.conftest import FakeJWKSEndpoint, SeededWorkspace, SigningAuthority, bearer
from tests.integration.test_human_auth import seed_member
from tests.integration.test_tools_api import seed_tools

WS_HEADER = "X-Workspace-Id"
SECRET = "sk-live-lifecycle-event-secret"  # noqa: S105 (test secret)

LIFECYCLE_TYPES = (
    "connection.activated",
    "connection.deactivated",
    "connection.revoked",
    "tool.enabled",
    "tool.disabled",
)


def hx(token: str, workspace_id: uuid.UUID) -> dict[str, str]:
    return {**bearer(token), WS_HEADER: str(workspace_id)}


@pytest.fixture
def recorder() -> Iterator[list[Event]]:
    """Record every lifecycle event delivered by the real shared-kernel bus, then restore the
    handler map — the same isolation pattern as the runtime's event test."""
    saved = {k: list(v) for k, v in event_bus._handlers.items()}
    event_bus._handlers.clear()
    seen: list[Event] = []
    for event_type in LIFECYCLE_TYPES:
        event_bus.subscribe(event_type, lambda e: seen.append(e))
    try:
        yield seen
    finally:
        event_bus._handlers.clear()
        event_bus._handlers.update(saved)


@pytest.fixture
async def owner(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> AsyncIterator[dict[str, object]]:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="ev-owner", role="owner")
    yield {"client": client, "ws": workspace_a.id, "token": authority.sign("ev-owner")}


async def _make_connection(owner: dict[str, object], slug: str) -> tuple[str, str]:
    """Create a connector + a `pending_auth` connection; return (connection_id, connector_id)."""
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
    return connection.json()["id"], connector.json()["id"]


async def _attach(owner: dict[str, object], conn_id: str) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    headers = hx(owner["token"], owner["ws"])  # type: ignore[arg-type]
    resp = await client.post(
        f"/v1/connections/{conn_id}/credential",
        headers=headers,
        json={"credential_type": "api_key", "value": SECRET},
    )
    assert resp.status_code == 201, resp.text


def _only(recorder: list[Event], event_type: str) -> Event:
    matching = [e for e in recorder if e.event_type == event_type]
    assert len(matching) == 1, f"expected exactly one {event_type}, got {len(matching)}"
    return matching[0]


# ----------------------------------------------------------------- connection.activated (attach)


async def test_attach_emits_connection_activated_exactly_once(
    owner: dict[str, object], recorder: list[Event]
) -> None:
    conn_id, connector_id = await _make_connection(owner, "ev-act")
    assert recorder == [], "creating a pending_auth connection emits no lifecycle event"

    await _attach(owner, conn_id)

    event = _only(recorder, "connection.activated")
    assert event.workspace_id == owner["ws"]
    assert event.payload == {"connection_id": conn_id, "connector_id": connector_id}
    assert SECRET not in str(recorder), "no secret may ever ride in an event"


async def test_failed_second_attach_emits_nothing(
    owner: dict[str, object], recorder: list[Event]
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    headers = hx(owner["token"], owner["ws"])  # type: ignore[arg-type]
    conn_id, _ = await _make_connection(owner, "ev-409")
    await _attach(owner, conn_id)
    recorder.clear()

    dup = await client.post(
        f"/v1/connections/{conn_id}/credential",
        headers=headers,
        json={"credential_type": "api_key", "value": SECRET},
    )
    assert dup.status_code == 409
    assert recorder == [], "a 409 attach transitions nothing and must emit nothing"


async def test_rotate_emits_no_lifecycle_event(
    owner: dict[str, object], recorder: list[Event]
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    headers = hx(owner["token"], owner["ws"])  # type: ignore[arg-type]
    conn_id, _ = await _make_connection(owner, "ev-rot")
    await _attach(owner, conn_id)
    recorder.clear()

    rotated = await client.put(
        f"/v1/connections/{conn_id}/credential",
        headers=headers,
        json={"credential_type": "api_key", "value": "sk-rotated"},
    )
    assert rotated.status_code == 200, rotated.text
    assert recorder == [], "rotate keeps the connection active — no transition, no event"


# ----------------------------------------------------- connection.deactivated (credential revoke)


async def test_credential_revoke_emits_connection_deactivated(
    owner: dict[str, object], recorder: list[Event]
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    headers = hx(owner["token"], owner["ws"])  # type: ignore[arg-type]
    conn_id, connector_id = await _make_connection(owner, "ev-deact")
    await _attach(owner, conn_id)
    recorder.clear()

    resp = await client.delete(f"/v1/connections/{conn_id}/credential", headers=headers)
    assert resp.status_code == 204, resp.text

    event = _only(recorder, "connection.deactivated")
    assert event.workspace_id == owner["ws"]
    assert event.payload == {
        "connection_id": conn_id,
        "connector_id": connector_id,
        "status": "pending_auth",
    }


async def test_credential_revoke_404_emits_nothing(
    owner: dict[str, object], recorder: list[Event]
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    headers = hx(owner["token"], owner["ws"])  # type: ignore[arg-type]
    conn_id, _ = await _make_connection(owner, "ev-d404")  # pending_auth, no credential

    resp = await client.delete(f"/v1/connections/{conn_id}/credential", headers=headers)
    assert resp.status_code == 404
    assert recorder == []


# ------------------------------------------------------------------ connection.revoked (revoke)


async def test_connection_revoke_emits_connection_revoked_exactly_once(
    owner: dict[str, object], recorder: list[Event]
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    headers = hx(owner["token"], owner["ws"])  # type: ignore[arg-type]
    conn_id, connector_id = await _make_connection(owner, "ev-rev")

    resp = await client.delete(f"/v1/connections/{conn_id}", headers=headers)
    assert resp.status_code == 204, resp.text

    event = _only(recorder, "connection.revoked")
    assert event.workspace_id == owner["ws"]
    assert event.payload == {"connection_id": conn_id, "connector_id": connector_id}

    # The idempotent second revoke moves no row → uniform 404 → emits nothing further.
    recorder.clear()
    again = await client.delete(f"/v1/connections/{conn_id}", headers=headers)
    assert again.status_code == 404
    assert recorder == []


async def test_revoking_an_active_connection_emits_revoked_not_deactivated(
    owner: dict[str, object], recorder: list[Event]
) -> None:
    """Revoke is terminal: one `connection.revoked`, no `connection.deactivated` companion —
    a consumer sees exactly one authoritative fact per transition."""
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    headers = hx(owner["token"], owner["ws"])  # type: ignore[arg-type]
    conn_id, _ = await _make_connection(owner, "ev-ract")
    await _attach(owner, conn_id)
    recorder.clear()

    resp = await client.delete(f"/v1/connections/{conn_id}", headers=headers)
    assert resp.status_code == 204
    assert [e.event_type for e in recorder] == ["connection.revoked"]


# -------------------------------------------------------------------- tool.enabled / disabled


async def test_tool_flip_emits_exactly_once_and_noop_emits_nothing(
    owner: dict[str, object],
    recorder: list[Event],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    headers = hx(owner["token"], owner["ws"])  # type: ignore[arg-type]
    ids = await seed_tools(admin_engine, workspace_a.id, [("ev_toggle", True, False)])
    tool_id, connector_id = ids["ev_toggle"], ids["__connector__"]

    # Real flip: enabled → disabled. Exactly one event, canonical payload.
    r1 = await client.patch(f"/v1/tools/{tool_id}", headers=headers, json={"enabled": False})
    assert r1.status_code == 200 and r1.json()["enabled"] is False
    event = _only(recorder, "tool.disabled")
    assert event.workspace_id == workspace_a.id
    assert event.payload == {"tool_id": str(tool_id), "connector_id": str(connector_id)}

    # No-op: same value again. Still 200 (idempotent API), but no persisted transition → no event.
    recorder.clear()
    r2 = await client.patch(f"/v1/tools/{tool_id}", headers=headers, json={"enabled": False})
    assert r2.status_code == 200 and r2.json()["enabled"] is False
    assert recorder == [], "a no-op PATCH must emit nothing (INVARIANT 1)"

    # Flip back: disabled → enabled emits tool.enabled.
    r3 = await client.patch(f"/v1/tools/{tool_id}", headers=headers, json={"enabled": True})
    assert r3.status_code == 200 and r3.json()["enabled"] is True
    assert [e.event_type for e in recorder] == ["tool.enabled"]


async def test_tool_404_paths_emit_nothing(
    owner: dict[str, object],
    recorder: list[Event],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    headers = hx(owner["token"], owner["ws"])  # type: ignore[arg-type]
    ids = await seed_tools(admin_engine, workspace_a.id, [("ev_zombie", False, True)])

    missing = await client.patch(
        f"/v1/tools/{uuid.uuid4()}", headers=headers, json={"enabled": True}
    )
    assert missing.status_code == 404
    deprecated = await client.patch(
        f"/v1/tools/{ids['ev_zombie']}", headers=headers, json={"enabled": True}
    )
    assert deprecated.status_code == 404
    assert recorder == [], "a 404 transitions nothing and must emit nothing"


# ------------------------------------------------------------------------------ tenant binding


async def test_cross_tenant_attempts_generate_no_event_for_either_workspace(
    owner: dict[str, object],
    recorder: list[Event],
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """Workspace B's owner acting on A's resources gets the uniform 404 — and, critically for the
    future cache consumer, *no event exists at all*: B cannot make the system emit an event that
    would touch A's `ws:{A}:mcp:tools` namespace, nor one stamped with B's own workspace."""
    client, _ = human_client
    await seed_member(admin_engine, workspace_b.id, user_id="ev-b-owner", role="owner")
    b_headers = hx(authority.sign("ev-b-owner"), workspace_b.id)

    conn_id, _ = await _make_connection(owner, "ev-xt")
    ids = await seed_tools(admin_engine, workspace_a.id, [("ev_xt_tool", True, False)])
    recorder.clear()

    revoke = await client.delete(f"/v1/connections/{conn_id}", headers=b_headers)
    assert revoke.status_code == 404
    attach = await client.post(
        f"/v1/connections/{conn_id}/credential",
        headers=b_headers,
        json={"credential_type": "api_key", "value": SECRET},
    )
    assert attach.status_code == 404
    patch = await client.patch(
        f"/v1/tools/{ids['ev_xt_tool']}", headers=b_headers, json={"enabled": False}
    )
    assert patch.status_code == 404

    assert recorder == [], "cross-tenant attempts must generate no lifecycle event whatsoever"


async def test_every_lifecycle_event_carries_the_acting_workspace(
    owner: dict[str, object],
    recorder: list[Event],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    """One full lifecycle (create → attach → credential-revoke → re-attach → connection-revoke,
    plus a tool flip): every emitted event's envelope tenant is workspace A — the future eviction
    consumer may trust `event.workspace_id` as the cache namespace (INVARIANT 3)."""
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    headers = hx(owner["token"], owner["ws"])  # type: ignore[arg-type]
    conn_id, _ = await _make_connection(owner, "ev-full")
    ids = await seed_tools(admin_engine, workspace_a.id, [("ev_full_tool", True, False)])

    await _attach(owner, conn_id)
    assert (
        await client.delete(f"/v1/connections/{conn_id}/credential", headers=headers)
    ).status_code == 204
    await _attach(owner, conn_id)
    assert (await client.delete(f"/v1/connections/{conn_id}", headers=headers)).status_code == 204
    assert (
        await client.patch(
            f"/v1/tools/{ids['ev_full_tool']}", headers=headers, json={"enabled": False}
        )
    ).status_code == 200

    types = [e.event_type for e in recorder]
    assert types == [
        "connection.activated",
        "connection.deactivated",
        "connection.activated",
        "connection.revoked",
        "tool.disabled",
    ]
    assert all(e.workspace_id == workspace_a.id for e in recorder)
    assert SECRET not in str(recorder)


# ------------------------------------------------------------------------ transaction boundary


async def test_rolled_back_revoke_emits_nothing_and_leaves_the_row_live(
    owner: dict[str, object],
    recorder: list[Event],
    workspace_a: SeededWorkspace,
) -> None:
    """INVARIANT 8, at the lifecycle-service level: `connection.revoked` rides the UoW buffer, so
    a transaction that rolls back *after* the service call emits nothing — and the row stays
    live. Kills the mutation class where a service dispatches directly instead of publishing."""
    from app.core.security import CallerIdentity, WorkspaceContext
    from app.domains.connections.repository import ConnectionRepository
    from app.domains.connections.service import ConnectionService
    from app.workers.context import worker_tenant_uow

    conn_id, _ = await _make_connection(owner, "ev-rb")
    ctx = WorkspaceContext(
        workspace_id=workspace_a.id,
        caller=CallerIdentity(kind="api_token", api_token_id=uuid.uuid4()),
        request_id="req_test_rb",
    )

    with pytest.raises(RuntimeError):
        async with worker_tenant_uow(str(workspace_a.id)) as uow:
            service = ConnectionService(ConnectionRepository(uow.session, ctx))
            await service.revoke(uuid.UUID(conn_id))
            raise RuntimeError("boom after the service buffered its event")

    assert recorder == [], "a rolled-back transaction must emit nothing"

    # The rollback also undid the revoke: the connection is still live and revocable, and the
    # committed retry emits exactly one event — the fact tracks the durable state, not the call.
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    headers = hx(owner["token"], owner["ws"])  # type: ignore[arg-type]
    resp = await client.delete(f"/v1/connections/{conn_id}", headers=headers)
    assert resp.status_code == 204, "the rolled-back revoke must not have persisted"
    assert [e.event_type for e in recorder] == ["connection.revoked"]
