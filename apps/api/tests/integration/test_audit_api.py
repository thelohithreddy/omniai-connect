"""Audit Log Viewer end to end — `GET /v1/tool-calls` through the real app (M1-Audit-v1).

Real HTTP, real Postgres + RLS, real human JWT + centralized RBAC. Proves: `audit:read` gate
(owner/admin allowed; member/viewer/machine-token denied), tenant isolation (a workspace never sees
another's audit rows), cursor pagination + deterministic ordering, the canonical UJ-5.3 filters,
metadata-only responses (no secret/`workspace_id`/raw-column leakage), invalid-input 400s, and the
read-only posture (no mutation verbs on the resource beyond the runtime's own POST).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.conftest import FakeJWKSEndpoint, SeededWorkspace, SigningAuthority, bearer
from tests.integration.test_human_auth import seed_member

WS_HEADER = "X-Workspace-Id"
_BASE = datetime(2026, 8, 1, 12, 0, 0, tzinfo=UTC)


async def seed_calls(
    engine: AsyncEngine, workspace_id: uuid.UUID, rows: list[dict[str, object]]
) -> list[uuid.UUID]:
    """Insert `tool_calls` rows directly (superuser admin engine, bypassing RLS). The table has no
    FK to connections/tools, so arbitrary UUIDs suffice. Returns the row ids in insertion order."""
    ids: list[uuid.UUID] = []
    async with engine.begin() as conn:
        for i, r in enumerate(rows):
            row_id = uuid.UUID(str(r["id"])) if r.get("id") else uuid.uuid4()
            ids.append(row_id)
            await conn.execute(
                text(
                    "INSERT INTO tool_calls (id, workspace_id, connection_id, tool_id, request_id, "
                    "caller, status, input_summary, output_summary, error_code, duration_ms, "
                    "created_at) VALUES (:id, :ws, :conn, :tool, :req, :caller, :status, :insum, "
                    ":outsum, :err, :dur, :created)"
                ),
                {
                    "id": row_id,
                    "ws": workspace_id,
                    "conn": r.get("connection_id") or uuid.uuid4(),
                    "tool": r.get("tool_id") or uuid.uuid4(),
                    "req": r.get("request_id", f"req_{i}"),
                    "caller": json.dumps(
                        r.get("caller", {"interface": "rest", "kind": "api_token"})
                    ),
                    "status": r.get("status", "succeeded"),
                    "insum": json.dumps(r.get("input_summary", {})),
                    "outsum": json.dumps(r.get("output_summary"))
                    if r.get("output_summary") is not None
                    else None,
                    "err": r.get("error_code"),
                    "dur": r.get("duration_ms", 10),
                    "created": r.get("created_at", _BASE + timedelta(seconds=i)),
                },
            )
    return ids


def _hx(authority: SigningAuthority, user: str, ws: uuid.UUID) -> dict[str, str]:
    return {**bearer(authority.sign(user)), WS_HEADER: str(ws)}


@pytest.fixture
async def owner(
    human_client: tuple[httpx.AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> tuple[httpx.AsyncClient, dict[str, str]]:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="au-owner", role="owner")
    return client, _hx(authority, "au-owner", workspace_a.id)


# --------------------------------------------------------------------------- read + shape


async def test_owner_lists_workspace_audit_log_metadata_only(
    owner: tuple[httpx.AsyncClient, dict[str, str]],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, hx = owner
    await seed_calls(
        admin_engine,
        workspace_a.id,
        [
            {"request_id": "req_a", "status": "succeeded"},
            {"request_id": "req_b", "status": "failed"},
        ],
    )
    resp = await client.get("/v1/tool-calls", headers=hx)
    assert resp.status_code == 200, resp.text
    reqs = {r["request_id"] for r in resp.json()["data"]}
    assert {"req_a", "req_b"} <= reqs
    row = resp.json()["data"][0]
    assert set(row) == {
        "id",
        "connection_id",
        "tool_id",
        "request_id",
        "caller",
        "status",
        "error_code",
        "input_summary",
        "output_summary",
        "duration_ms",
        "created_at",
    }
    # tenant boundary and any ciphertext-bearing column never appear
    assert "workspace_id" not in json.dumps(row)
    assert "ciphertext" not in json.dumps(row)


async def test_newest_first_and_deterministic_tie_break(
    owner: tuple[httpx.AsyncClient, dict[str, str]],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, hx = owner
    # two rows share created_at → id (UUIDv7 descending) breaks the tie deterministically
    same = _BASE + timedelta(minutes=5)
    hi, lo = uuid.UUID(int=2**120), uuid.UUID(int=2**119)
    await seed_calls(
        admin_engine,
        workspace_a.id,
        [
            {"id": lo, "request_id": "older_id", "created_at": same},
            {"id": hi, "request_id": "newer_id", "created_at": same},
        ],
    )
    data = (await client.get("/v1/tool-calls", headers=hx)).json()["data"]
    order = [r["request_id"] for r in data]
    assert order.index("newer_id") < order.index("older_id")


async def test_pagination_cursor(
    owner: tuple[httpx.AsyncClient, dict[str, str]],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, hx = owner
    await seed_calls(
        admin_engine,
        workspace_a.id,
        [{"request_id": f"r{i}", "created_at": _BASE + timedelta(seconds=i)} for i in range(3)],
    )
    first = await client.get("/v1/tool-calls?limit=2", headers=hx)
    assert first.json()["has_more"] is True
    assert len(first.json()["data"]) == 2
    cursor = first.json()["next_cursor"]
    second = await client.get(f"/v1/tool-calls?limit=2&cursor={cursor}", headers=hx)
    first_ids = {r["id"] for r in first.json()["data"]}
    second_ids = {r["id"] for r in second.json()["data"]}
    assert first_ids.isdisjoint(second_ids)


async def test_empty_result(owner: tuple[httpx.AsyncClient, dict[str, str]]) -> None:
    client, hx = owner
    resp = await client.get("/v1/tool-calls", headers=hx)
    assert resp.status_code == 200
    assert resp.json() == {"data": [], "next_cursor": None, "has_more": False}


# --------------------------------------------------------------------------- filters


async def test_filter_by_connection_tool_status_interface_and_time(
    owner: tuple[httpx.AsyncClient, dict[str, str]],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, hx = owner
    conn_a, tool_a = uuid.uuid4(), uuid.uuid4()
    await seed_calls(
        admin_engine,
        workspace_a.id,
        [
            {
                "request_id": "match",
                "connection_id": conn_a,
                "tool_id": tool_a,
                "status": "denied",
                "caller": {"interface": "mcp", "kind": "member"},
                "created_at": _BASE + timedelta(hours=2),
            },
            {
                "request_id": "other",
                "status": "succeeded",
                "caller": {"interface": "rest", "kind": "api_token"},
                "created_at": _BASE,
            },
        ],
    )
    assert {
        r["request_id"]
        for r in (await client.get(f"/v1/tool-calls?connection_id={conn_a}", headers=hx)).json()[
            "data"
        ]
    } == {"match"}
    assert {
        r["request_id"]
        for r in (await client.get(f"/v1/tool-calls?tool_id={tool_a}", headers=hx)).json()["data"]
    } == {"match"}
    assert {
        r["request_id"]
        for r in (await client.get("/v1/tool-calls?status=denied", headers=hx)).json()["data"]
    } == {"match"}
    assert {
        r["request_id"]
        for r in (await client.get("/v1/tool-calls?interface=mcp", headers=hx)).json()["data"]
    } == {"match"}
    # `Z` form, not `+00:00` — a literal `+` in a query string decodes to a space.
    after = (_BASE + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    assert {
        r["request_id"]
        for r in (await client.get(f"/v1/tool-calls?created_after={after}", headers=hx)).json()[
            "data"
        ]
    } == {"match"}


async def test_invalid_status_filter_is_400(
    owner: tuple[httpx.AsyncClient, dict[str, str]],
) -> None:
    client, hx = owner
    resp = await client.get("/v1/tool-calls?status=bogus", headers=hx)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "validation_error"


async def test_unknown_query_param_is_400(owner: tuple[httpx.AsyncClient, dict[str, str]]) -> None:
    client, hx = owner
    assert (await client.get("/v1/tool-calls?surprise=1", headers=hx)).status_code == 400


async def test_bad_cursor_is_400(owner: tuple[httpx.AsyncClient, dict[str, str]]) -> None:
    client, hx = owner
    assert (await client.get("/v1/tool-calls?cursor=not-real", headers=hx)).status_code == 400


# --------------------------------------------------------------------------- authorization


async def test_admin_can_read(
    human_client: tuple[httpx.AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="au-admin", role="admin")
    assert (
        await client.get("/v1/tool-calls", headers=_hx(authority, "au-admin", workspace_a.id))
    ).status_code == 200


async def test_member_and_viewer_are_denied(
    human_client: tuple[httpx.AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="au-member", role="member")
    await seed_member(admin_engine, workspace_a.id, user_id="au-viewer", role="viewer")
    assert (
        await client.get("/v1/tool-calls", headers=_hx(authority, "au-member", workspace_a.id))
    ).status_code == 403
    assert (
        await client.get("/v1/tool-calls", headers=_hx(authority, "au-viewer", workspace_a.id))
    ).status_code == 403


async def test_unauthenticated_is_401(client: httpx.AsyncClient) -> None:
    assert (await client.get("/v1/tool-calls")).status_code == 401


async def test_machine_token_is_denied(
    client: httpx.AsyncClient, workspace_a: SeededWorkspace
) -> None:
    # A machine token has no membership → no audit:read (the audit log is a human control surface).
    assert (
        await client.get("/v1/tool-calls", headers=bearer(workspace_a.token.plaintext))
    ).status_code == 403


# --------------------------------------------------------------------------- isolation + read-only


async def test_cross_tenant_isolation(
    human_client: tuple[httpx.AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    client, _ = human_client
    await seed_calls(admin_engine, workspace_a.id, [{"request_id": "a_secret_call"}])
    await seed_member(admin_engine, workspace_b.id, user_id="b-owner", role="owner")
    data = (
        await client.get("/v1/tool-calls", headers=_hx(authority, "b-owner", workspace_b.id))
    ).json()["data"]
    assert all(r["request_id"] != "a_secret_call" for r in data)


async def test_no_mutation_verbs_on_the_log(
    owner: tuple[httpx.AsyncClient, dict[str, str]],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, hx = owner
    ids = await seed_calls(admin_engine, workspace_a.id, [{"request_id": "immutable"}])
    # The viewer adds no mutation surface: PATCH/PUT/DELETE on the resource are 405 (not allowed).
    assert (await client.patch("/v1/tool-calls", headers=hx, json={"x": 1})).status_code == 405
    assert (await client.put("/v1/tool-calls", headers=hx, json={"x": 1})).status_code == 405
    assert (await client.delete("/v1/tool-calls", headers=hx)).status_code == 405
    assert (await client.delete(f"/v1/tool-calls/{ids[0]}", headers=hx)).status_code == 405
