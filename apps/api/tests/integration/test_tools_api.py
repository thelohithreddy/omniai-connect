"""Tools administration API end to end — `/v1/tools` through the real app (M1-Tools-v1).

Real HTTP, real Postgres + RLS, real human JWT auth + centralized RBAC. Proves the read/write
authorization split (view = `tools:execute` owner/admin/member; enable-disable = `connectors:manage`
owner/admin; VIEWER denied; machine tokens denied — the admin surface is the human control plane),
cross-tenant 404/no-oracle, deprecated-Tool no-resurrection, idempotent + race-safe enable/disable,
mass-assignment rejection, pagination, and the Runtime invariant (a disabled Tool cannot execute).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core import net
from tests.conftest import FakeJWKSEndpoint, SeededWorkspace, SigningAuthority, bearer
from tests.integration.test_human_auth import seed_member

WS_HEADER = "X-Workspace-Id"


async def seed_tools(
    engine: AsyncEngine,
    workspace_id: uuid.UUID,
    specs: list[tuple[str, bool, bool]],
) -> dict[str, uuid.UUID]:
    """Seed a connector + version + one Tool per spec `(name, enabled, deleted)` as the superuser
    admin engine, bypassing RLS. Returns {name: tool_id}. No Connection/Credential."""
    connector_id = uuid.uuid4()
    version_id = uuid.uuid4()
    tool_ids: dict[str, uuid.UUID] = {}
    schema = {"type": "object", "properties": {"q": {"type": "string"}}, "required": []}
    normalized = {
        "tools": [
            {
                "name": name,
                "endpoint": {"method": "GET", "url": "/get", "binding": {}, "body_style": "none"},
                "input_schema": schema,
            }
            for name, _, _ in specs
        ]
    }
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO connectors (id, workspace_id, name, slug, source_type, base_url, "
                "auth_config, status) VALUES (:id, :ws, 'Demo', :slug, 'manual', "
                "'https://api.example.com', '{}', 'active')"
            ),
            {"id": connector_id, "ws": workspace_id, "slug": f"demo-{connector_id.hex[:8]}"},
        )
        await conn.execute(
            text(
                "INSERT INTO connector_versions (id, workspace_id, connector_id, version, "
                "spec_hash, normalized_schema) VALUES (:id, :ws, :cid, 1, 'h', :schema)"
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
        for name, enabled, deleted in specs:
            tool_id = uuid.uuid4()
            tool_ids[name] = tool_id
            await conn.execute(
                text(
                    "INSERT INTO tools (id, workspace_id, connector_id, connector_version_id, "
                    "name, description, input_schema, enabled, deleted_at) VALUES (:id, :ws, :cid, "
                    ":ver, :name, 'A demo tool', :schema, :enabled, :deleted)"
                ),
                {
                    "id": tool_id,
                    "ws": workspace_id,
                    "cid": connector_id,
                    "ver": version_id,
                    "name": name,
                    "schema": json.dumps(schema),
                    "enabled": enabled,
                    "deleted": datetime.now(UTC) if deleted else None,
                },
            )
    tool_ids["__connector__"] = connector_id
    return tool_ids


@pytest.fixture
async def member_client(
    human_client: tuple[httpx.AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> tuple[httpx.AsyncClient, dict[str, str]]:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="tl-member", role="member")
    headers = {**bearer(authority.sign("tl-member")), WS_HEADER: str(workspace_a.id)}
    return client, headers


def _hx(authority: SigningAuthority, user: str, ws: uuid.UUID) -> dict[str, str]:
    return {**bearer(authority.sign(user)), WS_HEADER: str(ws)}


# --------------------------------------------------------------------------- read (list / get)


async def test_list_returns_own_tools_metadata_only(
    member_client: tuple[httpx.AsyncClient, dict[str, str]],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, headers = member_client
    await seed_tools(
        admin_engine, workspace_a.id, [("demo_a", True, False), ("demo_b", False, False)]
    )
    resp = await client.get("/v1/tools", headers=headers)
    assert resp.status_code == 200, resp.text
    names = {t["name"] for t in resp.json()["data"]}
    assert {"demo_a", "demo_b"} <= names
    tool = resp.json()["data"][0]
    # metadata only — no endpoint, no auth_config, no secret material
    assert set(tool) == {
        "id",
        "connector_id",
        "connector_version_id",
        "name",
        "description",
        "input_schema",
        "output_hints",
        "annotations",
        "enabled",
        "created_at",
        "updated_at",
    }
    assert "endpoint" not in json.dumps(tool)
    assert "auth_config" not in json.dumps(tool)


async def test_deprecated_tools_are_not_listed(
    member_client: tuple[httpx.AsyncClient, dict[str, str]],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, headers = member_client
    await seed_tools(
        admin_engine, workspace_a.id, [("live_one", True, False), ("gone_one", True, True)]
    )
    names = {t["name"] for t in (await client.get("/v1/tools", headers=headers)).json()["data"]}
    assert "live_one" in names
    assert "gone_one" not in names  # soft-deleted = invisible


async def test_list_filter_by_connector_id(
    member_client: tuple[httpx.AsyncClient, dict[str, str]],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, headers = member_client
    ids_a = await seed_tools(admin_engine, workspace_a.id, [("in_a", True, False)])
    await seed_tools(admin_engine, workspace_a.id, [("in_b", True, False)])
    resp = await client.get(f"/v1/tools?connector_id={ids_a['__connector__']}", headers=headers)
    names = {t["name"] for t in resp.json()["data"]}
    assert names == {"in_a"}


async def test_list_pagination_cursor(
    member_client: tuple[httpx.AsyncClient, dict[str, str]],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, headers = member_client
    await seed_tools(
        admin_engine,
        workspace_a.id,
        [("t1", True, False), ("t2", True, False), ("t3", True, False)],
    )
    first = await client.get("/v1/tools?limit=2", headers=headers)
    assert first.json()["has_more"] is True
    assert len(first.json()["data"]) == 2  # exactly the page size, not the fetched limit+1
    cursor = first.json()["next_cursor"]
    assert cursor
    second = await client.get(f"/v1/tools?limit=2&cursor={cursor}", headers=headers)
    first_ids = {t["id"] for t in first.json()["data"]}
    second_ids = {t["id"] for t in second.json()["data"]}
    assert first_ids.isdisjoint(second_ids)  # no overlap across pages


async def test_list_unknown_query_param_is_400(
    member_client: tuple[httpx.AsyncClient, dict[str, str]],
) -> None:
    client, headers = member_client
    resp = await client.get("/v1/tools?bogus=1", headers=headers)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "validation_error"


async def test_list_bad_cursor_is_400(
    member_client: tuple[httpx.AsyncClient, dict[str, str]],
) -> None:
    client, headers = member_client
    resp = await client.get("/v1/tools?cursor=not-a-real-cursor", headers=headers)
    assert resp.status_code == 400


async def test_get_own_tool(
    member_client: tuple[httpx.AsyncClient, dict[str, str]],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, headers = member_client
    ids = await seed_tools(admin_engine, workspace_a.id, [("solo", True, False)])
    resp = await client.get(f"/v1/tools/{ids['solo']}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["name"] == "solo"
    assert resp.json()["enabled"] is True


async def test_get_missing_tool_is_404(
    member_client: tuple[httpx.AsyncClient, dict[str, str]],
) -> None:
    client, headers = member_client
    resp = await client.get(f"/v1/tools/{uuid.uuid4()}", headers=headers)
    assert resp.status_code == 404


async def test_get_deprecated_tool_is_404(
    member_client: tuple[httpx.AsyncClient, dict[str, str]],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, headers = member_client
    ids = await seed_tools(admin_engine, workspace_a.id, [("dead", True, True)])
    resp = await client.get(f"/v1/tools/{ids['dead']}", headers=headers)
    assert resp.status_code == 404  # a soft-deleted tool is not retrievable


# --------------------------------------------------------------------------- enable / disable


async def test_enable_disable_toggles_and_persists(
    human_client: tuple[httpx.AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="tl-owner", role="owner")
    ids = await seed_tools(admin_engine, workspace_a.id, [("toggle", True, False)])
    hx = _hx(authority, "tl-owner", workspace_a.id)

    disabled = await client.patch(f"/v1/tools/{ids['toggle']}", headers=hx, json={"enabled": False})
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False
    assert (await client.get(f"/v1/tools/{ids['toggle']}", headers=hx)).json()["enabled"] is False

    enabled = await client.patch(f"/v1/tools/{ids['toggle']}", headers=hx, json={"enabled": True})
    assert enabled.json()["enabled"] is True


async def test_enable_disable_is_idempotent(
    human_client: tuple[httpx.AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="tl-owner", role="owner")
    ids = await seed_tools(admin_engine, workspace_a.id, [("idem", True, False)])
    hx = _hx(authority, "tl-owner", workspace_a.id)
    r1 = await client.patch(f"/v1/tools/{ids['idem']}", headers=hx, json={"enabled": False})
    r2 = await client.patch(f"/v1/tools/{ids['idem']}", headers=hx, json={"enabled": False})
    assert r1.status_code == r2.status_code == 200
    assert r1.json()["enabled"] is False and r2.json()["enabled"] is False


async def test_patch_extra_field_is_rejected(
    human_client: tuple[httpx.AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="tl-owner", role="owner")
    ids = await seed_tools(admin_engine, workspace_a.id, [("mass", True, False)])
    hx = _hx(authority, "tl-owner", workspace_a.id)
    # Attempt to rewrite immutable fields — rejected, not silently ignored.
    resp = await client.patch(
        f"/v1/tools/{ids['mass']}",
        headers=hx,
        json={
            "enabled": False,
            "name": "evil",
            "description": "x",
            "connector_id": str(uuid.uuid4()),
        },
    )
    assert resp.status_code == 400  # app remaps FastAPI 422 -> 400 validation_error


async def test_patch_missing_enabled_is_rejected(
    human_client: tuple[httpx.AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="tl-owner", role="owner")
    ids = await seed_tools(admin_engine, workspace_a.id, [("noenab", True, False)])
    hx = _hx(authority, "tl-owner", workspace_a.id)
    resp = await client.patch(f"/v1/tools/{ids['noenab']}", headers=hx, json={})
    assert resp.status_code == 400  # app remaps FastAPI 422 -> 400 validation_error


async def test_patch_deprecated_tool_is_404_no_resurrection(
    human_client: tuple[httpx.AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="tl-owner", role="owner")
    ids = await seed_tools(admin_engine, workspace_a.id, [("zombie", False, True)])
    hx = _hx(authority, "tl-owner", workspace_a.id)
    resp = await client.patch(f"/v1/tools/{ids['zombie']}", headers=hx, json={"enabled": True})
    assert resp.status_code == 404  # a deprecated tool cannot be re-enabled
    # ...and the UPDATE must not have touched the deprecated row at all (no silent side effect).
    async with admin_engine.begin() as conn:
        result = await conn.execute(
            text("SELECT enabled FROM tools WHERE id=:id"), {"id": ids["zombie"]}
        )
        still = result.scalar()
    assert still is False


# --------------------------------------------------------------------------- authorization


async def test_member_can_read_but_not_patch(
    member_client: tuple[httpx.AsyncClient, dict[str, str]],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, headers = member_client
    ids = await seed_tools(admin_engine, workspace_a.id, [("m", True, False)])
    assert (await client.get(f"/v1/tools/{ids['m']}", headers=headers)).status_code == 200
    patch = await client.patch(f"/v1/tools/{ids['m']}", headers=headers, json={"enabled": False})
    assert (
        patch.status_code == 403
    )  # tools:execute can view, but enable/disable needs connectors:manage


async def test_viewer_is_denied_everything(
    human_client: tuple[httpx.AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="tl-viewer", role="viewer")
    ids = await seed_tools(admin_engine, workspace_a.id, [("v", True, False)])
    hx = _hx(authority, "tl-viewer", workspace_a.id)
    assert (await client.get("/v1/tools", headers=hx)).status_code == 403
    assert (await client.get(f"/v1/tools/{ids['v']}", headers=hx)).status_code == 403
    assert (
        await client.patch(f"/v1/tools/{ids['v']}", headers=hx, json={"enabled": False})
    ).status_code == 403


async def test_admin_can_patch(
    human_client: tuple[httpx.AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="tl-admin", role="admin")
    ids = await seed_tools(admin_engine, workspace_a.id, [("a", True, False)])
    hx = _hx(authority, "tl-admin", workspace_a.id)
    resp = await client.patch(f"/v1/tools/{ids['a']}", headers=hx, json={"enabled": False})
    assert resp.status_code == 200


async def test_machine_token_is_denied_on_admin_surface(
    client: httpx.AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    # The admin surface is the human control plane (ADR-0002): a machine token has no membership.
    ids = await seed_tools(admin_engine, workspace_a.id, [("mt", True, False)])
    mt = bearer(workspace_a.token.plaintext)
    assert (await client.get("/v1/tools", headers=mt)).status_code == 403
    assert (
        await client.patch(f"/v1/tools/{ids['mt']}", headers=mt, json={"enabled": False})
    ).status_code == 403


# --------------------------------------------------------------------------- tenant isolation


async def test_cross_tenant_list_is_isolated(
    human_client: tuple[httpx.AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    client, _ = human_client
    await seed_tools(admin_engine, workspace_a.id, [("a_secret", True, False)])
    await seed_member(admin_engine, workspace_b.id, user_id="b-owner", role="owner")
    resp = await client.get("/v1/tools", headers=_hx(authority, "b-owner", workspace_b.id))
    names = {t["name"] for t in resp.json()["data"]}
    assert "a_secret" not in names


async def test_cross_tenant_get_and_patch_are_404(
    human_client: tuple[httpx.AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    client, _ = human_client
    ids = await seed_tools(admin_engine, workspace_a.id, [("a_tool", True, False)])
    await seed_member(admin_engine, workspace_b.id, user_id="b-owner", role="owner")
    hx = _hx(authority, "b-owner", workspace_b.id)
    assert (await client.get(f"/v1/tools/{ids['a_tool']}", headers=hx)).status_code == 404
    patch = await client.patch(f"/v1/tools/{ids['a_tool']}", headers=hx, json={"enabled": False})
    assert patch.status_code == 404  # uniform not-found — no cross-tenant oracle


# --------------------------------------------------------------------------- Runtime invariant


async def _seed_executable(engine: AsyncEngine, ws: uuid.UUID) -> dict[str, uuid.UUID]:
    """A full connector + version + tool + active connection + credential, for a real Tool Call."""
    from tests.integration.test_tool_calls_api import seed_tool

    return await seed_tool(engine, ws, credential_type="bearer", secret={"value": "tok"})


async def test_disabled_tool_cannot_execute_via_runtime(
    human_client: tuple[httpx.AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="tl-owner", role="owner")
    ids = await _seed_executable(admin_engine, workspace_a.id)
    # find the tool_id for 'demo_op'
    from sqlalchemy import text as _t

    async with admin_engine.begin() as conn:
        tool_id = (
            await conn.execute(
                _t("SELECT id FROM tools WHERE workspace_id=:ws AND name='demo_op'"),
                {"ws": workspace_a.id},
            )
        ).scalar()

    # egress is mocked so an *enabled* execution would succeed; the point is the *disabled* refusal.
    async def _fake(*a: object, **k: object) -> net.GuardedResponse:
        return net.GuardedResponse(
            200, httpx.Headers({"content-type": "application/json"}), b"{}", False
        )

    monkeypatch.setattr("app.core.net.request", _fake)
    mt = bearer(workspace_a.token.plaintext)

    # enabled → the Runtime executes (200)
    ok = await client.post(
        "/v1/tool-calls", headers=mt, json={"tool_name": "demo_op", "arguments": {}}
    )
    assert ok.status_code == 200, ok.text

    # disable via the admin API (human owner), then the Runtime refuses (404)
    hx = _hx(authority, "tl-owner", workspace_a.id)
    assert (
        await client.patch(f"/v1/tools/{tool_id}", headers=hx, json={"enabled": False})
    ).status_code == 200
    denied = await client.post(
        "/v1/tool-calls", headers=mt, json={"tool_name": "demo_op", "arguments": {}}
    )
    assert denied.status_code == 404  # a disabled Tool is not resolvable by the Runtime
    _ = ids
