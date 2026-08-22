"""Connection Health end to end (M2.7-A, ROADMAP §58). Real Postgres, real RLS, real Runtime.

Only the outermost socket is faked. Everything the endpoint claims to reuse — authorization, the
Runtime pipeline, rate limits and quota, credential decrypt-at-use, the audit write — is the real
implementation, because the entire architectural claim of this slice is *"a health check is an
ordinary Tool Call"*. A test that mocked the Runtime would assert that claim instead of proving it.

What is proven here rather than asserted:

- the endpoint executes through `RuntimeService` and produces **exactly one** `tool_calls` row;
- an unsafe Tool inventory yields `health_check_unavailable` with **zero** egress;
- `last_health_check_at` is stamped from the audit row's own timestamp, on success *and* failure;
- the derived projection appears on the ordinary Connection read model;
- the tenant boundary, the RBAC matrix and the kill switch all hold at the HTTP edge.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core import net
from app.core.config import settings
from tests.conftest import FakeJWKSEndpoint, SeededWorkspace, SigningAuthority, bearer
from tests.integration.test_human_auth import seed_member

WS_HEADER = "X-Workspace-Id"

SAFE = {"readonly": True, "destructive": False, "idempotent": True}
UNSAFE = {"readonly": False, "destructive": True, "idempotent": False}
NO_ARGS = {"type": "object", "properties": {}, "required": []}
NEEDS_ARGS = {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}
ENDPOINT = {"method": "GET", "url": "/get", "binding": {}, "body_style": "none"}


@dataclass
class _Sent:
    method: str
    url: str


class _Egress:
    """Stand-in for the one guarded outbound call. Records attempts so a test can prove that a
    refused health check performed **no** egress at all."""

    def __init__(self) -> None:
        self.calls: list[_Sent] = []
        self.response = net.GuardedResponse(
            status_code=200,
            headers=httpx.Headers({"content-type": "application/json"}),
            body=b'{"ok":true}',
            truncated=False,
        )
        self.exc: Exception | None = None

    async def __call__(self, method: str, url: str, **_: object) -> net.GuardedResponse:
        self.calls.append(_Sent(method, url))
        if self.exc is not None:
            raise self.exc
        return self.response


@pytest.fixture
def egress(monkeypatch: pytest.MonkeyPatch) -> _Egress:
    fake = _Egress()
    monkeypatch.setattr("app.core.net.request", fake)
    return fake


async def seed(
    engine: AsyncEngine,
    workspace_id: uuid.UUID,
    *,
    tools: list[dict[str, object]] | None = None,
    status: str = "active",
    credential_type: str = "api_key",
    with_credential: bool = True,
    auth_config: dict[str, object] | None = None,
) -> dict[str, uuid.UUID]:
    """A Connector with an explicit Tool inventory, a Connection, and a sealed credential.

    Written as the superuser (bypassing RLS) exactly like the other integration helpers. Tool
    `annotations` are set **explicitly** here — the column defaults to `'{}'`, and a helper that
    silently produced safe-looking annotations would hide the fail-closed behaviour under test.
    """
    from app.domains.credentials import vault

    tools = tools or [{"name": "list_items", "annotations": SAFE, "input_schema": NO_ARGS}]
    # api_key injection needs the Connector to declare where the key goes; oauth2 needs nothing.
    if auth_config is None:
        auth_config = (
            {"type": "api_key", "key_name": "X-API-Key", "location": "header"}
            if credential_type == "api_key"
            else {}
        )
    connector_id, version_id, connection_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    normalized = {
        "tools": [
            {"name": t["name"], "endpoint": ENDPOINT, "input_schema": t["input_schema"]}
            for t in tools
        ]
    }
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO connectors (id, workspace_id, name, slug, source_type, base_url,"
                " auth_config, status) VALUES (:i,:w,'Demo',:s,'manual','https://api.example.com',"
                " :ac,'active')"
            ),
            {
                "i": connector_id,
                "w": workspace_id,
                "s": f"h-{connector_id.hex[:8]}",
                "ac": json.dumps(auth_config),
            },
        )
        await conn.execute(
            text(
                "INSERT INTO connector_versions (id, workspace_id, connector_id, version,"
                " spec_hash, normalized_schema) VALUES (:i,:w,:c,1,'h',:n)"
            ),
            {"i": version_id, "w": workspace_id, "c": connector_id, "n": json.dumps(normalized)},
        )
        await conn.execute(
            text("UPDATE connectors SET current_version_id=:v WHERE id=:i"),
            {"v": version_id, "i": connector_id},
        )
        for tool in tools:
            await conn.execute(
                text(
                    "INSERT INTO tools (id, workspace_id, connector_id, connector_version_id,"
                    " name, description, input_schema, annotations, enabled, deleted_at)"
                    " VALUES (:i,:w,:c,:v,:n,'op',:s,:a,:e,:d)"
                ),
                {
                    "i": uuid.uuid4(),
                    "w": workspace_id,
                    "c": connector_id,
                    "v": version_id,
                    "n": tool["name"],
                    "s": json.dumps(tool["input_schema"]),
                    "a": json.dumps(tool["annotations"]),
                    "e": tool.get("enabled", True),
                    "d": tool.get("deleted_at"),
                },
            )
        await conn.execute(
            text(
                "INSERT INTO connections (id, workspace_id, connector_id, name, status)"
                " VALUES (:i,:w,:c,:n,:s)"
            ),
            {
                "i": connection_id,
                "w": workspace_id,
                "c": connector_id,
                "n": f"c-{connection_id.hex[-12:]}",
                "s": status,
            },
        )
        if with_credential:
            secret = (
                {"access_token": "M2_7_HEALTH_CANARY_access", "token_type": "Bearer"}
                if credential_type == "oauth2"
                else {"value": "M2_7_HEALTH_CANARY_value"}
            )
            sealed = vault.seal(
                json.dumps(secret).encode(),
                workspace_id=workspace_id,
                connection_id=connection_id,
            )
            credential_id = uuid.uuid4()
            await conn.execute(
                text(
                    "INSERT INTO credentials (id, workspace_id, connection_id, credential_type,"
                    " ciphertext, encrypted_dek, nonce, key_version)"
                    " VALUES (:i,:w,:c,:t,:ct,:d,:n,:kv)"
                ),
                {
                    "i": credential_id,
                    "w": workspace_id,
                    "c": connection_id,
                    "t": credential_type,
                    "ct": sealed.ciphertext,
                    "d": sealed.encrypted_dek,
                    "n": sealed.nonce,
                    "kv": sealed.key_version,
                },
            )
            await conn.execute(
                text("UPDATE connections SET credential_id=:cr WHERE id=:i"),
                {"cr": credential_id, "i": connection_id},
            )
    return {"connector_id": connector_id, "connection_id": connection_id}


def token_headers(workspace: SeededWorkspace) -> dict[str, str]:
    return bearer(workspace.token.plaintext)


async def human_headers(
    engine: AsyncEngine,
    workspace: SeededWorkspace,
    authority: SigningAuthority,
    role: str,
    subject: str,
) -> dict[str, str]:
    await seed_member(engine, workspace.id, user_id=subject, role=role)
    return {**bearer(authority.sign(subject)), WS_HEADER: str(workspace.id)}


async def audit_rows(engine: AsyncEngine, connection_id: uuid.UUID) -> list[tuple[str, object]]:
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT status, created_at FROM tool_calls WHERE connection_id=:c"
                    " ORDER BY created_at"
                ),
                {"c": connection_id},
            )
        ).all()
    return [(r.status, r.created_at) for r in rows]


async def connection_row(engine: AsyncEngine, connection_id: uuid.UUID) -> object:
    async with engine.connect() as conn:
        return (
            await conn.execute(
                text("SELECT status, last_health_check_at FROM connections WHERE id=:i"),
                {"i": connection_id},
            )
        ).one()


# ------------------------------------------------------------------ happy path + audit identity


@pytest.mark.asyncio
async def test_a_healthy_connection_reports_healthy_and_writes_exactly_one_audit_row(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    """The central claim: one health check is one ordinary Tool Call, with one audit row."""
    ids = await seed(admin_engine, workspace_a.id)
    response = await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "healthy"
    assert body["reason"] is None
    assert body["checked_at"] is not None
    assert body["tool_call_id"] is not None

    rows = await audit_rows(admin_engine, ids["connection_id"])
    assert len(rows) == 1, f"expected exactly one audit row, got {rows}"
    assert rows[0][0] == "succeeded"
    # The stamp is the audit row's own instant — that equality is what binds the projection to
    # this specific check rather than to whatever Tool Call ran most recently.
    assert (await connection_row(admin_engine, ids["connection_id"])).last_health_check_at == rows[
        0
    ][1]
    assert len(egress.calls) == 1


@pytest.mark.asyncio
async def test_an_upstream_failure_reports_unhealthy_and_still_stamps_the_check(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    """A failed probe is a *completed* check: the Connection was tested and the answer was bad."""
    ids = await seed(admin_engine, workspace_a.id)
    egress.response = net.GuardedResponse(
        status_code=503, headers=httpx.Headers({}), body=b"upstream on fire", truncated=False
    )
    response = await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "unhealthy"
    assert body["reason"] is not None
    # The provider's body must not travel with the classification.
    assert "upstream on fire" not in response.text
    rows = await audit_rows(admin_engine, ids["connection_id"])
    assert len(rows) == 1
    assert (
        await connection_row(admin_engine, ids["connection_id"])
    ).last_health_check_at is not None


@pytest.mark.asyncio
async def test_a_failed_check_does_not_change_the_connection_lifecycle_status(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    """Health is an observation, not a lifecycle transition. If a probe could move a Connection to
    `error`, anyone holding `tools:execute` could deactivate it by pointing at a flaky endpoint."""
    ids = await seed(admin_engine, workspace_a.id)
    egress.response = net.GuardedResponse(
        status_code=500, headers=httpx.Headers({}), body=b"{}", truncated=False
    )
    await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    assert (await connection_row(admin_engine, ids["connection_id"])).status == "active"


# ------------------------------------------------------------------ safe-Tool selection at the edge


@pytest.mark.parametrize(
    ("label", "inventory"),
    [
        (
            "destructive only",
            [{"name": "delete_it", "annotations": UNSAFE, "input_schema": NO_ARGS}],
        ),
        (
            "readonly but requires arguments",
            [{"name": "get_it", "annotations": SAFE, "input_schema": NEEDS_ARGS}],
        ),
        (
            "unannotated (the DB default)",
            [{"name": "list_it", "annotations": {}, "input_schema": NO_ARGS}],
        ),
        (
            "safe but disabled",
            [
                {
                    "name": "list_it",
                    "annotations": SAFE,
                    "input_schema": NO_ARGS,
                    "enabled": False,
                }
            ],
        ),
    ],
)
@pytest.mark.asyncio
async def test_no_safe_tool_refuses_with_zero_egress(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    label: str,
    inventory: list[dict[str, object]],
) -> None:
    """Fail-closed at the HTTP edge, and — the part that matters — **nothing is sent upstream**.
    A refusal that still made the call would be the exact incident this control exists to stop."""
    ids = await seed(admin_engine, workspace_a.id, tools=inventory)
    response = await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    assert response.status_code == 200, label
    assert response.json()["reason"] == "health_check_unavailable", label
    assert response.json()["status"] == "unknown", label
    assert egress.calls == [], f"{label}: a refused health check performed egress"
    assert await audit_rows(admin_engine, ids["connection_id"]) == []
    assert (await connection_row(admin_engine, ids["connection_id"])).last_health_check_at is None


@pytest.mark.asyncio
async def test_the_safe_tool_is_chosen_over_an_unsafe_one_in_a_mixed_inventory(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    """`aaa_delete` sorts first and must still lose to the only eligible Tool."""
    ids = await seed(
        admin_engine,
        workspace_a.id,
        tools=[
            {"name": "aaa_delete", "annotations": UNSAFE, "input_schema": NO_ARGS},
            {"name": "zzz_list", "annotations": SAFE, "input_schema": NO_ARGS},
        ],
    )
    response = await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    assert response.json()["status"] == "healthy"
    async with admin_engine.connect() as conn:
        executed = (
            await conn.execute(
                text(
                    "SELECT t.name FROM tool_calls tc JOIN tools t ON t.id = tc.tool_id"
                    " WHERE tc.connection_id = :c"
                ),
                {"c": ids["connection_id"]},
            )
        ).scalar_one()
    assert executed == "zzz_list", "a destructive Tool was selected as a health probe"


# ------------------------------------------------------------------ projection on the read model


@pytest.mark.asyncio
async def test_health_appears_on_the_connection_read_model(
    client: AsyncClient,
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
    egress: _Egress,
) -> None:
    """`health` and `needs_reauth` must be real, not permanently-null decoration."""
    http, _ = human_client
    ids = await seed(admin_engine, workspace_a.id)
    reader = await human_headers(
        admin_engine, workspace_a, authority, "owner", f"h-read-{uuid.uuid4().hex[:8]}"
    )
    before = await http.get(f"/v1/connections/{ids['connection_id']}", headers=reader)
    assert before.json()["health"] == "unknown"
    assert before.json()["needs_reauth"] is False
    assert before.json()["last_health_check_at"] is None

    await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    after = await http.get(f"/v1/connections/{ids['connection_id']}", headers=reader)
    assert after.json()["health"] == "healthy"
    assert after.json()["last_health_check_at"] is not None


@pytest.mark.asyncio
async def test_needs_reauth_is_surfaced_for_an_errored_oauth_connection(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
) -> None:
    """The M2.5 D5 contract, finally observable through the API rather than only in a docstring."""
    http, _ = human_client
    ids = await seed(admin_engine, workspace_a.id, status="error", credential_type="oauth2")
    reader = await human_headers(
        admin_engine, workspace_a, authority, "owner", f"h-{uuid.uuid4().hex[:8]}"
    )
    body = (await http.get(f"/v1/connections/{ids['connection_id']}", headers=reader)).json()
    assert body["needs_reauth"] is True
    assert body["health"] == "needs_reauth"


@pytest.mark.asyncio
async def test_an_errored_api_key_connection_does_not_claim_needs_reauth(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
) -> None:
    http, _ = human_client
    ids = await seed(admin_engine, workspace_a.id, status="error", credential_type="api_key")
    reader = await human_headers(
        admin_engine, workspace_a, authority, "owner", f"h-{uuid.uuid4().hex[:8]}"
    )
    body = (await http.get(f"/v1/connections/{ids['connection_id']}", headers=reader)).json()
    assert body["needs_reauth"] is False
    assert body["health"] == "unknown"


@pytest.mark.asyncio
async def test_the_list_endpoint_renders_health_without_an_n_plus_one(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
) -> None:
    """Every listed Connection carries the projection, rendered from one batched query."""
    http, _ = human_client
    for _ in range(3):
        await seed(admin_engine, workspace_a.id)
    reader = await human_headers(
        admin_engine, workspace_a, authority, "owner", f"h-list-{uuid.uuid4().hex[:8]}"
    )
    body = (await http.get("/v1/connections", headers=reader)).json()
    assert len(body["data"]) >= 3
    assert all("health" in row and "needs_reauth" in row for row in body["data"])


# ------------------------------------------------------------------ authorization + tenancy


@pytest.mark.asyncio
async def test_a_machine_token_may_run_a_health_check(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    ids = await seed(admin_engine, workspace_a.id)
    response = await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    assert response.status_code == 200


@pytest.mark.parametrize(("role", "expected"), [("owner", 200), ("admin", 200), ("member", 200)])
@pytest.mark.asyncio
async def test_roles_holding_tools_execute_may_run_a_health_check(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
    egress: _Egress,
    role: str,
    expected: int,
) -> None:
    http, _ = human_client
    ids = await seed(admin_engine, workspace_a.id)
    headers = await human_headers(
        admin_engine, workspace_a, authority, role, f"health-{role}-{uuid.uuid4().hex[:8]}"
    )
    response = await http.post(f"/v1/connections/{ids['connection_id']}/test", headers=headers)
    assert response.status_code == expected, response.text


@pytest.mark.asyncio
async def test_a_viewer_is_denied(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
    egress: _Egress,
) -> None:
    """A health check is authenticated outbound egress with the customer's credential. A role that
    may not execute Tools must not be able to cause one."""
    http, _ = human_client
    ids = await seed(admin_engine, workspace_a.id)
    headers = await human_headers(
        admin_engine, workspace_a, authority, "viewer", f"health-viewer-{uuid.uuid4().hex[:8]}"
    )
    response = await http.post(f"/v1/connections/{ids['connection_id']}/test", headers=headers)
    assert response.status_code == 403
    assert egress.calls == []


@pytest.mark.asyncio
async def test_unauthenticated_is_refused(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    ids = await seed(admin_engine, workspace_a.id)
    response = await client.post(f"/v1/connections/{ids['connection_id']}/test")
    assert response.status_code == 401
    assert egress.calls == []


@pytest.mark.asyncio
async def test_a_foreign_connection_is_an_indistinguishable_404(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    egress: _Egress,
) -> None:
    """Workspace B's token must not be able to probe Workspace A's Connection — and must not learn
    that it exists. The 404 is byte-identical to a random id's."""
    ids = await seed(admin_engine, workspace_a.id)
    foreign = await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_b)
    )
    missing = await client.post(
        f"/v1/connections/{uuid.uuid4()}/test", headers=token_headers(workspace_b)
    )
    assert foreign.status_code == 404
    assert foreign.json()["error"]["code"] == missing.json()["error"]["code"]
    assert foreign.json()["error"]["message"] == missing.json()["error"]["message"]
    assert egress.calls == [], "a cross-tenant probe reached the network"
    assert await audit_rows(admin_engine, ids["connection_id"]) == []


@pytest.mark.asyncio
async def test_a_revoked_connection_cannot_be_probed(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    ids = await seed(admin_engine, workspace_a.id)
    async with admin_engine.begin() as conn:
        await conn.execute(
            text("UPDATE connections SET deleted_at=now(), status='revoked' WHERE id=:i"),
            {"i": ids["connection_id"]},
        )
    response = await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    assert response.status_code == 404
    assert egress.calls == []


# ------------------------------------------------------------------ kill switch


@pytest.mark.asyncio
async def test_the_feature_flag_refuses_before_any_work(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Disabled must mean *nothing happens*: no execution, no egress, no audit row, no stamp."""
    ids = await seed(admin_engine, workspace_a.id)
    monkeypatch.setattr(settings, "connection_health_enabled", False)
    response = await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    assert response.status_code == 409
    assert egress.calls == []
    assert await audit_rows(admin_engine, ids["connection_id"]) == []
    assert (await connection_row(admin_engine, ids["connection_id"])).last_health_check_at is None


@pytest.mark.asyncio
async def test_the_flag_enabled_path_still_works(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both flag states are exercised, so the ON path cannot rot while only OFF is tested."""
    ids = await seed(admin_engine, workspace_a.id)
    monkeypatch.setattr(settings, "connection_health_enabled", True)
    response = await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


# ------------------------------------------------------------------ secret containment


@pytest.mark.asyncio
async def test_no_credential_material_reaches_the_response_or_the_audit_row(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    """The canary is sealed into the credential and must appear only at the egress boundary."""
    ids = await seed(admin_engine, workspace_a.id)
    response = await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    assert "M2_7_HEALTH_CANARY_value" not in response.text
    async with admin_engine.connect() as conn:
        dumped = (
            await conn.execute(
                text("SELECT tc::text FROM tool_calls tc WHERE tc.connection_id=:c"),
                {"c": ids["connection_id"]},
            )
        ).scalar_one()
    assert "M2_7_HEALTH_CANARY_value" not in dumped


# ============================================ gaps found by the M2.7 mutation audit
#
# Each test below exists because a mutation survived the first-pass suite. They are written to
# isolate one control apiece, so removing that control — and nothing else — turns them red.


@pytest.mark.asyncio
async def test_the_failure_reason_is_a_canonical_code_not_a_prose_message(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    """`reason` is a contract field callers switch on, so it must be a stable enumerated token.

    The first-pass suite only checked that the provider's *body* did not leak, which a mutation
    swapping `error.code` for `error.message` sailed through: our own message happens to be
    harmless prose today. But prose is not a contract — it changes with copy edits, and for other
    error classes it carries interpolated detail. Pinning the closed vocabulary is what makes the
    field safe to depend on and safe to render.
    """
    from app.core.exceptions import DomainError

    ids = await seed(admin_engine, workspace_a.id)
    egress.response = net.GuardedResponse(
        status_code=502, headers=httpx.Headers({}), body=b"{}", truncated=False
    )
    body = (
        await client.post(
            f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
        )
    ).json()

    known_codes = {
        cls.code
        for cls in DomainError.__subclasses__()
        if isinstance(getattr(cls, "code", None), str)
    }
    assert body["reason"] in known_codes, (
        f"{body['reason']!r} is not one of the canonical DomainError codes {sorted(known_codes)}"
    )
    assert " " not in body["reason"], "reason must be a token, not a sentence"


@pytest.mark.asyncio
async def test_ordinary_tool_call_traffic_does_not_change_the_health_projection(
    client: AsyncClient,
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
    egress: _Egress,
) -> None:
    """Health reports what the last **health check** found — not the last Tool Call.

    This is the whole reason `last_health_check_at` is stamped from the audit row's own timestamp
    and joined on equality. Without that binding, any failing Tool Call on the Connection would
    silently flip the dashboard to `unhealthy`, and a passing one could mask a genuinely broken
    Connection. A mutation dropping the timestamp predicate survived until this existed.
    """
    http, _ = human_client
    ids = await seed(admin_engine, workspace_a.id)
    reader = await human_headers(
        admin_engine, workspace_a, authority, "owner", f"h-mix-{uuid.uuid4().hex[:8]}"
    )

    # 1. A health check succeeds.
    await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    assert (await http.get(f"/v1/connections/{ids['connection_id']}", headers=reader)).json()[
        "health"
    ] == "healthy"

    # 2. An ordinary Tool Call against the same Connection then fails, writing a later audit row.
    egress.response = net.GuardedResponse(
        status_code=500, headers=httpx.Headers({}), body=b"{}", truncated=False
    )
    call = await client.post(
        "/v1/tool-calls",
        headers=token_headers(workspace_a),
        json={"tool_name": "list_items", "connection_id": str(ids["connection_id"])},
    )
    assert call.status_code >= 400, "the ordinary Tool Call was supposed to fail"
    rows = await audit_rows(admin_engine, ids["connection_id"])
    assert len(rows) == 2, "expected a health check row and a later ordinary Tool Call row"

    # 3. Health is unchanged: the newer failure was not a health check.
    assert (await http.get(f"/v1/connections/{ids['connection_id']}", headers=reader)).json()[
        "health"
    ] == "healthy"


@pytest.mark.asyncio
async def test_probe_candidate_scoping_holds_without_rls_and_without_the_domain_filter(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    """Isolates the repository's own predicates from the two layers that currently mask them.

    Two mutations survived the first-pass suite here, for two different reasons:

    - dropping `Tool.workspace_id == ...` changed nothing, because **RLS** blocked the foreign row
      anyway. So this runs on an RLS-exempt connection, leaving the repository predicate as the
      only thing standing (P-14: two controls are two controls only if each is tested alone).
    - dropping `enabled` / `deleted_at` changed nothing, because `is_probe_eligible` re-checks
      both. That redundancy is deliberate defense in depth — but a defense nobody tests is a
      defense nobody knows is gone, so the SQL filter is asserted here directly.
    """
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.core.security import CallerIdentity, WorkspaceContext
    from app.domains.connections.repository import ConnectionRepository

    ids_b = await seed(
        admin_engine,
        workspace_b.id,
        tools=[
            {"name": "b_visible", "annotations": SAFE, "input_schema": NO_ARGS},
            {"name": "b_disabled", "annotations": SAFE, "input_schema": NO_ARGS, "enabled": False},
            {
                "name": "b_deleted",
                "annotations": SAFE,
                "input_schema": NO_ARGS,
                "deleted_at": datetime(2026, 1, 1, tzinfo=UTC),
            },
        ],
    )

    def context(workspace_id: uuid.UUID) -> WorkspaceContext:
        return WorkspaceContext(
            workspace_id=workspace_id,
            caller=CallerIdentity(kind="api_token", api_token_id=None),
            request_id="m27-audit",
        )

    async with AsyncSession(admin_engine) as session:
        # Premise: this connection really can see workspace B's rows, or the cross-tenant
        # assertion below would pass for the wrong reason.
        visible = (
            await session.execute(
                text("SELECT count(*) FROM tools WHERE connector_id = :c"),
                {"c": ids_b["connector_id"]},
            )
        ).scalar_one()
        assert visible == 3, "premise failed: the admin connection is subject to RLS here"

        # Cross-tenant: workspace A's repository must not see workspace B's Tools.
        foreign = await ConnectionRepository(session, context(workspace_a.id)).probe_candidates(
            ids_b["connector_id"]
        )
        assert foreign == [], "repository returned another workspace's Tools"

        # Same-tenant: the disabled and soft-deleted Tools are excluded by SQL alone.
        own = await ConnectionRepository(session, context(workspace_b.id)).probe_candidates(
            ids_b["connector_id"]
        )
        assert [tool.name for tool in own] == ["b_visible"]


# ==================================== second-pass: the health path inherits Runtime controls
#
# The architectural claim is that a health check is an ordinary Tool Call. That is only worth
# anything if the Runtime's protections actually apply *through this door* — so each is exercised
# here at the health endpoint rather than assumed from the Tool Call suite.


@pytest.mark.asyncio
async def test_an_oauth_connection_is_probed_through_the_existing_injection_path(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    """No second OAuth path: the bearer comes from M2.5's single injection branch, and the token
    itself must never appear in the response."""
    ids = await seed(admin_engine, workspace_a.id, credential_type="oauth2")
    response = await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert "M2_7_HEALTH_CANARY_access" not in response.text


@pytest.mark.asyncio
async def test_ssrf_refusal_propagates_through_the_health_path(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    """The health endpoint must not have its own egress policy. An SSRF refusal raised by the one
    guarded client becomes an ordinary unhealthy classification — never a 500, never a bypass."""
    ids = await seed(admin_engine, workspace_a.id)
    egress.exc = net.SSRFError("blocked-private")
    response = await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    assert response.status_code == 200
    assert response.json()["status"] == "unhealthy"
    assert "blocked-private" not in response.text, "the egress internal detail leaked"


@pytest.mark.asyncio
async def test_an_upstream_timeout_is_classified_not_raised(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    ids = await seed(admin_engine, workspace_a.id)
    egress.exc = httpx.TimeoutException("read timeout")
    response = await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    assert response.status_code == 200
    assert response.json()["status"] == "unhealthy"
    rows = await audit_rows(admin_engine, ids["connection_id"])
    assert [r[0] for r in rows] == ["timeout"], "the Runtime's timeout taxonomy was not used"


@pytest.mark.asyncio
async def test_a_redis_outage_fails_closed_with_zero_egress(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M2.4's fail-closed rule must hold here too. If health could execute while the limiter is
    blind, the endpoint would be an un-metered egress path exactly when the platform is degraded —
    the most attractive moment to abuse it."""
    ids = await seed(admin_engine, workspace_a.id)

    class _Down:
        async def __aenter__(self) -> object:
            raise ConnectionError("redis is down")

        async def __aexit__(self, *_: object) -> bool:
            return False

    # Patched where `limits` *uses* it — patching `app.core.redis.redis_client` would not rebind
    # the name the module already imported, and the test would silently exercise a live Redis.
    monkeypatch.setattr("app.domains.runtime.limits.redis_client", lambda: _Down())
    response = await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    # Fail-closed, and — the audit finding — reported as `unknown`, not `unhealthy`: the platform
    # refused before the Connection was evaluated, so it is not evidence the Connection is broken.
    assert response.json()["status"] == "unknown", response.text
    assert egress.calls == [], "health reached the network while the rate limiter was unavailable"


@pytest.mark.asyncio
async def test_rate_limit_denial_stops_the_probe_before_egress(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Health consumes the ordinary Tool Call budget — it is not exempt, and a denial is an
    audited `denied` outcome with nothing sent upstream."""
    from app.core.exceptions import RateLimitedError

    ids = await seed(admin_engine, workspace_a.id)

    async def _denied(**_: object) -> None:
        raise RateLimitedError("Rate limit exceeded for this workspace.")

    monkeypatch.setattr("app.domains.runtime.service.enforce_tool_call_limits", _denied)
    response = await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    assert response.status_code == 200
    # `unknown`, not `unhealthy`: the Connection was never reached. The denial is still audited —
    # the Runtime owns that record — it simply is not a health verdict.
    assert response.json()["status"] == "unknown"
    assert response.json()["reason"] == "rate_limited"
    assert egress.calls == [], "a rate-limited health check still called the provider"
    rows = await audit_rows(admin_engine, ids["connection_id"])
    assert [r[0] for r in rows] == ["denied"]


@pytest.mark.asyncio
async def test_a_platform_denial_does_not_overwrite_a_known_good_health_verdict(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    egress: _Egress,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression for the defect the release audit found (ADR-0040 §5).

    A Workspace exhausting its weekly quota — or a Redis outage failing closed down the same path —
    used to flip **every** Connection to `unhealthy` and overwrite its `last_health_check_at`,
    even though nothing about the Connection had changed and no request reached the provider. The
    bad verdict then outlived the incident, because only a fresh successful check could clear it.

    A stage-3 policy refusal must therefore leave the previous verdict and its timestamp exactly
    as they were.
    """
    from app.core.exceptions import QuotaExceededError

    ids = await seed(admin_engine, workspace_a.id)
    await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    good_stamp = (await connection_row(admin_engine, ids["connection_id"])).last_health_check_at
    assert good_stamp is not None

    async def _quota(**_: object) -> None:
        raise QuotaExceededError("The workspace's weekly Tool Call quota is exhausted.")

    monkeypatch.setattr("app.domains.runtime.service.enforce_tool_call_limits", _quota)
    denied = await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )

    assert denied.json()["status"] == "unknown"
    assert denied.json()["reason"] == "quota_exceeded"
    assert denied.json()["checked_at"] is None, "a refusal must not claim a check time"
    after = (await connection_row(admin_engine, ids["connection_id"])).last_health_check_at
    assert after == good_stamp, "a platform denial overwrote a known-good health timestamp"
    # The denial is still audited — audit integrity is the Runtime's, and it is unchanged.
    assert [r[0] for r in await audit_rows(admin_engine, ids["connection_id"])] == [
        "succeeded",
        "denied",
    ]


# ============================== release-audit additions: the REAL egress guard, not a fake
#
# The suite above fakes `net.request` and raises `SSRFError` from it, which proves the endpoint
# *handles* a refusal but not that a refusal actually happens. These tests use the genuine
# `core/net` stack — no monkeypatch on egress at all — so the DNS resolution, IP classification and
# refusal are the real implementation. If the health path ever grew its own HTTP client, or reached
# the network before validation, these are the tests that would notice.


@pytest.mark.parametrize(
    ("label", "base_url"),
    [
        ("loopback", "https://127.0.0.1"),
        ("ipv6 loopback", "https://[::1]"),
        ("cloud metadata", "https://169.254.169.254"),
        ("RFC1918", "https://10.0.0.1"),
        ("link-local", "https://169.254.1.1"),
    ],
)
@pytest.mark.asyncio
async def test_the_real_ssrf_guard_refuses_private_targets_through_the_health_path(
    client: AsyncClient,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    label: str,
    base_url: str,
) -> None:
    """No egress monkeypatch — the actual guarded client validates and refuses."""
    ids = await seed(admin_engine, workspace_a.id)
    async with admin_engine.begin() as conn:
        await conn.execute(
            text("UPDATE connectors SET base_url=:u WHERE id=:i"),
            {"u": base_url, "i": ids["connector_id"]},
        )
    response = await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    assert response.status_code == 200, label
    body = response.json()
    assert body["status"] == "unhealthy", f"{label}: a private target was not refused"
    assert body["reason"] == "ssrf_blocked", f"{label}: got {body['reason']}"
    # The refusal must not disclose what was resolved or attempted.
    for leak in ("127.0.0.1", "169.254", "10.0.0.1", "::1", "blocked-", "resolve"):
        assert leak not in response.text, f"{label}: response leaked {leak!r}"
    # A refused egress is a Connection fact, so it *is* a completed health check.
    assert [r[0] for r in await audit_rows(admin_engine, ids["connection_id"])] == ["denied"]
    assert (
        await connection_row(admin_engine, ids["connection_id"])
    ).last_health_check_at is not None


@pytest.mark.asyncio
async def test_an_unresolvable_host_is_refused_by_the_real_guard(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    ids = await seed(admin_engine, workspace_a.id)
    async with admin_engine.begin() as conn:
        await conn.execute(
            text("UPDATE connectors SET base_url=:u WHERE id=:i"),
            {"u": f"https://{uuid.uuid4().hex}.invalid", "i": ids["connector_id"]},
        )
    body = (
        await client.post(
            f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
        )
    ).json()
    assert body["status"] == "unhealthy"
    assert body["reason"] == "ssrf_blocked"
    assert ".invalid" not in json.dumps(body)


@pytest.mark.asyncio
async def test_concurrent_health_checks_each_produce_their_own_audited_outcome(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    """Concurrency semantics, asserted rather than assumed.

    No canonical source requires health checks to serialize, and none is invented here: a health
    check is an ordinary Tool Call, and concurrent Tool Calls are normal and already bounded by the
    M2.4 rate limiter. What must hold is that concurrency stays *coherent* — every invocation is
    independently audited, and the Connection ends on a real verdict with a timestamp that matches
    one of the rows actually written, never a blend of two.
    """
    import asyncio

    ids = await seed(admin_engine, workspace_a.id)
    responses = await asyncio.gather(
        *(
            client.post(
                f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
            )
            for _ in range(8)
        )
    )
    assert all(r.status_code == 200 for r in responses)
    assert all(r.json()["status"] == "healthy" for r in responses)

    rows = await audit_rows(admin_engine, ids["connection_id"])
    assert len(rows) == 8, f"expected one audit row per invocation, got {len(rows)}"
    assert len(egress.calls) == 8

    stamp = (await connection_row(admin_engine, ids["connection_id"])).last_health_check_at
    assert stamp in {created_at for _, created_at in rows}, (
        "the stored timestamp does not correspond to any audit row actually written"
    )


@pytest.mark.asyncio
async def test_an_identical_request_replayed_is_a_fresh_independent_check(
    client: AsyncClient, admin_engine: AsyncEngine, workspace_a: SeededWorkspace, egress: _Egress
) -> None:
    """Replay is not deduplicated, and should not be: a health check is a point-in-time probe, so
    asking twice must genuinely ask twice. Each replay is separately audited."""
    ids = await seed(admin_engine, workspace_a.id)
    first = await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    second = await client.post(
        f"/v1/connections/{ids['connection_id']}/test", headers=token_headers(workspace_a)
    )
    assert first.json()["tool_call_id"] != second.json()["tool_call_id"]
    assert len(await audit_rows(admin_engine, ids["connection_id"])) == 2
    assert len(egress.calls) == 2
