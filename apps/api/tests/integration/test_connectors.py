"""Connectors domain, end to end through the real application (M1.4-A, ADR-0003).

Real HTTP against the real app, real Postgres with RLS armed, the real centralized RBAC. The
only double is the JWKS endpoint (so human JWTs can be minted for arbitrary subjects). Nothing
about authorization, tenant isolation, the SSRF lint, or soft-delete is mocked.

The invariant under test: a Connector is a tenant-owned definition managed only by
`connectors:manage` (owner/admin); `source_type`/`status`/`workspace_id` are server-established;
`base_url` is SSRF-linted before storage; a foreign or soft-deleted connector is a uniform 404.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from app.core.exceptions import ValidationFailedError
from app.core.security import CallerIdentity, WorkspaceContext
from app.domains.connectors.repository import ConnectorRepository
from app.domains.connectors.service import validate_base_url
from tests.conftest import FakeJWKSEndpoint, SeededWorkspace, SigningAuthority, bearer
from tests.integration.test_human_auth import seed_member

WS_HEADER = "X-Workspace-Id"
GOOD_URL = "https://api.example.com/v1"


def hx(token: str, workspace_id: uuid.UUID) -> dict[str, str]:
    return {**bearer(token), WS_HEADER: str(workspace_id)}


@pytest.fixture
async def admin_ctx(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> AsyncIterator[dict[str, object]]:
    """An owner of workspace A who can manage connectors."""
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="conn-owner", role="owner")
    yield {"client": client, "ws": workspace_a.id, "token": authority.sign("conn-owner")}


async def make_connector(
    ctx: dict[str, object], *, name: str = "Example API", base_url: str = GOOD_URL, **extra: object
) -> dict[str, object]:
    client: AsyncClient = ctx["client"]  # type: ignore[assignment]
    body: dict[str, object] = {"name": name, "base_url": base_url, **extra}
    response = await client.post(
        "/v1/connectors",
        headers=hx(ctx["token"], ctx["ws"]),
        json=body,  # type: ignore[arg-type]
    )
    assert response.status_code == 201, response.text
    return response.json()


# ---------------------------------------------------------------------------------------
# Authorization (connectors:manage → owner/admin)
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role", "expected"), [("owner", 201), ("admin", 201), ("member", 403), ("viewer", 403)]
)
async def test_only_connectors_manage_may_create(
    role: str,
    expected: int,
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id=f"c-{role}", role=role)
    r = await client.post(
        "/v1/connectors",
        headers=hx(authority.sign(f"c-{role}"), workspace_a.id),
        json={"name": "X", "base_url": GOOD_URL},
    )
    assert r.status_code == expected


async def test_machine_token_cannot_manage_connectors(
    client: AsyncClient, workspace_a: SeededWorkspace
) -> None:
    """A machine token resolves to no membership (ADR-0002), so every connector op denies."""
    creds = {
        "Authorization": f"Bearer {workspace_a.token.plaintext}",
        WS_HEADER: str(workspace_a.id),
    }
    assert (
        await client.post("/v1/connectors", headers=creds, json={"name": "X", "base_url": GOOD_URL})
    ).status_code == 403
    assert (await client.get("/v1/connectors", headers=creds)).status_code == 403
    assert (await client.get(f"/v1/connectors/{uuid.uuid4()}", headers=creds)).status_code == 403
    assert (await client.delete(f"/v1/connectors/{uuid.uuid4()}", headers=creds)).status_code == 403


# ---------------------------------------------------------------------------------------
# Creation contract
# ---------------------------------------------------------------------------------------


async def test_creation_sets_server_fields_and_derives_slug(admin_ctx: dict[str, object]) -> None:
    body = await make_connector(admin_ctx, name="My Cool API")
    assert body["source_type"] == "manual", "source_type is server-set, not client-chosen"
    assert body["status"] == "draft"
    assert body["slug"] == "my-cool-api", "slug derived from the name"
    assert body["base_url"] == GOOD_URL
    assert "workspace_id" not in body, "the tenant key is never serialized"
    assert uuid.UUID(body["id"])


async def test_an_explicit_slug_is_honored(admin_ctx: dict[str, object]) -> None:
    body = await make_connector(admin_ctx, name="Whatever", slug="custom-slug")
    assert body["slug"] == "custom-slug"


async def test_server_owned_and_unknown_fields_are_refused(admin_ctx: dict[str, object]) -> None:
    client: AsyncClient = admin_ctx["client"]  # type: ignore[assignment]
    headers = hx(admin_ctx["token"], admin_ctx["ws"])  # type: ignore[arg-type]
    for bad in (
        {"name": "X", "base_url": GOOD_URL, "source_type": "openapi3"},  # server-owned
        {"name": "X", "base_url": GOOD_URL, "status": "active"},  # server-owned
        {"name": "X", "base_url": GOOD_URL, "workspace_id": str(uuid.uuid4())},  # tenant key
        {"name": "X", "base_url": GOOD_URL, "id": str(uuid.uuid4())},  # server-owned
    ):
        r = await client.post("/v1/connectors", headers=headers, json=bad)
        assert r.status_code == 400, f"{bad} should be rejected: {r.text}"


async def test_a_blank_name_or_bad_slug_is_rejected(admin_ctx: dict[str, object]) -> None:
    client: AsyncClient = admin_ctx["client"]  # type: ignore[assignment]
    headers = hx(admin_ctx["token"], admin_ctx["ws"])  # type: ignore[arg-type]
    for bad in (
        {"name": "   ", "base_url": GOOD_URL},  # blank after strip
        {"name": "X", "base_url": GOOD_URL, "slug": "Not A Slug"},  # spaces
        {"name": "X", "base_url": GOOD_URL, "slug": "under_score"},  # underscore not allowed
        {"name": "X", "base_url": GOOD_URL, "slug": "bad!char"},  # symbol
    ):
        assert (await client.post("/v1/connectors", headers=headers, json=bad)).status_code == 400


async def test_a_mixed_case_slug_is_normalized_to_lowercase(admin_ctx: dict[str, object]) -> None:
    """A slug is normalized (lower-cased) rather than rejected — user-friendly and consistent
    with the stored form, so `MixedCase` becomes `mixedcase`."""
    body = await make_connector(admin_ctx, name="Z", slug="MixedCase")
    assert body["slug"] == "mixedcase"


# ---------------------------------------------------------------------------------------
# SSRF lint on base_url (CONNECTOR_SPECIFICATION §11, SECURITY §6) — through HTTP and direct
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://api.example.com",  # not https
        "https://localhost/api",
        "https://127.0.0.1/api",  # loopback
        "https://10.0.0.5/api",  # RFC1918
        "https://192.168.1.1/api",  # RFC1918
        "https://172.16.0.1/api",  # RFC1918
        "https://169.254.169.254/latest/meta-data",  # link-local / cloud metadata
        "https://[::1]/api",  # IPv6 loopback
        "https://user:pass@api.example.com/api",  # embedded credentials
        "https://internal.local/api",  # .local mDNS
        "not-a-url",
    ],
)
async def test_base_url_ssrf_lint_rejects(admin_ctx: dict[str, object], bad_url: str) -> None:
    client: AsyncClient = admin_ctx["client"]  # type: ignore[assignment]
    r = await client.post(
        "/v1/connectors",
        headers=hx(admin_ctx["token"], admin_ctx["ws"]),  # type: ignore[arg-type]
        json={"name": "X", "base_url": bad_url},
    )
    assert r.status_code == 400, f"{bad_url} must be refused"


def test_validate_base_url_directly() -> None:
    """The SSRF lint lives in the service so non-HTTP callers are guarded too (BACKEND_SPEC §2)."""
    assert validate_base_url("https://api.example.com/v1") == "https://api.example.com/v1"
    for bad in (
        "http://api.example.com",
        "https://localhost",
        "https://127.0.0.1",
        "https://10.1.2.3",
        "https://169.254.169.254",
        "https://user:pass@host.example.com",
        "ftp://api.example.com",
    ):
        with pytest.raises(ValidationFailedError):
            validate_base_url(bad)


# ---------------------------------------------------------------------------------------
# Slug uniqueness + soft delete
# ---------------------------------------------------------------------------------------


async def test_duplicate_live_slug_is_conflict(admin_ctx: dict[str, object]) -> None:
    await make_connector(admin_ctx, name="Dup", slug="dup")
    client: AsyncClient = admin_ctx["client"]  # type: ignore[assignment]
    r = await client.post(
        "/v1/connectors",
        headers=hx(admin_ctx["token"], admin_ctx["ws"]),  # type: ignore[arg-type]
        json={"name": "Dup2", "base_url": GOOD_URL, "slug": "dup"},
    )
    assert r.status_code == 409


async def test_soft_delete_hides_the_connector_and_frees_the_slug(
    admin_ctx: dict[str, object],
) -> None:
    body = await make_connector(admin_ctx, name="Temp", slug="temp")
    client: AsyncClient = admin_ctx["client"]  # type: ignore[assignment]
    headers = hx(admin_ctx["token"], admin_ctx["ws"])  # type: ignore[arg-type]

    assert (await client.delete(f"/v1/connectors/{body['id']}", headers=headers)).status_code == 204
    # Gone: get is 404, list excludes it, a second delete is a uniform 404.
    assert (await client.get(f"/v1/connectors/{body['id']}", headers=headers)).status_code == 404
    listing = (await client.get("/v1/connectors", headers=headers)).json()
    assert all(c["id"] != body["id"] for c in listing["data"])
    assert (await client.delete(f"/v1/connectors/{body['id']}", headers=headers)).status_code == 404
    # The freed slug can be reused by a new live connector.
    reused = await make_connector(admin_ctx, name="Temp Again", slug="temp")
    assert reused["slug"] == "temp" and reused["id"] != body["id"]


# ---------------------------------------------------------------------------------------
# Listing + pagination
# ---------------------------------------------------------------------------------------


async def test_list_paginates_and_rejects_unknown_params(admin_ctx: dict[str, object]) -> None:
    for i in range(3):
        await make_connector(admin_ctx, name=f"C{i}", slug=f"c-{i}")
    client: AsyncClient = admin_ctx["client"]  # type: ignore[assignment]
    headers = hx(admin_ctx["token"], admin_ctx["ws"])  # type: ignore[arg-type]

    page = (await client.get("/v1/connectors?limit=2", headers=headers)).json()
    assert len(page["data"]) == 2 and page["has_more"] is True and page["next_cursor"]
    nxt = (
        await client.get(f"/v1/connectors?limit=2&cursor={page['next_cursor']}", headers=headers)
    ).json()
    assert len(nxt["data"]) >= 1
    # Unknown query param and a malformed cursor are both 400 (never a silent full page).
    assert (await client.get("/v1/connectors?revoked=false", headers=headers)).status_code == 400
    assert (await client.get("/v1/connectors?cursor=@@bad@@", headers=headers)).status_code == 400


# ---------------------------------------------------------------------------------------
# Cross-tenant isolation (RLS active) + RLS-independent repository predicate
# ---------------------------------------------------------------------------------------


async def test_cross_tenant_isolation(
    admin_ctx: dict[str, object],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_b: SeededWorkspace,
) -> None:
    a_body = await make_connector(admin_ctx, name="A side", slug="a-side")
    await seed_member(admin_engine, workspace_b.id, user_id="b-owner", role="owner")
    client: AsyncClient = admin_ctx["client"]  # type: ignore[assignment]
    b_creds = hx(authority.sign("b-owner"), workspace_b.id)

    # B cannot see A's connector in its list, cannot GET it, cannot DELETE it — all uniform 404.
    b_list = (await client.get("/v1/connectors", headers=b_creds)).json()
    assert all(c["id"] != a_body["id"] for c in b_list["data"])
    assert (await client.get(f"/v1/connectors/{a_body['id']}", headers=b_creds)).status_code == 404
    assert (
        await client.delete(f"/v1/connectors/{a_body['id']}", headers=b_creds)
    ).status_code == 404


async def test_repository_workspace_predicate_holds_without_rls(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
) -> None:
    """On an RLS-EXEMPT (superuser) connection, an A-scoped repository still cannot get or
    delete a B connector — proving the application's own `workspace_id` predicate is correct,
    not that RLS happened to hide the row (directive: RLS active AND bypassed)."""
    b_id = uuid.uuid4()
    async with admin_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO connectors (id, workspace_id, name, slug, source_type, base_url, "
                "status) VALUES (:i, :w, 'B', 'b-conn', 'manual', :u, 'draft')"
            ),
            {"i": b_id, "w": workspace_b.id, "u": GOOD_URL},
        )
    ctx_a = WorkspaceContext(
        workspace_id=workspace_a.id,
        caller=CallerIdentity(kind="member", member_id=None),
        request_id="req_test",
    )
    session = async_sessionmaker(admin_engine, expire_on_commit=False)()
    try:
        async with session.begin():
            visible = await session.scalar(
                text("SELECT count(*) FROM connectors WHERE id = :i"), {"i": b_id}
            )
            assert visible == 1, "expected an RLS-exempt connection for this test"
            repo = ConnectorRepository(session, ctx_a)
            assert await repo.get(b_id) is None, "A must not read B's connector"
            assert await repo.soft_delete(b_id) is False, "A must not delete B's connector"
    finally:
        await session.close()

    async with admin_engine.connect() as conn:
        deleted = await conn.scalar(
            text("SELECT deleted_at FROM connectors WHERE id = :i"), {"i": b_id}
        )
    assert deleted is None, "B's connector must be untouched"
