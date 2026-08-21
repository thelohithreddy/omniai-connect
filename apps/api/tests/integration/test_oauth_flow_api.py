"""OAuth 2.0 authorization-code flow end to end (M2.5, ADR-0038).

Real HTTP through the real ASGI app, real Postgres + RLS (including the SECURITY DEFINER consume),
real vault sealing, real connection lifecycle events. The only mocked boundary is the outermost
socket, where a deterministic RFC-conformant fake provider stands in (D4).

Covers the mandated adversarial matrix: state (wrong / replayed / expired / cross-tenant /
concurrent), PKCE (mismatch, downgrade), redirect binding, provider failures (4xx, 5xx, malformed,
missing token, unsupported type), SSRF on the token endpoint, secret-leak canaries, and the
credential/connection outcomes.
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
from app.core.config import settings
from app.domains.oauth.state import hash_state
from tests.conftest import FakeJWKSEndpoint, SeededWorkspace, SigningAuthority, bearer
from tests.integration.fake_oauth_provider import FakeOAuthProvider
from tests.integration.test_human_auth import seed_member

WS_HEADER = "X-Workspace-Id"
CANARY_ACCESS_TOKEN = "M2_5_OAUTH_CANARY_access_do_not_leak"  # noqa: S105 (synthetic test secret)

AUTH_CONFIG = {
    "type": "oauth2",
    "grant": "authorization_code",
    "authorization_url": "https://provider.example.com/authorize",
    "token_url": "https://provider.example.com/token",
    "scopes": ["read", "write"],
    "client_id": "test-client",
}


@pytest.fixture
def fake_provider(monkeypatch: pytest.MonkeyPatch) -> FakeOAuthProvider:
    """Stand in at the guarded-egress seam — the one boundary the testing standard allows."""
    provider = FakeOAuthProvider(access_token_value=CANARY_ACCESS_TOKEN)
    monkeypatch.setattr("app.core.net.request", provider)
    return provider


@pytest.fixture
async def owner(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> dict[str, Any]:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="oauth-owner", role="owner")
    return {
        "client": client,
        "ws": workspace_a.id,
        "headers": {
            **bearer(authority.sign("oauth-owner")),
            WS_HEADER: str(workspace_a.id),
        },
    }


async def _seed_oauth_connection(
    engine: AsyncEngine, workspace_id: uuid.UUID, *, auth_config: dict[str, Any] | None = None
) -> uuid.UUID:
    """A `pending_auth` Connection on an oauth2 Connector, seeded as superuser (bypassing RLS)."""
    connector_id, connection_id = uuid.uuid4(), uuid.uuid4()
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
                "s": f"p-{connector_id.hex[:8]}",
                "a": json.dumps(auth_config if auth_config is not None else AUTH_CONFIG),
            },
        )
        await conn.execute(
            text(
                "INSERT INTO connections (id, workspace_id, connector_id, name, status)"
                " VALUES (:i,:w,:c,:n,'pending_auth')"
            ),
            {
                "i": connection_id,
                "w": workspace_id,
                "c": connector_id,
                "n": f"c-{connection_id.hex[-12:]}",
            },
        )
    return connection_id


async def _start(owner: dict[str, Any], connection_id: uuid.UUID) -> dict[str, Any]:
    client: AsyncClient = owner["client"]
    resp = await client.post(
        f"/v1/connections/{connection_id}/oauth/authorize", headers=owner["headers"]
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _callback(client: AsyncClient, *, code: str, state: str) -> Any:
    return await client.get("/v1/oauth/callback", params={"code": code, "state": state})


async def _connection_row(engine: AsyncEngine, connection_id: uuid.UUID) -> Any:
    async with engine.begin() as conn:
        return (
            await conn.execute(
                text(
                    "SELECT c.status, c.credential_id, cr.credential_type, cr.expires_at"
                    " FROM connections c LEFT JOIN credentials cr ON cr.connection_id = c.id"
                    " WHERE c.id = :i"
                ),
                {"i": connection_id},
            )
        ).first()


# ------------------------------------------------------------------------------- happy path


async def test_full_flow_activates_the_connection_and_seals_tokens(
    owner: dict[str, Any],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    fake_provider: FakeOAuthProvider,
) -> None:
    connection_id = await _seed_oauth_connection(admin_engine, workspace_a.id)
    start = await _start(owner, connection_id)

    # The authorize response carries the URL and expiry — and no flow secrets of its own.
    assert set(start) == {"authorize_url", "expires_at"}
    assert "code_challenge_method=S256" in start["authorize_url"]
    assert "code_verifier" not in start["authorize_url"]

    code = fake_provider.issue_code(start["authorize_url"])
    state = FakeOAuthProvider.state_from(start["authorize_url"])
    resp = await _callback(owner["client"], code=code, state=state)
    assert resp.status_code == 200
    assert resp.headers["Cache-Control"] == "no-store"
    assert CANARY_ACCESS_TOKEN not in resp.text  # never echoed to the browser

    row = await _connection_row(admin_engine, connection_id)
    assert row.status == "active"
    assert row.credential_id is not None
    assert row.credential_type == "oauth2"
    assert row.expires_at is not None and row.expires_at > datetime.now(UTC)

    # The exchange presented a verifier and the stored redirect URI — never a client-supplied one.
    grant, form = fake_provider.exchanges[-1]
    assert grant == "authorization_code"
    assert form["code_verifier"] and form["redirect_uri"] == settings.oauth_redirect_uri

    # Nothing plaintext at rest: the ciphertext column must not contain the token.
    async with admin_engine.begin() as conn:
        ciphertext = (
            await conn.execute(
                text("SELECT ciphertext FROM credentials WHERE connection_id=:i"),
                {"i": connection_id},
            )
        ).scalar()
    assert CANARY_ACCESS_TOKEN.encode() not in bytes(ciphertext)


async def test_state_is_never_persisted_in_the_clear(
    owner: dict[str, Any], admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    connection_id = await _seed_oauth_connection(admin_engine, workspace_a.id)
    start = await _start(owner, connection_id)
    state = FakeOAuthProvider.state_from(start["authorize_url"])
    async with admin_engine.begin() as conn:
        stored = (
            await conn.execute(
                text("SELECT state_hash FROM oauth_states WHERE connection_id=:i"),
                {"i": connection_id},
            )
        ).scalar()
    assert stored == hash_state(state)
    assert stored != state


# ----------------------------------------------------------------------------- state security


async def test_unknown_replayed_and_expired_states_all_fail_uniformly(
    owner: dict[str, Any],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    fake_provider: FakeOAuthProvider,
) -> None:
    client: AsyncClient = owner["client"]
    connection_id = await _seed_oauth_connection(admin_engine, workspace_a.id)
    start = await _start(owner, connection_id)
    code = fake_provider.issue_code(start["authorize_url"])
    state = FakeOAuthProvider.state_from(start["authorize_url"])

    unknown = await _callback(client, code=code, state="not-a-real-state")
    assert unknown.status_code == 400

    ok = await _callback(client, code=code, state=state)
    assert ok.status_code == 200
    replay = await _callback(client, code=code, state=state)  # same state, second time
    assert replay.status_code == 400
    assert replay.text == unknown.text, "replay and unknown must be indistinguishable"


async def test_expired_state_is_refused(
    owner: dict[str, Any],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    fake_provider: FakeOAuthProvider,
) -> None:
    connection_id = await _seed_oauth_connection(admin_engine, workspace_a.id)
    start = await _start(owner, connection_id)
    code = fake_provider.issue_code(start["authorize_url"])
    state = FakeOAuthProvider.state_from(start["authorize_url"])
    async with admin_engine.begin() as conn:  # age the row past its TTL
        await conn.execute(
            text("UPDATE oauth_states SET expires_at = :t WHERE state_hash = :h"),
            {"t": datetime.now(UTC) - timedelta(seconds=1), "h": hash_state(state)},
        )
    resp = await _callback(owner["client"], code=code, state=state)
    assert resp.status_code == 400
    assert (await _connection_row(admin_engine, connection_id)).status == "pending_auth"


async def test_concurrent_callbacks_produce_exactly_one_winner(
    owner: dict[str, Any],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    fake_provider: FakeOAuthProvider,
) -> None:
    """The atomic consume is the whole defense: two racing redirects, one activation."""
    client: AsyncClient = owner["client"]
    connection_id = await _seed_oauth_connection(admin_engine, workspace_a.id)
    start = await _start(owner, connection_id)
    code = fake_provider.issue_code(start["authorize_url"])
    state = FakeOAuthProvider.state_from(start["authorize_url"])

    results = await asyncio.gather(*(_callback(client, code=code, state=state) for _ in range(4)))
    statuses = sorted(r.status_code for r in results)
    assert statuses == [200, 400, 400, 400], statuses
    # Exactly one token exchange reached the provider.
    assert sum(1 for grant, _ in fake_provider.exchanges if grant == "authorization_code") == 1


async def test_state_from_another_workspace_activates_only_its_own_connection(
    owner: dict[str, Any],
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    fake_provider: FakeOAuthProvider,
) -> None:
    """Identity comes from the row, never the request: A's state can only ever activate A's
    connection, and B's caller cannot start a flow for A's connection."""
    client, _ = human_client
    await seed_member(admin_engine, workspace_b.id, user_id="oauth-b-owner", role="owner")
    b_headers = {
        **bearer(authority.sign("oauth-b-owner")),
        WS_HEADER: str(workspace_b.id),
    }
    a_connection = await _seed_oauth_connection(admin_engine, workspace_a.id)
    b_connection = await _seed_oauth_connection(admin_engine, workspace_b.id)

    # B cannot start a flow for A's connection — uniform 404.
    cross = await client.post(f"/v1/connections/{a_connection}/oauth/authorize", headers=b_headers)
    assert cross.status_code == 404

    start = await _start(owner, a_connection)
    code = fake_provider.issue_code(start["authorize_url"])
    state = FakeOAuthProvider.state_from(start["authorize_url"])
    assert (await _callback(client, code=code, state=state)).status_code == 200

    assert (await _connection_row(admin_engine, a_connection)).status == "active"
    assert (await _connection_row(admin_engine, b_connection)).status == "pending_auth"


# ------------------------------------------------------------------------------------ PKCE


async def test_pkce_verifier_mismatch_is_rejected_by_the_provider(
    owner: dict[str, Any],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    fake_provider: FakeOAuthProvider,
) -> None:
    """Bind a code to a DIFFERENT challenge: our stored verifier no longer matches, and the
    provider refuses — proving the verifier we present is the one from the authorize step."""
    connection_id = await _seed_oauth_connection(admin_engine, workspace_a.id)
    start = await _start(owner, connection_id)
    state = FakeOAuthProvider.state_from(start["authorize_url"])
    foreign = start["authorize_url"].replace(
        "code_challenge=", "code_challenge=x"
    )  # a challenge we hold no verifier for
    code = fake_provider.issue_code(foreign)

    resp = await _callback(owner["client"], code=code, state=state)
    assert resp.status_code == 400
    assert (await _connection_row(admin_engine, connection_id)).status == "pending_auth"


async def test_authorize_url_never_offers_plain_pkce(
    owner: dict[str, Any], admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    connection_id = await _seed_oauth_connection(admin_engine, workspace_a.id)
    start = await _start(owner, connection_id)
    assert "code_challenge_method=S256" in start["authorize_url"]
    assert "plain" not in start["authorize_url"]


# ------------------------------------------------------------------------- provider failures


@pytest.mark.parametrize(
    "response",
    [
        (400, b'{"error":"invalid_grant","error_description":"SENSITIVE-PROVIDER-DETAIL"}'),
        (500, b"upstream exploded"),
        (200, b"not json at all"),
        (200, b'{"token_type":"Bearer","expires_in":3600}'),  # no access_token
        (200, b'{"access_token":"t","token_type":"mac","expires_in":3600}'),  # wrong type
        (200, b'{"access_token":"t","token_type":"Bearer","expires_in":"soon"}'),  # bad expiry
    ],
)
async def test_provider_failures_leave_the_connection_unactivated_and_leak_nothing(
    owner: dict[str, Any],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    fake_provider: FakeOAuthProvider,
    response: tuple[int, bytes],
) -> None:
    connection_id = await _seed_oauth_connection(admin_engine, workspace_a.id)
    start = await _start(owner, connection_id)
    code = fake_provider.issue_code(start["authorize_url"])
    state = FakeOAuthProvider.state_from(start["authorize_url"])
    fake_provider.next_response = response

    resp = await _callback(owner["client"], code=code, state=state)
    assert resp.status_code == 400
    assert "SENSITIVE-PROVIDER-DETAIL" not in resp.text
    assert "provider.example.com" not in resp.text  # no internal/provider URL leakage
    row = await _connection_row(admin_engine, connection_id)
    assert row.status == "pending_auth" and row.credential_id is None


async def test_token_endpoint_ssrf_is_refused_by_the_canonical_egress(
    owner: dict[str, Any],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    fake_provider: FakeOAuthProvider,
) -> None:
    """Even if a hostile token_url reached the database, the exchange still dies at the one
    canonical egress boundary — no OAuth-specific SSRF logic exists to be bypassed."""
    connection_id = await _seed_oauth_connection(admin_engine, workspace_a.id)
    start = await _start(owner, connection_id)
    code = fake_provider.issue_code(start["authorize_url"])
    state = FakeOAuthProvider.state_from(start["authorize_url"])
    fake_provider.raise_error = net.SSRFError("blocked-private")

    resp = await _callback(owner["client"], code=code, state=state)
    assert resp.status_code == 400
    assert (await _connection_row(admin_engine, connection_id)).status == "pending_auth"


async def test_hostile_provider_endpoints_are_refused_at_connector_save(
    owner: dict[str, Any],
) -> None:
    """The definition-time half of the two-layer defense, through the real API."""
    client: AsyncClient = owner["client"]
    for bad in ("https://169.254.169.254/token", "https://127.0.0.1/token", "http://p.io/token"):
        resp = await client.post(
            "/v1/connectors",
            headers=owner["headers"],
            json={
                "name": "Hostile",
                "base_url": "https://api.example.com",
                "slug": f"h-{uuid.uuid4().hex[:8]}",
                "auth_config": {**AUTH_CONFIG, "token_url": bad},
            },
        )
        assert resp.status_code == 400, bad
        assert resp.json()["error"]["code"] == "validation_error"


async def test_client_secret_in_auth_config_is_refused_through_the_api(
    owner: dict[str, Any],
) -> None:
    client: AsyncClient = owner["client"]
    resp = await client.post(
        "/v1/connectors",
        headers=owner["headers"],
        json={
            "name": "Leaky",
            "base_url": "https://api.example.com",
            "slug": f"l-{uuid.uuid4().hex[:8]}",
            "auth_config": {**AUTH_CONFIG, "client_secret": "should-never-be-public"},
        },
    )
    assert resp.status_code == 400
    assert "should-never-be-public" not in resp.text


# --------------------------------------------------------------------------- callback surface


async def test_provider_error_and_missing_parameters_render_the_same_page(
    owner: dict[str, Any],
) -> None:
    client: AsyncClient = owner["client"]
    denied = await client.get("/v1/oauth/callback", params={"error": "access_denied"})
    missing = await client.get("/v1/oauth/callback", params={"code": "x"})  # no state
    assert denied.status_code == missing.status_code == 400
    assert denied.text == missing.text


async def test_callback_ignores_a_client_supplied_redirect_uri(
    owner: dict[str, Any],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    fake_provider: FakeOAuthProvider,
) -> None:
    """An attacker-supplied `redirect_uri` on the callback must change nothing: the exchange
    replays the value stored at authorize time (RFC 6749 §4.1.3)."""
    client: AsyncClient = owner["client"]
    connection_id = await _seed_oauth_connection(admin_engine, workspace_a.id)
    start = await _start(owner, connection_id)
    code = fake_provider.issue_code(start["authorize_url"])
    state = FakeOAuthProvider.state_from(start["authorize_url"])

    resp = await client.get(
        "/v1/oauth/callback",
        params={"code": code, "state": state, "redirect_uri": "https://evil.example/steal"},
    )
    assert resp.status_code == 200
    _, form = fake_provider.exchanges[-1]
    assert form["redirect_uri"] == settings.oauth_redirect_uri


# ------------------------------------------------------------------------ authorization gate


async def test_authorize_requires_permission_and_an_oauth_connector(
    owner: dict[str, Any],
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> None:
    client, _ = human_client
    connection_id = await _seed_oauth_connection(admin_engine, workspace_a.id)

    # Unauthenticated.
    assert (
        await client.post(f"/v1/connections/{connection_id}/oauth/authorize")
    ).status_code == 401

    # A VIEWER holds no `connections:manage`.
    await seed_member(admin_engine, workspace_a.id, user_id="oauth-viewer", role="viewer")
    viewer = await client.post(
        f"/v1/connections/{connection_id}/oauth/authorize",
        headers={**bearer(authority.sign("oauth-viewer")), WS_HEADER: str(workspace_a.id)},
    )
    assert viewer.status_code == 403

    # A non-oauth2 Connector cannot start a dance.
    api_key_connection = await _seed_oauth_connection(
        admin_engine, workspace_a.id, auth_config={"type": "api_key", "key_name": "X-Key"}
    )
    resp = await client.post(
        f"/v1/connections/{api_key_connection}/oauth/authorize", headers=owner["headers"]
    )
    assert resp.status_code == 400


async def test_oauth2_cannot_be_written_through_the_public_credential_api(
    owner: dict[str, Any], admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """Tokens are minted by the dance, never posted by a client — otherwise anyone with
    `connections:manage` could inject an arbitrary bearer token as an 'OAuth' credential."""
    client: AsyncClient = owner["client"]
    connection_id = await _seed_oauth_connection(admin_engine, workspace_a.id)
    resp = await client.post(
        f"/v1/connections/{connection_id}/credential",
        headers=owner["headers"],
        json={"credential_type": "oauth2", "value": "attacker-supplied"},
    )
    assert resp.status_code == 400


async def test_provider_error_bodies_never_reach_logs(
    owner: dict[str, Any],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    fake_provider: FakeOAuthProvider,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """RFC 6749 §5.2 error bodies routinely echo request parameters, so a provider's response
    body must not reach any sink — not the browser (asserted elsewhere) and not the logs.

    This closes the gap that let a `leak-provider-error-body` mutation survive the first audit:
    the response is a static page, so a body smuggled into an exception message would have been
    invisible to every other test.
    """
    connection_id = await _seed_oauth_connection(admin_engine, workspace_a.id)
    start = await _start(owner, connection_id)
    code = fake_provider.issue_code(start["authorize_url"])
    state = FakeOAuthProvider.state_from(start["authorize_url"])
    fake_provider.next_response = (
        400,
        b'{"error":"invalid_grant","error_description":"SENSITIVE-PROVIDER-DETAIL"}',
    )

    capsys.readouterr()  # drop anything emitted while seeding
    resp = await _callback(owner["client"], code=code, state=state)
    assert resp.status_code == 400
    captured = capsys.readouterr()
    emitted = captured.out + captured.err
    assert "SENSITIVE-PROVIDER-DETAIL" not in emitted, "a provider error body reached the logs"
    assert "invalid_grant" not in emitted
