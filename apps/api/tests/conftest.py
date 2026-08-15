"""Shared fixtures.

Two engines, deliberately:

- `admin_engine` seeds data *across* tenants, which no application code may ever do. It
  connects as the schema owner/superuser, so it is not constrained by RLS. Tests need
  this to construct the "workspace B exists and has rows" precondition that the isolation
  tests then try, and fail, to reach.
- `app_engine` is what the application uses: the least-privileged role. Every assertion
  about isolation must be made through this one, or it proves nothing.

Mixing them up is the single easiest way to write a tenant-isolation suite that passes
while the system leaks.
"""

from __future__ import annotations

import base64
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core import human_auth, readiness
from app.core.config import settings
from app.core.db import UnitOfWork, get_uow
from app.core.human_auth import get_jwks_cache
from app.core.ids import new_id
from app.core.logging import configure_logging
from app.core.security import GeneratedToken, generate_token
from app.main import app


@dataclass(frozen=True, slots=True)
class SeededWorkspace:
    id: uuid.UUID
    slug: str
    token: GeneratedToken


@pytest.fixture(scope="session", autouse=True)
def _pin_log_level() -> Iterator[None]:
    """Pin a permissive log level for the whole session, **before any logger is used**.

    Session-scoped and autouse for a reason that is not obvious and cost one red CI run to
    find. `configure_logging` sets `cache_logger_on_first_use=True`, which is the correct
    production setting — logging is configured once at startup and the cache removes a
    per-call config lookup from every request. Its documented consequence is that a logger
    **freezes its wrapper class, and therefore its level filter, on first use** and never
    consults the configuration again.

    The application holds module-level loggers (`app/core/middleware.py`,
    `app/core/security.py`). Once any test has made a request, the middleware's logger is
    frozen at whatever level was active at that moment. A later test that sets
    `settings.log_level = "debug"` and calls `configure_logging()` changes the config but
    *not* that frozen logger, so `.info()` stays a no-op for the rest of the session.

    That is exactly how M1.2-F failed in CI and passed locally: CI runs at `LOG_LEVEL=warning`,
    so by the time the log-leak test ran, the middleware logger had long since frozen at
    warning and emitted nothing — while locally, at `LOG_LEVEL=debug`, it had frozen at debug
    and emitted normally. The test ran green in one environment and red in the other while
    the application behaved identically in both.

    Pinning here, before the first test runs, is what makes log-observing tests deterministic
    rather than dependent on the ambient environment and on test ordering. It applies to every
    module-level logger, not just the middleware's — so a secret leaked from any module during
    a request is observable, instead of being silently filtered out.
    """
    original = settings.log_level
    settings.log_level = "debug"
    configure_logging()
    yield
    settings.log_level = original
    configure_logging()


@pytest.fixture(autouse=True)
def _readiness_probe_uses_the_per_test_engine(app_engine: AsyncEngine) -> Iterator[None]:
    """Point the readiness probe at this test's engine.

    Production is right to probe `app.core.db.engine`: readiness must exercise the pool the
    application actually serves from, not a private one that could be healthy while the real
    pool is exhausted. But that engine is created at import and binds its pooled connections
    to whichever event loop first touches them, and pytest-asyncio gives every test a fresh
    loop — so the second test to reach `/health/ready` finds connections owned by a closed
    loop.

    Suite-wide rather than file-local because any test that touches the readiness endpoint
    needs it, and the failure mode when it is missing is an unrelated-looking
    `RuntimeError: Event loop is closed` rather than an assertion. It changes nothing about
    what the probe does: still the application pool, still `SELECT 1`, still returned clean.
    """
    original = readiness.engine
    readiness.engine = app_engine
    yield
    readiness.engine = original


@pytest.fixture(autouse=True)
def _isolate_jwks_cache() -> Iterator[None]:
    """Fresh JWKS cache singleton per test.

    Two reasons, both load-bearing. Isolation: the cache carries fetched keys and a
    cooldown timestamp, so a test that poisoned or warmed it must not leak that state into
    the next. Event loops: the cache holds an `asyncio.Lock`, which binds to the loop that
    first acquires it — pytest-asyncio gives every test a fresh loop, so a singleton
    surviving across tests raises "attached to a different loop" exactly like the engine
    problem `client` solves for `get_uow`.
    """
    human_auth.reset_jwks_cache()
    yield
    human_auth.reset_jwks_cache()


@dataclass
class SigningAuthority:
    """A local Ed25519 issuer able to mint real, verifiable Better Auth-shaped JWTs.

    This is a *test double for the provider*, not for the verifier: everything it signs is
    verified by the actual production code path over genuine cryptography. Tests use it to
    produce the shapes an attacker or a rotated provider would produce — wrong keys, wrong
    claims, unknown kids — with full control over every field.
    """

    kid: str = "test-key-1"
    # Named `signer`, not `private_key`: the latter reads as a secret assignment to
    # gitleaks, which flags the type annotation as a high-entropy value (a false
    # positive that failed CI once). This is a test signing key generated per run.
    signer: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)

    @property
    def jwk(self) -> dict[str, str]:
        raw = self.signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "kid": self.kid,
            "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
        }

    def jwks_document(self) -> dict[str, Any]:
        return {"keys": [self.jwk]}

    def sign(
        self,
        sub: str | object = "user-under-test",
        *,
        headers: dict[str, Any] | None = None,
        drop: tuple[str, ...] = (),
        **overrides: Any,
    ) -> str:
        """A token with valid defaults; every deviation is explicit at the call site."""
        now = int(time.time())
        claims: dict[str, Any] = {
            "sub": sub,
            "iss": settings.better_auth_url,
            "aud": settings.better_auth_url,
            "iat": now,
            "exp": now + 900,
        }
        claims.update(overrides)
        for claim in drop:
            claims.pop(claim, None)
        return pyjwt.encode(
            claims,
            self.signer,
            algorithm="EdDSA",
            headers={"kid": self.kid, **(headers or {})},
        )


class FakeJWKSEndpoint:
    """An in-process JWKS endpoint with a controllable failure mode and a call counter.

    Backed by `httpx.MockTransport`, injected through the JWKSCache's transport parameter —
    the seam the cache exposes by design — so no network, no monkeypatching, and the fetch
    count is a hard fact tests can assert (amplification bounds, single-flight).
    """

    def __init__(self, document: dict[str, Any]) -> None:
        self.document = document
        self.calls = 0
        self.mode = "ok"  # ok | http_error | timeout | not_json | wrong_shape

    def transport(self) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            self.calls += 1
            if self.mode == "http_error":
                return httpx.Response(500, text="upstream broke")
            if self.mode == "timeout":
                raise httpx.ConnectTimeout("simulated timeout")
            if self.mode == "not_json":
                return httpx.Response(200, text="<html>definitely not a jwks</html>")
            if self.mode == "wrong_shape":
                return httpx.Response(200, json={"not_keys": []})
            return httpx.Response(200, json=self.document)

        return httpx.MockTransport(handler)

    def cache(self) -> human_auth.JWKSCache:
        return human_auth.JWKSCache(
            url="http://jwks.test/api/auth/jwks", transport=self.transport()
        )


@pytest.fixture
def authority() -> SigningAuthority:
    return SigningAuthority()


@pytest.fixture
def jwks_endpoint(authority: SigningAuthority) -> FakeJWKSEndpoint:
    return FakeJWKSEndpoint(authority.jwks_document())


@pytest.fixture
async def human_client(
    client: AsyncClient, jwks_endpoint: FakeJWKSEndpoint
) -> AsyncIterator[tuple[AsyncClient, FakeJWKSEndpoint]]:
    """The app client with the JWKS dependency pointing at the in-process endpoint.

    Shared by every human-auth suite (M1.3-B verification and M1.3-C selection). One cache
    instance for the whole test — the override returns the same object on every request,
    exactly like production's module singleton; a fresh cache per request would reset the
    fetch counter and make the amplification/single-flight assertions vacuous.
    """
    cache = jwks_endpoint.cache()
    app.dependency_overrides[get_jwks_cache] = lambda: cache
    # `client`'s teardown clears ALL overrides, including this one.
    yield client, jwks_endpoint


def bearer(token: str) -> dict[str, str]:
    """Authorization header for a bearer credential (JWT or api token)."""
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def admin_engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(settings.database_admin_url)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture
async def app_engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(settings.database_url)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture
async def app_session(app_engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    factory = async_sessionmaker(app_engine, expire_on_commit=False)
    async with factory() as session:
        yield session


async def _create_workspace(engine: AsyncEngine, label: str) -> SeededWorkspace:
    workspace_id = new_id()
    # The FULL id hex, not a prefix. `new_id()` is UUIDv7 and its first 10 hex characters
    # are pure timestamp advancing once every ~256 ms — so a truncated slug is identical
    # for every workspace created inside that window, and any row a failed teardown left
    # behind collided with later tests in nondeterministic bursts (found during M1.3-B's
    # regression: one mid-suite failure cascaded into 15-38 setup errors). The full hex is
    # unique unconditionally and, at 32 chars + prefix, still fits slug's String(64).
    slug = f"test-{label}-{workspace_id.hex}"
    token = generate_token()
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO workspaces (id, name, slug, plan) VALUES (:id, :name, :slug, 'free')"
            ),
            {"id": workspace_id, "name": f"Test {label}", "slug": slug},
        )
        await conn.execute(
            text(
                "INSERT INTO api_tokens (id, workspace_id, name, token_hash, token_prefix, scopes)"
                " VALUES (:id, :ws, :name, :hash, :prefix, '[]'::jsonb)"
            ),
            {
                "id": new_id(),
                "ws": workspace_id,
                "name": f"{label}-token",
                "hash": token.token_hash,
                "prefix": token.token_prefix,
            },
        )
    return SeededWorkspace(id=workspace_id, slug=slug, token=token)


@pytest.fixture
async def client(app_engine: AsyncEngine) -> AsyncIterator[AsyncClient]:
    """An HTTP client against the real ASGI app, with the DB provider overridden.

    `app.core.db.engine` is created at import time and binds its pooled connections to
    whichever event loop first touches them. pytest-asyncio gives each test a fresh loop,
    so by the second API test those connections belong to a closed loop and asyncpg raises
    "attached to a different loop".

    Overriding `get_uow` — rather than monkeypatching the module global — is what
    BACKEND_SPEC.md §3 prescribes, and it fixes the loop problem as a side effect: each
    test gets a function-scoped engine.

    FastAPI caches dependency results per request, so `get_workspace_context` and the
    router's service factory both receive the *same* UnitOfWork. That matters: the tenant
    is bound with `SET LOCAL` on one transaction, and the query must run on that same one.
    """
    factory = async_sessionmaker(app_engine, expire_on_commit=False, autoflush=False)

    async def override_get_uow() -> AsyncIterator[UnitOfWork]:
        async with factory() as session, session.begin():
            yield UnitOfWork(session=session)

    app.dependency_overrides[get_uow] = override_get_uow
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as http_client:
            yield http_client
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
async def workspace_a(admin_engine: AsyncEngine) -> AsyncIterator[SeededWorkspace]:
    ws = await _create_workspace(admin_engine, "a")
    yield ws
    async with admin_engine.begin() as conn:
        await conn.execute(text("DELETE FROM workspaces WHERE id = :id"), {"id": ws.id})


@pytest.fixture
async def workspace_b(admin_engine: AsyncEngine) -> AsyncIterator[SeededWorkspace]:
    ws = await _create_workspace(admin_engine, "b")
    yield ws
    async with admin_engine.begin() as conn:
        await conn.execute(text("DELETE FROM workspaces WHERE id = :id"), {"id": ws.id})
