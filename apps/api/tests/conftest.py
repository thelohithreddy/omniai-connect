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

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings
from app.core.db import UnitOfWork, get_uow
from app.core.ids import new_id
from app.core.security import GeneratedToken, generate_token
from app.main import app


@dataclass(frozen=True, slots=True)
class SeededWorkspace:
    id: uuid.UUID
    slug: str
    token: GeneratedToken


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
    # Unique per run so parallel or repeated runs never collide on the slug constraint.
    slug = f"test-{label}-{workspace_id.hex[:10]}"
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
