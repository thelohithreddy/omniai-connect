"""Connections domain against real Postgres + RLS (M1-Connections-v1).

Exercises `ConnectionService`/`ConnectionRepository` under a real tenant-bound session (the worker
tenant context binds the `app.workspace_id` GUC, so RLS is genuinely active — no fabricated
WorkspaceContext substituting for the database). Proves: create → pending_auth + projection;
connector-in-workspace enforcement (a foreign or soft-deleted connector is not attachable);
live-name uniqueness at the DB under concurrency; revoke soft-deletes and frees the name; rollback
persists nothing; and RLS keeps one tenant's connections invisible and immutable to another.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.exceptions import ConflictError, NotFoundError
from app.core.security import CallerIdentity, WorkspaceContext
from app.domains.connections.models import Connection
from app.domains.connections.repository import ConnectionRepository
from app.domains.connections.service import ConnectionService
from app.workers.context import worker_tenant_uow
from tests.conftest import SeededWorkspace


def _ctx(workspace_id: uuid.UUID) -> WorkspaceContext:
    return WorkspaceContext(
        workspace_id=workspace_id,
        caller=CallerIdentity(kind="api_token", api_token_id=uuid.uuid4()),
        request_id="req_test",
    )


async def _seed_connector(
    engine: AsyncEngine, workspace_id: uuid.UUID, *, slug: str = "demo", deleted: bool = False
) -> uuid.UUID:
    cid = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO connectors"
                " (id, workspace_id, name, slug, source_type, base_url, status)"
                " VALUES (:i,:w,:n,:s,'manual','https://api.demo.com','active')"
            ),
            {"i": cid, "w": workspace_id, "n": slug, "s": slug},
        )
        if deleted:
            await conn.execute(
                text("UPDATE connectors SET deleted_at=now() WHERE id=:i"), {"i": cid}
            )
    return cid


def _svc(uow_session: object, workspace_id: uuid.UUID) -> ConnectionService:
    return ConnectionService(ConnectionRepository(uow_session, _ctx(workspace_id)))  # type: ignore[arg-type]


# ------------------------------------------------------------------ happy path


async def test_create_persists_a_pending_auth_connection(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        conn = await _svc(uow.session, workspace_a.id).create(
            connector_id=cid, name="prod", config_overrides={"base_url": "https://api.demo.com/v2"}
        )
        conn_id = conn.id
    async with admin_engine.connect() as c:
        row = (
            await c.execute(
                text(
                    "SELECT status, credential_id, config_overrides, deleted_at"
                    " FROM connections WHERE id=:i AND workspace_id=:w"
                ),
                {"i": conn_id, "w": workspace_a.id},
            )
        ).one()
    assert row.status == "pending_auth"
    assert row.credential_id is None  # no credential attached in this module
    assert row.config_overrides == {"base_url": "https://api.demo.com/v2"}
    assert row.deleted_at is None


async def test_get_and_list_return_the_connection(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        svc = _svc(uow.session, workspace_a.id)
        created = await svc.create(connector_id=cid, name="c1", config_overrides={})
        fetched = await svc.get(created.id)
        page = await svc.list_page()
    assert fetched.id == created.id
    assert [c.name for c in page.connections] == ["c1"]


# ------------------------------------------------------------------ connector-in-workspace


async def test_cannot_bind_a_foreign_workspaces_connector(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    a_cid = await _seed_connector(admin_engine, workspace_a.id)  # A's connector
    # Acting in B, attaching A's connector id → not found (RLS + the workspace predicate).
    with pytest.raises(NotFoundError):
        async with worker_tenant_uow(str(workspace_b.id)) as uow:
            await _svc(uow.session, workspace_b.id).create(
                connector_id=a_cid, name="x", config_overrides={}
            )


async def test_cannot_bind_a_soft_deleted_connector(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    cid = await _seed_connector(admin_engine, workspace_a.id, deleted=True)
    with pytest.raises(NotFoundError):
        async with worker_tenant_uow(str(workspace_a.id)) as uow:
            await _svc(uow.session, workspace_a.id).create(
                connector_id=cid, name="x", config_overrides={}
            )


async def test_create_for_a_nonexistent_connector_is_not_found(
    workspace_a: SeededWorkspace,
) -> None:
    with pytest.raises(NotFoundError):
        async with worker_tenant_uow(str(workspace_a.id)) as uow:
            await _svc(uow.session, workspace_a.id).create(
                connector_id=uuid.uuid4(), name="x", config_overrides={}
            )


# ------------------------------------------------------------------ uniqueness / lifecycle


async def test_duplicate_live_name_conflicts_then_revoke_frees_it(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    cid = await _seed_connector(admin_engine, workspace_a.id)
    # Each create is its own transaction (as a real request is): the first commits...
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        first = await _svc(uow.session, workspace_a.id).create(
            connector_id=cid, name="dup", config_overrides={}
        )
    # ...and a second live create with the same name is a 409 from the DB unique index.
    with pytest.raises(ConflictError):
        async with worker_tenant_uow(str(workspace_a.id)) as uow:
            await _svc(uow.session, workspace_a.id).create(
                connector_id=cid, name="dup", config_overrides={}
            )
    # Revoke the first, then the name is reusable.
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await _svc(uow.session, workspace_a.id).revoke(first.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        again = await _svc(uow.session, workspace_a.id).create(
            connector_id=cid, name="dup", config_overrides={}
        )
    assert again.name == "dup"


async def test_update_changes_name_and_config_and_relints_base_url(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    from app.core.exceptions import ValidationFailedError

    cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        svc = _svc(uow.session, workspace_a.id)
        created = await svc.create(connector_id=cid, name="n1", config_overrides={})
        updated = await svc.update(
            created.id, name="n2", config_overrides={"base_url": "https://api.demo.com/v3"}
        )
        assert updated.name == "n2"
        assert updated.config_overrides["base_url"] == "https://api.demo.com/v3"
        # An unsafe override on update is refused (SSRF lint re-runs).
        with pytest.raises(ValidationFailedError):
            await svc.update(
                created.id, name=None, config_overrides={"base_url": "http://localhost"}
            )


async def test_rename_to_an_existing_live_name_conflicts(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        svc = _svc(uow.session, workspace_a.id)
        await svc.create(connector_id=cid, name="taken", config_overrides={})
        other = await svc.create(connector_id=cid, name="other", config_overrides={})
    # Renaming `other` onto the live name `taken` is a DB-arbitrated 409.
    with pytest.raises(ConflictError):
        async with worker_tenant_uow(str(workspace_a.id)) as uow:
            await _svc(uow.session, workspace_a.id).update(
                other.id, name="taken", config_overrides=None
            )


async def test_revoke_soft_deletes_and_is_idempotent(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        svc = _svc(uow.session, workspace_a.id)
        created = await svc.create(connector_id=cid, name="r", config_overrides={})
        await svc.revoke(created.id)
        # After revoke: invisible to reads (uniform 404) and a second revoke matches nothing.
        with pytest.raises(NotFoundError):
            await svc.get(created.id)
        with pytest.raises(NotFoundError):
            await svc.revoke(created.id)
    async with admin_engine.connect() as c:
        row = (
            await c.execute(
                text("SELECT status, deleted_at FROM connections WHERE id=:i"), {"i": created.id}
            )
        ).one()
    assert row.status == "revoked" and row.deleted_at is not None  # retained, not hard-deleted


# ------------------------------------------------------------------ rollback / concurrency


async def test_rollback_persists_no_connection(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    cid = await _seed_connector(admin_engine, workspace_a.id)
    with pytest.raises(RuntimeError):
        async with worker_tenant_uow(str(workspace_a.id)) as uow:
            await _svc(uow.session, workspace_a.id).create(
                connector_id=cid, name="rb", config_overrides={}
            )
            raise RuntimeError("boom before commit")
    async with admin_engine.connect() as c:
        count = await c.scalar(
            text("SELECT count(*) FROM connections WHERE connector_id=:c"), {"c": cid}
        )
    assert count == 0


async def test_concurrent_same_name_creates_are_resolved_by_the_database(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    cid = await _seed_connector(admin_engine, workspace_a.id)

    async def create() -> Connection:
        async with worker_tenant_uow(str(workspace_a.id)) as uow:
            return await _svc(uow.session, workspace_a.id).create(
                connector_id=cid, name="race", config_overrides={}
            )

    results = await asyncio.gather(create(), create(), return_exceptions=True)
    successes = [r for r in results if isinstance(r, Connection)]
    conflicts = [r for r in results if isinstance(r, ConflictError)]
    assert len(successes) == 1 and len(conflicts) == 1  # the DB, not the app, is the arbiter
    async with admin_engine.connect() as c:
        live = await c.scalar(
            text(
                "SELECT count(*) FROM connections"
                " WHERE connector_id=:c AND name='race' AND deleted_at IS NULL"
            ),
            {"c": cid},
        )
    assert live == 1  # exactly one live connection with the contested name


# ------------------------------------------------------------------ RLS cross-tenant


async def test_rls_hides_and_protects_a_foreign_tenants_connection(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    a_cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        a_conn = await _svc(uow.session, workspace_a.id).create(
            connector_id=a_cid, name="secret", config_overrides={}
        )
    # B, under its own bound context, cannot see, get, or revoke A's connection.
    async with worker_tenant_uow(str(workspace_b.id)) as uow:
        b_svc = _svc(uow.session, workspace_b.id)
        page = await b_svc.list_page()
        assert page.connections == []  # RLS hides A's rows entirely
        with pytest.raises(NotFoundError):
            await b_svc.get(a_conn.id)  # uniform 404 — not an existence oracle
        with pytest.raises(NotFoundError):
            await b_svc.revoke(a_conn.id)  # cannot mutate A's row
    # A's connection is untouched.
    async with admin_engine.connect() as c:
        status = await c.scalar(
            text("SELECT status FROM connections WHERE id=:i"), {"i": a_conn.id}
        )
    assert status == "pending_auth"
