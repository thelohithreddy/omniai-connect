"""Connector ingestion pipeline against real Postgres + real MinIO (M1.4-B1.1).

Exercises `ingest_from_url` under the real worker tenant context (B0.3), the real ObjectStore
(B0.5), and the real event bus (B0.4) — only the network fetch is a seam (a controlled spec, never
the internet, per §41). Proves: an immutable version is persisted and the connector activates; a
no-op re-sync creates no version; a changed spec appends version 2; the raw object lands under the
tenant key; RLS keeps versions tenant-private; a hard failure marks the connector `failed`; and
concurrent tenants never cross.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import AsyncIterator, Callable

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.events import Event, event_bus
from app.core.net import SSRFError
from app.core.object_store import ObjectNotFoundError, TenantObjectKey, get_object_store
from app.domains.connectors.ingestion import ingest_from_url, mark_failed
from app.domains.connectors.openapi import IngestionError
from app.workers.context import worker_tenant_uow
from tests.conftest import SeededWorkspace

SPEC_V1 = json.dumps(
    {
        "openapi": "3.0.3",
        "info": {"title": "T", "version": "1"},
        "servers": [{"url": "https://api.demo.com/v1"}],
        "paths": {
            "/customers": {
                "get": {"operationId": "listCustomers"},
                "post": {"operationId": "createCustomer"},
            }
        },
    }
).encode()

SPEC_V2 = json.dumps(
    {
        "openapi": "3.0.3",
        "info": {"title": "T", "version": "2"},
        "servers": [{"url": "https://api.demo.com/v2"}],
        "paths": {"/customers": {"get": {"operationId": "listCustomers"}}},  # one op removed
    }
).encode()

URL = "https://api.demo.com/openapi.json"


def _fetcher(body: bytes) -> Callable[[str], object]:
    async def fetch(_url: str) -> bytes:
        return body

    return fetch


async def _seed_connector(
    engine: AsyncEngine, workspace_id: uuid.UUID, slug: str = "demo"
) -> uuid.UUID:
    cid = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO connectors"
                " (id, workspace_id, name, slug, source_type, base_url, status)"
                " VALUES (:i,:w,:n,:s,'manual','https://api.demo.com','draft')"
            ),
            {"i": cid, "w": workspace_id, "n": slug, "s": slug},
        )
    return cid


@pytest.fixture
def captured_events() -> AsyncIterator[list[Event]]:
    """Capture events on the real bus for one test; restore the handler map after."""
    saved = {k: list(v) for k, v in event_bus._handlers.items()}
    event_bus._handlers.clear()
    seen: list[Event] = []
    event_bus.subscribe("connector.ingested", lambda e: seen.append(e))
    event_bus.subscribe("connector.ingestion_failed", lambda e: seen.append(e))
    try:
        yield seen
    finally:
        event_bus._handlers.clear()
        event_bus._handlers.update(saved)


@pytest.fixture(scope="module", autouse=True)
async def _bucket() -> None:
    try:
        await get_object_store().ensure_bucket()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"object storage not available: {exc}")


# ------------------------------------------------------------------ happy path


async def test_ingestion_persists_a_version_and_activates(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, captured_events: list[Event]
) -> None:
    cid = await _seed_connector(admin_engine, workspace_a.id)

    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        result = await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(SPEC_V1))
    assert result.status == "ingested" and result.version == 1

    # Version row persisted (via admin, RLS-exempt), immutable snapshot fields present.
    async with admin_engine.connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT version, spec_hash, raw_spec_ref, normalized_schema"
                    " FROM connector_versions WHERE connector_id=:c AND workspace_id=:w"
                ),
                {"c": cid, "w": workspace_a.id},
            )
        ).one()
        connector = (
            await conn.execute(
                text("SELECT status, current_version_id, base_url FROM connectors WHERE id=:c"),
                {"c": cid},
            )
        ).one()
    assert row.version == 1
    assert len(row.spec_hash) == 64
    assert row.raw_spec_ref == f"ws/{workspace_a.id}/connectors/{cid}/specs/v1.json"
    assert [t["name"] for t in row.normalized_schema] == [
        "demo_listcustomers",
        "demo_createcustomer",
    ]
    assert all(t["connector_version"] == 1 for t in row.normalized_schema)
    assert connector.status == "active"
    assert connector.base_url == "https://api.demo.com/v1"

    # The event fired post-commit with the exact payload.
    ingested = [e for e in captured_events if e.event_type == "connector.ingested"]
    assert len(ingested) == 1
    assert ingested[0].payload == {
        "connector_id": str(cid),
        "connector_version": 1,
        "spec_hash": row.spec_hash,
    }

    # The raw object landed under the tenant key.
    body = await get_object_store().get(
        TenantObjectKey.for_workspace(workspace_a.id, f"connectors/{cid}/specs/v1.json")
    )
    assert body == SPEC_V1


async def test_no_event_or_object_on_rollback(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, captured_events: list[Event]
) -> None:
    cid = await _seed_connector(admin_engine, workspace_a.id)
    with pytest.raises(RuntimeError):
        async with worker_tenant_uow(str(workspace_a.id)) as uow:
            await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(SPEC_V1))
            raise RuntimeError("boom before commit")
    assert captured_events == []  # rolled back → nothing emitted
    async with admin_engine.connect() as conn:
        count = await conn.scalar(
            text("SELECT count(*) FROM connector_versions WHERE connector_id=:c"), {"c": cid}
        )
    assert count == 0


# ------------------------------------------------------------------ dedup + versioning


async def test_reingest_identical_spec_is_a_noop(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, captured_events: list[Event]
) -> None:
    cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(SPEC_V1))
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        second = await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(SPEC_V1))
    assert second.status == "unchanged" and second.version == 1
    async with admin_engine.connect() as conn:
        count = await conn.scalar(
            text("SELECT count(*) FROM connector_versions WHERE connector_id=:c"), {"c": cid}
        )
    assert count == 1  # no empty version
    assert len([e for e in captured_events if e.event_type == "connector.ingested"]) == 1


async def test_reingest_changed_spec_appends_version_2(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, captured_events: list[Event]
) -> None:
    cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(SPEC_V1))
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        second = await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(SPEC_V2))
    assert second.status == "ingested" and second.version == 2
    async with admin_engine.connect() as conn:
        versions = list(
            await conn.scalars(
                text(
                    "SELECT version FROM connector_versions WHERE connector_id=:c ORDER BY version"
                ),
                {"c": cid},
            )
        )
    assert versions == [1, 2]
    assert len([e for e in captured_events if e.event_type == "connector.ingested"]) == 2


# ------------------------------------------------------------------ failure handling


async def test_ssrf_rejection_raises_and_marks_failed(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, captured_events: list[Event]
) -> None:
    cid = await _seed_connector(admin_engine, workspace_a.id)

    async def _ssrf(_url: str) -> bytes:
        raise SSRFError("private address")

    with pytest.raises(IngestionError) as exc:
        async with worker_tenant_uow(str(workspace_a.id)) as uow:
            await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_ssrf)
    assert exc.value.reason_code == "ssrf_rejected"

    # The task records failure in a fresh transaction.
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await mark_failed(uow, workspace_a.id, cid, exc.value.reason_code)
    async with admin_engine.connect() as conn:
        status = await conn.scalar(text("SELECT status FROM connectors WHERE id=:c"), {"c": cid})
    assert status == "failed"
    failed = [e for e in captured_events if e.event_type == "connector.ingestion_failed"]
    assert failed and failed[0].payload == {
        "connector_id": str(cid),
        "reason_code": "ssrf_rejected",
    }


async def test_malformed_spec_raises_without_persisting(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    cid = await _seed_connector(admin_engine, workspace_a.id)
    with pytest.raises(IngestionError) as exc:
        async with worker_tenant_uow(str(workspace_a.id)) as uow:
            await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(b"not a spec {"))
    assert exc.value.reason_code == "malformed_spec"
    async with admin_engine.connect() as conn:
        count = await conn.scalar(
            text("SELECT count(*) FROM connector_versions WHERE connector_id=:c"), {"c": cid}
        )
    assert count == 0


# ------------------------------------------------------------------ tenant isolation


async def test_a_worker_cannot_ingest_a_foreign_connector(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    cid = await _seed_connector(admin_engine, workspace_a.id)  # A's connector
    # A worker bound to B cannot resolve A's connector (RLS + the workspace filter).
    with pytest.raises(IngestionError) as exc:
        async with worker_tenant_uow(str(workspace_b.id)) as uow:
            await ingest_from_url(uow, workspace_b.id, cid, URL, fetcher=_fetcher(SPEC_V1))
    assert exc.value.reason_code == "connector_not_found"


async def test_versions_are_tenant_private_under_rls(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(SPEC_V1))
    # B, under its own bound context, sees zero of A's versions (RLS).
    async with worker_tenant_uow(str(workspace_b.id)) as uow:
        visible = await uow.session.scalar(text("SELECT count(*) FROM connector_versions"))
    assert visible == 0


# ------------------------------------------------------------------ concurrency


async def test_concurrent_tenants_never_cross(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    a_ids = [await _seed_connector(admin_engine, workspace_a.id, f"a{i}") for i in range(8)]
    b_ids = [await _seed_connector(admin_engine, workspace_b.id, f"b{i}") for i in range(8)]

    async def run(ws: uuid.UUID, cid: uuid.UUID) -> None:
        await asyncio.sleep(0)
        async with worker_tenant_uow(str(ws)) as uow:
            await ingest_from_url(uow, ws, cid, URL, fetcher=_fetcher(SPEC_V1))

    await asyncio.gather(
        *[run(workspace_a.id, c) for c in a_ids], *[run(workspace_b.id, c) for c in b_ids]
    )

    # Every version sits under its own tenant; no crossover.
    async with admin_engine.connect() as conn:
        for ws, ids in ((workspace_a.id, a_ids), (workspace_b.id, b_ids)):
            for cid in ids:
                got = await conn.scalar(
                    text(
                        "SELECT workspace_id FROM connector_versions"
                        " WHERE connector_id=:c AND version=1"
                    ),
                    {"c": cid},
                )
                assert got == ws


async def test_object_missing_after_a_fresh_key(
    workspace_a: SeededWorkspace,
) -> None:
    # Sanity: a never-written version key is absent (no accidental cross-object read).
    with pytest.raises(ObjectNotFoundError):
        await get_object_store().get(
            TenantObjectKey.for_workspace(
                workspace_a.id, f"connectors/{uuid.uuid4()}/specs/v9.json"
            )
        )
