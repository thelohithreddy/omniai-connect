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

# Additive change vs SPEC_V1: keeps both operations, adds a third — nothing removed or narrowed.
SPEC_V1_PLUS = json.dumps(
    {
        "openapi": "3.0.3",
        "info": {"title": "T", "version": "1"},
        "servers": [{"url": "https://api.demo.com/v1"}],
        "paths": {
            "/customers": {
                "get": {"operationId": "listCustomers"},
                "post": {"operationId": "createCustomer"},
            },
            "/orders": {"get": {"operationId": "listOrders"}},
        },
    }
).encode()

URL = "https://api.demo.com/openapi.json"


async def _current_and_live_tools(conn: object, cid: uuid.UUID) -> tuple[int | None, list[str]]:
    """(current version number, sorted names of the connector's LIVE tool rows) via the admin
    connection — the projection an authorized reader would see."""
    current = await conn.scalar(  # type: ignore[attr-defined]
        text(
            "SELECT v.version FROM connectors c JOIN connector_versions v"
            " ON v.id = c.current_version_id WHERE c.id=:c"
        ),
        {"c": cid},
    )
    names = list(
        await conn.scalars(  # type: ignore[attr-defined]
            text(
                "SELECT name FROM tools WHERE connector_id=:c AND deleted_at IS NULL ORDER BY name"
            ),
            {"c": cid},
        )
    )
    return current, names


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


async def test_additive_resync_auto_promotes_version_2(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, captured_events: list[Event]
) -> None:
    # An additive re-sync (a new operation, nothing removed/narrowed) auto-promotes (§7): version 2
    # becomes current, its tools are projected, and a second connector.ingested fires.
    cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(SPEC_V1))
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        second = await ingest_from_url(
            uow, workspace_a.id, cid, URL, fetcher=_fetcher(SPEC_V1_PLUS)
        )
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
        current, live_tools = await _current_and_live_tools(conn, cid)
    assert versions == [1, 2]
    assert current == 2  # auto-promoted to v2
    assert live_tools == ["demo_createcustomer", "demo_listcustomers", "demo_listorders"]
    assert len([e for e in captured_events if e.event_type == "connector.ingested"]) == 2


async def test_breaking_resync_persists_a_pending_version_without_promoting(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, captured_events: list[Event]
) -> None:
    # A breaking re-sync (SPEC_V2 removes createCustomer) is persisted with its diff_summary but is
    # NOT auto-promoted: the connector keeps serving v1, its live tools are unchanged, and no second
    # connector.ingested fires. The gate awaits an explicit promotion (§4/§7).
    cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(SPEC_V1))
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        second = await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(SPEC_V2))
    assert second.status == "pending" and second.version == 2

    async with admin_engine.connect() as conn:
        current, live_tools = await _current_and_live_tools(conn, cid)
        status = await conn.scalar(text("SELECT status FROM connectors WHERE id=:c"), {"c": cid})
        diff = await conn.scalar(
            text("SELECT diff_summary FROM connector_versions WHERE connector_id=:c AND version=2"),
            {"c": cid},
        )
    assert current == 1  # still serving v1
    assert status == "active"  # not stuck ingesting
    assert live_tools == ["demo_createcustomer", "demo_listcustomers"]  # v1's tools, unchanged
    assert diff["breaking"] is True and diff["removed"] == ["demo_createcustomer"]
    # v1's ingest published exactly one connector.ingested; the breaking, un-promoted v2 published
    # none (the live set is unchanged).
    assert len([e for e in captured_events if e.event_type == "connector.ingested"]) == 1


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


# ------------------------------------------------------------------ upload path (M1.4-B1.2)


async def _stage_upload(ws: uuid.UUID, cid: uuid.UUID, body: bytes) -> str:
    """Mimic the API: stage raw bytes under the tenant upload prefix, return the relative ref."""
    ref = f"connectors/{cid}/uploads/{uuid.uuid4().hex}.json"
    await get_object_store().put(TenantObjectKey.for_workspace(ws, ref), body)
    return ref


async def test_upload_ingestion_reads_staged_bytes_and_persists_a_version(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, captured_events: list[Event]
) -> None:
    from app.domains.connectors.ingestion import ingest_from_upload

    cid = await _seed_connector(admin_engine, workspace_a.id)
    ref = await _stage_upload(workspace_a.id, cid, SPEC_V1)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        result = await ingest_from_upload(uow, workspace_a.id, cid, ref)
    assert result.status == "ingested" and result.version == 1

    async with admin_engine.connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT raw_spec_ref, normalized_schema FROM connector_versions"
                    " WHERE connector_id=:c"
                ),
                {"c": cid},
            )
        ).one()
    # The canonical raw_spec_ref is the version key (not the staging ref); content normalized.
    assert row.raw_spec_ref == f"ws/{workspace_a.id}/connectors/{cid}/specs/v1.json"
    names = [t["name"] for t in row.normalized_schema]
    assert names == ["demo_listcustomers", "demo_createcustomer"]
    assert [e.event_type for e in captured_events] == ["connector.ingested"]


async def test_a_malformed_upload_raises_without_persisting(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    from app.domains.connectors.ingestion import ingest_from_upload
    from app.domains.connectors.openapi import IngestionError

    cid = await _seed_connector(admin_engine, workspace_a.id)
    ref = await _stage_upload(workspace_a.id, cid, b"not a spec {")
    with pytest.raises(IngestionError) as exc:
        async with worker_tenant_uow(str(workspace_a.id)) as uow:
            await ingest_from_upload(uow, workspace_a.id, cid, ref)
    assert exc.value.reason_code == "malformed_spec"
    async with admin_engine.connect() as conn:
        count = await conn.scalar(
            text("SELECT count(*) FROM connector_versions WHERE connector_id=:c"), {"c": cid}
        )
    assert count == 0


async def test_a_missing_staged_upload_fails_closed(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    from app.domains.connectors.ingestion import ingest_from_upload
    from app.domains.connectors.openapi import IngestionError

    cid = await _seed_connector(admin_engine, workspace_a.id)
    with pytest.raises(IngestionError) as exc:
        async with worker_tenant_uow(str(workspace_a.id)) as uow:
            await ingest_from_upload(
                uow, workspace_a.id, cid, f"connectors/{cid}/uploads/nope.json"
            )
    assert exc.value.reason_code == "upload_missing"


async def test_the_same_uploaded_bytes_dedupe_to_no_new_version(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    from app.domains.connectors.ingestion import ingest_from_upload

    cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        ref = await _stage_upload(workspace_a.id, cid, SPEC_V1)
        await ingest_from_upload(uow, workspace_a.id, cid, ref)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        ref2 = await _stage_upload(workspace_a.id, cid, SPEC_V1)
        second = await ingest_from_upload(uow, workspace_a.id, cid, ref2)
    assert second.status == "unchanged"


# ----------------------------------------------------------- remote $ref through the pipeline


async def test_a_remote_ref_is_resolved_through_the_pipeline_fetcher(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """The pipeline hands the SAME fetcher to normalize, so a remote $ref in a URL-ingested spec is
    resolved (here via a multi-URL canned fetcher) and inlined into the persisted Tool set."""
    from app.domains.connectors.ingestion import ingest_from_url

    root = json.dumps(
        {
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.demo.com/v1"}],
            "paths": {
                "/x": {
                    "get": {
                        "operationId": "x",
                        "parameters": [
                            {
                                "name": "q",
                                "in": "query",
                                "schema": {"$ref": "https://s.demo.com/c.json#/S"},
                            }
                        ],
                    }
                }
            },
        }
    ).encode()
    remote = json.dumps({"S": {"type": "string", "maxLength": 7}}).encode()
    docs = {"https://api.demo.com/openapi.json": root, "https://s.demo.com/c.json": remote}

    async def multi_fetch(url: str) -> bytes:
        if url not in docs:
            raise RuntimeError("blocked")
        return docs[url]

    cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        result = await ingest_from_url(
            uow, workspace_a.id, cid, "https://api.demo.com/openapi.json", fetcher=multi_fetch
        )
    assert result.status == "ingested"
    async with admin_engine.connect() as conn:
        schema = await conn.scalar(
            text("SELECT normalized_schema FROM connector_versions WHERE connector_id=:c"),
            {"c": cid},
        )
    assert schema[0]["input_schema"]["properties"]["q"] == {"type": "string", "maxLength": 7}


# ----------------------------------------------------------- Swagger 2 → OpenAPI 3 (M1.4-B1.3)

# The SAME two operations as SPEC_V1, described as Swagger 2.0 — so they normalize to an identical
# Tool set (and thus an identical spec_hash), proving conversion adds no separate normalization.
SWAGGER_SPEC = json.dumps(
    {
        "swagger": "2.0",
        "info": {"title": "T", "version": "1"},
        "host": "api.demo.com",
        "basePath": "/v1",
        "schemes": ["https"],
        "paths": {
            "/customers": {
                "get": {"operationId": "listCustomers"},
                "post": {"operationId": "createCustomer"},
            }
        },
    }
).encode()


async def test_a_swagger2_spec_is_converted_and_ingested_with_the_original_bytes_retained(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, captured_events: list[Event]
) -> None:
    cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        result = await ingest_from_url(
            uow, workspace_a.id, cid, URL, fetcher=_fetcher(SWAGGER_SPEC)
        )
    assert result.status == "ingested" and result.version == 1

    async with admin_engine.connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT raw_spec_ref, normalized_schema FROM connector_versions"
                    " WHERE connector_id=:c"
                ),
                {"c": cid},
            )
        ).one()
        connector = (
            await conn.execute(
                text("SELECT status, base_url FROM connectors WHERE id=:c"), {"c": cid}
            )
        ).one()
    # Converted + normalized: canonical tools, base_url from the synthesized servers.
    assert [t["name"] for t in row.normalized_schema] == [
        "demo_listcustomers",
        "demo_createcustomer",
    ]
    assert connector.status == "active"
    assert connector.base_url == "https://api.demo.com/v1"  # from Swagger host + basePath
    # The ORIGINAL Swagger bytes are the canonical raw_spec_ref — not the converted intermediate.
    stored = await get_object_store().get(
        TenantObjectKey.for_workspace(workspace_a.id, f"connectors/{cid}/specs/v1.json")
    )
    assert stored == SWAGGER_SPEC
    assert json.loads(stored)["swagger"] == "2.0"
    assert [e.event_type for e in captured_events] == ["connector.ingested"]


async def test_swagger_and_native_openapi3_dedupe_to_one_version(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    # Ingesting the Swagger spec then its native OpenAPI-3 equivalent (SPEC_V1) is a no-op re-sync:
    # equal normalized content → equal spec_hash → no second version. Cross-format determinism.
    cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(SWAGGER_SPEC))
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        second = await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(SPEC_V1))
    assert second.status == "unchanged" and second.version == 1
    async with admin_engine.connect() as conn:
        count = await conn.scalar(
            text("SELECT count(*) FROM connector_versions WHERE connector_id=:c"), {"c": cid}
        )
    assert count == 1


async def test_a_swagger_remote_ref_resolves_through_the_guarded_fetcher(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    # A Swagger body-schema remote $ref keeps its `#/definitions/...` fragment after conversion; the
    # ONE resolver (B1.2) fetches the remote doc through the SAME guarded fetcher and navigates it.
    root = json.dumps(
        {
            "swagger": "2.0",
            "host": "api.demo.com",
            "basePath": "/v1",
            "schemes": ["https"],
            "paths": {
                "/x": {
                    "post": {
                        "operationId": "x",
                        "parameters": [
                            {
                                "name": "body",
                                "in": "body",
                                "schema": {
                                    "type": "object",
                                    "properties": {"q": {"$ref": "https://s.demo.com/d.json#/S"}},
                                },
                            }
                        ],
                    }
                }
            },
        }
    ).encode()
    remote = json.dumps({"S": {"type": "string", "maxLength": 4}}).encode()
    docs = {"https://api.demo.com/openapi.json": root, "https://s.demo.com/d.json": remote}

    async def multi_fetch(url: str) -> bytes:
        if url not in docs:
            raise RuntimeError("blocked")
        return docs[url]

    cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        result = await ingest_from_url(
            uow, workspace_a.id, cid, "https://api.demo.com/openapi.json", fetcher=multi_fetch
        )
    assert result.status == "ingested"
    async with admin_engine.connect() as conn:
        schema = await conn.scalar(
            text("SELECT normalized_schema FROM connector_versions WHERE connector_id=:c"),
            {"c": cid},
        )
    assert schema[0]["input_schema"]["properties"]["q"] == {"type": "string", "maxLength": 4}


# ----------------------------------------------------- tools projection + promotion (M1.4-B1.4)


async def test_first_version_projects_tools_and_a_diff_summary(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(SPEC_V1))

    async with admin_engine.connect() as conn:
        current, live = await _current_and_live_tools(conn, cid)
        vid = await conn.scalar(
            text("SELECT current_version_id FROM connectors WHERE id=:c"), {"c": cid}
        )
        diff = await conn.scalar(
            text("SELECT diff_summary FROM connector_versions WHERE connector_id=:c AND version=1"),
            {"c": cid},
        )
        rows = (
            await conn.execute(
                text(
                    "SELECT input_schema, annotations, enabled, connector_version_id"
                    " FROM tools WHERE connector_id=:c AND deleted_at IS NULL ORDER BY name"
                ),
                {"c": cid},
            )
        ).all()
    assert current == 1
    assert live == ["demo_createcustomer", "demo_listcustomers"]
    assert diff["added"] == ["demo_createcustomer", "demo_listcustomers"]
    assert diff["breaking"] is False
    # Each row points at the active version, defaults enabled, and carries annotations (+ tags).
    for input_schema, annots, enabled, cvid in rows:
        assert cvid == vid
        assert enabled is True
        assert input_schema["type"] == "object"
        assert "tags" in annots


async def test_promoting_a_pending_breaking_version_swaps_the_active_tools(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, captured_events: list[Event]
) -> None:
    from sqlalchemy import select

    from app.domains.connectors import promotion
    from app.domains.connectors.models import Connector, ConnectorVersion

    cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(SPEC_V1))
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(SPEC_V2))  # pending

    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        connector = await uow.session.scalar(select(Connector).where(Connector.id == cid))
        v2 = await uow.session.scalar(
            select(ConnectorVersion).where(
                ConnectorVersion.connector_id == cid, ConnectorVersion.version == 2
            )
        )
        assert connector is not None and v2 is not None
        changed = await promotion.promote(uow, workspace_a.id, connector, v2)
    assert changed is True

    async with admin_engine.connect() as conn:
        current, live = await _current_and_live_tools(conn, cid)
    assert current == 2
    assert live == ["demo_listcustomers"]  # createcustomer removed → soft-deleted (deprecated)
    # v1 auto-promote + v2 explicit promote = exactly two activations.
    assert len([e for e in captured_events if e.event_type == "connector.ingested"]) == 2

    # Idempotent: promoting the already-current version changes nothing.
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        connector = await uow.session.scalar(select(Connector).where(Connector.id == cid))
        v2 = await uow.session.scalar(
            select(ConnectorVersion).where(
                ConnectorVersion.connector_id == cid, ConnectorVersion.version == 2
            )
        )
        assert connector is not None and v2 is not None
        assert await promotion.promote(uow, workspace_a.id, connector, v2) is False


async def test_enabled_overrides_survive_promotion(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(SPEC_V1))
    # The user disables a tool on v1.
    async with admin_engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE tools SET enabled=false WHERE connector_id=:c AND name='demo_listcustomers'"
            ),
            {"c": cid},
        )
    # An additive re-sync auto-promotes v2; the override must re-apply to v2's row (§3), while a
    # brand-new tool defaults to enabled.
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(SPEC_V1_PLUS))

    async with admin_engine.connect() as conn:
        carried = await conn.scalar(
            text(
                "SELECT enabled FROM tools"
                " WHERE connector_id=:c AND name='demo_listcustomers' AND deleted_at IS NULL"
            ),
            {"c": cid},
        )
        fresh = await conn.scalar(
            text(
                "SELECT enabled FROM tools"
                " WHERE connector_id=:c AND name='demo_listorders' AND deleted_at IS NULL"
            ),
            {"c": cid},
        )
    assert carried is False  # the disable survived promotion
    assert fresh is True  # the new tool defaults enabled


async def test_concurrent_promotions_project_no_duplicate_tools(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    from app.core.security import CallerIdentity, WorkspaceContext
    from app.domains.connectors.repository import ConnectorRepository
    from app.domains.connectors.service import ConnectorService

    cid = await _seed_connector(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(SPEC_V1))
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await ingest_from_url(uow, workspace_a.id, cid, URL, fetcher=_fetcher(SPEC_V2))  # pending

    ctx = WorkspaceContext(
        workspace_id=workspace_a.id,
        caller=CallerIdentity(kind="api_token", api_token_id=uuid.uuid4()),
        request_id="req_test",
    )

    async def promote_v2() -> None:
        # The production path: service.promote → repository.get_for_update (SELECT … FOR UPDATE) →
        # promotion. The row lock serializes the two racers — the winner projects, the loser reads
        # v2 already current and no-ops. Without the lock, both would insert v2's tools and the
        # partial-unique index would fail the second → a raised error here, not a silent duplicate.
        async with worker_tenant_uow(str(workspace_a.id)) as uow:
            service = ConnectorService(ConnectorRepository(uow.session, ctx))
            await service.promote(uow, connector_id=cid, version=2)

    await asyncio.gather(promote_v2(), promote_v2())

    async with admin_engine.connect() as conn:
        current, live = await _current_and_live_tools(conn, cid)
    assert current == 2
    assert live == ["demo_listcustomers"]  # exactly v2's live set — no duplicate rows
