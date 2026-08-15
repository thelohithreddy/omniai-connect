"""Connector spec ingestion pipeline (M1.4-B1.1, ADR-0025) — the worker-side composition.

Runs inside the worker tenant context (B0.3). Composes the proven foundation:

    guarded fetch (B0.1) → parse + normalize (openapi.py) → spec_hash dedup
        → store raw (B0.5) → persist connector_versions + advance connector
        → COMMIT → post-commit connector.ingested (B0.4)

Tenant authority is the worker's server-established `workspace_id` (never the source URL, the
spec, or any payload field). The fetch is the only network egress and it goes through the guarded
fetcher; the importer never fetches directly. On success the connector advances to `active` with a
new `current_version_id`; a re-sync that normalizes identically to the current version is a no-op
(no new row); a hard failure raises `IngestionError`, which the task records as `failed`.

Transaction ordering (CONNECTOR_SPECIFICATION §28): the spec is fetched *before* the transaction
(no DB connection is held during network I/O); the raw object is written *before* COMMIT, so a
persisted `raw_spec_ref` always points at a real object. Object storage and Postgres are not one
atomic unit — a rollback after the object write leaves an orphan object keyed by version number
(overwritten on the next attempt, since the version number is not consumed until COMMIT); no
cross-system distributed transaction is claimed and no cleanup infrastructure is built in B1.1.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from sqlalchemy import func, select

from app.core.db import UnitOfWork
from app.core.net import SSRFError, fetch
from app.core.object_store import (
    ObjectNotFoundError,
    ObjectStore,
    TenantObjectKey,
    get_object_store,
)
from app.domains.connectors import openapi, promotion
from app.domains.connectors.diff import compute_diff
from app.domains.connectors.events import connector_ingestion_failed
from app.domains.connectors.models import Connector, ConnectorVersion
from app.domains.connectors.openapi import IngestionError

# The egress boundary is the guarded fetcher (B0.1); a test may inject a MockTransport-backed one.
Fetcher = Callable[[str], Awaitable[bytes]]


@dataclass(frozen=True, slots=True)
class IngestionResult:
    connector_id: uuid.UUID
    # "ingested" (new version, auto-promoted) | "unchanged" (no-op re-sync) |
    # "pending" (breaking version persisted, awaiting explicit promotion — M1.4-B1.4)
    status: str
    version: int | None
    spec_hash: str


async def _load_connector(
    uow: UnitOfWork, workspace_id: uuid.UUID, connector_id: uuid.UUID
) -> Connector:
    stmt = select(Connector).where(
        Connector.id == connector_id,
        Connector.workspace_id == workspace_id,
        Connector.deleted_at.is_(None),
    )
    connector: Connector | None = await uow.session.scalar(stmt)
    if connector is None:
        # Refers to nothing this tenant owns — fail closed rather than proceed unbound.
        raise IngestionError("connector_not_found", "connector does not exist in this workspace")
    return connector


async def _current_version(
    uow: UnitOfWork, workspace_id: uuid.UUID, connector: Connector
) -> ConnectorVersion | None:
    if connector.current_version_id is None:
        return None
    stmt = select(ConnectorVersion).where(
        ConnectorVersion.id == connector.current_version_id,
        ConnectorVersion.workspace_id == workspace_id,
    )
    version: ConnectorVersion | None = await uow.session.scalar(stmt)
    return version


async def _next_version_number(
    uow: UnitOfWork, workspace_id: uuid.UUID, connector_id: uuid.UUID
) -> int:
    stmt = select(func.coalesce(func.max(ConnectorVersion.version), 0)).where(
        ConnectorVersion.connector_id == connector_id,
        ConnectorVersion.workspace_id == workspace_id,
    )
    return int(await uow.session.scalar(stmt) or 0) + 1


def _raw_key(workspace_id: uuid.UUID, connector_id: uuid.UUID, version: int) -> TenantObjectKey:
    return TenantObjectKey.for_workspace(
        workspace_id, f"connectors/{connector_id}/specs/v{version}.json"
    )


async def ingest_from_url(
    uow: UnitOfWork,
    workspace_id: uuid.UUID,
    connector_id: uuid.UUID,
    source_url: str,
    *,
    store: ObjectStore | None = None,
    fetcher: Fetcher = fetch,
) -> IngestionResult:
    """Fetch, normalize, dedup, persist, and (via the UoW) emit `connector.ingested` on commit.

    The caller (the Celery task) owns the transaction (`uow`); the connector's tenant is
    `workspace_id`, established by the worker context — never derived from `source_url`. `fetcher`
    defaults to the guarded fetcher (B0.1) and is a test seam only.
    """
    object_store = store or get_object_store()
    connector = await _load_connector(uow, workspace_id, connector_id)

    # The only egress: the guarded fetcher (B0.1). SSRF/oversize/timeout surface as IngestionError.
    try:
        raw = await fetcher(source_url)
    except SSRFError as exc:
        raise IngestionError("ssrf_rejected", "source URL failed egress validation") from exc
    except IngestionError:
        raise
    except Exception as exc:  # network/timeout/size — never leak the raw error text
        raise IngestionError("fetch_failed", "could not fetch the specification") from exc

    return await _persist(
        uow, workspace_id, connector_id, connector, raw, source_url, object_store, fetcher
    )


async def ingest_from_upload(
    uow: UnitOfWork,
    workspace_id: uuid.UUID,
    connector_id: uuid.UUID,
    upload_ref: str,
    *,
    store: ObjectStore | None = None,
    fetcher: Fetcher = fetch,
) -> IngestionResult:
    """Ingest a spec the API already staged to ObjectStore (M1.4-B1.2, upload path).

    The worker cannot re-fetch an uploaded file, so the API validated and stored the raw bytes at
    `upload_ref` (a workspace-relative key); the worker reads them back through the tenant
    ObjectStore boundary — `TenantObjectKey.for_workspace(workspace_id, upload_ref)` confines the
    read to *this*
    tenant's prefix and rejects any traversal, so even a tampered ref cannot cross tenants. Remote
    `$ref`s in the uploaded spec still resolve through the guarded fetcher (`fetcher`)."""
    object_store = store or get_object_store()
    connector = await _load_connector(uow, workspace_id, connector_id)
    try:
        key = TenantObjectKey.for_workspace(workspace_id, upload_ref)
        raw = await object_store.get(key)
    except ObjectNotFoundError as exc:
        raise IngestionError("upload_missing", "the staged upload was not found") from exc
    except IngestionError:
        raise
    except Exception as exc:  # storage/key error — never leak the key or provider detail
        raise IngestionError("upload_read_failed", "could not read the staged upload") from exc
    return await _persist(
        uow, workspace_id, connector_id, connector, raw, None, object_store, fetcher
    )


async def _persist(
    uow: UnitOfWork,
    workspace_id: uuid.UUID,
    connector_id: uuid.UUID,
    connector: Connector,
    raw: bytes,
    source_url: str | None,
    object_store: ObjectStore,
    fetcher: Fetcher,
) -> IngestionResult:
    """Shared tail of both source paths: parse → to_openapi3 (Swagger 2 upgraded, then OpenAPI-3
    validated) → normalize (remote refs via `fetcher`) → dedup → store raw → persist an immutable
    version → advance the connector → buffer the event."""
    document = openapi.load_spec(raw)
    # Single upfront format step (M1.4-B1.3): a Swagger 2.0 document is converted to OpenAPI 3
    # here, then the ONE OpenAPI-3 importer runs unchanged. The ORIGINAL bytes (`raw`) remain the
    # canonical raw_spec_ref — the converted document is a transient intermediate.
    document = openapi.to_openapi3(document)
    # Remote $refs are resolved through the SAME guarded fetcher as the root spec (B0.1, §15/§18).
    tools = await openapi.normalize(document, connector.slug, fetch=fetcher)
    new_hash = openapi.spec_hash(tools)

    current = await _current_version(uow, workspace_id, connector)
    if current is not None and current.spec_hash == new_hash:
        # No-op re-sync: nothing changed after normalization — no empty version, no event.
        connector.status = "active"
        return IngestionResult(connector_id, "unchanged", current.version, new_hash)

    # Diff the new Tool set against the current version on source identity; the breaking flag drives
    # the promotion gate (§185). A first version has no predecessor — every Tool is additive.
    old_tools = [
        {key: value for key, value in tool.items() if key != "connector_version"}
        for tool in (current.normalized_schema if current is not None else [])
        if isinstance(tool, dict)
    ]
    diff = compute_diff(old_tools, tools)

    version = await _next_version_number(uow, workspace_id, connector_id)
    # Persist the version number into the stored Tool set (hash stays version-independent).
    normalized_schema = [{**tool, "connector_version": version} for tool in tools]

    # Write the raw object before COMMIT so raw_spec_ref points at a real object.
    raw_key = _raw_key(workspace_id, connector_id, version)
    await object_store.put(raw_key, raw, content_type="application/json")

    row = ConnectorVersion(
        workspace_id=workspace_id,
        connector_id=connector_id,
        version=version,
        spec_hash=new_hash,
        raw_spec_ref=raw_key.full_key,
        normalized_schema=normalized_schema,
        diff_summary=diff,
    )
    uow.session.add(row)
    await uow.session.flush()  # assign row.id for the pointer

    if source_url is not None:
        connector.source_url = source_url[:2048]

    if current is None or not diff["breaking"]:
        # First version, or a non-breaking (purely additive) diff → auto-promote (§7, §381):
        # advance the pointer, project the tools, and buffer `connector.ingested` (in `promote`).
        await promotion.promote(uow, workspace_id, connector, row)
        base_url = openapi.base_url_from_servers(document)
        if base_url:
            connector.base_url = base_url[:2048]
        return IngestionResult(connector_id, "ingested", version, new_hash)

    # Breaking diff → the version is persisted with its diff_summary but NOT promoted: the connector
    # keeps serving its current version (status returns to active) and an owner/admin promotes it
    # explicitly (§4/§7). No tools projection, no `connector.ingested` — the live set is unchanged.
    connector.status = "active"
    return IngestionResult(connector_id, "pending", version, new_hash)


async def mark_failed(
    uow: UnitOfWork, workspace_id: uuid.UUID, connector_id: uuid.UUID, reason_code: str
) -> None:
    """Record a hard ingestion failure: the connector moves to `failed` and a non-secret
    `connector.ingestion_failed` event is emitted post-commit. Called in a *fresh* transaction
    after the ingesting transaction has rolled back."""
    connector = await uow.session.scalar(
        select(Connector).where(
            Connector.id == connector_id,
            Connector.workspace_id == workspace_id,
            Connector.deleted_at.is_(None),
        )
    )
    if connector is None:
        return
    connector.status = "failed"
    uow.buffer_event(connector_ingestion_failed(workspace_id, connector_id, reason_code))


__all__ = [
    "IngestionError",
    "IngestionResult",
    "ingest_from_upload",
    "ingest_from_url",
    "mark_failed",
]
