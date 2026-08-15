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
from app.core.object_store import ObjectStore, TenantObjectKey, get_object_store
from app.domains.connectors import openapi
from app.domains.connectors.events import connector_ingested, connector_ingestion_failed
from app.domains.connectors.models import Connector, ConnectorVersion
from app.domains.connectors.openapi import IngestionError

# The egress boundary is the guarded fetcher (B0.1); a test may inject a MockTransport-backed one.
Fetcher = Callable[[str], Awaitable[bytes]]


@dataclass(frozen=True, slots=True)
class IngestionResult:
    connector_id: uuid.UUID
    status: str  # "ingested" (new version) | "unchanged" (no-op re-sync)
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

    document = openapi.load_spec(raw)
    openapi.detect_version(document)
    tools = openapi.normalize(document, connector.slug)
    new_hash = openapi.spec_hash(tools)

    current = await _current_version(uow, workspace_id, connector)
    if current is not None and current.spec_hash == new_hash:
        # No-op re-sync: nothing changed after normalization — no empty version, no event.
        connector.status = "active"
        return IngestionResult(connector_id, "unchanged", current.version, new_hash)

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
    )
    uow.session.add(row)
    await uow.session.flush()  # assign row.id for the pointer

    connector.current_version_id = row.id
    connector.status = "active"
    base_url = openapi.base_url_from_servers(document)
    if base_url:
        connector.base_url = base_url[:2048]
    connector.source_url = source_url[:2048]

    # Buffered directly on this UoW; dispatches only after COMMIT (B0.4). Buffering on the held
    # UoW (not the ambient-sink `event_bus.publish`) keeps this correct regardless of caller
    # context, and still enforces the event-tenant == bound-tenant match.
    uow.buffer_event(connector_ingested(workspace_id, connector_id, version, new_hash))
    return IngestionResult(connector_id, "ingested", version, new_hash)


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


__all__ = ["IngestionError", "IngestionResult", "ingest_from_url", "mark_failed"]
