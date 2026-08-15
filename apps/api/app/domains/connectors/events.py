"""Domain events for the connectors domain (M1.4-B1.1).

Published to the internal event bus (B0.4) after the ingesting transaction commits. The payload
carries only non-secret identifiers a subscriber needs to invalidate caches (MCP_RUNTIME §4): the
connector, the new version number, and the content hash — never the raw spec, a URL, or a secret.
The workspace is the envelope's trusted `workspace_id`, never a payload field.
"""

from __future__ import annotations

import uuid

from app.core.events import Event

CONNECTOR_INGESTED = "connector.ingested"
CONNECTOR_INGESTION_FAILED = "connector.ingestion_failed"
# Internal trigger (not a public domain fact): the request path buffers this on its UoW and a
# startup-registered handler enqueues the Celery ingestion task *after* the `ingesting` status
# commits — so the worker never reads the connector before the transition is durable.
CONNECTOR_INGESTION_REQUESTED = "connector.ingestion_requested"


def connector_ingestion_requested(
    workspace_id: uuid.UUID, connector_id: uuid.UUID, source_url: str
) -> Event:
    """Buffered post-commit trigger to enqueue ingestion. `source_url` is user-provided, not
    secret; the workspace is the trusted envelope value."""
    return Event(
        event_type=CONNECTOR_INGESTION_REQUESTED,
        workspace_id=workspace_id,
        payload={"connector_id": str(connector_id), "source_url": source_url},
    )


def connector_ingested(
    workspace_id: uuid.UUID, connector_id: uuid.UUID, connector_version: int, spec_hash: str
) -> Event:
    """A new immutable version was persisted for a connector."""
    return Event(
        event_type=CONNECTOR_INGESTED,
        workspace_id=workspace_id,
        payload={
            "connector_id": str(connector_id),
            "connector_version": connector_version,
            "spec_hash": spec_hash,
        },
    )


def connector_ingestion_failed(
    workspace_id: uuid.UUID, connector_id: uuid.UUID, reason_code: str
) -> Event:
    """Ingestion hard-failed for a connector. `reason_code` is a stable, non-secret taxonomy
    value — never a stack trace, a URL, or raw spec content."""
    return Event(
        event_type=CONNECTOR_INGESTION_FAILED,
        workspace_id=workspace_id,
        payload={"connector_id": str(connector_id), "reason_code": reason_code},
    )


__all__ = [
    "CONNECTOR_INGESTED",
    "CONNECTOR_INGESTION_FAILED",
    "CONNECTOR_INGESTION_REQUESTED",
    "connector_ingested",
    "connector_ingestion_failed",
    "connector_ingestion_requested",
]
