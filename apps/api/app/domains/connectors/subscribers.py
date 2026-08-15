"""Connectors domain event subscribers (M1.4-B1.1).

Explicit, startup-registered handlers (BACKEND_SPEC §4 — no magic discovery). The one handler
here bridges the request path to the Celery pipeline: when a `connector.ingestion_requested`
trigger is dispatched *after* the request's transaction commits, it enqueues the ingestion task.
Enqueuing post-commit (not inline in the handler) is what guarantees the worker never reads the
Connector before its `ingesting` transition is durable, and that a rolled-back request enqueues
nothing.
"""

from __future__ import annotations

from app.core.events import Event, EventBus, event_bus
from app.core.logging import get_logger
from app.domains.connectors.events import CONNECTOR_INGESTION_REQUESTED

log = get_logger(__name__)


def _enqueue_ingestion(event: Event) -> None:
    # Imported lazily so importing this module does not pull Celery/tasks (and its transitive
    # ingestion imports) into the request-path import graph at module load.
    from app.workers.celery_app import INGESTION_QUEUE
    from app.workers.tasks import ingest_connector_spec

    ingest_connector_spec.apply_async(
        args=[
            str(event.workspace_id),
            str(event.payload["connector_id"]),
            str(event.payload["source_url"]),
        ],
        queue=INGESTION_QUEUE,
    )
    log.info("connector.ingestion_enqueued", connector_id=event.payload["connector_id"])


def register_connector_subscribers(bus: EventBus = event_bus) -> None:
    """Register the connectors domain's event handlers. Idempotent per process is the caller's
    concern (call once at startup)."""
    bus.subscribe(CONNECTOR_INGESTION_REQUESTED, _enqueue_ingestion)


__all__ = ["register_connector_subscribers"]
