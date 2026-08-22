"""Notification subscribers — the bridge from a committed failure to the Celery task.

Two handlers, one task, one dedup key space. Both run **post-commit** (the UnitOfWork dispatches
its buffered events only after COMMIT), so nothing here can observe or influence a transaction that
might still roll back, and a rolled-back health check or refresh enqueues nothing.

Registered explicitly at both composition roots — `app/main.py` for the API process and
`app/workers/celery_app.py` for the worker. **Both** are required and the second is not optional
housekeeping: `connection.deactivated` is published by the OAuth refresh worker, in the worker
process, and a subscriber registered only in the API would never see it. That path is the primary
production value of this feature (nobody is watching when a refresh budget runs out), so registering
in one place would have shipped a feature whose important half never fires.

Handler failures are isolated by the bus (`core/events.py`) and logged, never raised: the publisher
has already committed, so a notification problem must not surface as a failed health check or a
failed token refresh.
"""

from __future__ import annotations

from app.core.events import Event, EventBus, Handler, event_bus
from app.core.logging import get_logger
from app.domains.connections.events import (
    CONNECTION_DEACTIVATED,
    CONNECTION_HEALTH_CHECK_FAILED,
)
from app.domains.notifications.classification import NotificationEvent, notifiable_deactivation

log = get_logger(__name__)


def _enqueue(event: Event, notification: NotificationEvent) -> None:
    """Enqueue one notification task. Identifiers and one closed-vocabulary word, nothing else."""
    # Imported lazily so importing this module does not pull Celery into the request-path import
    # graph — and, more practically, so the worker's composition root can import it without a cycle
    # (celery_app → subscribers → tasks → celery_app).
    from app.workers.celery_app import RUNTIME_QUEUE
    from app.workers.notification_tasks import send_health_notification

    connection_id = str(event.payload["connection_id"])
    send_health_notification.apply_async(
        # The workspace comes from the **envelope**, which `UnitOfWork.buffer_event` already
        # fail-closed-matched against the publishing transaction's bound tenant (ADR-0022). A
        # payload field is never a tenant selector.
        args=[str(event.workspace_id), connection_id, notification.value],
        queue=RUNTIME_QUEUE,
    )
    log.info(
        "notification.enqueued",
        event_type=event.event_type,
        workspace_id=str(event.workspace_id),
        connection_id=connection_id,
        notification=notification.value,
    )


def _on_health_check_failed(event: Event) -> None:
    """A completed health check found the Connection unusable → notify `unhealthy`.

    The connections domain only publishes this event on the unhealthy branch, so there is nothing
    to re-classify: a policy refusal reported `unknown` and never reached the bus.
    """
    _enqueue(event, NotificationEvent.UNHEALTHY)


def _on_connection_deactivated(event: Event) -> None:
    """A Connection left the active set → notify **only** when it did so by failing.

    The `status` discriminator is mandatory (ADR-0041 §10). `error` is the OAuth refresh worker
    exhausting its budget; `pending_auth` is a user revoking their own credential, which is a
    deliberate act and must never generate an alert.
    """
    status = event.payload.get("status")
    notification = notifiable_deactivation(str(status)) if status is not None else None
    if notification is None:
        return
    _enqueue(event, notification)


#: The two (event, handler) pairs, declared once so registration and the idempotence check below
#: cannot drift apart.
_HANDLERS: tuple[tuple[str, Handler], ...] = (
    (CONNECTION_HEALTH_CHECK_FAILED, _on_health_check_failed),
    (CONNECTION_DEACTIVATED, _on_connection_deactivated),
)


def register_notification_subscribers(bus: EventBus = event_bus) -> None:
    """Register the notification handlers, at most once per bus.

    **Idempotent on purpose.** `EventBus.subscribe` appends, and this function is called from two
    composition roots. In production those are two processes and the question never arises, but a
    test process — and any future single-process deployment — imports both `app.main` and
    `app.workers.celery_app`, which would register each handler twice and enqueue two tasks per
    failure. Dedup would still deliver exactly one email, so the duplicate would be invisible in
    behaviour while doubling broker traffic: the kind of defect that survives a test suite. The
    guard makes the second call a no-op instead of relying on nobody ever making it.
    """
    for event_type, handler in _HANDLERS:
        if not bus.is_subscribed(event_type, handler):
            bus.subscribe(event_type, handler)


__all__ = ["register_notification_subscribers"]
