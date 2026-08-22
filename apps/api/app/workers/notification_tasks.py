"""Connection Health notification delivery on the canonical `runtime` queue (M2.10, ADR-0041).

One task, three arguments, all of them identifiers or members of a closed vocabulary. Celery
serializes arguments as JSON into the broker, so an address in a signature would be **PII at rest in
Redis** and a credential would be a plaintext secret there — the same rule the OAuth and vault tasks
already follow, applied to a different kind of sensitive value.

The destination is **not** an argument. It is read server-side from the Workspace row inside the
task's own tenant-bound transaction, which is what makes this task structurally incapable of being
used to mail an arbitrary address: there is no parameter through which one could be supplied, and a
crafted queue entry can only ever cause a Workspace to be notified at the address its own owner
configured.

Retry semantics matter here more than usual. `ResendEmailSender` raises on a non-2xx, so the first
attempt can claim the dedup window and *then* fail to send. Celery preserves the task id across
`self.retry`, and the claim is stored under that id, so a retry re-enters its own window and still
delivers — while a genuinely different worker is refused. Deduplication therefore discriminates
between *workers*, not between *attempts*, which is the boundary ADR-0041 §7 requires.
"""

from __future__ import annotations

import asyncio
import uuid

import structlog

from app.core.email import EmailSender, get_notification_email_sender
from app.core.security import CallerIdentity, WorkspaceContext
from app.domains.notifications.classification import parse_event
from app.domains.notifications.dedup import DedupUnavailableError
from app.domains.notifications.repository import NotificationRepository
from app.domains.notifications.service import HealthNotificationService, NotificationOutcome
from app.workers.celery_app import (
    MAX_RETRIES,
    RETRY_BACKOFF_MAX_SECONDS,
    RUNTIME_QUEUE,
    celery_app,
)
from app.workers.context import WorkerContextError, validate_workspace_id, worker_tenant_uow

log = structlog.get_logger(__name__)

#: Refused before any work. A task argument that is not a UUID, or an event word outside the closed
#: vocabulary, is a malformed or crafted queue entry — not something to coerce into meaning.
REJECTED = "rejected"


def _email_sender() -> EmailSender:
    """The sender this task uses. A module-level seam, because a Celery task cannot use FastAPI's
    `dependency_overrides`; tests monkeypatch this name exactly as the OAuth worker tests do."""
    return get_notification_email_sender()


def _context(workspace_id: uuid.UUID) -> WorkspaceContext:
    """The worker acts as the platform, not as a member or a token holder — the same shape the
    OAuth refresh worker uses. The workspace is the one already bound on the transaction; this
    object carries it to the repository, it does not choose it."""
    return WorkspaceContext(
        workspace_id=workspace_id,
        caller=CallerIdentity(kind="api_token", api_token_id=None),
        request_id="health_notification",
    )


@celery_app.task(
    bind=True,
    name="workers.notifications.send_health_notification",
    queue=RUNTIME_QUEUE,
    max_retries=MAX_RETRIES,
    retry_backoff=True,
    retry_backoff_max=RETRY_BACKOFF_MAX_SECONDS,
    retry_jitter=True,
)
def send_health_notification(
    self: object, workspace_id: str, connection_id: str, event: str
) -> str:
    """Deliver one Connection Health failure notification. Arguments are identifiers only."""
    try:
        workspace = validate_workspace_id(workspace_id)
        connection = uuid.UUID(connection_id)
    except (WorkerContextError, ValueError, TypeError):
        # `validate_workspace_id` raises WorkerContextError, not ValueError. Catching only the
        # latter let a crafted queue entry crash the task into Celery's retry ladder instead of
        # being refused once — found by the malformed-argument test.
        log.warning("notification.rejected_bad_identifier")
        return REJECTED

    notification = parse_event(event)
    if notification is None:
        log.warning("notification.rejected_unknown_event", workspace_id=str(workspace))
        return REJECTED

    # The Celery task id owns the dedup window. It is stable across `self.retry` — which is what
    # lets a retry re-enter — and distinct per dispatch, which is what keeps two workers apart. A
    # missing id (a direct in-process call, never production) falls back to a fresh value rather
    # than to something derived from the arguments: a derived owner would make *every* caller
    # re-enter the same window and silently destroy the concurrency guarantee.
    request_id = getattr(self, "request", None)
    owner = str(getattr(request_id, "id", None) or uuid.uuid4())

    try:
        outcome = asyncio.run(_send(workspace, connection, notification.value, owner))
    except DedupUnavailableError as exc:
        # Ownership of the window is unknown. Sending anyway would turn a Redis outage into one
        # message per worker per retry; the health verdict is already committed and is untouched.
        raise self.retry(exc=exc) from exc  # type: ignore[attr-defined]

    return outcome


async def _send(workspace_id: uuid.UUID, connection_id: uuid.UUID, event: str, owner: str) -> str:
    notification = parse_event(event)
    assert notification is not None  # noqa: S101 — validated by the caller; narrows the type
    async with worker_tenant_uow(str(workspace_id)) as uow:
        service = HealthNotificationService(
            NotificationRepository(uow.session, _context(workspace_id)),
            _email_sender(),
        )
        outcome: NotificationOutcome = await service.notify(
            workspace_id=workspace_id,
            connection_id=connection_id,
            event=notification,
            owner=owner,
        )
    return outcome.value


__all__ = ["REJECTED", "send_health_notification"]
