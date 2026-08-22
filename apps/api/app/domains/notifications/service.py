"""Delivering one Connection Health failure notification. The single path both triggers share.

Order is the design. The destination and the Connection are resolved *before* the dedup window is
claimed, so a Workspace with no destination — the default — never consumes a 24-hour window it
would then be unable to use. The claim comes last before sending, so it is held for as short a time
as the work allows.

This service has no authority over health. It reads two rows and sends a message. It never writes
`connections`, never touches `tool_calls`, never opens a credential, and never re-enters the
Runtime. That is not merely current behaviour: nothing here imports a vault, an HTTP client, or
`RuntimeService`, so the property is structural rather than a promise.
"""

from __future__ import annotations

import uuid
from enum import StrEnum

from app.core.config import settings
from app.core.email import EmailMessage, EmailSender
from app.core.logging import get_logger
from app.domains.notifications import messages
from app.domains.notifications.classification import NotificationEvent
from app.domains.notifications.dedup import ClaimOutcome, claim_window
from app.domains.notifications.repository import NotificationRepository

log = get_logger(__name__)


class NotificationOutcome(StrEnum):
    """What one notification attempt actually did. Every branch is a first-class, logged result."""

    #: The message was handed to the provider.
    SENT = "sent"
    #: The Workspace has configured no destination. Not an error — notification is opt-in.
    NO_DESTINATION = "no_destination"
    #: The Connection is gone (deleted, or never in this tenant). Nothing to report.
    NO_CONNECTION = "no_connection"
    #: Another worker owns the window. Exactly one of them sends; this is the other one.
    DUPLICATE_SUPPRESSED = "duplicate_suppressed"
    #: The feature is switched off.
    DISABLED = "disabled"


class HealthNotificationService:
    """Sends one notification. Constructed per task, scoped to one Workspace."""

    def __init__(self, repository: NotificationRepository, email_sender: EmailSender) -> None:
        self._repository = repository
        self._email_sender = email_sender

    async def notify(
        self,
        *,
        workspace_id: uuid.UUID,
        connection_id: uuid.UUID,
        event: NotificationEvent,
        owner: str,
        reason_code: str | None = None,
    ) -> NotificationOutcome:
        """Deliver one failure notification, or explain why it was not delivered.

        `owner` identifies the claimant — the Celery task id — so a retry of the same task can
        re-enter its own window while a different worker is still refused.

        Raises only what the caller should retry on: `DedupUnavailableError` when Redis cannot say
        who owns the window, and whatever the email provider raises. Both leave every other piece
        of state exactly as it was.
        """
        if not settings.connection_health_notifications_enabled:
            return NotificationOutcome.DISABLED

        destination = await self._repository.destination()
        if destination is None:
            log.info(
                "notification.skipped_no_destination",
                workspace_id=str(workspace_id),
                connection_id=str(connection_id),
                notification=event.value,
            )
            return NotificationOutcome.NO_DESTINATION

        connection = await self._repository.connection(connection_id)
        if connection is None:
            log.info(
                "notification.skipped_unknown_connection",
                workspace_id=str(workspace_id),
                connection_id=str(connection_id),
                notification=event.value,
            )
            return NotificationOutcome.NO_CONNECTION

        outcome = await claim_window(
            workspace_id=workspace_id,
            connection_id=connection_id,
            event=event,
            owner=owner,
            ttl_seconds=settings.health_notification_dedup_ttl_seconds,
        )
        if outcome is ClaimOutcome.HELD:
            log.info(
                "notification.duplicate_suppressed",
                workspace_id=str(workspace_id),
                connection_id=str(connection_id),
                notification=event.value,
            )
            return NotificationOutcome.DUPLICATE_SUPPRESSED

        await self._email_sender.send(
            EmailMessage(
                to=destination,
                subject=messages.subject(connection_name=connection.name, event=event),
                html=messages.html_body(
                    connection_name=connection.name, event=event, reason_code=reason_code
                ),
            )
        )
        # The destination is deliberately absent from this record. `EmailSender` already logs the
        # recipient at the transport boundary (one place, operationally necessary); repeating it
        # here would spread an address across the log stream for no additional diagnostic value.
        log.info(
            "notification.sent",
            workspace_id=str(workspace_id),
            connection_id=str(connection_id),
            notification=event.value,
            claim=outcome.value,
        )
        return NotificationOutcome.SENT


__all__ = ["HealthNotificationService", "NotificationOutcome"]
