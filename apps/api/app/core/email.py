"""First-party control-plane email delivery (ADR-0017 §10).

Invitation email is *platform* mail sent by the API — not tenant egress through the
Execution Runtime, the same class of first-party call as the JWKS fetch (ADR-0015 §6). It
goes through Resend. Nothing here logs the recipient's token or the invite URL: the message
body is handed to the provider and never echoed.

The `EmailSender` protocol is the seam tests override (BACKEND_SPEC §3): the real
`ResendEmailSender` is swapped for a capturing fake so CI never sends live mail and never
needs a real Resend key, while the production code path is exercised end-to-end in the one
place it matters — the service that calls `.send(...)`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

import httpx
import structlog

from app.core.config import settings

log = structlog.get_logger(__name__)

RESEND_ENDPOINT = "https://api.resend.com/emails"
EMAIL_SEND_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True, slots=True)
class EmailMessage:
    """One outbound email. `to` is a single recipient; invitations are targeted."""

    to: str
    subject: str
    html: str


class EmailSender(Protocol):
    async def send(self, message: EmailMessage) -> None: ...


@dataclass(frozen=True, slots=True)
class ResendEmailSender:
    """Sends via Resend's HTTP API. Fails loud rather than pretending success.

    A `from` address and an API key are required; without them the sender refuses to
    construct a request rather than silently drop mail. The recipient and subject may be
    logged (operational), but the body — which contains the invite URL and token — is
    never logged.
    """

    api_key: str
    from_address: str

    async def send(self, message: EmailMessage) -> None:
        async with httpx.AsyncClient(timeout=EMAIL_SEND_TIMEOUT_SECONDS) as client:
            response = await client.post(
                RESEND_ENDPOINT,
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "from": self.from_address,
                    "to": [message.to],
                    "subject": message.subject,
                    "html": message.html,
                },
            )
            response.raise_for_status()
        log.info("email.sent", to=message.to, subject=message.subject)


@dataclass
class CapturingEmailSender:
    """Test double: records messages instead of sending. Never used in production."""

    sent: list[EmailMessage] = field(default_factory=list)

    async def send(self, message: EmailMessage) -> None:
        self.sent.append(message)


def get_email_sender() -> EmailSender:
    """FastAPI dependency: the configured production sender.

    Tests override this via `app.dependency_overrides` with a `CapturingEmailSender`, so no
    live mail is sent and the invite token can be asserted on — the seam, not a patch.
    """
    return ResendEmailSender(
        api_key=settings.resend_api_key.get_secret_value(),
        from_address=settings.invitation_from_email,
    )
