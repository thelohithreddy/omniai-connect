"""What counts as a notifiable failure. Pure, dependency-free, and the only place that decides.

Deliberately imports nothing from another domain. It deals in its own closed vocabulary and in the
state *words* the connections domain already publishes on the bus, so "which failures notify" can be
read, tested, and mutated in one file without dragging health projection or the Runtime into scope.

The ratified transition matrix (ADR-0041 §8) is satisfied by two facts and no state comparison:

    healthy      → unhealthy      notify        unknown → unhealthy      notify
    unhealthy    → unhealthy      notify (dedup suppresses)
    healthy      → needs_reauth   notify        unknown → needs_reauth   notify
    needs_reauth → needs_reauth   notify (dedup suppresses)
    healthy      → healthy        no            unhealthy → healthy      no
    needs_reauth → healthy        no            anything → unknown       no

Every "notify" row depends only on the state being *entered*, and every "no" row likewise. That is
not a shortcut — it is the ratified design: **deduplication is the anti-spam mechanism, not edge
detection.** ADR-0041 §8 states the guarantee as "at most one notification winner per Connection per
failure event type within the TTL window", which is a property of the Redis claim. Deriving the
prior state would add a query, a second source of truth about history, and a failure mode, and would
change no row. The tests enumerate all nine pairs regardless, so the claim is proven, not argued.

`unknown` never notifies, and that is load-bearing rather than incidental: `unknown` is exactly what
the health service reports for a **platform** refusal — `rate_limited`, `quota_exceeded`, or a Redis
outage failing closed — which says nothing about the Connection (ADR-0040 §5). Treating it as a
failure would email a Workspace every time its weekly quota ran out.
"""

from __future__ import annotations

from enum import StrEnum

#: The persisted `connections.status` word that means an OAuth Connection's refresh budget is spent
#: and only a human can recover it (ADR-0038 D2/D5). The *other* deactivation word is
#: `pending_auth`, which is a user revoking their own credential — a deliberate act, not a failure.
_ERROR_STATUS = "error"


class NotificationEvent(StrEnum):
    """The closed vocabulary of notifiable failures.

    Closed because this value is both a Celery argument and a component of the Redis dedup key.
    Free text in either position would let a caller widen the key space or push an arbitrary
    payload into the broker; an enum makes both structurally impossible.
    """

    #: A completed health check found the provider unusable.
    UNHEALTHY = "unhealthy"
    #: The OAuth credential is spent; only a human re-authorizing recovers the Connection.
    NEEDS_REAUTH = "needs_reauth"


def notifiable_deactivation(status: str) -> NotificationEvent | None:
    """The notification a `connection.deactivated` event warrants, or None.

    `connection.deactivated` is emitted from two places with two different meanings, and the
    payload's `status` word is what tells them apart (ADR-0034): `error` is the OAuth refresh worker
    giving up — unattended, and the failure this feature exists for — while `pending_auth` is a user
    revoking their own credential on purpose. Notifying on the second would email people for their
    own deliberate actions, so the discriminator is mandatory rather than defensive.
    """
    return NotificationEvent.NEEDS_REAUTH if status == _ERROR_STATUS else None


def parse_event(raw: str) -> NotificationEvent | None:
    """Parse a task argument back into the vocabulary; None if it is not a member.

    A Celery argument arrives as JSON from the broker, so it is a string that *should* be one of two
    words. Validating rather than trusting means a malformed or crafted queue entry is refused
    before it can reach a dedup key or an email template.
    """
    try:
        return NotificationEvent(raw)
    except ValueError:
        return None


__all__ = ["NotificationEvent", "notifiable_deactivation", "parse_event"]
