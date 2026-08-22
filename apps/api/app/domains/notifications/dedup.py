"""The notification dedup claim — one Redis round trip, and the whole anti-spam guarantee.

The ratified contract (ADR-0041 §8) is precise about what this buys and what it does not:

    exactly one notification winner within the TTL window

and **not** durable exactly-once delivery. Redis is not durable here. An eviction, a failover, or a
`FLUSHDB` re-arms the key and permits one subsequent duplicate email, which ADR-0041 §9 accepts
explicitly: a dedup miss grants no capability, so its worst outcome is a redundant message. That is
the opposite posture from rate limits and quota, which fail **closed** because they are policy and
failing open would grant unauthorized capability.

**Why `SET key owner NX GET EX ttl` rather than `SET NX` followed by `GET`.** Plain `SET NX` already
gives the mutual exclusion, but it cannot tell a *losing worker* apart from *this same task
retrying*. That distinction matters: `ResendEmailSender` raises on a non-2xx, so the first attempt
can claim the key and then fail to send, and a Celery retry blocked by its own claim would drop the
email silently — dedup would have caused the loss it exists to prevent. Reading the claim's owner in
the same atomic operation resolves it without weakening concurrency: a different owner is still
refused. Doing it as two commands would open a window in which the key expires between them.
Requires Redis ≥ 7.0 (`NX` + `GET` together); the deployment pins `redis:7-alpine`.

The held path deliberately does **not** rewrite the key, so a losing worker cannot slide the window
forward and a busy Connection cannot postpone its own next notification indefinitely.

Nothing here stores PII or secrets. The key is built from two server-derived UUIDs and a member of a
closed vocabulary; the value is a task identifier. No address, token, credential, or provider text
is representable in either.
"""

from __future__ import annotations

import uuid
from enum import StrEnum

from redis.exceptions import RedisError

from app.core.logging import get_logger
from app.core.redis import redis_client
from app.domains.notifications.classification import NotificationEvent

log = get_logger(__name__)


class DedupUnavailableError(Exception):
    """Redis could not answer, so ownership of the window is unknown.

    Deliberately not "assume we won". Sending on an unknown claim converts a Redis outage into a
    mail storm — one message per worker, per retry, per Connection — which is precisely the failure
    the TTL exists to prevent. The caller retries; it does not send.
    """


class ClaimOutcome(StrEnum):
    """Who owns the notification window."""

    #: This caller created the claim. It may send.
    WON = "won"
    #: The claim already exists and belongs to this caller — a retry of the same task. It may send.
    REENTERED = "reentered"
    #: Another caller owns the window. This caller must not send.
    HELD = "held"


def dedup_key(
    *, workspace_id: uuid.UUID, connection_id: uuid.UUID, event: NotificationEvent
) -> str:
    """`ws:{workspace_id}:health-notify:{connection_id}:{event}` — the repository's key grammar.

    Scoped three ways on purpose. **Workspace** so one tenant's notifications can never suppress
    another's, matching every other namespace in the codebase. **Connection** so one failing
    Connection does not silence the rest of the Workspace. **Event** so `unhealthy` and
    `needs_reauth` are separate windows — a Connection that has already reported a provider failure
    must still be able to report that it now needs re-authorization, which is a different problem
    with a different remedy.
    """
    return f"ws:{workspace_id}:health-notify:{connection_id}:{event.value}"


async def claim_window(
    *,
    workspace_id: uuid.UUID,
    connection_id: uuid.UUID,
    event: NotificationEvent,
    owner: str,
    ttl_seconds: int,
) -> ClaimOutcome:
    """Atomically claim the notification window for `owner`, or report who holds it.

    `owner` is the Celery task id — an identifier, never PII. It is what makes a retry of the same
    task distinguishable from a second worker.
    """
    key = dedup_key(workspace_id=workspace_id, connection_id=connection_id, event=event)
    try:
        async with redis_client() as redis:
            # One round trip: sets and returns None when the key was absent, otherwise leaves the
            # key (and its remaining TTL) untouched and returns the existing owner.
            existing = await redis.set(key, owner, nx=True, get=True, ex=ttl_seconds)
    except RedisError as exc:
        # The key is never logged with a value that could identify a person; the workspace and
        # connection ids are reference identifiers the redaction rules deliberately preserve.
        log.warning(
            "notification.dedup_unavailable",
            workspace_id=str(workspace_id),
            connection_id=str(connection_id),
            notification=event.value,
        )
        raise DedupUnavailableError("dedup claim could not be evaluated") from exc

    if existing is None:
        return ClaimOutcome.WON
    return ClaimOutcome.REENTERED if existing == owner else ClaimOutcome.HELD


__all__ = [
    "ClaimOutcome",
    "DedupUnavailableError",
    "claim_window",
    "dedup_key",
]
