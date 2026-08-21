"""OAuth refresh tasks on the canonical `runtime` queue (M2.5, ADR-0038).

Two tasks with one rule between them: **no secret ever appears in a task argument.** Both carry
identifiers only (`workspace_id`, `connection_id`); the worker re-reads ciphertext from the
database and decrypts through the single boundary. Celery serializes arguments as JSON into the
broker, so a token in an argument would be a plaintext secret at rest in Redis.

- `sweep_refreshes` — the scheduled discovery tick. It runs before any workspace is bound, so it
  reads due credentials through the `auth.due_oauth_refreshes` SECURITY DEFINER carve-out, which
  returns **identifiers only**, then fans out one task per credential with per-task jitter so a
  thousand credentials expiring together do not stampede one provider.
- `refresh_oauth_credential` — one credential, under a row lock, with bounded retry. When the
  retry budget is spent the Connection transitions to `error` and emits `connection.deactivated`
  (D2); `needs_reauth` is derived from that state, never stored (D5).
"""

from __future__ import annotations

import asyncio
import random
import uuid

import structlog
from sqlalchemy import text

from app.core.config import settings
from app.domains.oauth.refresh import RefreshOutcome, mark_refresh_exhausted, refresh_connection
from app.workers.celery_app import (
    REFRESH_SWEEP_INTERVAL_SECONDS,
    RUNTIME_QUEUE,
    celery_app,
)
from app.workers.context import worker_sessions, worker_tenant_uow

log = structlog.get_logger(__name__)

#: How many credentials one tick may schedule. A ceiling, not a target: the sweep runs again in a
#: minute, so a backlog drains steadily instead of flooding the queue in one burst.
SWEEP_BATCH_LIMIT = 500
#: Look this far ahead for credentials about to expire — one sweep interval of headroom beyond
#: the refresh threshold, so nothing slips between ticks.
SWEEP_LOOKAHEAD_SECONDS = 900


@celery_app.task(name="workers.oauth.sweep_refreshes", queue=RUNTIME_QUEUE)
def sweep_refreshes() -> dict[str, int]:
    """Discover credentials due for refresh and fan out one task each, with jitter."""
    if not settings.oauth_enabled:
        return {"scheduled": 0}
    return asyncio.run(_sweep())


async def _sweep() -> dict[str, int]:
    async with worker_sessions() as session, session.begin():
        rows = list(
            await session.execute(
                text(
                    "SELECT workspace_id, connection_id"
                    " FROM auth.due_oauth_refreshes(:within, :limit)"
                ),
                {"within": SWEEP_LOOKAHEAD_SECONDS, "limit": SWEEP_BATCH_LIMIT},
            )
        )
    for row in rows:
        # Jitter across the sweep interval (CONNECTOR_SPECIFICATION §215 requires jittered
        # scheduling): without it every credential minted in the same deploy would refresh in
        # the same second and hammer one provider.
        refresh_oauth_credential.apply_async(
            args=[str(row.workspace_id), str(row.connection_id)],
            queue=RUNTIME_QUEUE,
            countdown=random.uniform(0, REFRESH_SWEEP_INTERVAL_SECONDS),  # noqa: S311
        )
    log.info("oauth.refresh_sweep", scheduled=len(rows))
    return {"scheduled": len(rows)}


@celery_app.task(
    bind=True,
    name="workers.oauth.refresh_credential",
    queue=RUNTIME_QUEUE,
    max_retries=settings.oauth_refresh_max_attempts,
    retry_backoff=True,
    retry_backoff_max=300,
    retry_jitter=True,
)
def refresh_oauth_credential(self: object, workspace_id: str, connection_id: str) -> str:
    """Refresh one Connection's OAuth credential. Arguments are identifiers only."""
    outcome = asyncio.run(_refresh_one(workspace_id, connection_id))
    if outcome is RefreshOutcome.RETRYABLE:
        try:
            raise self.retry(countdown=None)  # type: ignore[attr-defined]
        except Exception as exc:  # MaxRetriesExceededError — the budget is spent
            if type(exc).__name__ != "MaxRetriesExceededError":
                raise
            asyncio.run(_mark_exhausted(workspace_id, connection_id))
            return RefreshOutcome.TERMINAL.value
    return outcome.value


async def _refresh_one(workspace_id: str, connection_id: str) -> RefreshOutcome:
    async with worker_tenant_uow(workspace_id) as uow:
        result = await refresh_connection(
            uow, workspace_id=uuid.UUID(workspace_id), connection_id=uuid.UUID(connection_id)
        )
    return result.outcome


async def _mark_exhausted(workspace_id: str, connection_id: str) -> None:
    async with worker_tenant_uow(workspace_id) as uow:
        await mark_refresh_exhausted(
            uow, workspace_id=uuid.UUID(workspace_id), connection_id=uuid.UUID(connection_id)
        )


__all__ = [
    "SWEEP_BATCH_LIMIT",
    "SWEEP_LOOKAHEAD_SECONDS",
    "refresh_oauth_credential",
    "sweep_refreshes",
]
