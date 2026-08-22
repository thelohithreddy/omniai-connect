"""Credential key-rotation tasks on the canonical `runtime` queue (M2.6, ADR-0039).

Same rule as the OAuth tasks, for the same reason: **no secret ever appears in a task argument.**
Celery serializes arguments as JSON into the broker, so anything passed here is plaintext at rest
in Redis. These tasks carry `workspace_id` and `credential_id` and nothing else — no ciphertext, no
DEK, no KEK, no key material of any kind. The worker re-reads the row from the database and works
through the vault.

The target version is deliberately **not** a task argument either. It is process configuration
(`CREDENTIAL_KEY_VERSION`), read at execution time, so a task that sat in the queue across a
config change re-wraps toward the version that is actually current rather than a stale target it
was born with.

- `sweep_key_rotations` — the scheduled tick. Runs before any workspace is bound, so it discovers
  work through the `auth.pending_key_rotations` SECURITY DEFINER carve-out (identifiers only) and
  fans out with per-task jitter. It also logs `pending` — the retirement gate's live reading, so
  "is the rotation finished?" is answerable from the logs without a DB session.
- `rewrap_credential_key` — one credential, under a row lock, re-wrapping the DEK only.

Idle cost when no rotation is in progress: one indexed COUNT returning 0 and no fan-out.
"""

from __future__ import annotations

import asyncio
import random
import uuid

import structlog
from sqlalchemy import text

from app.core.config import settings
from app.domains.credentials import vault
from app.domains.credentials.rotation import RewrapOutcome, count_pending, rewrap_credential
from app.workers.celery_app import RUNTIME_QUEUE, celery_app
from app.workers.context import worker_sessions, worker_tenant_uow

log = structlog.get_logger(__name__)

#: How many credentials one tick may schedule. A ceiling, not a target: the sweep runs again
#: shortly, so a backlog drains steadily instead of flooding the queue in one burst.
ROTATION_BATCH_LIMIT = 500


@celery_app.task(name="workers.vault.sweep_key_rotations", queue=RUNTIME_QUEUE)
def sweep_key_rotations() -> dict[str, int]:
    """Discover credentials below the active key version and fan out one re-wrap task each."""
    if not settings.credential_rotation_enabled:
        return {"scheduled": 0, "pending": 0}
    return asyncio.run(_sweep())


async def _sweep() -> dict[str, int]:
    target = vault.active_key_version()
    async with worker_sessions() as session, session.begin():
        pending = await count_pending(session, target_version=target)
        rows = list(
            await session.execute(
                text(
                    "SELECT workspace_id, credential_id"
                    " FROM auth.pending_key_rotations(:target, :limit)"
                ),
                {"target": target, "limit": ROTATION_BATCH_LIMIT},
            )
        )
    for row in rows:
        # Jitter across the sweep interval: without it a whole batch would re-wrap in the same
        # second and contend on the same connection pool.
        rewrap_credential_key.apply_async(
            args=[str(row.workspace_id), str(row.credential_id)],
            queue=RUNTIME_QUEUE,
            countdown=random.uniform(0, settings.credential_rotation_sweep_seconds),  # noqa: S311
        )
    # `pending` is the retirement gate's reading at this instant. It is the number that must reach
    # 0 — and stay 0 across the ratified overlap — before an old KEK may leave the keyring.
    log.info("vault.rotation_sweep", target_version=target, pending=pending, scheduled=len(rows))
    return {"scheduled": len(rows), "pending": pending}


@celery_app.task(name="workers.vault.rewrap_credential_key", queue=RUNTIME_QUEUE)
def rewrap_credential_key(workspace_id: str, credential_id: str) -> str:
    """Re-wrap one Credential's DEK to the active key version. Arguments are identifiers only.

    No retry policy: re-wrap is idempotent and the sweep is periodic, so a failed attempt is simply
    picked up by the next tick. That is strictly safer than a retry ladder here — a transient error
    resolves on its own schedule, and a persistent one (a retired key) needs an operator, not
    another attempt.
    """
    return asyncio.run(_rewrap_one(workspace_id, credential_id))


async def _rewrap_one(workspace_id: str, credential_id: str) -> str:
    target = vault.active_key_version()
    async with worker_tenant_uow(workspace_id) as uow:
        outcome: RewrapOutcome = await rewrap_credential(
            uow,
            workspace_id=uuid.UUID(workspace_id),
            credential_id=uuid.UUID(credential_id),
            to_version=target,
        )
    return outcome.value


__all__ = ["ROTATION_BATCH_LIMIT", "rewrap_credential_key", "sweep_key_rotations"]
