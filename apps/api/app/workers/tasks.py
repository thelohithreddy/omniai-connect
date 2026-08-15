"""Demonstration tasks for the worker execution foundation (M1.4-B0.2).

These exist ONLY to prove the substrate: registration, routing, JSON serialization, broker
delivery, worker execution, and bounded retry. They deliberately touch **no** connector, **no**
database, **no** R2, and **no** event bus, and they carry **no** tenant authority — a task
payload is never trusted for identity, role, or permission. Tenant context is B0.3.

Nothing here logs a payload dump: only the task's own id (via Celery) and non-secret values.
"""

from __future__ import annotations

import asyncio

import structlog
from sqlalchemy import text

from app.workers.celery_app import DEFAULT_TASK_RETRY, celery_app
from app.workers.context import worker_tenant_uow

log = structlog.get_logger(__name__)


class TransientTaskError(Exception):
    """A retryable failure, used to exercise the bounded-retry path deterministically."""


@celery_app.task(name="workers.ping")
def ping(nonce: str) -> dict[str, str]:
    """Return the nonce — a DB-free, side-effect-free proof that a worker executed the task.

    The single scalar argument is JSON-serializable by construction; no ORM object, request,
    context, or secret is ever passed. Logs the non-secret nonce only.
    """
    log.info("worker.ping", nonce=nonce)
    return {"pong": nonce}


@celery_app.task(name="workers.count_visible_connectors")
def count_visible_connectors(workspace_id: str) -> int:
    """Demo TENANT task (B0.3): count the connectors visible under the bound workspace — i.e.
    only *this* tenant's, enforced by RLS. Proves the worker → UnitOfWork → transaction-local
    GUC → RLS boundary end to end.

    Read-only, creates nothing. `workspace_id` is the tenant *selector* only; no role,
    permission, member id, or identity is read from the payload — the persisted DB + RLS decide
    what is visible. Runs the async boundary in a fresh loop (`asyncio.run`), the prefork-worker
    idiom.
    """

    async def _run() -> int:
        async with worker_tenant_uow(workspace_id) as uow:
            count = await uow.session.scalar(text("SELECT count(*) FROM connectors"))
            return int(count or 0)

    return asyncio.run(_run())


# A separate, fast probe (no backoff) so the *bounded-retry behaviour* is observable in a unit
# test without real sleeps. The production retry *policy* (backoff + jitter + max_retries=5) is
# `DEFAULT_TASK_RETRY`, asserted directly and applied to `retry_probe` below.
_probe_attempts: list[str] = []


@celery_app.task(
    bind=True,
    name="workers.always_fails",
    autoretry_for=(TransientTaskError,),
    max_retries=3,
    retry_backoff=False,
    retry_jitter=False,
    default_retry_delay=0,
)
def always_fails(self: object, marker: str) -> None:  # noqa: ARG001  (bind gives `self`)
    """Always raises a transient error. Retries are BOUNDED (max_retries=3) — terminal after
    the limit, never an infinite loop. `default_retry_delay=0` lets the real worker exhaust the
    retries immediately so the behaviour is observable without a slow test. Records each attempt
    (the in-process test worker shares this module) so the test can assert the exact count."""
    _probe_attempts.append(marker)
    raise TransientTaskError(marker)


@celery_app.task(
    bind=True, name="workers.retry_probe", autoretry_for=(TransientTaskError,), **DEFAULT_TASK_RETRY
)
def retry_probe(self: object, marker: str) -> str:  # noqa: ARG001
    """Carries the production retry *policy* (`DEFAULT_TASK_RETRY`): bounded, exponential,
    jittered. Demo only — proves the policy attaches to a task."""
    raise TransientTaskError(marker)


__all__ = ["TransientTaskError", "always_fails", "ping", "retry_probe"]
