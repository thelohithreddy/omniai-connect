"""Real broker + real worker execution (M1.4-B0.2, §17/§11/§25).

Not eager: an in-process Celery worker (`start_worker`) consumes the `ingestion` queue over the
real Redis broker and executes real tasks, proving the production execution *machinery* works —
a cached/eager-only test would not be that proof.

A dedicated app on an isolated broker DB is used, configured exactly like the production
`celery_app` (JSON-only, `ingestion` queue, late-ack, no auto-queues, never eager). Isolation is
deliberate: the docker-compose `worker` service already consumes `ingestion` on the default DB
and would otherwise race these tasks. The production app's own config/serialization/queue/eager
behaviour is asserted directly in tests/unit/test_celery_app.py.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Iterator

import pytest
from celery import Celery
from celery.contrib.testing.worker import start_worker
from kombu import Queue
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.config import settings
from app.workers.celery_app import INGESTION_QUEUE
from app.workers.context import worker_tenant_uow
from tests.conftest import SeededWorkspace


def _isolated(db: int) -> str:
    """A redis URL on a high, otherwise-unused logical DB, derived from the configured broker so
    it is portable (local `redis:6379`, CI `localhost:6379`) and never the app's default DB."""
    base = settings.resolved_celery_broker_url.rsplit("/", 1)[0]
    return f"{base}/{db}"


# A dedicated app mirroring production config, on an isolated broker/result DB.
worker_app = Celery("b0-worker-test", broker=_isolated(15), backend=_isolated(14))
worker_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_default_queue=INGESTION_QUEUE,
    task_queues=(Queue(INGESTION_QUEUE),),
    task_create_missing_queues=False,
    task_always_eager=False,
    enable_utc=True,
    timezone="UTC",
)

_attempts: list[str] = []


class _TransientError(Exception):
    """Retryable error for the bounded-retry probe."""


@worker_app.task(name="b0.echo")
def echo(marker: str) -> dict[str, str]:
    return {"echo": marker}


@worker_app.task(
    name="b0.always_fails",
    bind=True,
    autoretry_for=(_TransientError,),
    max_retries=3,
    retry_backoff=False,
    default_retry_delay=0,
)
def always_fails(self: object, marker: str) -> None:  # noqa: ARG001
    _attempts.append(marker)
    raise _TransientError(marker)


@worker_app.task(name="b0.tenant_count")
def tenant_count(workspace_id: str) -> int:
    """Runs the PRODUCTION worker tenant boundary (`worker_tenant_uow`) inside a real worker,
    the prefork idiom (`asyncio.run`): binds the workspace GUC and counts connectors visible
    under RLS. Proves the full Redis → worker → UnitOfWork → GUC → RLS path for a tenant task."""

    async def _run() -> int:
        async with worker_tenant_uow(workspace_id) as uow:
            return int(await uow.session.scalar(text("SELECT count(*) FROM connectors")) or 0)

    return asyncio.run(_run())


def _wait_until(predicate: object, timeout: float = 20.0, interval: float = 0.2) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():  # type: ignore[operator]
            return True
        time.sleep(interval)
    return False


@pytest.fixture
def live_worker() -> Iterator[None]:
    with start_worker(
        worker_app,
        queues=[INGESTION_QUEUE],
        perform_ping_check=False,
        loglevel="warning",
        shutdown_timeout=30,
    ):
        yield


def test_a_task_travels_the_real_broker_and_executes_on_a_worker(live_worker: None) -> None:
    """A task enqueued over Redis is picked up and run by a real worker; its return value is read
    back through the result backend — the real production execution path, not eager."""
    result = echo.apply_async(args=["real-broker-nonce"], queue=INGESTION_QUEUE)
    assert result.get(timeout=20) == {"echo": "real-broker-nonce"}


def test_retry_is_bounded_over_the_real_worker_path(live_worker: None) -> None:
    """A permanently-failing task retries over the real broker and terminates at max_retries=3 —
    attempted exactly 4 times (1 + 3 retries), never an infinite loop. Observed via the attempt
    log the in-process worker thread shares."""
    _attempts.clear()
    always_fails.apply_async(args=["retry-marker"], queue=INGESTION_QUEUE)
    assert _wait_until(lambda: len(_attempts) >= 4), f"expected 4 attempts, saw {len(_attempts)}"
    time.sleep(1.0)  # settle: assert it stopped at the bound, no runaway
    assert len(_attempts) == 4


async def test_a_real_worker_runs_a_tenant_scoped_task_under_rls(
    live_worker: None, admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """A real worker executes the production tenant boundary end to end: seed 2 connectors in A,
    enqueue the tenant task for A, and the worker (binding A's GUC, filtered by RLS) returns 2 —
    the full Redis → worker → UnitOfWork → GUC → RLS path, not eager, not in-process."""
    async with admin_engine.begin() as conn:
        for i in range(2):
            await conn.execute(
                text(
                    "INSERT INTO connectors (id, workspace_id, name, slug, source_type, base_url,"
                    " status) VALUES (:i, :w, :n, :s, 'manual', 'https://api.example.com', 'draft')"
                ),
                {"i": uuid.uuid4(), "w": workspace_a.id, "n": f"t{i}", "s": f"t{i}"},
            )
    result = tenant_count.apply_async(args=[str(workspace_a.id)], queue=INGESTION_QUEUE)
    assert result.get(timeout=20) == 2
