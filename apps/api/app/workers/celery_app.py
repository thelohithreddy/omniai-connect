"""Celery application for OmniAI background work (M1.4-B0.2, ADR-0007/ADR-0021).

The execution substrate future connector-spec ingestion will run on. It is deliberately
tenant-unaware: binding a WorkspaceContext / GUC to a task is B0.3, publishing events is B0.4,
R2 is B0.5, and the OpenAPI/Swagger importer is M1.4-B1. What this module guarantees is a
hardened execution *boundary* those slices build on without redesigning the worker.

Every security-sensitive setting is explicit — Celery's defaults are not trusted:

- **JSON only.** `task_serializer`/`result_serializer` = json, `accept_content` = ['json'].
  Pickle is remote code execution on the broker; it can never be accepted.
- **No result backend.** Correctness never depends on a persisted return value — a task's
  effect is its own (idempotent) side effect, not a stored result.
- **One declared queue, `ingestion`, no auto-creation.** `task_create_missing_queues=False`
  means a task cannot conjure or route itself to an arbitrary queue.
- **At-least-once with late ack.** `task_acks_late` + `task_reject_on_worker_lost`: a task is
  acknowledged only after it finishes, so a crashed worker's job is redelivered, not lost.
  Duplicate execution is therefore possible — tasks must be idempotent (owned from B0.3).
- **Bounded execution.** Hard/soft time limits stop a hung/hostile job holding a slot forever;
  `worker_prefetch_multiplier=1` stops one worker hoarding long ingestion jobs.
- **Never eager in production.** `task_always_eager=False`; eager is a test-only override, and
  a test asserts production never inherits it.
"""

from __future__ import annotations

from celery import Celery
from kombu import Queue

from app.core.config import settings
from app.core.logging import configure_logging

#: The queue the ingestion pipeline runs on.
INGESTION_QUEUE = "ingestion"
#: The canonical queue for runtime-adjacent background work — today the OAuth token refresh
#: worker (CONNECTOR_ENGINE §8 names this queue explicitly). Declared, never auto-created.
RUNTIME_QUEUE = "runtime"

#: How often the refresh sweep runs. It only *discovers* due credentials and fans out one task
#: per credential, so the tick is cheap; individual refreshes carry their own jitter.
REFRESH_SWEEP_INTERVAL_SECONDS = 60.0

#: Retry foundation for future ingestion tasks (BACKEND_SPEC §5, CONNECTOR_ENGINE §4): bounded,
#: exponential, jittered. Applied per-task (each task opts into its own transient exceptions via
#: `autoretry_for`) rather than as a global that would silently retry non-idempotent work.
MAX_RETRIES = 5
RETRY_BACKOFF_MAX_SECONDS = 60
DEFAULT_TASK_RETRY: dict[str, object] = {
    "max_retries": MAX_RETRIES,
    "retry_backoff": True,
    "retry_backoff_max": RETRY_BACKOFF_MAX_SECONDS,
    "retry_jitter": True,
}

#: Bounded execution (§12). Soft limit lets a task clean up (SoftTimeLimitExceeded) before the
#: hard limit kills the worker process. Conservative infra defaults; tuned when ingestion lands.
TASK_HARD_TIME_LIMIT_SECONDS = 300
TASK_SOFT_TIME_LIMIT_SECONDS = 270

# The worker uses the app's structlog config, not Celery's root-logger hijack.
configure_logging()

celery_app = Celery(
    "omniai",
    broker=settings.resolved_celery_broker_url,
    # Deterministic, explicit task registration — no import-time autodiscovery magic
    # (CONNECTOR_SPECIFICATION §15 registration discipline).
    include=["app.workers.tasks", "app.workers.oauth_tasks", "app.workers.vault_tasks"],
)

celery_app.conf.update(
    # --- serialization: JSON only, never pickle/yaml -------------------------------------
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    # --- results: none; correctness never depends on stored results ----------------------
    result_backend=None,
    # --- time / tz -----------------------------------------------------------------------
    timezone="UTC",
    enable_utc=True,
    # --- delivery: at-least-once, late ack, redeliver on worker loss ---------------------
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    # --- fairness: one long job at a time per worker slot --------------------------------
    worker_prefetch_multiplier=1,
    # --- queue topology: one declared queue, no client-chosen/auto queues ----------------
    task_default_queue=INGESTION_QUEUE,
    task_queues=(Queue(INGESTION_QUEUE), Queue(RUNTIME_QUEUE)),
    task_create_missing_queues=False,
    # --- scheduler: OAuth refresh discovery (M2.5) and vault key re-wrap (M2.6) ------------
    beat_schedule={
        "oauth-refresh-sweep": {
            "task": "workers.oauth.sweep_refreshes",
            "schedule": REFRESH_SWEEP_INTERVAL_SECONDS,
            "options": {"queue": RUNTIME_QUEUE, "expires": REFRESH_SWEEP_INTERVAL_SECONDS},
        },
        # Idle until an operator introduces a new key version; then it drains the backlog toward
        # the ratified 24h re-wrap target. `expires` keeps a tick from piling up behind an outage:
        # a missed rotation tick is not worth replaying, the next one sees the same work.
        "vault-key-rotation-sweep": {
            "task": "workers.vault.sweep_key_rotations",
            "schedule": settings.credential_rotation_sweep_seconds,
            "options": {
                "queue": RUNTIME_QUEUE,
                "expires": settings.credential_rotation_sweep_seconds,
            },
        },
    },
    # --- bounded execution ---------------------------------------------------------------
    task_time_limit=TASK_HARD_TIME_LIMIT_SECONDS,
    task_soft_time_limit=TASK_SOFT_TIME_LIMIT_SECONDS,
    # --- never eager in production; a test overrides this for fast unit runs only ---------
    task_always_eager=False,
    task_track_started=True,
    # --- broker resilience: retry the initial connection instead of crash-looping ---------
    broker_connection_retry_on_startup=True,
    worker_hijack_root_logger=False,
)


__all__ = [
    "DEFAULT_TASK_RETRY",
    "INGESTION_QUEUE",
    "REFRESH_SWEEP_INTERVAL_SECONDS",
    "RUNTIME_QUEUE",
    "MAX_RETRIES",
    "TASK_HARD_TIME_LIMIT_SECONDS",
    "TASK_SOFT_TIME_LIMIT_SECONDS",
    "celery_app",
]
