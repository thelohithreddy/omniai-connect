"""Celery worker execution foundation — configuration & security (M1.4-B0.2, ADR-0021).

Configuration is asserted against the *real* production `celery_app` (not a fixture), and the
serialization/queue/retry behaviour is exercised through the real task path in eager mode. The
actual broker + worker path is proven separately in tests/integration/test_worker.py.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from kombu.exceptions import EncodeError

from app.workers import tasks
from app.workers.celery_app import (
    DEFAULT_TASK_RETRY,
    INGESTION_QUEUE,
    MAX_RETRIES,
    celery_app,
)

# ------------------------------------------------------------------ serialization security


def test_serialization_is_json_only_never_pickle() -> None:
    conf = celery_app.conf
    assert conf.task_serializer == "json"
    assert conf.result_serializer == "json"
    assert conf.accept_content == ["json"]
    assert "pickle" not in conf.accept_content and "yaml" not in conf.accept_content


def test_a_non_json_argument_cannot_be_serialized_into_a_task() -> None:
    """A pickle serializer would happily marshal an arbitrary object (RCE on the broker). The
    JSON serializer refuses it at send time, so a non-JSON payload can never ride the queue."""
    with pytest.raises(EncodeError):
        tasks.ping.apply_async(args=[object()], queue=INGESTION_QUEUE)


# ------------------------------------------------------------------ broker / results / delivery


def test_no_result_backend() -> None:
    assert celery_app.conf.result_backend is None


def test_at_least_once_delivery_with_late_ack() -> None:
    assert celery_app.conf.task_acks_late is True
    assert celery_app.conf.task_reject_on_worker_lost is True


def test_prefetch_is_one_for_fair_long_job_dispatch() -> None:
    assert celery_app.conf.worker_prefetch_multiplier == 1


def test_utc_is_enabled() -> None:
    assert celery_app.conf.enable_utc is True
    assert celery_app.conf.timezone == "UTC"


# ------------------------------------------------------------------ queue topology


def test_only_the_ingestion_queue_is_declared() -> None:
    assert celery_app.conf.task_default_queue == INGESTION_QUEUE
    assert [q.name for q in celery_app.conf.task_queues] == [INGESTION_QUEUE]


def test_arbitrary_queues_are_not_auto_created() -> None:
    """A task cannot conjure or route itself to an off-topology queue."""
    assert celery_app.conf.task_create_missing_queues is False


def test_the_three_demo_tasks_are_registered() -> None:
    names = {t for t in celery_app.tasks if t.startswith("workers.")}
    assert names == {"workers.ping", "workers.always_fails", "workers.retry_probe"}


def test_the_worker_autodiscovers_tasks_via_include() -> None:
    """The worker imports the tasks module via `include` at startup. This test imports `tasks`
    itself (above), which would mask an empty `include`, so the config the *worker* actually
    uses is asserted directly — an empty include means a worker that registers nothing."""
    assert celery_app.conf.include == ["app.workers.tasks"]


# ------------------------------------------------------------------ bounded execution / retry


def test_execution_is_time_bounded() -> None:
    assert celery_app.conf.task_time_limit == 300
    assert celery_app.conf.task_soft_time_limit == 270
    assert celery_app.conf.task_soft_time_limit < celery_app.conf.task_time_limit


def test_retry_policy_is_bounded_backed_off_and_jittered() -> None:
    assert DEFAULT_TASK_RETRY["max_retries"] == MAX_RETRIES == 5
    assert DEFAULT_TASK_RETRY["retry_backoff"] is True
    assert DEFAULT_TASK_RETRY["retry_jitter"] is True
    assert DEFAULT_TASK_RETRY["retry_backoff_max"] == 60


def test_task_level_retries_are_finite_not_infinite() -> None:
    """Every retrying task declares a finite `max_retries` (infinite retry = `None`), so a
    permanently-failing job dead-letters instead of looping forever. The behavioural proof that
    it actually terminates at the bound is in tests/integration/test_worker.py."""
    assert tasks.retry_probe.max_retries == 5
    assert tasks.always_fails.max_retries == 3
    assert tasks.always_fails.max_retries is not None


def test_production_config_is_never_eager() -> None:
    assert celery_app.conf.task_always_eager is False


# --- eager execution (fast unit path) ---


@pytest.fixture
def eager() -> Iterator[None]:
    """Enable eager execution for the body of a test, then restore production config exactly."""
    conf = celery_app.conf
    prior_eager, prior_prop = conf.task_always_eager, conf.task_eager_propagates
    conf.task_always_eager = True
    conf.task_eager_propagates = True
    try:
        yield
    finally:
        conf.task_always_eager = prior_eager
        conf.task_eager_propagates = prior_prop


def test_ping_executes_and_returns_the_nonce(eager: None) -> None:
    assert tasks.ping.apply(args=["abc123"]).get() == {"pong": "abc123"}
