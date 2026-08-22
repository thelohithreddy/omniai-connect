"""Connection Health failure notifications end to end (M2.10, ROADMAP §58, ADR-0041).

Real Postgres, real RLS, real Redis, the real event bus, the real Runtime, the real Celery task.
Only two things are substituted, and both are the outermost socket: the guarded egress call (so the
provider can be made to fail on demand) and the email transport (so CI sends no live mail). Every
decision under test — what is notifiable, who owns the dedup window, which address is used, what the
message may contain — runs its production code path.

The claims that matter here are negative ones, so each is paired with a positive control: a test
that proves no email was sent is worthless beside a test that proves an email *would* have been.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

import httpx
import pytest
from httpx import AsyncClient
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core import net
from app.core.email import EmailMessage
from app.core.events import event_bus
from app.core.redis import redis_client
from app.domains.connections.events import connection_deactivated
from app.domains.notifications.classification import NotificationEvent
from app.domains.notifications.dedup import dedup_key
from app.workers import notification_tasks
from app.workers.notification_tasks import send_health_notification
from tests.conftest import FakeJWKSEndpoint, SeededWorkspace, SigningAuthority, bearer
from tests.integration.test_connection_health_api import seed
from tests.integration.test_human_auth import seed_member

WS_HEADER = "X-Workspace-Id"

#: Distinct canaries so a leak is attributable. The credential canary is the one `seed()` stores.
CREDENTIAL_CANARY = "M2_7_HEALTH_CANARY_value"
DESTINATION = "m210-dest-canary@example.com"
OTHER_DESTINATION = "m210-other-canary@example.com"


class _Egress:
    """The one guarded outbound call, faked so the provider can be made to fail deliberately."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.exc: Exception | None = None
        self.status = 200

    async def __call__(self, method: str, url: str, **_: object) -> net.GuardedResponse:
        self.calls.append(url)
        if self.exc is not None:
            raise self.exc
        return net.GuardedResponse(
            status_code=self.status,
            headers=httpx.Headers({"content-type": "application/json"}),
            body=b'{"ok":true}',
            truncated=False,
        )


@pytest.fixture
def egress(monkeypatch: pytest.MonkeyPatch) -> _Egress:
    fake = _Egress()
    monkeypatch.setattr("app.core.net.request", fake)
    return fake


class _Mailbox:
    """Captures what would have been sent. Records failures rather than swallowing them."""

    def __init__(self) -> None:
        self.sent: list[EmailMessage] = []
        self.exc: Exception | None = None

    async def send(self, message: EmailMessage) -> None:
        if self.exc is not None:
            raise self.exc
        self.sent.append(message)


@pytest.fixture
def mailbox(monkeypatch: pytest.MonkeyPatch) -> _Mailbox:
    """Substitutes the transport at the task's own seam — a Celery task cannot use
    `app.dependency_overrides`, so the module-level factory is the override point."""
    box = _Mailbox()
    monkeypatch.setattr(notification_tasks, "_email_sender", lambda: box)
    return box


class _Dispatches:
    """Captures `apply_async` so the *dispatch contract* can be asserted without a broker."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)


@pytest.fixture
def dispatches(monkeypatch: pytest.MonkeyPatch) -> _Dispatches:
    captured = _Dispatches()
    monkeypatch.setattr(send_health_notification, "apply_async", captured)
    return captured


@pytest.fixture(autouse=True)
async def _clean_dedup_namespace() -> Any:
    """Each test starts with no claims. A leaked window from a previous test would make a
    'duplicate suppressed' assertion pass for the wrong reason."""
    async with redis_client() as redis:
        keys = [k async for k in redis.scan_iter(match="ws:*:health-notify:*")]
        if keys:
            await redis.delete(*keys)
    yield
    async with redis_client() as redis:
        keys = [k async for k in redis.scan_iter(match="ws:*:health-notify:*")]
        if keys:
            await redis.delete(*keys)


async def set_destination(
    engine: AsyncEngine, workspace_id: uuid.UUID, address: str | None
) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE workspaces SET notification_email = :e WHERE id = :i"),
            {"e": address, "i": workspace_id},
        )


async def owner_headers(
    engine: AsyncEngine, workspace: SeededWorkspace, authority: SigningAuthority
) -> dict[str, str]:
    subject = f"m210-{uuid.uuid4().hex[:8]}"
    await seed_member(engine, workspace.id, user_id=subject, role="owner")
    return {**bearer(authority.sign(subject)), WS_HEADER: str(workspace.id)}


def run_task(workspace_id: uuid.UUID, connection_id: uuid.UUID, event: str) -> Any:
    """Execute the real task the way Celery would, with a real per-dispatch task id."""
    return send_health_notification.apply(args=[str(workspace_id), str(connection_id), event])


# ============================================================ trigger A: the health-check path


@pytest.mark.asyncio
async def test_a_failing_health_check_enqueues_exactly_one_notification(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
    egress: _Egress,
    dispatches: _Dispatches,
) -> None:
    http, _ = human_client
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)
    egress.status = 500

    response = await http.post(
        f"/v1/connections/{ids['connection_id']}/test",
        headers=await owner_headers(admin_engine, workspace_a, authority),
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "unhealthy"
    assert len(dispatches.calls) == 1, dispatches.calls
    assert dispatches.calls[0]["args"] == [
        str(workspace_a.id),
        str(ids["connection_id"]),
        "unhealthy",
    ]
    assert dispatches.calls[0]["queue"] == "runtime"


@pytest.mark.asyncio
async def test_a_healthy_check_notifies_nobody(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
    egress: _Egress,
    dispatches: _Dispatches,
) -> None:
    """The positive control for this negative is the test directly above."""
    http, _ = human_client
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)

    response = await http.post(
        f"/v1/connections/{ids['connection_id']}/test",
        headers=await owner_headers(admin_engine, workspace_a, authority),
    )

    assert response.json()["status"] == "healthy", response.text
    assert dispatches.calls == []


@pytest.mark.asyncio
async def test_a_recovery_sends_no_email(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
    egress: _Egress,
    dispatches: _Dispatches,
) -> None:
    """unhealthy → healthy. Canon requires no recovery email; ADR-0041 §8 forbids inventing
    one."""
    http, _ = human_client
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)
    headers = await owner_headers(admin_engine, workspace_a, authority)
    url = f"/v1/connections/{ids['connection_id']}/test"

    egress.status = 500
    await http.post(url, headers=headers)
    assert len(dispatches.calls) == 1

    egress.status = 200
    await http.post(url, headers=headers)

    assert len(dispatches.calls) == 1, "a recovery must not enqueue anything"


@pytest.mark.asyncio
async def test_a_refused_probe_notifies_nobody(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
    egress: _Egress,
    dispatches: _Dispatches,
) -> None:
    """`health_check_unavailable` is `unknown`: no check completed, so there is no failure."""
    http, _ = human_client
    ids = await seed(
        admin_engine,
        workspace_a.id,
        tools=[
            {
                "name": "delete_everything",
                "annotations": {"readonly": False},
                "input_schema": {"type": "object", "properties": {}, "required": []},
            }
        ],
    )
    await set_destination(admin_engine, workspace_a.id, DESTINATION)

    response = await http.post(
        f"/v1/connections/{ids['connection_id']}/test",
        headers=await owner_headers(admin_engine, workspace_a, authority),
    )

    assert response.json()["status"] == "unknown", response.text
    assert egress.calls == []
    assert dispatches.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("refusal", ["rate_limited", "quota_exceeded"])
async def test_a_platform_policy_refusal_never_becomes_a_failure_notification(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
    egress: _Egress,
    dispatches: _Dispatches,
    monkeypatch: pytest.MonkeyPatch,
    refusal: str,
) -> None:
    """The row that stops one exhausted quota emailing an entire Workspace (ADR-0040 §5).

    The refusal is injected at the Runtime's stage-3 policy check — the real one — rather than by
    faking a health result, so this proves the *pipeline* classifies it as `unknown`.
    """
    from app.core.exceptions import QuotaExceededError, RateLimitedError

    http, _ = human_client
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)

    error = RateLimitedError("slow down") if refusal == "rate_limited" else QuotaExceededError("no")

    async def _refuse(**_: object) -> None:
        raise error

    monkeypatch.setattr("app.domains.runtime.service.enforce_tool_call_limits", _refuse)

    response = await http.post(
        f"/v1/connections/{ids['connection_id']}/test",
        headers=await owner_headers(admin_engine, workspace_a, authority),
    )

    assert response.json()["status"] == "unknown", response.text
    assert dispatches.calls == [], "a platform refusal must never notify"


# ============================================================ trigger B: the unattended OAuth path


@pytest.mark.asyncio
async def test_an_oauth_exhaustion_enqueues_a_needs_reauth_notification(
    workspace_a: SeededWorkspace, dispatches: _Dispatches
) -> None:
    """`connection.deactivated(status="error")` — the failure nobody is watching."""
    connection_id, connector_id = uuid.uuid4(), uuid.uuid4()

    await event_bus.dispatch(
        [
            connection_deactivated(
                workspace_a.id,
                connection_id=connection_id,
                connector_id=connector_id,
                status="error",
            )
        ]
    )

    assert len(dispatches.calls) == 1, dispatches.calls
    assert dispatches.calls[0]["args"] == [
        str(workspace_a.id),
        str(connection_id),
        "needs_reauth",
    ]


@pytest.mark.asyncio
async def test_a_user_revoking_their_own_credential_notifies_nobody(
    workspace_a: SeededWorkspace, dispatches: _Dispatches
) -> None:
    """`status="pending_auth"` is a deliberate act. The discriminator is mandatory (ADR-0041 §10);
    the test above is its positive control."""
    await event_bus.dispatch(
        [
            connection_deactivated(
                workspace_a.id,
                connection_id=uuid.uuid4(),
                connector_id=uuid.uuid4(),
                status="pending_auth",
            )
        ]
    )

    assert dispatches.calls == []


@pytest.mark.asyncio
async def test_the_worker_process_has_the_subscribers_registered() -> None:
    """The whole OAuth path depends on this, and it was absent before M2.10: `app/main.py`
    registered subscribers for the API process only, so an event published inside a Celery task
    dispatched to an empty handler map."""
    import importlib

    from app.domains.notifications import subscribers as subs

    celery_module = importlib.import_module("app.workers.celery_app")
    assert celery_module is not None
    assert event_bus.is_subscribed("connection.deactivated", subs._on_connection_deactivated)
    assert event_bus.is_subscribed("connection.health_check_failed", subs._on_health_check_failed)


@pytest.mark.asyncio
async def test_registration_is_idempotent_so_one_failure_never_enqueues_twice(
    workspace_a: SeededWorkspace, dispatches: _Dispatches
) -> None:
    """A single process importing both composition roots must not double-register. Dedup would
    still deliver one email, so the duplicate would be invisible in behaviour."""
    from app.domains.notifications.subscribers import register_notification_subscribers

    register_notification_subscribers()
    register_notification_subscribers()

    await event_bus.dispatch(
        [
            connection_deactivated(
                workspace_a.id,
                connection_id=uuid.uuid4(),
                connector_id=uuid.uuid4(),
                status="error",
            )
        ]
    )

    assert len(dispatches.calls) == 1, dispatches.calls


# ==================================================================== the task: delivery and dedup


@pytest.mark.asyncio
async def test_the_task_sends_to_the_workspaces_own_destination(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, mailbox: _Mailbox
) -> None:
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)

    result = await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")

    assert result.successful(), result.traceback
    assert result.result == "sent"
    assert [m.to for m in mailbox.sent] == [DESTINATION]


@pytest.mark.asyncio
async def test_a_workspace_with_no_destination_sends_nothing(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, mailbox: _Mailbox
) -> None:
    """The default state of every Workspace that existed before migration 0015."""
    ids = await seed(admin_engine, workspace_a.id)

    result = await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")

    assert result.result == "no_destination"
    assert mailbox.sent == []


@pytest.mark.asyncio
async def test_a_deleted_connection_evaporates_rather_than_emailing(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, mailbox: _Mailbox
) -> None:
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)
    async with admin_engine.begin() as conn:
        await conn.execute(
            text("UPDATE connections SET deleted_at = now() WHERE id = :i"),
            {"i": ids["connection_id"]},
        )

    result = await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")

    assert result.result == "no_connection"
    assert mailbox.sent == []


@pytest.mark.asyncio
async def test_a_second_worker_within_the_window_is_suppressed(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, mailbox: _Mailbox
) -> None:
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)

    first = await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")
    second = await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")

    assert first.result == "sent"
    assert second.result == "duplicate_suppressed"
    assert len(mailbox.sent) == 1


@pytest.mark.asyncio
async def test_the_two_failure_kinds_do_not_suppress_each_other(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, mailbox: _Mailbox
) -> None:
    """A Connection already reported unhealthy must still be able to report needs_reauth."""
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)

    a = await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")
    b = await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "needs_reauth")

    assert (a.result, b.result) == ("sent", "sent")
    assert len(mailbox.sent) == 2


@pytest.mark.asyncio
async def test_one_failing_connection_does_not_silence_another(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, mailbox: _Mailbox
) -> None:
    first = await seed(admin_engine, workspace_a.id)
    second = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)

    a = await asyncio.to_thread(run_task, workspace_a.id, first["connection_id"], "unhealthy")
    b = await asyncio.to_thread(run_task, workspace_a.id, second["connection_id"], "unhealthy")

    assert (a.result, b.result) == ("sent", "sent")


@pytest.mark.asyncio
@pytest.mark.parametrize("workers", [2, 4, 8])
async def test_exactly_one_concurrent_worker_wins_the_window(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, mailbox: _Mailbox, workers: int
) -> None:
    """The concurrency guarantee, against real Redis. A claim that is not atomic shows up here."""
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)

    results = await asyncio.gather(
        *(
            asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")
            for _ in range(workers)
        )
    )

    outcomes = [r.result for r in results]
    assert outcomes.count("sent") == 1, outcomes
    assert outcomes.count("duplicate_suppressed") == workers - 1, outcomes
    assert len(mailbox.sent) == 1


@pytest.mark.asyncio
async def test_the_window_carries_the_ratified_twenty_four_hour_ttl(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, mailbox: _Mailbox
) -> None:
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)

    await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")

    key = dedup_key(
        workspace_id=workspace_a.id,
        connection_id=ids["connection_id"],
        event=NotificationEvent.UNHEALTHY,
    )
    async with redis_client() as redis:
        ttl = await redis.ttl(key)
    assert 86_000 < ttl <= 86_400, ttl


@pytest.mark.asyncio
async def test_a_losing_worker_cannot_slide_the_window_forward(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, mailbox: _Mailbox
) -> None:
    """A held claim must not be rewritten, or a busy Connection could postpone its own next
    notification indefinitely."""
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)
    key = dedup_key(
        workspace_id=workspace_a.id,
        connection_id=ids["connection_id"],
        event=NotificationEvent.UNHEALTHY,
    )

    await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")
    async with redis_client() as redis:
        owner_before = await redis.get(key)
        await redis.expire(key, 100)
    await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")
    async with redis_client() as redis:
        assert await redis.ttl(key) <= 100
        assert await redis.get(key) == owner_before


@pytest.mark.asyncio
async def test_after_the_window_expires_a_new_notification_is_permitted(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, mailbox: _Mailbox
) -> None:
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)

    await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")
    async with redis_client() as redis:
        await redis.delete(
            dedup_key(
                workspace_id=workspace_a.id,
                connection_id=ids["connection_id"],
                event=NotificationEvent.UNHEALTHY,
            )
        )
    second = await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")

    assert second.result == "sent"
    assert len(mailbox.sent) == 2


@pytest.mark.asyncio
async def test_a_redis_flush_permits_exactly_one_duplicate_as_ratified(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, mailbox: _Mailbox
) -> None:
    """ADR-0041 §9 accepts this explicitly. Asserted so the accepted trade stays a decision rather
    than becoming folklore — and so a future change to durable dedup breaks this test loudly."""
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)

    await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")
    async with redis_client() as redis:
        keys = [k async for k in redis.scan_iter(match="ws:*:health-notify:*")]
        await redis.delete(*keys)
    second = await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")
    third = await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")

    assert second.result == "sent"
    assert third.result == "duplicate_suppressed", "the window must re-arm after the duplicate"
    assert len(mailbox.sent) == 2


# ================================================================== failure isolation and retries


@pytest.mark.asyncio
async def test_a_retry_of_the_same_task_re_enters_its_own_window(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, mailbox: _Mailbox
) -> None:
    """The defect this design exists to prevent: the first attempt claims the window, the provider
    fails, and a retry blocked by its own claim silently drops the email dedup was protecting."""
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)
    task_id = str(uuid.uuid4())

    mailbox.exc = RuntimeError("provider down")
    first = await asyncio.to_thread(
        lambda: send_health_notification.apply(
            args=[str(workspace_a.id), str(ids["connection_id"]), "unhealthy"], task_id=task_id
        )
    )
    assert not first.successful()
    assert mailbox.sent == []

    mailbox.exc = None
    retry = await asyncio.to_thread(
        lambda: send_health_notification.apply(
            args=[str(workspace_a.id), str(ids["connection_id"]), "unhealthy"], task_id=task_id
        )
    )

    assert retry.result == "sent", "the same task must re-enter its own claim"
    assert len(mailbox.sent) == 1


@pytest.mark.asyncio
async def test_a_different_worker_is_still_refused_after_a_failed_send(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, mailbox: _Mailbox
) -> None:
    """Re-entry must not have weakened mutual exclusion — the negative control for the
    test above."""
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)

    mailbox.exc = RuntimeError("provider down")
    await asyncio.to_thread(
        lambda: send_health_notification.apply(
            args=[str(workspace_a.id), str(ids["connection_id"]), "unhealthy"],
            task_id=str(uuid.uuid4()),
        )
    )
    mailbox.exc = None
    other = await asyncio.to_thread(
        lambda: send_health_notification.apply(
            args=[str(workspace_a.id), str(ids["connection_id"]), "unhealthy"],
            task_id=str(uuid.uuid4()),
        )
    )

    assert other.result == "duplicate_suppressed"
    assert mailbox.sent == []


@pytest.mark.asyncio
async def test_redis_unavailable_during_dedup_sends_nothing(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    mailbox: _Mailbox,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assuming "we won" would turn a Redis outage into one message per worker per retry."""
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)

    def _broken() -> Any:
        raise RedisConnectionError("redis is down")

    monkeypatch.setattr("app.domains.notifications.dedup.redis_client", _broken)

    result = await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")

    assert not result.successful(), "the task must fail so Celery retries it"
    assert mailbox.sent == []


@pytest.mark.asyncio
async def test_an_email_failure_leaves_the_health_verdict_and_audit_untouched(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
    egress: _Egress,
    mailbox: _Mailbox,
) -> None:
    """Notification has no authority over health, proven against the database rather than argued."""
    http, _ = human_client
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)
    egress.status = 500

    response = await http.post(
        f"/v1/connections/{ids['connection_id']}/test",
        headers=await owner_headers(admin_engine, workspace_a, authority),
    )
    assert response.json()["status"] == "unhealthy"

    async with admin_engine.connect() as conn:
        before = (
            await conn.execute(
                text(
                    "SELECT status, last_health_check_at,"
                    " (SELECT count(*) FROM tool_calls WHERE connection_id = :i)"
                    " FROM connections WHERE id = :i"
                ),
                {"i": ids["connection_id"]},
            )
        ).first()

    mailbox.exc = RuntimeError("provider down")
    failed = await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")
    assert not failed.successful()

    async with admin_engine.connect() as conn:
        after = (
            await conn.execute(
                text(
                    "SELECT status, last_health_check_at,"
                    " (SELECT count(*) FROM tool_calls WHERE connection_id = :i)"
                    " FROM connections WHERE id = :i"
                ),
                {"i": ids["connection_id"]},
            )
        ).first()

    assert before == after
    assert egress.calls and len(egress.calls) == 1, "no second provider call"


@pytest.mark.asyncio
async def test_a_notification_failure_never_fails_the_health_request(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
    egress: _Egress,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bus isolates handler errors; the publisher has already committed."""
    from app.domains.notifications import subscribers as subs

    def _explode(*_: object, **__: object) -> None:
        raise RuntimeError("enqueue exploded")

    monkeypatch.setattr(subs, "_enqueue", _explode)

    http, _ = human_client
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)
    egress.status = 500

    response = await http.post(
        f"/v1/connections/{ids['connection_id']}/test",
        headers=await owner_headers(admin_engine, workspace_a, authority),
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "unhealthy"


@pytest.mark.asyncio
async def test_a_rolled_back_health_check_enqueues_nothing(
    workspace_a: SeededWorkspace, dispatches: _Dispatches
) -> None:
    """Events buffer on the UnitOfWork and dispatch only after COMMIT, so a transaction that never
    commits emits nothing. Asserted by publishing into a UoW that is rolled back."""
    from app.core.events import Event, current_sink
    from app.domains.connections.events import connection_health_check_failed

    class _Buffer:
        """The minimum `publish` needs: somewhere to buffer. Standing in for a transaction that
        will roll back, so the buffer is simply never drained."""

        def __init__(self) -> None:
            self.buffered: list[Event] = []

        def buffer_event(self, event: Event) -> None:
            self.buffered.append(event)

    sink = _Buffer()
    token = current_sink.set(sink)
    try:
        event_bus.publish(
            connection_health_check_failed(
                workspace_a.id, connection_id=uuid.uuid4(), reason="upstream_error"
            )
        )
    finally:
        current_sink.reset(token)

    # The event was buffered, not delivered: a rolled-back transaction never drains it.
    assert len(sink.buffered) == 1
    assert dispatches.calls == []


# =========================================================================== tenant isolation


@pytest.mark.asyncio
async def test_a_task_cannot_reach_another_tenants_connection(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    mailbox: _Mailbox,
) -> None:
    """B's connection id under A's workspace must resolve to nothing, not to B's Connection."""
    b_ids = await seed(admin_engine, workspace_b.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)
    await set_destination(admin_engine, workspace_b.id, OTHER_DESTINATION)

    result = await asyncio.to_thread(run_task, workspace_a.id, b_ids["connection_id"], "unhealthy")

    assert result.result == "no_connection"
    assert mailbox.sent == []


@pytest.mark.asyncio
async def test_a_task_uses_its_own_workspaces_destination_only(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    mailbox: _Mailbox,
) -> None:
    a_ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)
    await set_destination(admin_engine, workspace_b.id, OTHER_DESTINATION)

    await asyncio.to_thread(run_task, workspace_a.id, a_ids["connection_id"], "unhealthy")

    assert [m.to for m in mailbox.sent] == [DESTINATION]
    assert OTHER_DESTINATION not in json.dumps([m.to for m in mailbox.sent])


@pytest.mark.asyncio
async def test_two_workspaces_never_share_a_dedup_window(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    mailbox: _Mailbox,
) -> None:
    """A workspace-only key would let one tenant suppress another's notifications."""
    a_ids = await seed(admin_engine, workspace_a.id)
    b_ids = await seed(admin_engine, workspace_b.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)
    await set_destination(admin_engine, workspace_b.id, OTHER_DESTINATION)

    a = await asyncio.to_thread(run_task, workspace_a.id, a_ids["connection_id"], "unhealthy")
    b = await asyncio.to_thread(run_task, workspace_b.id, b_ids["connection_id"], "unhealthy")

    assert (a.result, b.result) == ("sent", "sent")
    assert sorted(m.to for m in mailbox.sent) == sorted([DESTINATION, OTHER_DESTINATION])


# ================================================================== secret red-team with controls


@pytest.mark.asyncio
async def test_no_credential_reaches_the_email_redis_or_the_task_arguments(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
    egress: _Egress,
    mailbox: _Mailbox,
    dispatches: _Dispatches,
) -> None:
    """Drive the whole path with a real sealed credential, then hunt its plaintext everywhere the
    notification feature could have put it."""
    http, _ = human_client
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)
    egress.status = 500

    await http.post(
        f"/v1/connections/{ids['connection_id']}/test",
        headers=await owner_headers(admin_engine, workspace_a, authority),
    )
    assert json.dumps(dispatches.calls, default=str).count(CREDENTIAL_CANARY) == 0

    await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")
    assert mailbox.sent, "nothing was sent — the assertions below would be vacuous"

    rendered = json.dumps(
        [{"to": m.to, "subject": m.subject, "html": m.html} for m in mailbox.sent]
    )
    assert CREDENTIAL_CANARY not in rendered

    async with redis_client() as redis:
        for key in [k async for k in redis.scan_iter(match="ws:*:health-notify:*")]:
            assert CREDENTIAL_CANARY not in key
            assert CREDENTIAL_CANARY not in (await redis.get(key) or "")


@pytest.mark.asyncio
async def test_the_canary_scan_would_actually_catch_a_leak(mailbox: _Mailbox) -> None:
    """The positive control. Without it the assertions above would pass just as happily against a
    scanner that never matched anything."""
    leaky = EmailMessage(to=DESTINATION, subject="x", html=f"token={CREDENTIAL_CANARY}")
    rendered = json.dumps([{"to": leaky.to, "subject": leaky.subject, "html": leaky.html}])
    assert CREDENTIAL_CANARY in rendered

    async with redis_client() as redis:
        planted = "ws:planted:health-notify:planted:unhealthy"
        await redis.set(planted, CREDENTIAL_CANARY, ex=30)
        try:
            found = [
                k
                async for k in redis.scan_iter(match="ws:*:health-notify:*")
                if CREDENTIAL_CANARY in (await redis.get(k) or "")
            ]
            assert found == [planted]
        finally:
            await redis.delete(planted)


@pytest.mark.asyncio
async def test_the_destination_never_reaches_the_task_arguments(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
    egress: _Egress,
    dispatches: _Dispatches,
) -> None:
    """Celery arguments are JSON at rest in the Redis broker, so an address there is PII at rest.
    It is also what makes the task incapable of mailing an arbitrary destination."""
    http, _ = human_client
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)
    egress.status = 500

    await http.post(
        f"/v1/connections/{ids['connection_id']}/test",
        headers=await owner_headers(admin_engine, workspace_a, authority),
    )

    assert dispatches.calls, "nothing was dispatched — the assertion below would be vacuous"
    payload = json.dumps(dispatches.calls, default=str)
    assert DESTINATION not in payload
    assert "@" not in payload
    for call in dispatches.calls:
        assert len(call["args"]) == 3
        uuid.UUID(call["args"][0])
        uuid.UUID(call["args"][1])
        assert call["args"][2] in {"unhealthy", "needs_reauth"}


@pytest.mark.asyncio
async def test_a_provider_error_body_never_reaches_the_email(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, mailbox: _Mailbox
) -> None:
    """Only the Runtime's stable enumerated code may describe a failure — never provider text,
    which is attacker-influenced and may itself carry a leaked secret."""
    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)

    await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")

    assert mailbox.sent
    body = mailbox.sent[0].html
    for forbidden in ("Authorization", "Bearer ", "X-API-Key", "https://api.example.com"):
        assert forbidden not in body, forbidden


# ================================================================================ malformed input


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("ws", "conn", "event"),
    [
        ("not-a-uuid", str(uuid.uuid4()), "unhealthy"),
        (str(uuid.uuid4()), "not-a-uuid", "unhealthy"),
        (str(uuid.uuid4()), str(uuid.uuid4()), "healthy"),
        (str(uuid.uuid4()), str(uuid.uuid4()), "*"),
        (str(uuid.uuid4()), str(uuid.uuid4()), ""),
    ],
)
async def test_a_crafted_queue_entry_is_refused_before_any_work(
    mailbox: _Mailbox, ws: str, conn: str, event: str
) -> None:
    result = await asyncio.to_thread(lambda: send_health_notification.apply(args=[ws, conn, event]))

    assert result.result == "rejected"
    assert mailbox.sent == []


@pytest.mark.asyncio
async def test_the_kill_switch_stops_delivery_without_touching_health(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    mailbox: _Mailbox,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import settings

    ids = await seed(admin_engine, workspace_a.id)
    await set_destination(admin_engine, workspace_a.id, DESTINATION)
    monkeypatch.setattr(settings, "connection_health_notifications_enabled", False)

    result = await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")

    assert result.result == "disabled"
    assert mailbox.sent == []


# ======================================== RLS-independent repository scoping (mutation-audit gaps)
#
# The cross-tenant tests above pass on RLS alone: deleting a repository's explicit `workspace_id`
# predicate does not fail them, which the M2.10 mutation audit confirmed (M21/M22 survived). Two
# independent controls are only two controls if each is tested with the other absent, so these ask
# the same questions on an **admin connection RLS does not constrain**, leaving the repository
# filter as the only thing standing. Same pattern as the M2.6 vault suite (P-14, defense in depth).


def _platform_context(workspace_id: uuid.UUID) -> Any:
    from app.core.security import CallerIdentity, WorkspaceContext

    return WorkspaceContext(
        workspace_id=workspace_id,
        caller=CallerIdentity(kind="api_token", api_token_id=None),
        request_id="m210-rls-independent",
    )


@pytest.mark.asyncio
async def test_the_destination_lookup_is_scoped_by_the_repository_alone(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    """Without this, dropping the tenant predicate would let a task read another Workspace's
    address — and mail one tenant's failure to another tenant's inbox."""
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.domains.notifications.repository import NotificationRepository

    await set_destination(admin_engine, workspace_b.id, OTHER_DESTINATION)
    await set_destination(admin_engine, workspace_a.id, None)

    async with AsyncSession(admin_engine) as session:
        visible = (
            await session.execute(
                text("SELECT notification_email FROM workspaces WHERE id = :i"),
                {"i": workspace_b.id},
            )
        ).scalar()
        assert visible == OTHER_DESTINATION, "premise failed: the admin connection cannot see B"

        repository = NotificationRepository(session, _platform_context(workspace_a.id))
        assert await repository.destination() is None


@pytest.mark.asyncio
async def test_the_connection_lookup_is_scoped_by_the_repository_alone(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.domains.notifications.repository import NotificationRepository

    b_ids = await seed(admin_engine, workspace_b.id)

    async with AsyncSession(admin_engine) as session:
        visible = (
            await session.execute(
                text("SELECT count(*) FROM connections WHERE id = :i"),
                {"i": b_ids["connection_id"]},
            )
        ).scalar_one()
        assert visible == 1, "premise failed: the admin connection cannot see B's Connection"

        repository = NotificationRepository(session, _platform_context(workspace_a.id))
        assert await repository.connection(b_ids["connection_id"]) is None


@pytest.mark.asyncio
async def test_the_destination_update_is_scoped_by_the_repository_alone(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    """An UPDATE whose tenant predicate was dropped writes every row in the table. RLS hides that
    at the HTTP edge, so the predicate is asserted here with RLS out of the way."""
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.domains.workspaces.repository import WorkspaceRepository

    await set_destination(admin_engine, workspace_b.id, OTHER_DESTINATION)

    async with AsyncSession(admin_engine) as session:
        matched, stored = await WorkspaceRepository(
            session, _platform_context(workspace_a.id)
        ).set_notification_email(DESTINATION)
        await session.commit()

    assert (matched, stored) == (True, DESTINATION)
    async with admin_engine.connect() as conn:
        untouched = (
            await conn.execute(
                text("SELECT notification_email FROM workspaces WHERE id = :i"),
                {"i": workspace_b.id},
            )
        ).scalar()
    assert untouched == OTHER_DESTINATION, "B's destination was overwritten"


# ================================================ remaining mutation-audit gaps (M15, M20, M25)


@pytest.mark.asyncio
async def test_the_published_failure_reason_is_the_stable_code_not_provider_text(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    authority: SigningAuthority,
    egress: _Egress,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The event payload rides the bus and can reach logs, so its `reason` must be the enumerated
    Runtime code — never `str(exception)`, which for an upstream failure carries provider text."""
    from app.domains.notifications import subscribers as subs

    seen: list[Any] = []
    monkeypatch.setattr(subs, "_enqueue", lambda event, notification: seen.append(event))

    http, _ = human_client
    ids = await seed(admin_engine, workspace_a.id)
    egress.status = 500

    await http.post(
        f"/v1/connections/{ids['connection_id']}/test",
        headers=await owner_headers(admin_engine, workspace_a, authority),
    )

    assert len(seen) == 1, seen
    reason = seen[0].payload["reason"]
    assert reason.islower() and " " not in reason, f"not an enumerated code: {reason!r}"
    assert "api.example.com" not in reason
    assert set(seen[0].payload) == {"connection_id", "reason"}


@pytest.mark.asyncio
async def test_a_missing_destination_does_not_burn_the_dedup_window(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, mailbox: _Mailbox
) -> None:
    """Order matters: claiming before resolving the destination would consume a 24-hour window for
    a Workspace that could not be mailed, silently suppressing the next real notification."""
    ids = await seed(admin_engine, workspace_a.id)

    first = await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")
    assert first.result == "no_destination"

    await set_destination(admin_engine, workspace_a.id, DESTINATION)
    second = await asyncio.to_thread(run_task, workspace_a.id, ids["connection_id"], "unhealthy")

    assert second.result == "sent", "the earlier no-destination run consumed the window"
    assert len(mailbox.sent) == 1


@pytest.mark.asyncio
async def test_a_payload_supplied_workspace_id_is_ignored_in_favour_of_the_envelope(
    workspace_a: SeededWorkspace, workspace_b: SeededWorkspace, dispatches: _Dispatches
) -> None:
    """The envelope's tenant was already fail-closed-matched against the publishing transaction
    (ADR-0022). A payload field is never a tenant selector, so a domain that puts `workspace_id` in
    a payload — the envelope forbids extras, the payload does not — cannot redirect a
    notification."""
    from app.core.events import Event
    from app.domains.connections.events import CONNECTION_DEACTIVATED

    await event_bus.dispatch(
        [
            Event(
                event_type=CONNECTION_DEACTIVATED,
                workspace_id=workspace_a.id,
                payload={
                    "connection_id": str(uuid.uuid4()),
                    "connector_id": str(uuid.uuid4()),
                    "status": "error",
                    "workspace_id": str(workspace_b.id),
                },
            )
        ]
    )

    assert len(dispatches.calls) == 1, dispatches.calls
    assert dispatches.calls[0]["args"][0] == str(workspace_a.id)
    assert str(workspace_b.id) not in json.dumps(dispatches.calls, default=str)
