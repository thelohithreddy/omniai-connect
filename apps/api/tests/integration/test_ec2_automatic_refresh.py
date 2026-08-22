"""EC2 — "OAuth tokens refresh automatically across expiry without user action" (ROADMAP §64).

M2.5 proved the refresh *mechanics* thoroughly — renewal, expiry extension, refresh-token rotation,
exactly-one-exchange under contention, tenant scoping, terminal failure. Every one of those tests
calls `refresh_connection` **directly**. What none of them proved is the word EC2 actually turns
on: **automatically**. The scheduled chain — beat tick → `sweep_refreshes` →
`auth.due_oauth_refreshes` discovering a due credential → fan-out → refresh — had no coverage;
`sweep_refreshes` appeared in the suite only as a registry-name assertion.

These tests start from **database state** and enter through the **production sweep**. Nothing about
discovery is mocked: `auth.due_oauth_refreshes` is the real SECURITY DEFINER function created by
migration 0013, running against real rows. If discovery were bypassed, hand-written, or widened,
these tests fail — which is the property that makes them evidence rather than decoration.

**On the queue hop.** `sweep_refreshes` fans out with `apply_async`; a broker and a worker then
deliver the task. The tests capture that dispatch and feed *exactly the arguments discovery
produced* into the task's own body. That is the production chain with the transport elided — and
the transport is elided honestly, not stepped around: the arguments are never hand-authored, and a
mutation that stops the sweep scheduling anything kills these tests.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.config import settings
from app.domains.credentials import vault
from app.domains.oauth.refresh import RefreshOutcome
from app.workers import oauth_tasks
from tests.conftest import SeededWorkspace
from tests.integration.fake_oauth_provider import FakeOAuthProvider
from tests.integration.test_oauth_refresh_api import seed_oauth_tool

#: Four independent canaries, so the test can say *where each secret is allowed to exist* rather
#: than merely "no secret anywhere". A shared value could not distinguish "the old token was
#: replaced" from "the new token was never written".
OLD_ACCESS = "EC2_OLD_ACCESS_CANARY"  # noqa: S105 (synthetic test secret)
OLD_REFRESH = "EC2_OLD_REFRESH_CANARY"  # noqa: S105 (synthetic test secret)
NEW_ACCESS = "EC2_NEW_ACCESS_CANARY"  # noqa: S105 (synthetic test secret)
NEW_REFRESH = "EC2_NEW_REFRESH_CANARY"  # noqa: S105 (synthetic test secret)
UNTOUCHED_ACCESS = "EC2_UNTOUCHED_ACCESS"  # noqa: S105 (synthetic test secret)
UNTOUCHED_REFRESH = "EC2_UNTOUCHED_REFRESH"  # noqa: S105 (synthetic test secret)
B_ACCESS = "EC2_B_ACCESS"  # noqa: S105 (synthetic test secret)
B_REFRESH = "EC2_B_REFRESH"  # noqa: S105 (synthetic test secret)


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> FakeOAuthProvider:
    """The existing deterministic provider — no second implementation introduced."""
    fake = FakeOAuthProvider()
    fake.access_token_value = NEW_ACCESS
    # The provider only honours refresh tokens it has issued, so a seeded one must be registered —
    # exactly as the M2.5 refresh tests do. Without this the provider answers 400 and the test
    # would be exercising the failure path while claiming to prove the success path.
    fake.valid_refresh_tokens.add(OLD_REFRESH)
    monkeypatch.setattr("app.core.net.request", fake)
    return fake


@pytest.fixture
def dispatched(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture the sweep's fan-out.

    Patched on the task object rather than replacing the sweep, so discovery still runs for real
    and what is captured is precisely what production would have put on the queue.
    """
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        oauth_tasks.refresh_oauth_credential, "apply_async", lambda **kwargs: calls.append(kwargs)
    )
    return calls


def due_soon() -> datetime:
    """Inside the refresh threshold *and* inside the sweep's look-ahead — genuinely due by the
    production predicates, not by a value chosen to satisfy one of them."""
    return datetime.now(UTC) + timedelta(seconds=120)


def not_due() -> datetime:
    """Comfortably outside both windows."""
    return datetime.now(UTC) + timedelta(days=2)


async def credential_row(engine: AsyncEngine, connection_id: uuid.UUID) -> Any:
    async with engine.connect() as conn:
        return (
            await conn.execute(
                text(
                    "SELECT c.id, c.workspace_id, c.ciphertext, c.encrypted_dek, c.nonce,"
                    " c.key_version, c.expires_at, c.rotated_at, n.status"
                    " FROM credentials c JOIN connections n ON n.id = c.connection_id"
                    " WHERE c.connection_id = :i"
                ),
                {"i": connection_id},
            )
        ).one()


def open_secret(row: Any, connection_id: uuid.UUID) -> dict[str, Any]:
    """Decrypt through the real vault to prove the persisted material is usable."""
    sealed = vault.SealedSecret(
        ciphertext=bytes(row.ciphertext),
        encrypted_dek=bytes(row.encrypted_dek),
        nonce=bytes(row.nonce),
        key_version=row.key_version,
    )
    plaintext = vault.unseal_flow_secret(
        sealed, workspace_id=row.workspace_id, connection_id=connection_id
    )
    return json.loads(plaintext)


async def run_sweep() -> dict[str, int]:
    """Invoke the **real** `sweep_refreshes` Celery task, not its inner coroutine.

    The task body calls `asyncio.run`, which cannot nest inside the test's running loop, so it is
    executed in a worker thread with a loop of its own. That keeps the production entry point — the
    kill-switch check and all — inside the evidence instead of testing one layer beneath it.
    """
    return await asyncio.to_thread(oauth_tasks.sweep_refreshes)


async def run_refresh(args: list[str]) -> str:
    """Execute the **real** `refresh_oauth_credential` task object with the arguments discovery
    produced, via Celery's local synchronous `.apply()`.

    `.apply()` runs the full task wrapper — `bind=True` self, the retry ladder, result handling —
    rather than the inner `_refresh_one`, so what is proven is the task a worker would actually run.
    """
    result = await asyncio.to_thread(lambda: oauth_tasks.refresh_oauth_credential.apply(args=args))
    if not result.successful():
        # A retryable outcome makes the real wrapper raise `Retry` — machinery the inner coroutine
        # does not have. Surfaced as a state marker so a test can assert the ladder engaged.
        return f"<{result.state}>"
    return str(result.result)


# ============================================================== EC2, the automatic chain


@pytest.mark.asyncio
async def test_ec2_a_due_credential_is_discovered_and_refreshed_with_no_user_action(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    provider: FakeOAuthProvider,
    dispatched: list[dict[str, Any]],
) -> None:
    """The whole of EC2, driven from database state through the production sweep."""
    provider.rotate_refresh_tokens = False
    due = await seed_oauth_tool(
        admin_engine,
        workspace_a.id,
        tool_name="ec2_due_op",
        access_token=OLD_ACCESS,
        refresh_token=OLD_REFRESH,
        expires_at=due_soon(),
    )
    # A control in the SAME workspace that must not be touched: if discovery were widened to
    # "every oauth2 credential", this row would be swept up with it.
    fresh = await seed_oauth_tool(
        admin_engine,
        workspace_a.id,
        tool_name="ec2_fresh_op",
        access_token=UNTOUCHED_ACCESS,
        refresh_token=UNTOUCHED_REFRESH,
        expires_at=not_due(),
    )
    before = await credential_row(admin_engine, due["connection_id"])

    # 1–5. THE PRODUCTION SWEEP. Real session, real `auth.due_oauth_refreshes`, real fan-out.
    result = await run_sweep()

    discovered = [tuple(call["args"]) for call in dispatched]
    assert (str(workspace_a.id), str(due["connection_id"])) in discovered, (
        "the due credential was not discovered by auth.due_oauth_refreshes"
    )
    assert (str(workspace_a.id), str(fresh["connection_id"])) not in discovered, (
        "a credential that is not due was scheduled for refresh"
    )
    assert result["scheduled"] == len(dispatched)

    # 12. Nothing but identifiers crosses the queue boundary.
    for call in dispatched:
        assert set(call) <= {"args", "queue", "countdown"}
        for argument in call["args"]:
            uuid.UUID(str(argument))  # raises unless every argument is an identifier
        assert call["queue"] == oauth_tasks.RUNTIME_QUEUE
        serialized = json.dumps(call, default=str)
        for secret in (OLD_ACCESS, OLD_REFRESH, NEW_ACCESS, NEW_REFRESH):
            assert secret not in serialized

    # 6. The worker leg, with exactly the arguments discovery produced — never hand-authored.
    args = next(c["args"] for c in dispatched if c["args"][1] == str(due["connection_id"]))
    assert await run_refresh(args) == RefreshOutcome.REFRESHED.value

    # 7. Exactly one provider exchange, and it presented the OLD refresh token.
    assert len(provider.exchanges) == 1, provider.exchanges
    grant, form = provider.exchanges[0]
    assert grant == "refresh_token"
    assert form.get("refresh_token") == OLD_REFRESH

    # 9–11. The new material is persisted, decryptable, and the expiry moved forward.
    after = await credential_row(admin_engine, due["connection_id"])
    secret = open_secret(after, due["connection_id"])
    assert secret["access_token"] == NEW_ACCESS, "the refreshed access token was not persisted"
    assert secret["refresh_token"] == OLD_REFRESH, "a non-rotating provider must keep the token"
    assert after.expires_at > before.expires_at, "expiry was not extended"
    assert after.rotated_at is not None, "the re-seal was not stamped"
    assert after.status == "active", "a successful refresh must not change the lifecycle"

    # The untouched control is genuinely untouched.
    control = await credential_row(admin_engine, fresh["connection_id"])
    assert open_secret(control, fresh["connection_id"])["access_token"] == UNTOUCHED_ACCESS

    # 15. A second sweep must not refresh it again — the extended expiry removes it from the
    # due set, which is what stops a scheduled job re-burning a provider's rate limit.
    dispatched.clear()
    await run_sweep()
    assert (str(workspace_a.id), str(due["connection_id"])) not in [
        tuple(c["args"]) for c in dispatched
    ], "a freshly refreshed credential was rediscovered as due"


@pytest.mark.asyncio
async def test_ec2_refresh_token_rotation_survives_the_scheduled_path(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    provider: FakeOAuthProvider,
    dispatched: list[dict[str, Any]],
) -> None:
    """A rotating provider invalidates the old refresh token, so losing the new one strands the
    Connection permanently. Proven through the scheduled path, not a direct call."""
    provider.rotate_refresh_tokens = True
    provider.access_token_value = NEW_ACCESS
    due = await seed_oauth_tool(
        admin_engine,
        workspace_a.id,
        tool_name="ec2_rotate_op",
        access_token=OLD_ACCESS,
        refresh_token=OLD_REFRESH,
        expires_at=due_soon(),
    )
    await run_sweep()
    args = next(c["args"] for c in dispatched if c["args"][1] == str(due["connection_id"]))
    assert await run_refresh(args) == RefreshOutcome.REFRESHED.value

    secret = open_secret(
        await credential_row(admin_engine, due["connection_id"]), due["connection_id"]
    )
    assert secret["access_token"] == NEW_ACCESS
    assert secret["refresh_token"] != OLD_REFRESH, "the rotated refresh token was not persisted"
    assert secret["refresh_token"] in provider.valid_refresh_tokens


@pytest.mark.asyncio
async def test_ec2_a_persistent_provider_failure_exhausts_retries_and_deactivates(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    provider: FakeOAuthProvider,
    dispatched: list[dict[str, Any]],
) -> None:
    """The automatic path's failure branch, through the REAL task wrapper.

    Driving `refresh_oauth_credential` itself rather than its inner coroutine is what makes this
    meaningful: the wrapper owns the bounded retry ladder and the terminal hand-off. A persistent
    transport failure therefore exhausts the budget and transitions the Connection to `error`
    (ADR-0038 D2) — behaviour no test of the inner function can reach.

    The credential must survive intact: a refresh that cannot complete must never destroy the
    token it failed to replace.
    """
    due = await seed_oauth_tool(
        admin_engine,
        workspace_a.id,
        tool_name="ec2_fail_op",
        access_token=OLD_ACCESS,
        refresh_token=OLD_REFRESH,
        expires_at=due_soon(),
    )
    await run_sweep()
    args = next(c["args"] for c in dispatched if c["args"][1] == str(due["connection_id"]))

    # Persistent, not one-shot: `raise_error` is never cleared, so every attempt fails. A
    # `TimeoutException` is what the provider client classifies as a transport failure
    # (`provider.py` catches it explicitly), so this drives the canonical retryable path rather
    # than an unhandled error.
    provider.raise_error = httpx.TimeoutException("provider unreachable")
    outcome = await run_refresh(args)
    assert outcome == RefreshOutcome.TERMINAL.value, outcome

    row = await credential_row(admin_engine, due["connection_id"])
    assert row.status == "error", "an exhausted refresh must deactivate the Connection"
    secret = open_secret(row, due["connection_id"])
    assert secret["access_token"] == OLD_ACCESS, "a failed refresh destroyed the stored token"
    assert secret["refresh_token"] == OLD_REFRESH

    # A later sweep must not resurrect it: the Connection is no longer active, so discovery's
    # `n.status = 'active'` predicate excludes it.
    dispatched.clear()
    await run_sweep()
    assert (str(workspace_a.id), str(due["connection_id"])) not in [
        tuple(c["args"]) for c in dispatched
    ], "a terminally failed Connection was rediscovered by the sweep"


@pytest.mark.asyncio
async def test_ec2_discovery_is_platform_wide_but_refresh_is_tenant_bound(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    provider: FakeOAuthProvider,
    dispatched: list[dict[str, Any]],
) -> None:
    """The actual contract, asserted rather than an assumed one.

    `auth.due_oauth_refreshes` is a SECURITY DEFINER carve-out that deliberately spans tenants —
    a cron tick has no current workspace — and returns **identifiers only**. Isolation lives one
    layer down: each fan-out task binds its own workspace, so A's identifiers can never drive a
    refresh under B's context. Both halves are checked here.
    """
    a = await seed_oauth_tool(
        admin_engine,
        workspace_a.id,
        tool_name="ec2_a_op",
        access_token=OLD_ACCESS,
        refresh_token=OLD_REFRESH,
        expires_at=due_soon(),
    )
    b = await seed_oauth_tool(
        admin_engine,
        workspace_b.id,
        tool_name="ec2_b_op",
        access_token=B_ACCESS,
        refresh_token=B_REFRESH,
        expires_at=due_soon(),
    )
    await run_sweep()
    pairs = [tuple(c["args"]) for c in dispatched]

    # Each due credential is scheduled under its OWN workspace id — never another's.
    assert (str(workspace_a.id), str(a["connection_id"])) in pairs
    assert (str(workspace_b.id), str(b["connection_id"])) in pairs
    assert (str(workspace_a.id), str(b["connection_id"])) not in pairs
    assert (str(workspace_b.id), str(a["connection_id"])) not in pairs

    # Cross-tenant execution: B's context, A's connection id. Nothing happens, no exchange.
    provider.exchanges.clear()
    outcome = await run_refresh([str(workspace_b.id), str(a["connection_id"])])
    assert outcome == RefreshOutcome.SKIPPED.value, outcome
    assert provider.exchanges == [], "a cross-tenant refresh reached the provider"
    assert (
        open_secret(await credential_row(admin_engine, a["connection_id"]), a["connection_id"])[
            "access_token"
        ]
        == OLD_ACCESS
    )


def test_ec2_the_scheduled_entry_point_honours_the_kill_switch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The production entry point, not its inner function.

    `sweep_refreshes` is what beat invokes; with OAuth disabled it must return before touching the
    database at all. Synchronous on purpose — this is the real task, `asyncio.run` and all.
    """

    def explode() -> None:  # pragma: no cover - invoked only if the flag check is gone
        raise AssertionError("the disabled sweep opened a database session")

    monkeypatch.setattr(settings, "oauth_enabled", False)
    # Asserting only `{"scheduled": 0}` would pass for the wrong reason — it cannot tell "the flag
    # stopped it" from "nothing happened to be due". Making the session factory fatal turns this
    # into a real assertion: with the check removed the sweep reaches the database and fails.
    monkeypatch.setattr(oauth_tasks, "worker_sessions", explode)
    assert oauth_tasks.sweep_refreshes() == {"scheduled": 0}


def test_ec2_the_sweep_is_actually_scheduled_to_run_automatically() -> None:
    """ "Automatically" also means something schedules it. Asserted against the beat config that
    the scheduler container actually loads."""
    from app.workers.celery_app import REFRESH_SWEEP_INTERVAL_SECONDS, RUNTIME_QUEUE, celery_app

    entry = celery_app.conf.beat_schedule["oauth-refresh-sweep"]
    assert entry["task"] == "workers.oauth.sweep_refreshes"
    assert entry["schedule"] == REFRESH_SWEEP_INTERVAL_SECONDS
    assert entry["options"]["queue"] == RUNTIME_QUEUE
    assert "workers.oauth.sweep_refreshes" in celery_app.tasks


@pytest.mark.asyncio
async def test_ec2_a_stale_queued_refresh_does_not_re_exchange(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    provider: FakeOAuthProvider,
    dispatched: list[dict[str, Any]],
) -> None:
    """The queue is asynchronous, so a task can arrive after the work is already done.

    Two sweeps can discover the same credential before either refresh lands, and a redelivered
    task can arrive minutes late. The in-lock `is_due` re-check is what makes the second arrival a
    no-op; without it a provider would be charged a second exchange and a rotating provider would
    invalidate the refresh token we just stored — stranding the Connection.

    Found by mutation: removing that re-check broke no test, because every existing test fed the
    task a credential that was genuinely due.
    """
    due = await seed_oauth_tool(
        admin_engine,
        workspace_a.id,
        tool_name="ec2_stale_op",
        access_token=OLD_ACCESS,
        refresh_token=OLD_REFRESH,
        expires_at=due_soon(),
    )
    await run_sweep()
    args = next(c["args"] for c in dispatched if c["args"][1] == str(due["connection_id"]))

    assert await run_refresh(args) == RefreshOutcome.REFRESHED.value
    assert len(provider.exchanges) == 1

    # The identical task is redelivered — same arguments discovery produced, nothing else changed.
    assert await run_refresh(args) == RefreshOutcome.NOT_DUE.value
    assert len(provider.exchanges) == 1, "a stale queued task re-exchanged with the provider"

    secret = open_secret(
        await credential_row(admin_engine, due["connection_id"]), due["connection_id"]
    )
    assert secret["access_token"] == NEW_ACCESS, "the replay disturbed the stored credential"
