"""Liveness and readiness: two endpoints that must fail differently.

OBSERVABILITY.md §6 assigns them different jobs — *"Railway uses readiness for deploy
gating; liveness for restarts"* — and the tests that matter most here are the ones proving
they do **not** behave the same way when a dependency is down.

The failure mode this file exists to prevent is well known and self-inflicted: if liveness
checked the database, a thirty-second Neon blip would make the orchestrator conclude every
API process was broken and kill them all, leaving nothing warm to serve when the database
came back. So the central test is not "readiness returns 200" — it is that with the
database unavailable, readiness says 503 **and liveness still says 200**.

Failures are injected at the dependency, not by mocking the endpoint: the probes are
pointed at an unreachable database or Redis, so the real code path runs and the real
exception handling is exercised.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

import app.core.readiness as readiness_module
from app.core.readiness import (
    PROBE_TIMEOUT_SECONDS,
    ReadinessReport,
    check_database,
    check_readiness,
    check_redis,
)
from app.main import app as real_app

pytestmark = pytest.mark.asyncio

#: Routed to a port nothing listens on, so the probe exercises a genuine connection failure
#: rather than a mocked exception.
DEAD_POSTGRES = "postgresql+asyncpg://omniai_app:omniai_app@127.0.0.1:59999/omniai"
DEAD_REDIS = "redis://127.0.0.1:59998/0"


@pytest.fixture
async def ops_client() -> Any:
    """The real application, unmodified — no dependency overrides at all.

    Health endpoints must work for infrastructure that has no credentials and no knowledge
    of the app's internals, so overriding anything here would defeat the point.
    """
    async with AsyncClient(transport=ASGITransport(app=real_app), base_url="http://ops") as client:
        yield client


@contextlib.contextmanager
def broken_database() -> Any:
    """Point the readiness probe at a database that is not there."""
    original = readiness_module.engine
    readiness_module.engine = create_async_engine(DEAD_POSTGRES, pool_pre_ping=False)
    try:
        yield
    finally:
        readiness_module.engine = original


@contextlib.contextmanager
def broken_redis() -> Any:
    original = readiness_module.settings.redis_url
    readiness_module.settings.redis_url = DEAD_REDIS
    try:
        yield
    finally:
        readiness_module.settings.redis_url = original


# =======================================================================================
# Liveness — must depend on nothing
# =======================================================================================


async def test_liveness_is_unauthenticated_and_reports_ok(ops_client: AsyncClient) -> None:
    response = await ops_client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert "authorization" not in {k.lower() for k in response.request.headers}


async def test_liveness_survives_every_dependency_being_down(ops_client: AsyncClient) -> None:
    """The single most important behaviour in this module.

    §6: liveness is *"process up, event loop responsive. No dependency checks, so a Neon
    blip doesn't restart-loop healthy processes."* If this ever returns non-200 because a
    dependency is unavailable, a brief outage of that dependency becomes a rolling restart
    of every healthy API process — the dependency recovers and there is nothing left warm
    to serve it.
    """
    with broken_database(), broken_redis():
        response = await ops_client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_liveness_discloses_nothing(ops_client: AsyncClient) -> None:
    """Unauthenticated and internet-reachable, so every field is public by definition."""
    response = await ops_client.get("/health")
    body = response.json()

    assert set(body) == {"status"}
    for forbidden in ("postgres", "redis", "password", "omniai_app", "://", "env", "version"):
        assert forbidden not in response.text.lower()


# =======================================================================================
# Readiness — healthy path
# =======================================================================================


async def test_readiness_reports_ready_when_dependencies_answer(
    ops_client: AsyncClient,
) -> None:
    response = await ops_client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}
    assert response.headers["X-Request-Id"]


async def test_readiness_is_unauthenticated(ops_client: AsyncClient) -> None:
    """Infrastructure has no credentials and must be able to call this before any exist.

    Asserted by sending a deliberately invalid bearer token as well: a probe that *processed*
    the header would fail on the garbage value, proving it had wandered into the
    authentication path.
    """
    plain = await ops_client.get("/health/ready")
    with_garbage = await ops_client.get(
        "/health/ready", headers={"Authorization": "Bearer omc_not-a-real-token"}
    )

    assert plain.status_code == with_garbage.status_code == 200
    assert plain.json() == with_garbage.json() == {"status": "ready"}


# =======================================================================================
# Readiness — failure injection, and the liveness contrast
# =======================================================================================


async def test_readiness_fails_with_503_when_the_database_is_unreachable(
    ops_client: AsyncClient,
) -> None:
    with broken_database():
        response = await ops_client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}


async def test_readiness_fails_with_503_when_redis_is_unreachable(
    ops_client: AsyncClient,
) -> None:
    """Redis is readiness-critical because §6 says so, explicitly and by name.

    It is *not* otherwise integrated — no application code path uses it — so this is the
    one place its availability matters today. Removing it from the probe would make
    readiness lie about a dependency the canonical design requires.
    """
    with broken_redis():
        response = await ops_client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}


async def test_liveness_and_readiness_disagree_when_a_dependency_is_down(
    ops_client: AsyncClient,
) -> None:
    """The whole point of having two endpoints, asserted in one place.

    Same process, same instant, opposite answers: withdraw me from the load balancer, but
    do not kill me. A single endpoint cannot express both, which is why §6 defines two.
    """
    with broken_database():
        live = await ops_client.get("/health")
        ready = await ops_client.get("/health/ready")

    assert live.status_code == 200, "a dependency outage must not make the process look dead"
    assert ready.status_code == 503, "a dependency outage must withdraw the process from traffic"


async def test_a_readiness_failure_discloses_nothing_about_the_dependency(
    ops_client: AsyncClient,
) -> None:
    """A 503 body must not become reconnaissance.

    The endpoint is unauthenticated and monitored from the public internet (§6). Naming the
    failing dependency, the driver, the host, or the role would tell an attacker both what
    the stack is made of and that part of it is currently down — which is precisely when
    an attack is cheapest. Diagnosis goes to the log stream instead.
    """
    with broken_database(), broken_redis():
        response = await ops_client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}
    lowered = response.text.lower()
    for forbidden in (
        "postgres",
        "asyncpg",
        "redis",
        "omniai_app",
        "password",
        "connect",
        "127.0.0.1",
        "59999",
        "traceback",
        "sqlalchemy",
        "://",
    ):
        assert forbidden not in lowered, f"a 503 disclosed {forbidden!r}"


async def test_an_unexpected_probe_exception_still_yields_503_not_500(
    ops_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any failure means "not ready" — never a 500 with a traceback.

    An orchestrator reads the status code. A 500 from a readiness endpoint is ambiguous
    (is the app broken, or the check?) and, worse, would render a stack trace through the
    error path on an unauthenticated endpoint.
    """

    async def exploding_probe() -> bool:
        raise MemoryError("something entirely unexpected")

    monkeypatch.setattr(readiness_module, "check_redis", exploding_probe)
    response = await ops_client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}
    assert "MemoryError" not in response.text
    assert "Traceback" not in response.text


# =======================================================================================
# Timeouts — a probe that hangs is worse than one that fails
# =======================================================================================


async def test_the_probe_is_bounded_when_a_dependency_never_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A black-holed dependency must not hold the request open.

    Without a bound, every probe against a hung dependency occupies a worker until the
    orchestrator's own timeout fires — so a slow dependency becomes an outage of the
    process checking it. Asserted by wall-clock: the probe returns False within the budget
    rather than waiting for a connection that never completes.
    """

    # A non-routable address: packets are dropped rather than refused, so the TCP connect
    # hangs instead of failing fast. That is the real shape of a black-holed dependency —
    # a refused connection is the easy case and would not test the timeout at all.
    black_hole = create_async_engine(
        "postgresql+asyncpg://omniai_app:omniai_app@10.255.255.1:5432/omniai",
        pool_pre_ping=False,
    )
    monkeypatch.setattr(readiness_module, "engine", black_hole)

    started = asyncio.get_running_loop().time()
    result = await check_database()
    elapsed = asyncio.get_running_loop().time() - started
    await black_hole.dispose()

    assert result is False
    # Asserted against an ABSOLUTE ceiling, not against PROBE_TIMEOUT_SECONDS. Comparing to
    # the constant would be a tautology: raising it to ten minutes would keep this test
    # green while the endpoint hung, which is exactly what a mutation proved.
    assert elapsed < 5.0, f"probe took {elapsed:.1f}s — not bounded"
    assert PROBE_TIMEOUT_SECONDS <= 5.0, (
        "the probe budget must stay under docker-compose's 5s healthcheck timeout, or the"
        " orchestrator gives up before this endpoint answers"
    )


async def test_both_probes_run_concurrently_rather_than_in_sequence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Worst case is one timeout, not the sum of them.

    With two dependencies that is 2s versus 4s; with more it degrades linearly, and the
    orchestrator is waiting on the answer the whole time.
    """

    async def slow_true() -> bool:
        await asyncio.sleep(0.3)
        return True

    monkeypatch.setattr(readiness_module, "check_database", slow_true)
    monkeypatch.setattr(readiness_module, "check_redis", slow_true)

    started = asyncio.get_running_loop().time()
    report = await check_readiness()
    elapsed = asyncio.get_running_loop().time() - started

    assert report.ready is True
    assert elapsed < 0.55, f"probes appear sequential: {elapsed:.2f}s for two 0.3s checks"


# =======================================================================================
# Tenancy, transactions, and pooled-connection safety
# =======================================================================================


async def test_readiness_leaves_no_tenant_binding_on_the_pooled_connection(
    ops_client: AsyncClient, app_engine: AsyncEngine
) -> None:
    """A probe that bound a tenant would poison whichever request reused the connection.

    Readiness borrows a connection from the application pool. If it ever set
    `app.workspace_id` — or ran inside a transaction that left one set — the next request
    to pick up that connection could read another tenant's rows before binding its own.
    Asserted by reading the GUC directly after a burst of probes.
    """
    for _ in range(5):
        assert (await ops_client.get("/health/ready")).status_code == 200

    factory = async_sessionmaker(app_engine, expire_on_commit=False)
    for _ in range(3):
        async with factory() as session, session.begin():
            inherited = await session.scalar(
                text("SELECT current_setting('app.workspace_id', true)")
            )
            assert not inherited, f"readiness left a tenant bound: {inherited!r}"


async def test_readiness_writes_nothing_and_creates_no_state(
    ops_client: AsyncClient, admin_engine: AsyncEngine
) -> None:
    """A health check must be free to run every few seconds forever.

    Compares the full row count of every application table before and after a burst of
    probes — a probe that inserted an audit row, touched `last_used_at`, or created a
    session record would grow the database at the orchestrator's polling rate.
    """

    async def snapshot() -> dict[str, int]:
        async with admin_engine.begin() as conn:
            # noqa S608: the table names are literals in the tuple below, never input.
            return {
                table: (await conn.scalar(text(f"SELECT count(*) FROM {table}")) or 0)  # noqa: S608
                for table in ("workspaces", "members", "api_tokens")
            }

    before = await snapshot()
    for _ in range(5):
        await ops_client.get("/health/ready")
    assert await snapshot() == before


async def test_readiness_does_not_hold_a_transaction_open(admin_engine: AsyncEngine) -> None:
    """No idle-in-transaction connections left behind.

    A probe that opened a transaction and never closed it would accumulate
    `idle in transaction` backends at the polling rate, each holding a snapshot that
    blocks vacuum — a slow-motion outage that looks like nothing until the table bloats.
    """
    for _ in range(5):
        assert await check_database() is True

    async with admin_engine.begin() as conn:
        idle = await conn.scalar(
            text(
                "SELECT count(*) FROM pg_stat_activity"
                " WHERE state = 'idle in transaction' AND application_name <> ''"
            )
        )
    assert (idle or 0) == 0, f"{idle} connections left idle in transaction"


# =======================================================================================
# Isolation from the application's security machinery
# =======================================================================================


async def test_readiness_never_touches_authentication_or_authorization(
    ops_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Proven by making those paths explode, not by reading the route signature.

    If the endpoint ever acquired an authentication or authorization dependency — directly
    or by someone adding a global one — infrastructure would start receiving 401s and the
    service would be marked permanently unready. Booby-trapping both paths turns that into
    a test failure instead of an outage.
    """
    import app.core.authorization as authorization_module
    import app.core.security as security_module

    async def must_not_run(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a health endpoint reached the authentication/authorization path")

    monkeypatch.setattr(security_module, "get_workspace_context", must_not_run)
    monkeypatch.setattr(authorization_module, "resolve_member_role", must_not_run)

    assert (await ops_client.get("/health")).status_code == 200
    assert (await ops_client.get("/health/ready")).status_code == 200


async def test_readiness_ignores_caller_supplied_parameters(ops_client: AsyncClient) -> None:
    """Nothing a caller sends can influence an infrastructure probe."""
    for params in (
        {"workspace_id": "11111111-1111-1111-1111-111111111111"},
        {"ready": "false"},
        {"database": "skip"},
        {"redis": "skip"},
    ):
        response = await ops_client.get("/health/ready", params=params)
        assert response.status_code == 200
        assert response.json() == {"status": "ready"}


# =======================================================================================
# Concurrency and observability
# =======================================================================================


async def test_concurrent_probes_are_consistent_and_leak_nothing(
    ops_client: AsyncClient, admin_engine: AsyncEngine
) -> None:
    """Infrastructure calls this endpoint constantly and from several monitors at once."""

    async def probe() -> int:
        return (await ops_client.get("/health/ready")).status_code

    async with admin_engine.begin() as conn:
        before = await conn.scalar(text("SELECT count(*) FROM pg_stat_activity"))

    results = await asyncio.gather(*(probe() for _ in range(20)))

    assert set(results) == {200}
    async with admin_engine.begin() as conn:
        after = await conn.scalar(text("SELECT count(*) FROM pg_stat_activity"))
    assert (after or 0) - (before or 0) < 15, "concurrent probes leaked connections"


async def test_a_readiness_failure_is_logged_without_disclosing_anything_sensitive(
    ops_client: AsyncClient,
) -> None:
    """Diagnosis belongs in the logs — but the logs must not carry the DSN either.

    `assert emitted` runs first and is doing real work: `configure_logging` installs
    `PrintLoggerFactory`, so `caplog` observes nothing, and structlog freezes a logger's
    level on first use. Without the guard this would pass against an empty buffer, which is
    exactly the defect CI caught in M1.2-F.
    """
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer), broken_database(), broken_redis():
        response = await ops_client.get("/health/ready")

    assert response.status_code == 503
    emitted = buffer.getvalue()
    assert emitted, "nothing was logged — every assertion below would be vacuous"
    assert "readiness" in emitted, "the readiness failure was not recorded at all"

    lowered = emitted.lower()
    for forbidden in (
        "omniai_app",
        "password",
        "postgresql://",
        "postgresql+asyncpg://",
        "redis://",
        "59999",
        "59998",
    ):
        assert forbidden not in lowered, f"the log stream disclosed {forbidden!r}"


async def test_the_report_shape_is_deterministic() -> None:
    """`ReadinessReport` is what the logs render; it must stay boring and total."""
    healthy = ReadinessReport(database=True, redis=True)
    degraded = ReadinessReport(database=True, redis=False)

    assert healthy.ready is True
    assert degraded.ready is False
    assert healthy.as_log_fields() == {"database": "ok", "redis": "ok"}
    assert degraded.as_log_fields() == {"database": "ok", "redis": "unavailable"}


async def test_each_probe_reports_failure_independently() -> None:
    """Both probes always run, so a double outage is visible as a double outage."""
    with broken_database():
        assert await check_database() is False
        assert await check_redis() is True

    with broken_redis():
        assert await check_redis() is False
        assert await check_database() is True

    with broken_database(), broken_redis():
        report = await check_readiness()
    assert report.database is False and report.redis is False and report.ready is False
