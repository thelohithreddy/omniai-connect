"""Readiness probes for the dependencies OBSERVABILITY.md §6 names.

§6 defines the split this module implements the second half of:

- `GET /health` — *"liveness on the API — process up, event loop responsive. **No
  dependency checks**, so a Neon blip doesn't restart-loop healthy processes."*
- `GET /health/ready` — *"readiness — verifies DB connectivity (cheap `SELECT 1`) and
  Redis ping. Railway uses readiness for deploy gating; liveness for restarts."*

That distinction is the whole point, and getting it wrong is a well-known way to turn a
brief dependency outage into a total one: if liveness checked the database, a thirty-second
Neon blip would make the orchestrator conclude every API process was broken and kill them
all, so the moment the database returned there would be no warm processes left to serve.
Readiness is the signal that means "stop sending me traffic"; liveness means "this process
is beyond saving, replace it". Only readiness may depend on anything external.

**These probes are deliberately not application requests.** They take no
`WorkspaceContext`, open no `UnitOfWork`, touch no tenant table, and never set
`app.workspace_id` — a readiness check that bound a tenant would leave that binding on a
pooled connection for whatever request picked it up next. They read nothing, write nothing,
and commit nothing.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass

import redis.asyncio as aioredis
import structlog
from sqlalchemy import text

from app.core.config import settings
from app.core.db import engine

log = structlog.get_logger(__name__)

#: Per-dependency budget. A readiness probe that can hang is worse than one that fails:
#: the orchestrator's own timeout fires instead, every probe occupies a worker until it
#: does, and a slow dependency becomes an outage of the process checking it. No canonical
#: value exists, so this is derived from the in-repo precedent — docker-compose's API
#: healthcheck uses `timeout: 5s` — and set comfortably below it so this endpoint answers
#: before the caller gives up, even with both dependencies degraded.
PROBE_TIMEOUT_SECONDS = 2.0


@dataclass(frozen=True, slots=True)
class ReadinessReport:
    """Per-dependency outcome. Structured for logs, never for the HTTP body.

    The endpoint is unauthenticated and, per §6, monitored from the public internet. Which
    dependency is failing is genuinely useful to an operator and mildly useful to an
    attacker choosing a moment, so it goes to the log stream — where OBSERVABILITY.md
    already routes diagnosis — while the response says only ready or not.
    """

    database: bool
    redis: bool

    @property
    def ready(self) -> bool:
        return self.database and self.redis

    def as_log_fields(self) -> dict[str, str]:
        return {
            "database": "ok" if self.database else "unavailable",
            "redis": "ok" if self.redis else "unavailable",
        }


async def check_database() -> bool:
    """`SELECT 1` on the application pool, bounded. Exactly what §6 specifies.

    Uses `engine.connect()` rather than the request's `UnitOfWork` on purpose. `get_uow`
    opens a transaction so that `SET LOCAL` has something to be local to — appropriate for
    tenant work and wrong here, because readiness is not a tenant request and must not
    begin one. The connection is returned to the pool with nothing set on it.

    `SELECT 1` rather than a table read: it proves the pool can hand out a connection and
    the server will answer, without depending on any schema, any row, or any RLS policy —
    so readiness cannot start failing because a migration is mid-flight.
    """
    try:
        async with asyncio.timeout(PROBE_TIMEOUT_SECONDS):
            async with engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
        return True
    except Exception as exc:  # noqa: BLE001 — a probe converts every failure into "not ready"
        # Deliberately broad. A readiness probe exists to answer one boolean, and the ways a
        # database can be unreachable (DNS, TLS, auth, pool exhaustion, cancellation) are
        # not worth enumerating: any of them means "do not send this process traffic".
        # Letting one escape would return a 500 with a traceback instead of the operational
        # 503 the orchestrator needs.
        log.warning("readiness.database_unavailable", error_type=type(exc).__name__)
        return False


async def check_redis() -> bool:
    """`PING`, bounded. Also exactly what §6 specifies.

    The client is created per probe and closed in a `finally`. A module-level client would
    avoid the connection churn, but it would also outlive failures and require shutdown
    wiring the application does not currently have; at one probe every few seconds the
    churn is irrelevant and a leaked connection would not be.

    Socket timeouts are set in addition to the outer `asyncio.timeout` because they bound
    the connect and read separately — the outer timeout would otherwise be the only thing
    standing between a black-holed TCP connection and a hung probe.
    """
    client: aioredis.Redis | None = None
    try:
        async with asyncio.timeout(PROBE_TIMEOUT_SECONDS):
            client = aioredis.from_url(
                settings.redis_url,
                socket_connect_timeout=PROBE_TIMEOUT_SECONDS,
                socket_timeout=PROBE_TIMEOUT_SECONDS,
            )
            await client.ping()
        return True
    except Exception as exc:  # noqa: BLE001 — same reasoning as the database probe
        log.warning("readiness.redis_unavailable", error_type=type(exc).__name__)
        return False
    finally:
        if client is not None:
            # A failure while closing must not change the probe's answer or replace it with
            # an exception: the dependency has already been judged, and the likeliest reason
            # `aclose()` raises is the very outage the probe just detected.
            with contextlib.suppress(Exception):
                await client.aclose()


async def check_readiness() -> ReadinessReport:
    """Probe every dependency §6 requires, concurrently.

    Concurrent rather than sequential so the endpoint's worst case is one timeout rather
    than the sum of them — with two dependencies that is the difference between answering
    in two seconds and four, and the orchestrator is waiting on the answer.

    Both probes always run: short-circuiting on the first failure would make the logs say
    only "database down" during an outage that took both, and an operator would fix one
    dependency and be surprised the service was still unready.

    `return_exceptions=True` makes this function **total**. Each probe already converts its
    own failures into `False`, so in normal operation nothing propagates — but "the probe
    itself raised" is a different event from "the dependency is down", and it must not be
    the one case where readiness answers 500 instead of 503. A 500 here is ambiguous to an
    orchestrator (is the app broken, or the check?) and would render a traceback through the
    error path on an unauthenticated endpoint. Anything other than `True` means not ready.
    """
    results = await asyncio.gather(check_database(), check_redis(), return_exceptions=True)
    for outcome in results:
        if isinstance(outcome, BaseException):
            log.warning("readiness.probe_failed", error_type=type(outcome).__name__)
    database, redis_ok = (outcome is True for outcome in results)
    return ReadinessReport(database=database, redis=redis_ok)


__all__ = [
    "PROBE_TIMEOUT_SECONDS",
    "ReadinessReport",
    "check_database",
    "check_readiness",
    "check_redis",
]
