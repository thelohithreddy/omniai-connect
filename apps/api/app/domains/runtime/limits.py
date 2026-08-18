"""Tool-Call rate limits & quotas — the Runtime's stage-3 policy checks (M2.4, ADR-0037).

The canonical architecture (AI_RUNTIME §2 stage 3; founder-ratified D1–D5, 2026-08-18):

- **One enforcement point**: `RuntimeService.execute`, at the top of the audited region — REST
  and MCP share one budget structurally because both surfaces call the same method. No
  interface-specific counters exist (`interface` is audit metadata, never a key dimension).
- **Algorithm**: Redis **token bucket**, atomic via one Lua script evaluated server-side, with
  the clock read from Redis `TIME` inside the script — application clocks never participate in
  refill math, so multi-instance skew cannot over- or under-admit.
- **Keys** (canonical namespace, identity always from the server-derived `WorkspaceContext`):
  `ws:{workspace_id}:rl:tools` — the per-Workspace bucket;
  `ws:{workspace_id}:rl:conn:{connection_id}` — per-Connection, **only** when the Tool's
  canonical `annotations.rate_hints` declares `requests_per_minute` (hints are advisory data;
  no hint → no fabricated default bucket);
  `ws:{workspace_id}:quota:{iso-week}` — the weekly executed-call counter.
- **D1 numbers (Free plan)**: 60 Tool Calls/min sustained (refill 1/s), burst capacity 10;
  1,000 executed Tool Calls per ISO week (UTC). Paid plans (`pro|team|enterprise`) are
  unenforced until M3 billing wires real plan limits — `workspaces.plan` is authoritative.
- **D2 consumption**: a rate token is consumed by every call reaching stage 3; a **quota unit
  is consumed only by an executed call** — audit statuses `succeeded`/`failed`/`timeout`,
  recorded exactly once at audit-write time. `denied` calls (rate/quota/egress/state) and
  pre-audit failures never consume quota, so quota accounting stays aligned with the audit
  ledger the M3 billing reconciliation will read.
- **D3 failure policy**: Redis unavailable → **fail closed** for both checks. The denial is a
  `RateLimitedError` with a safe generic message (the call is retryable — 429 semantics are
  the honest contract) and a `limits_unavailable` structured log for alerting. The
  post-execution quota *increment* is the one exception: the call has already executed, so an
  increment failure is logged and swallowed (an under-count can never over-charge; M3
  reconciles from the audit ledger).
- **Kill switch** (`settings.rate_limiting_enabled`): an operational rollback lever restoring
  exact pre-M2.4 behavior (no checks, no counting). It is all-or-nothing and cannot partially
  bypass quota semantics: enabled → full canonical enforcement including fail-closed.

Nothing here reads client-supplied identity, logs a secret, or opens a second enforcement
path. Errors carry only numbers and reset timestamps.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from app.core.config import settings
from app.core.exceptions import QuotaExceededError, RateLimitedError
from app.core.logging import get_logger
from app.core.redis import redis_client

log = get_logger(__name__)

#: Audit statuses that constitute an *executed* call (D2) — the only quota-consuming outcomes.
EXECUTED_STATUSES: Final = frozenset({"succeeded", "failed", "timeout"})

_UNAVAILABLE_MESSAGE: Final = (
    "Rate limiting is temporarily unavailable; the call was not executed. Retry shortly."
)
_RATE_MESSAGE: Final = "Rate limit exceeded for this workspace. Retry after the indicated delay."
_CONN_RATE_MESSAGE: Final = (
    "Rate limit exceeded for this connection. Retry after the indicated delay."
)
_QUOTA_MESSAGE: Final = "The workspace's weekly Tool Call quota is exhausted."

# One atomic token-bucket step. State: HASH {tokens, ts}; clock: Redis TIME (server-side,
# microsecond precision) — deterministic under script-effect replication, immune to app-server
# clock skew. Malformed/foreign state (non-numeric fields) safely resets to a full bucket.
# Returns {allowed(0|1), retry_after_seconds(int)}.
_BUCKET_SCRIPT: Final = """
local rate = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000
local state = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts = tonumber(state[2])
if tokens == nil or ts == nil or ts > now then
  tokens = capacity
  ts = now
end
tokens = math.min(capacity, tokens + (now - ts) * rate)
local allowed = 0
local retry = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
else
  retry = math.ceil((1 - tokens) / rate)
end
redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', KEYS[1], ttl)
return {allowed, retry}
"""


@dataclass(frozen=True, slots=True)
class PlanLimits:
    """The enforced limits for one plan. `None` fields mean unenforced (paid plans until M3)."""

    rate_per_minute: int | None
    burst: int | None
    weekly_quota: int | None


def limits_for_plan(plan: str) -> PlanLimits:
    """D1: Free is enforced; paid plans are canonically generous/unlimited until M3 billing."""
    if plan == "free":
        return PlanLimits(
            rate_per_minute=settings.free_workspace_rate_per_minute,
            burst=settings.free_workspace_burst,
            weekly_quota=settings.free_weekly_quota,
        )
    return PlanLimits(rate_per_minute=None, burst=None, weekly_quota=None)


def _workspace_bucket_key(workspace_id: uuid.UUID) -> str:
    return f"ws:{workspace_id}:rl:tools"


def _connection_bucket_key(workspace_id: uuid.UUID, connection_id: uuid.UUID) -> str:
    return f"ws:{workspace_id}:rl:conn:{connection_id}"


def _quota_key(workspace_id: uuid.UUID, now: datetime) -> str:
    year, week, _ = now.isocalendar()
    return f"ws:{workspace_id}:quota:{year}-W{week:02d}"


def _week_end(now: datetime) -> datetime:
    """Start of the next ISO week (Monday 00:00 UTC) — when the weekly quota resets."""
    start_of_week = (now - timedelta(days=now.isoweekday() - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    return start_of_week + timedelta(days=7)


def _bucket_ttl(rate_per_minute: int, burst: int) -> int:
    """Idle-expiry: long enough to refill from empty several times over, so an active bucket
    never expires mid-conversation while an abandoned workspace's key self-cleans."""
    return max(120, int(burst / max(rate_per_minute / 60.0, 0.001)) * 4)


def _rate_hint(tool_annotations: Any) -> tuple[int, int] | None:
    """The canonical per-Connection seed (CONNECTOR_SPEC §9): `rate_hints.requests_per_minute`
    (+ optional `burst`). Advisory data — absent or malformed hints mean no Connection bucket;
    a hint can only *narrow* within the workspace limit, never grant beyond it."""
    if not isinstance(tool_annotations, dict):
        return None
    hints = tool_annotations.get("rate_hints")
    if not isinstance(hints, dict):
        return None
    rpm = hints.get("requests_per_minute")
    if not isinstance(rpm, int) or isinstance(rpm, bool) or rpm <= 0:
        return None
    burst = hints.get("burst")
    if not isinstance(burst, int) or isinstance(burst, bool) or burst <= 0:
        # A full minute's allowance as capacity when no burst is declared.
        burst = rpm
    return rpm, burst


async def _take_token(key: str, rate_per_minute: int, burst: int) -> tuple[bool, int]:
    """One atomic bucket step; returns (allowed, retry_after_seconds). Raises on Redis failure
    (the caller maps it to the fail-closed denial)."""
    async with redis_client() as redis:
        allowed, retry = await redis.eval(
            _BUCKET_SCRIPT,
            1,
            key,
            rate_per_minute / 60.0,
            burst,
            _bucket_ttl(rate_per_minute, burst),
        )
    return bool(allowed), int(retry)


async def enforce_tool_call_limits(
    *,
    workspace_id: uuid.UUID,
    plan: str,
    connection_id: uuid.UUID,
    tool_annotations: Any,
) -> None:
    """The stage-3 policy checks, in canonical order: workspace bucket → Connection bucket
    (hint-seeded) → weekly quota (check only; consumption happens at audit-write). Raises
    `RateLimitedError` / `QuotaExceededError`; every identity input is server-derived.
    """
    if not settings.rate_limiting_enabled:
        return
    limits = limits_for_plan(plan)
    hint = _rate_hint(tool_annotations)
    if limits.rate_per_minute is None and hint is None:
        return  # nothing to enforce for this plan/tool

    try:
        if limits.rate_per_minute is not None and limits.burst is not None:
            allowed, retry = await _take_token(
                _workspace_bucket_key(workspace_id), limits.rate_per_minute, limits.burst
            )
            if not allowed:
                raise RateLimitedError(
                    _RATE_MESSAGE,
                    details={
                        "retry_after_seconds": retry,
                        "limit_per_minute": limits.rate_per_minute,
                    },
                )
        if hint is not None:
            rpm, burst = hint
            allowed, retry = await _take_token(
                _connection_bucket_key(workspace_id, connection_id), rpm, burst
            )
            if not allowed:
                raise RateLimitedError(
                    _CONN_RATE_MESSAGE,
                    details={"retry_after_seconds": retry, "limit_per_minute": rpm},
                )
        if limits.weekly_quota is not None:
            now = datetime.now(UTC)
            async with redis_client() as redis:
                raw = await redis.get(_quota_key(workspace_id, now))
            used = int(raw) if raw is not None else 0
            if used >= limits.weekly_quota:
                resets_at = _week_end(now)
                raise QuotaExceededError(
                    _QUOTA_MESSAGE,
                    details={
                        "quota": limits.weekly_quota,
                        "used": used,
                        "retry_after_seconds": max(1, int((resets_at - now).total_seconds())),
                        "quota_resets_at": resets_at.isoformat().replace("+00:00", "Z"),
                    },
                )
    except (RateLimitedError, QuotaExceededError):
        raise
    except Exception:
        # D3: Redis unavailable/failed mid-check → FAIL CLOSED. Never silent bypass; the
        # denial is retryable (429) and loudly logged for alerting. No OS/Redis detail leaks.
        log.warning("runtime.limits_unavailable", workspace_id=str(workspace_id))
        raise RateLimitedError(_UNAVAILABLE_MESSAGE, details={"retry_after_seconds": 10}) from None


async def record_executed_call(*, workspace_id: uuid.UUID, plan: str, status: str) -> None:
    """D2 quota consumption: exactly one increment per *executed* audited call, at audit-write.

    Called by the Runtime's audit step; never by adapters. Denied calls and non-Free plans are
    no-ops. An increment failure after execution is logged and swallowed — the call already
    ran, and an under-count can never over-charge (M3 reconciles from the audit ledger)."""
    if not settings.rate_limiting_enabled:
        return
    if status not in EXECUTED_STATUSES:
        return
    if limits_for_plan(plan).weekly_quota is None:
        return
    now = datetime.now(UTC)
    key = _quota_key(workspace_id, now)
    try:
        async with redis_client() as redis:
            await redis.incr(key)
            # Idempotent, cheap, and self-healing: even if a crash once skipped it, the next
            # increment re-stamps expiry. One day of slack past the reset keeps the counter
            # inspectable just after rollover without ever spanning two periods of enforcement.
            await redis.expireat(key, int((_week_end(now) + timedelta(days=1)).timestamp()))
    except Exception:
        log.warning("runtime.quota_record_failed", workspace_id=str(workspace_id))


__all__ = [
    "EXECUTED_STATUSES",
    "PlanLimits",
    "enforce_tool_call_limits",
    "limits_for_plan",
    "record_executed_call",
]
