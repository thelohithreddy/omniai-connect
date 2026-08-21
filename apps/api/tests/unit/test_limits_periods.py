"""Pure math of the M2.4 limiter — period keys, week rollover, plan table, hint parsing.

No Redis, no DB. The atomic bucket itself lives in Lua and is proven against real Redis in
tests/integration/test_rate_limits_api.py.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.domains.runtime.limits import (
    EXECUTED_STATUSES,
    _quota_key,
    _rate_hint,
    _week_end,
    limits_for_plan,
)

WS = uuid.uuid4()


def test_quota_key_is_iso_week_scoped_and_workspace_namespaced() -> None:
    # 2026-08-18 is a Tuesday in ISO week 34.
    now = datetime(2026, 8, 18, 13, 0, tzinfo=UTC)
    assert _quota_key(WS, now) == f"ws:{WS}:quota:2026-W34"


def test_week_end_is_next_monday_midnight_utc() -> None:
    tuesday = datetime(2026, 8, 18, 13, 45, 12, tzinfo=UTC)
    assert _week_end(tuesday) == datetime(2026, 8, 24, 0, 0, tzinfo=UTC)
    # A Monday resets the FOLLOWING Monday — a full week, never same-day.
    monday = datetime(2026, 8, 24, 0, 0, tzinfo=UTC)
    assert _week_end(monday) == datetime(2026, 8, 31, 0, 0, tzinfo=UTC)
    # Sunday 23:59 rolls over within the minute.
    sunday = datetime(2026, 8, 23, 23, 59, tzinfo=UTC)
    assert _week_end(sunday) == datetime(2026, 8, 24, 0, 0, tzinfo=UTC)


def test_iso_year_boundary_keys_differ() -> None:
    # 2026-12-28 is ISO 2026-W53; 2027-01-04 is ISO 2027-W01 — distinct counters.
    late = _quota_key(WS, datetime(2026, 12, 28, tzinfo=UTC))
    early = _quota_key(WS, datetime(2027, 1, 4, tzinfo=UTC))
    assert late != early and late.endswith("2026-W53") and early.endswith("2027-W01")


def test_plan_table_free_enforced_paid_unenforced() -> None:
    free = limits_for_plan("free")
    assert (free.rate_per_minute, free.burst, free.weekly_quota) == (60, 10, 1000)
    for plan in ("pro", "team", "enterprise"):
        limits = limits_for_plan(plan)
        assert limits.rate_per_minute is None and limits.weekly_quota is None


def test_rate_hint_parsing_is_strict() -> None:
    assert _rate_hint({"rate_hints": {"requests_per_minute": 30, "burst": 5}}) == (30, 5)
    assert _rate_hint({"rate_hints": {"requests_per_minute": 30}}) == (30, 30)  # derived burst
    # Absent, malformed, non-positive, or boolean-typed hints yield NO connection bucket.
    for candidate in (
        None,
        {},
        {"rate_hints": None},
        {"rate_hints": "60"},
        {"rate_hints": {"requests_per_minute": 0}},
        {"rate_hints": {"requests_per_minute": -5}},
        {"rate_hints": {"requests_per_minute": True}},
        {"rate_hints": {"requests_per_minute": "60"}},
    ):
        assert _rate_hint(candidate) is None, candidate


def test_executed_statuses_are_exactly_the_d2_set() -> None:
    assert {"succeeded", "failed", "timeout"} == EXECUTED_STATUSES
    assert "denied" not in EXECUTED_STATUSES
