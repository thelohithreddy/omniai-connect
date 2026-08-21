"""Bounded in-process counters (M2.6, ADR-0039).

The ratified vault-access audit (A2) is **structured logs + metrics only** — no second audit
ledger, no new table. Logs carry the per-event detail (they handle high cardinality; that is what
a log platform is for); this module carries the aggregate, which must not.

The one thing a counter has to get right is **cardinality**, because an unbounded label is how a
metric quietly becomes an outage: one series per workspace, per connection, or per error string is
memory that only grows. So boundedness here is enforced rather than documented — every metric
declares its labels and the exact closed set of values each may take, and an undeclared value
raises instead of silently allocating a series. A programming error surfaces in tests; it cannot
become a slow leak in production.

Deliberately not a metrics *backend*: nothing is scraped or exported yet. This is the hook and the
bound, sized to what M2.6 ratified. Wiring it to an exporter is the observability milestone's job,
and when that happens the call sites do not change.
"""

from __future__ import annotations

import threading
from types import MappingProxyType

from app.domains.credentials.models import CREDENTIAL_TYPES

#: Every counter, with the closed set of values each label may take. The product of these sets is
#: the hard ceiling on series count — for the vault counter, 6 types × 4 outcomes = 24.
_DECLARED: dict[str, dict[str, frozenset[str]]] = {
    # One increment per attempt to open a Credential at the runtime's decrypt boundary.
    "vault.credential_opens": {
        "credential_type": frozenset(CREDENTIAL_TYPES),
        "outcome": frozenset({"ok", "decrypt_failed", "key_unavailable", "malformed"}),
    },
}

_lock = threading.Lock()
_counters: dict[tuple[str, tuple[tuple[str, str], ...]], int] = {}


def increment(name: str, **labels: str) -> None:
    """Add one to a declared counter. Raises on an undeclared metric, label, or label value.

    Raising is the point: these call sites are internal and pass values from closed sets they
    control, so a violation is a bug to be caught by a test — not a condition to tolerate at
    runtime by allocating whatever series it was handed.
    """
    try:
        declared = _DECLARED[name]
    except KeyError:
        raise ValueError(f"undeclared metric: {name}") from None
    if set(labels) != set(declared):
        raise ValueError(f"metric {name} expects labels {sorted(declared)}, got {sorted(labels)}")
    for label, value in labels.items():
        if value not in declared[label]:
            raise ValueError(f"metric {name} label {label} has undeclared value {value!r}")
    key = (name, tuple(sorted(labels.items())))
    with _lock:
        _counters[key] = _counters.get(key, 0) + 1


def snapshot() -> MappingProxyType[tuple[str, tuple[tuple[str, str], ...]], int]:
    """A read-only view of current counter values, for tests and a future exporter."""
    with _lock:
        return MappingProxyType(dict(_counters))


def reset() -> None:
    """Clear all counters. Test-support only — nothing in the request path calls this."""
    with _lock:
        _counters.clear()


__all__ = ["increment", "reset", "snapshot"]
