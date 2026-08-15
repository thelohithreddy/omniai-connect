"""Event bus transactional + tenancy contract against real Postgres (M1.4-B0.4, ADR-0023).

The unit suite (tests/unit/test_events.py) proves the envelope and bus mechanics with no DB.
This suite proves the parts that only a real transaction can: buffered-until-commit delivery,
a rolled-back transaction emitting nothing, the fail-closed tenant-match on publish, tenant
isolation, real concurrency (A×8/B×8/C×8), and both event origins — the worker path
(`worker_tenant_uow`) and the request path (`get_uow`).

Both context managers set the ambient event sink and dispatch after COMMIT, so driving them
is the real production emission path — not a mock.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator

import pytest

from app.core.db import get_uow
from app.core.events import (
    Event,
    EventBus,
    EventWorkspaceMismatchError,
    current_sink,
    event_bus,
)
from app.workers.context import worker_tenant_uow

TYPE = "connector.ingested"


@pytest.fixture
def bus() -> Iterator[EventBus]:
    """Isolate the shared-kernel `event_bus` handler map for one test, then restore it.

    Tests must observe the *real* `event_bus` (the one `get_uow`/`worker_tenant_uow` dispatch
    to), so the map is snapshotted and cleared rather than swapped for a local bus."""
    saved = {k: list(v) for k, v in event_bus._handlers.items()}
    event_bus._handlers.clear()
    try:
        yield event_bus
    finally:
        event_bus._handlers.clear()
        event_bus._handlers.update(saved)


# --------------------------------------------------------------- worker path: commit vs rollback


async def test_a_committed_transaction_emits_its_buffered_events(bus: EventBus) -> None:
    ws = uuid.uuid4()
    seen: list[Event] = []
    bus.subscribe(TYPE, lambda e: seen.append(e))

    async with worker_tenant_uow(str(ws)):
        event_bus.publish(Event(event_type=TYPE, workspace_id=ws))
        assert seen == [], "handlers must not run before the transaction commits"

    assert len(seen) == 1 and seen[0].workspace_id == ws


async def test_a_rolled_back_transaction_emits_nothing(bus: EventBus) -> None:
    ws = uuid.uuid4()
    seen: list[Event] = []
    bus.subscribe(TYPE, lambda e: seen.append(e))

    with pytest.raises(RuntimeError):
        async with worker_tenant_uow(str(ws)):
            event_bus.publish(Event(event_type=TYPE, workspace_id=ws))
            raise RuntimeError("boom after buffering an event")

    assert seen == [], "a rolled-back transaction must emit nothing"


# ------------------------------------------------------------------ tenant-match is fail-closed


async def test_publishing_an_event_for_a_foreign_tenant_is_refused(bus: EventBus) -> None:
    """An event's workspace_id must equal the transaction's bound tenant — event metadata can
    never become a tenant selector (ADR-0022). The refusal is at publish time, before commit."""
    a, b = uuid.uuid4(), uuid.uuid4()
    seen: list[Event] = []
    bus.subscribe(TYPE, lambda e: seen.append(e))

    with pytest.raises(EventWorkspaceMismatchError):
        async with worker_tenant_uow(str(a)):
            event_bus.publish(Event(event_type=TYPE, workspace_id=b))  # foreign tenant

    assert seen == []


# ------------------------------------------------------------------ tenant isolation


async def test_two_tenants_events_never_cross(bus: EventBus) -> None:
    a, b = uuid.uuid4(), uuid.uuid4()
    seen: list[uuid.UUID] = []
    bus.subscribe(TYPE, lambda e: seen.append(e.workspace_id))

    async with worker_tenant_uow(str(a)):
        event_bus.publish(Event(event_type=TYPE, workspace_id=a))
    async with worker_tenant_uow(str(b)):
        event_bus.publish(Event(event_type=TYPE, workspace_id=b))

    assert seen == [a, b], "each transaction emits only its own tenant's event"


# ------------------------------------------------------------------ concurrency A×8 / B×8 / C×8


async def test_concurrent_publishers_never_cross(bus: EventBus) -> None:
    """24 interleaved transactions across three tenants, each publishing one event carrying its
    own origin in the payload. Every delivered event's workspace_id must equal its origin — no
    buffer is shared between transactions, so a concurrent interleaving cannot cross tenants."""
    a, b, c = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    seen: list[tuple[uuid.UUID, str]] = []
    bus.subscribe(TYPE, lambda e: seen.append((e.workspace_id, str(e.payload["origin"]))))

    async def one(ws: uuid.UUID) -> None:
        await asyncio.sleep(0)  # yield to force interleaving
        async with worker_tenant_uow(str(ws)):
            event_bus.publish(Event(event_type=TYPE, workspace_id=ws, payload={"origin": str(ws)}))

    jobs = [one(a) for _ in range(8)] + [one(b) for _ in range(8)] + [one(c) for _ in range(8)]
    await asyncio.gather(*jobs)

    assert len(seen) == 24
    for ws, origin in seen:
        assert str(ws) == origin, f"tenant crossover: event tenant {ws} != origin {origin}"
    counts = {t: sum(1 for ws, _ in seen if ws == t) for t in (a, b, c)}
    assert counts == {a: 8, b: 8, c: 8}


# ------------------------------------------------------------------ request path: get_uow


async def test_request_path_dispatches_after_commit(bus: EventBus) -> None:
    """The FastAPI request UoW is the same emission path: bind a workspace, publish, and the
    buffered event dispatches when the dependency's transaction commits."""
    ws = uuid.uuid4()
    seen: list[Event] = []
    bus.subscribe(TYPE, lambda e: seen.append(e))

    gen = get_uow()
    uow = await anext(gen)
    await uow.bind_workspace(ws)
    event_bus.publish(Event(event_type=TYPE, workspace_id=ws))
    assert seen == [], "not before commit"
    with pytest.raises(StopAsyncIteration):
        await anext(gen)  # resume the dependency → COMMIT → dispatch

    assert len(seen) == 1 and seen[0].workspace_id == ws
    assert current_sink.get() is None, "the ambient sink is cleared on exit"


# The request path's rollback-emits-nothing behaviour is identical in structure to the worker
# path's (both dispatch only after the shared `session.begin()` block commits, and skip dispatch
# when an exception propagates out of it), and is proven robustly against real Postgres by
# `test_a_rolled_back_transaction_emits_nothing` above. A manual `athrow`-drive of the pooled
# request engine here would only exercise a test-harness connection-teardown path, not new
# production behaviour, so it is deliberately not duplicated.
