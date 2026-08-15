"""Event envelope + bus mechanics (M1.4-B0.4, ADR-0023) — no database.

Covers the contract that does not need a transaction: envelope validation, immutability,
JSON-safe payloads, the forbidding of smuggled authority fields, explicit registration,
type-scoped dispatch, handler-failure isolation, bounded reentrancy, fail-closed publish
outside a transaction, and secret-safe handler-failure logging. The transactional
(post-commit / rollback / tenant-isolation / concurrency) contract is proven against real
Postgres in tests/integration/test_event_bus.py.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta, timezone

import pytest
import structlog
from pydantic import ValidationError

from app.core.db import UnitOfWork, WorkspaceNotBoundError
from app.core.events import (
    MAX_DISPATCH_DEPTH,
    Event,
    EventBus,
    EventPublishOutsideTransactionError,
    EventWorkspaceMismatchError,
    current_sink,
    event_bus,
)

WS = uuid.uuid4()


def _event(**over: object) -> Event:
    base: dict[str, object] = {"event_type": "connector.ingested", "workspace_id": WS}
    base.update(over)
    return Event(**base)  # type: ignore[arg-type]


# ------------------------------------------------------------------ envelope: identity & time


def test_event_id_defaults_to_a_server_generated_uuidv7() -> None:
    """The id is server-generated and time-ordered (UUIDv7), not a v4 — reused from core/ids."""
    e = _event()
    assert isinstance(e.event_id, uuid.UUID)
    assert e.event_id.version == 7
    assert _event().event_id != e.event_id  # a fresh id each construction


def test_occurred_at_defaults_to_aware_utc() -> None:
    e = _event()
    assert e.occurred_at.tzinfo is not None
    assert e.occurred_at.utcoffset() == timedelta(0)


def test_a_naive_occurred_at_is_rejected() -> None:
    """A wall-clock with no offset must never silently become the canonical event time."""
    with pytest.raises(ValidationError):
        _event(occurred_at=datetime(2026, 1, 1, 12, 0, 0))  # noqa: DTZ001 (intentionally naive)


def test_an_aware_non_utc_occurred_at_is_normalised_to_utc() -> None:
    ist = timezone(timedelta(hours=5, minutes=30))
    e = _event(occurred_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=ist))
    assert e.occurred_at.utcoffset() == timedelta(0)
    assert e.occurred_at == datetime(2026, 1, 1, 6, 30, 0, tzinfo=UTC)


# ------------------------------------------------------------------ envelope: type & version


@pytest.mark.parametrize("bad", ["", "nodot", "UPPER.Case", "a.", ".b", "a..b", "a.b ", " a.b"])
def test_event_type_must_be_a_dotted_namespace(bad: str) -> None:
    with pytest.raises(ValidationError):
        _event(event_type=bad)


@pytest.mark.parametrize("good", ["connector.ingested", "connection.activated", "a.b.c"])
def test_event_type_accepts_dotted_namespaces(good: str) -> None:
    assert _event(event_type=good).event_type == good


def test_version_defaults_to_one() -> None:
    assert _event().version == 1


@pytest.mark.parametrize("bad", [0, -1, -99])
def test_version_must_be_positive(bad: int) -> None:
    with pytest.raises(ValidationError):
        _event(version=bad)


# ------------------------------------------------------------------ envelope: tenancy & payload


def test_workspace_id_is_required() -> None:
    with pytest.raises(ValidationError):
        Event(event_type="a.b")  # type: ignore[call-arg]


def test_payload_defaults_to_empty_and_accepts_json_safe_values() -> None:
    e = _event(payload={"n": 1, "s": "x", "b": True, "nil": None, "nested": {"a": [1, 2]}})
    assert e.payload["nested"] == {"a": [1, 2]}
    assert _event().payload == {}


@pytest.mark.parametrize("bad", [object(), {1, 2, 3}, datetime.now(UTC), lambda: 1])
def test_payload_rejects_arbitrary_python_objects(bad: object) -> None:
    """`JsonValue` admits only JSON-safe values, so an ORM entity, a set, a datetime, a
    connection, or any arbitrary object cannot ride in a payload."""
    with pytest.raises(ValidationError):
        _event(payload={"x": bad})


@pytest.mark.parametrize("field", ["role", "permissions", "member_id", "actor_id", "token", "jwt"])
def test_authority_fields_cannot_be_smuggled_into_the_envelope(field: str) -> None:
    """`extra='forbid'` is a security control: an event carries WHERE, never WHO/ROLE — a
    caller cannot add an authority field to the envelope (ADR-0022)."""
    with pytest.raises(ValidationError):
        _event(**{field: "admin"})


# ------------------------------------------------------------------ immutability


@pytest.mark.parametrize("field", ["event_id", "event_type", "version", "workspace_id"])
def test_the_envelope_is_frozen(field: str) -> None:
    e = _event()
    with pytest.raises(ValidationError):
        setattr(e, field, uuid.uuid4() if field in {"event_id", "workspace_id"} else "x")


# ------------------------------------------------------------------ bus: registration & dispatch


async def test_subscribe_then_dispatch_delivers_to_the_handler() -> None:
    bus = EventBus()
    seen: list[Event] = []
    bus.subscribe("connector.ingested", lambda e: seen.append(e))
    e = _event()
    await bus.dispatch([e])
    assert seen == [e]


async def test_multiple_handlers_for_a_type_all_run() -> None:
    bus = EventBus()
    calls: list[str] = []
    bus.subscribe("connector.ingested", lambda _e: calls.append("h1"))
    bus.subscribe("connector.ingested", lambda _e: calls.append("h2"))
    await bus.dispatch([_event()])
    assert calls == ["h1", "h2"]


async def test_a_handler_only_receives_its_subscribed_type() -> None:
    bus = EventBus()
    seen: list[str] = []
    bus.subscribe("connector.ingested", lambda e: seen.append(e.event_type))
    await bus.dispatch([_event(event_type="connection.activated")])  # different type
    assert seen == []


async def test_an_unknown_event_type_dispatches_to_nobody() -> None:
    bus = EventBus()
    # No subscribers registered at all — dispatch is a clean no-op, never an error.
    await bus.dispatch([_event(event_type="nobody.listening")])


async def test_both_sync_and_async_handlers_run() -> None:
    bus = EventBus()
    calls: list[str] = []

    async def async_handler(_e: Event) -> None:
        calls.append("async")

    bus.subscribe("connector.ingested", lambda _e: calls.append("sync"))
    bus.subscribe("connector.ingested", async_handler)
    await bus.dispatch([_event()])
    assert sorted(calls) == ["async", "sync"]


# ------------------------------------------------------------------ handler-failure isolation


async def test_a_failing_handler_is_isolated_and_the_others_still_run() -> None:
    bus = EventBus()
    calls: list[str] = []

    def boom(_e: Event) -> None:
        calls.append("boom")
        raise RuntimeError("handler blew up")

    bus.subscribe("connector.ingested", boom)
    bus.subscribe("connector.ingested", lambda _e: calls.append("survivor"))
    await bus.dispatch([_event()])  # must not raise
    assert calls == ["boom", "survivor"]


async def test_a_failing_handler_does_not_propagate_to_the_caller() -> None:
    bus = EventBus()

    def boom(_e: Event) -> None:
        raise ValueError("nope")

    bus.subscribe("connector.ingested", boom)
    await bus.dispatch([_event()])  # the (already-committed) publisher is never failed


# ------------------------------------------------------------------ reentrancy is bounded


async def test_nested_dispatch_is_bounded() -> None:
    """A handler that re-enters `dispatch` cannot recurse without limit: the depth guard stops
    it at MAX_DISPATCH_DEPTH, so a runaway handler fails loudly instead of overflowing the
    stack. The handler's own 50-call ceiling keeps this test fast if the guard is removed."""
    bus = EventBus()
    calls: list[int] = []

    async def reentrant(e: Event) -> None:
        calls.append(1)
        if len(calls) < 50:  # safety valve so a guard-removal mutation fails fast, never hangs
            await bus.dispatch([e])

    bus.subscribe("connector.ingested", reentrant)
    await bus.dispatch([_event()])
    assert len(calls) == MAX_DISPATCH_DEPTH


# ------------------------------------------------------------------ publish fails closed


async def test_publish_without_a_bound_transaction_fails_closed() -> None:
    """`publish` needs an ambient transaction to buffer on; with none it refuses rather than
    delivering immediately (which would break the rolled-back-emits-nothing guarantee)."""
    assert current_sink.get() is None
    with pytest.raises(EventPublishOutsideTransactionError):
        event_bus.publish(_event())


# ------------------------------------------------------------------ secret-safe logging


async def test_a_handler_failure_logs_identifiers_only_never_the_payload() -> None:
    """The isolation log records the non-secret envelope identifiers and *not* the payload —
    so a secret a domain accidentally placed in a payload cannot ride a handler traceback out
    to the logs (§34: zero raw event payload dumps)."""
    bus = EventBus()

    def boom(_e: Event) -> None:
        raise RuntimeError("boom")

    bus.subscribe("connector.ingested", boom)
    leaked_marker = "sk-must-not-appear"  # noqa: S105 (a fake marker, not a real credential)
    with structlog.testing.capture_logs() as logs:
        await bus.dispatch([_event(payload={"api_key": leaked_marker})])

    failed = [e for e in logs if e.get("event") == "event.handler_failed"]
    assert failed, "the handler failure must be logged"
    record = failed[0]
    assert record["event_type"] == "connector.ingested"
    assert "workspace_id" in record and "event_id" in record
    assert "payload" not in record  # the payload is never passed to the logger
    assert leaked_marker not in repr(record)  # the marker never appears anywhere in the record


# ---------------------------------------------- UnitOfWork buffer/drain (the post-commit sink)
#
# buffer_event and drain_events never touch the session (they only guard the tenant and manage
# the in-memory buffer), so they are unit-testable without a database — the transactional
# wiring is proven against real Postgres in tests/integration/test_event_bus.py.


def _bound_uow(ws: uuid.UUID) -> UnitOfWork:
    uow = UnitOfWork(session=None)  # type: ignore[arg-type]  # buffer/drain never use it
    uow._bound.append(ws)
    return uow


def test_buffer_event_requires_a_bound_workspace() -> None:
    uow = UnitOfWork(session=None)  # type: ignore[arg-type]  # unbound
    with pytest.raises(WorkspaceNotBoundError):
        uow.buffer_event(_event())


def test_buffer_event_refuses_an_event_for_a_foreign_tenant() -> None:
    uow = _bound_uow(uuid.uuid4())
    with pytest.raises(EventWorkspaceMismatchError):
        uow.buffer_event(_event(workspace_id=uuid.uuid4()))


def test_buffer_event_accepts_the_bound_tenant_and_drain_clears_the_buffer() -> None:
    ws = uuid.uuid4()
    uow = _bound_uow(ws)
    e = _event(workspace_id=ws)
    uow.buffer_event(e)
    assert uow.drain_events() == [e]
    assert uow.drain_events() == [], "drain clears the buffer — no event is emitted twice"
