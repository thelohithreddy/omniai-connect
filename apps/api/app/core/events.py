"""Internal event bus — the shared-kernel domain-event transport (M1.4-B0.4, ADR-0023).

Canon (BACKEND_SPEC §4, ADR-0001): the bus is **in-process now, broker later** (Redis
Streams is the planned swap) and the contract is designed so callers never notice the swap.
That single design goal drives every choice here:

- **`bus.publish(event)` takes no transaction handle.** A broker would not buffer on a
  UnitOfWork, so the publisher API must not mention one. In-process, the ambient transaction
  is found through a task-scoped `ContextVar` — the same mechanism `core/logging.py` already
  uses for `request_id`/`workspace_id`, which follows `await` boundaries and never bleeds
  between concurrently-served requests. When the bus becomes a broker, `publish` enqueues to
  Redis Streams instead; the call site is unchanged.
- **Handlers run after COMMIT, buffered on the UoW.** A publish records the event on the
  ambient UnitOfWork; the UoW's own lifecycle (`core/db.py`) dispatches the buffer *after* the
  transaction commits, and a rolled-back transaction discards it — "a rolled-back request
  emits nothing." The bus never opens, commits, or rolls back a transaction.

What this bus is deliberately NOT (all out of scope by canon):

- not an authorization mechanism — an event carries WHERE (`workspace_id`), never WHO / ROLE /
  PERMISSION; publishing an event for a tenant other than the transaction's bound workspace is
  refused (ADR-0022's payload-is-not-authority invariant, enforced in `UnitOfWork.publish`);
- not a tenant selector — the workspace comes from the already-bound trusted context, never
  from a client or a payload field;
- not a second transaction system — the UnitOfWork owns the transaction;
- not a job queue — heavy work is a Celery task a handler enqueues (ADR-0007), never the bus;
- not durable delivery — in-process delivery is best-effort at-most-once (a crash between
  COMMIT and dispatch loses the event); **at-least-once is a property of the *future* broker**,
  so handlers must be idempotent and this module claims no exactly-once guarantee;
- not a persistence layer — it adds no table (customer-facing events use `webhooks_outbox`,
  DATABASE_DESIGN.md, not this bus).
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Awaitable, Callable, Iterable
from contextvars import ContextVar
from datetime import UTC, datetime
from inspect import isawaitable
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from app.core.ids import new_id
from app.core.logging import get_logger

log = get_logger(__name__)

# A dotted namespace: `domain.event`, lowercase, e.g. `connector.ingested` (BACKEND_SPEC §4).
# At least two segments so a bare word can never be a type; machine-readable and stable.
_EVENT_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")

# A loop-guard, NOT a security bound: handlers run post-commit and cannot re-`publish` (there is
# no ambient transaction then), but one that re-enters `dispatch` directly must not recurse
# without limit. Small and deterministic — a handler that exceeds it is a bug, surfaced loudly.
MAX_DISPATCH_DEPTH = 8


class EventBusError(Exception):
    """Base for event-bus misuse. Messages never carry a payload, secret, or credential."""


class EventPublishOutsideTransactionError(EventBusError):
    """`publish` was called with no ambient bound transaction — fail closed.

    An event is a fact about committed work; there is nothing to buffer it on and nothing to
    gate its emission on, so it is refused rather than delivered immediately (which would break
    the rolled-back-emits-nothing guarantee).
    """


class EventWorkspaceMismatchError(EventBusError):
    """An event's `workspace_id` did not match the transaction's bound tenant — fail closed.

    Defence in depth over RLS: an event can never target a tenant other than the one the
    publishing transaction is bound to, so event metadata can never become a tenant selector.
    """


class EventReentrancyError(EventBusError):
    """Nested `dispatch` exceeded `MAX_DISPATCH_DEPTH` — a runaway handler, refused."""


class Event(BaseModel):
    """A frozen domain event (BACKEND_SPEC §4). Immutable fact; server-authored envelope.

    Domains declare their own events in `domains/<name>/events.py` by subclassing this and
    narrowing `payload` to a typed model. The envelope carries WHERE (`workspace_id`) and WHAT
    (`event_type` + `payload`); it carries no actor/role/permission field — WHO, when a domain
    needs it, rides in the typed payload as a non-authoritative reference, never as authority
    (canon lists no actor field; ADR-0022).
    """

    # `extra="forbid"` is a security control, not tidiness: a caller cannot smuggle a `role`,
    # `member_id`, `token`, or any other authority field into the envelope — it is rejected.
    model_config = ConfigDict(frozen=True, extra="forbid")

    # Server-generated UUIDv7 (core/ids.py). There is no endpoint that constructs an event, so
    # the id is structurally server-side; the default makes it so even when omitted.
    event_id: uuid.UUID = Field(default_factory=new_id)
    event_type: str
    # Contract version for this event type. Explicit and starting at 1; same type + higher
    # version = contract evolution. The smallest mechanism — an integer, no schema registry;
    # compatibility is the subscriber's responsibility (documented, ADR-0023).
    version: int = 1
    workspace_id: uuid.UUID
    # Server clock, UTC-aware (the repository's canonical timestamp form — see core/logging.py
    # `TimeStamper(utc=True)`). A client-supplied or naive value is refused by the validator.
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    # JSON-safe by type: `JsonValue` recursively admits only null/bool/int/float/str/list/dict,
    # so an ORM entity, a DB connection, a request object, or any arbitrary Python object is
    # rejected at construction. No size bound is imposed here: in B0.4 an event is authored only
    # by trusted server code (there is no untrusted → payload path), so a byte cap is not a
    # security-critical bound to derive; a future module that accepts untrusted event input owns
    # that limit (ADR-0023).
    payload: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("event_type")
    @classmethod
    def _event_type_is_a_dotted_namespace(cls, value: str) -> str:
        if not _EVENT_TYPE_RE.match(value):
            # No offending value echoed — the field name alone locates the bug.
            raise ValueError("event_type must be a dotted namespace, e.g. 'connector.ingested'")
        return value

    @field_validator("version")
    @classmethod
    def _version_is_positive(cls, value: int) -> int:
        if value < 1:
            raise ValueError("version must be >= 1")
        return value

    @field_validator("occurred_at")
    @classmethod
    def _occurred_at_is_aware_utc(cls, value: datetime) -> datetime:
        # A naive datetime has no offset; accepting it would let a local wall-clock silently
        # become the canonical event time. Refuse it, and normalise any aware value to UTC.
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must be timezone-aware")
        return value.astimezone(UTC)


# Signature domains implement. Sync or async; the bus awaits a coroutine result.
Handler = Callable[[Event], Awaitable[None] | None]


@runtime_checkable
class EventSink(Protocol):
    """What `publish` needs from the ambient transaction: somewhere fail-closed to buffer.

    A Protocol, not an import of `UnitOfWork`, so this module has no dependency on `core/db.py`
    (the dependency runs the other way). `UnitOfWork` structurally satisfies it.
    """

    def buffer_event(self, event: Event) -> None: ...


# The ambient transaction for the current request/task. Task-scoped (follows `await`), set by
# `get_uow` / `worker_tenant_uow` and reset on exit — never a shared mutable global.
current_sink: ContextVar[EventSink | None] = ContextVar("current_event_sink", default=None)


class EventBus:
    """Explicit publish/subscribe. Registration is deterministic (no filesystem scan, no import
    side effects); dispatch reads an immutable handler map and immutable events.
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = {}
        # Nested-dispatch depth, task-scoped so concurrent tenants never share a counter.
        self._depth: ContextVar[int] = ContextVar(f"event_dispatch_depth_{id(self)}", default=0)

    def subscribe(self, event_type: str, handler: Handler) -> None:
        """Register a handler for an event type. Startup-only by contract: the handler map is
        not designed to be mutated concurrently with `dispatch` (BACKEND_SPEC §4 registers at
        startup). Appends, so multiple handlers per type all run.
        """
        self._handlers.setdefault(event_type, []).append(handler)

    def is_subscribed(self, event_type: str, handler: Handler) -> bool:
        """Whether this exact handler is already registered for `event_type`.

        Exists so a domain whose subscribers are registered from more than one composition root
        (M2.10: the API process *and* the Celery worker) can make its registration idempotent
        without reaching into the handler map. `subscribe` deliberately appends — multiple distinct
        handlers per type is a supported shape — so "already registered" is a question only the
        caller can decide is relevant.
        """
        return handler in self._handlers.get(event_type, ())

    def publish(self, event: Event) -> None:
        """Buffer an event on the ambient transaction (canon `bus.publish(event)`).

        Fire-and-forget from the publisher's view: it does not run handlers. Fail closed if
        there is no bound transaction to buffer on. The UoW enforces the tenant-match invariant.
        """
        sink = current_sink.get()
        if sink is None:
            raise EventPublishOutsideTransactionError(
                "publish requires a bound transaction; none is active"
            )
        sink.buffer_event(event)

    async def dispatch(self, events: Iterable[Event]) -> None:
        """Run handlers for already-committed events. Called by the UoW after COMMIT; never by
        the publisher. Each handler is isolated — one handler's failure is logged and never
        stops the others or propagates to the (already-committed) publisher.
        """
        depth = self._depth.get()
        if depth >= MAX_DISPATCH_DEPTH:
            raise EventReentrancyError(f"nested dispatch exceeded depth {MAX_DISPATCH_DEPTH}")
        token = self._depth.set(depth + 1)
        try:
            for event in events:
                await self._dispatch_one(event)
        finally:
            self._depth.reset(token)

    async def _dispatch_one(self, event: Event) -> None:
        for handler in self._handlers.get(event.event_type, ()):
            try:
                result = handler(event)
                if isawaitable(result):
                    await result
            except Exception:
                # Isolate and log — never the payload, only the non-secret envelope identifiers.
                # structlog's redact_secrets scrubs the traceback text (core/logging.py).
                log.exception(
                    "event.handler_failed",
                    event_type=event.event_type,
                    event_id=str(event.event_id),
                    workspace_id=str(event.workspace_id),
                )


# The shared-kernel singleton (SYSTEM_ARCHITECTURE §: "Shared kernel: event bus · DB session ·
# settings · logging"). Domains import this to subscribe at startup and publish from services.
event_bus = EventBus()


__all__ = [
    "MAX_DISPATCH_DEPTH",
    "Event",
    "EventBus",
    "EventBusError",
    "EventPublishOutsideTransactionError",
    "EventReentrancyError",
    "EventSink",
    "EventWorkspaceMismatchError",
    "Handler",
    "current_sink",
    "event_bus",
]
