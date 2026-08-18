"""Contract of the M2.1 lifecycle events (ADR-0034) — pure construction, no DB.

Proves for each factory: the canonical dotted event type, version 1, the workspace bound on the
trusted envelope (never a payload field), the exact non-secret payload key set (a new field cannot
appear silently), JSON-safe serialization, and immutability. The transactional and tenant-match
halves of the contract live in the integration suites (the bus's own, and
tests/integration/test_lifecycle_events_api.py).
"""

from __future__ import annotations

import json
import uuid

import pytest
from pydantic import ValidationError

from app.domains.connections.events import (
    CONNECTION_ACTIVATED,
    CONNECTION_DEACTIVATED,
    CONNECTION_REVOKED,
    connection_activated,
    connection_deactivated,
    connection_revoked,
)
from app.domains.tools.events import TOOL_DISABLED, TOOL_ENABLED, tool_disabled, tool_enabled

WS = uuid.uuid4()
CONN = uuid.uuid4()
CTOR = uuid.uuid4()
TOOL = uuid.uuid4()


# ------------------------------------------------------------------ connection lifecycle events


def test_connection_activated_contract() -> None:
    event = connection_activated(WS, connection_id=CONN, connector_id=CTOR)
    assert event.event_type == CONNECTION_ACTIVATED == "connection.activated"
    assert event.version == 1
    assert event.workspace_id == WS
    assert event.payload == {"connection_id": str(CONN), "connector_id": str(CTOR)}


def test_connection_deactivated_contract() -> None:
    event = connection_deactivated(WS, connection_id=CONN, connector_id=CTOR, status="pending_auth")
    assert event.event_type == CONNECTION_DEACTIVATED == "connection.deactivated"
    assert event.version == 1
    assert event.workspace_id == WS
    assert event.payload == {
        "connection_id": str(CONN),
        "connector_id": str(CTOR),
        "status": "pending_auth",
    }


def test_connection_revoked_contract() -> None:
    event = connection_revoked(WS, connection_id=CONN, connector_id=CTOR)
    assert event.event_type == CONNECTION_REVOKED == "connection.revoked"
    assert event.version == 1
    assert event.workspace_id == WS
    assert event.payload == {"connection_id": str(CONN), "connector_id": str(CTOR)}


# ------------------------------------------------------------------------ tool lifecycle events


def test_tool_enabled_contract() -> None:
    event = tool_enabled(WS, tool_id=TOOL, connector_id=CTOR)
    assert event.event_type == TOOL_ENABLED == "tool.enabled"
    assert event.version == 1
    assert event.workspace_id == WS
    assert event.payload == {"tool_id": str(TOOL), "connector_id": str(CTOR)}


def test_tool_disabled_contract() -> None:
    event = tool_disabled(WS, tool_id=TOOL, connector_id=CTOR)
    assert event.event_type == TOOL_DISABLED == "tool.disabled"
    assert event.version == 1
    assert event.workspace_id == WS
    assert event.payload == {"tool_id": str(TOOL), "connector_id": str(CTOR)}


# --------------------------------------------------------------------------- envelope hardening


def _all_events() -> list[object]:
    return [
        connection_activated(WS, connection_id=CONN, connector_id=CTOR),
        connection_deactivated(WS, connection_id=CONN, connector_id=CTOR, status="pending_auth"),
        connection_revoked(WS, connection_id=CONN, connector_id=CTOR),
        tool_enabled(WS, tool_id=TOOL, connector_id=CTOR),
        tool_disabled(WS, tool_id=TOOL, connector_id=CTOR),
    ]


def test_payloads_carry_identifiers_only_never_secret_shaped_fields() -> None:
    """The payload key set is closed: identifiers (+ the deactivation status word) and nothing
    else — no credential, token, header, or value-bearing field can ride along unnoticed."""
    allowed = {"connection_id", "connector_id", "tool_id", "status"}
    for event in _all_events():
        keys = set(event.payload)  # type: ignore[attr-defined]
        assert keys <= allowed, f"unexpected payload field(s): {keys - allowed}"
        for key in keys - {"status"}:
            uuid.UUID(event.payload[key])  # type: ignore[attr-defined]  # identifiers parse as UUIDs


def test_events_serialize_to_json_and_are_frozen() -> None:
    for event in _all_events():
        dumped = json.loads(event.model_dump_json())  # type: ignore[attr-defined]
        assert dumped["event_type"] == event.event_type  # type: ignore[attr-defined]
        assert dumped["workspace_id"] == str(WS)
        with pytest.raises(ValidationError):
            event.event_type = "tampered.event"  # type: ignore[attr-defined, misc]


def test_envelope_rejects_smuggled_authority_fields() -> None:
    """`extra="forbid"` on the envelope: a factory-built event cannot be reconstructed with a
    role/actor/permission rider — the bus is not an authorization surface (INVARIANT 5)."""
    base = connection_activated(WS, connection_id=CONN, connector_id=CTOR)
    with pytest.raises(ValidationError):
        type(base).model_validate({**base.model_dump(), "role": "owner"})
