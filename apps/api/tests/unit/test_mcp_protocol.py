"""MCP protocol contract — pure functions, no IO (M2.2, ADR-0035).

Proves: the founder-ratified revision allowlist and negotiation; single-message JSON-RPC
validation (batch rejection); the strict canonical-Tool → MCP-tool projection (only `name`,
`description`, `inputSchema`, and the three safety hints ever cross — internal metadata is
structurally absent); and the initialize result shape.
"""

from __future__ import annotations

import uuid
from typing import Any

from app.interfaces.mcp import protocol


class _Row:
    """A duck-typed canonical Tool row."""

    def __init__(self, annotations: Any = None) -> None:
        self.id = uuid.uuid4()
        self.workspace_id = uuid.uuid4()
        self.connector_id = uuid.uuid4()
        self.name = "crm_create_contact"
        self.description = "Create a contact."
        self.input_schema = {"type": "object", "properties": {"email": {"type": "string"}}}
        self.annotations = annotations
        self.enabled = True


# ------------------------------------------------------------------------------- version pin


def test_allowlist_is_the_ratified_pin() -> None:
    assert protocol.SUPPORTED_PROTOCOL_VERSIONS == ("2025-11-25", "2025-06-18")
    assert protocol.ADVERTISED_PROTOCOL_VERSION == "2025-11-25"
    assert "2026-07-28" not in protocol.SUPPORTED_PROTOCOL_VERSIONS


def test_negotiation_echoes_supported_and_advertises_otherwise() -> None:
    assert protocol.negotiate_version("2025-06-18") == "2025-06-18"
    assert protocol.negotiate_version("2025-11-25") == "2025-11-25"
    assert protocol.negotiate_version("2026-07-28") == "2025-11-25"
    assert protocol.negotiate_version(None) == "2025-11-25"
    assert protocol.negotiate_version(123) == "2025-11-25"


def test_initialize_result_shape() -> None:
    result = protocol.initialize_result("2025-06-18")
    assert result["protocolVersion"] == "2025-06-18"
    assert result["capabilities"] == {"tools": {"listChanged": False}}
    assert result["serverInfo"] == {"name": "omniai-connect", "version": "1.0"}


# -------------------------------------------------------------------------- message validation


def test_valid_request_and_notification_parse() -> None:
    assert protocol.validate_message(
        {"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}}
    ) == ("tools/list", 7, {})
    method, msg_id, _ = protocol.validate_message(  # type: ignore[misc]
        {"jsonrpc": "2.0", "method": "notifications/initialized"}
    )
    assert method == "notifications/initialized" and msg_id is None


def test_batches_and_malformed_messages_are_rejected() -> None:
    for bad in (
        [{"jsonrpc": "2.0", "id": 1, "method": "ping"}],  # batch — removed in 2025-06-18
        "ping",
        {"jsonrpc": "1.0", "id": 1, "method": "ping"},
        {"jsonrpc": "2.0", "id": 1},  # no method
        {"jsonrpc": "2.0", "id": 1, "method": ""},
        {"jsonrpc": "2.0", "id": {"k": 1}, "method": "ping"},  # non-scalar id
        {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": [1]},  # non-object params
    ):
        assert isinstance(protocol.validate_message(bad), str)


# ------------------------------------------------------------------------------ tool mapping


def test_mapping_projects_only_the_llm_facing_fields() -> None:
    row = _Row(
        annotations={
            "readonly": True,
            "destructive": False,
            "idempotent": True,
            "tags": ["crm"],
            "rate_hints": {"requests_per_minute": 60},
        }
    )
    entry = protocol.mcp_tool(row)
    assert set(entry) == {"name", "description", "inputSchema", "annotations"}
    assert entry["name"] == row.name
    assert entry["inputSchema"] == row.input_schema
    assert entry["annotations"] == {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
    }
    # Internal metadata never crosses: no ids, no tenant, no tags/rate_hints, no enabled flag.
    flat = str(entry)
    assert "tags" not in flat and "rate_hints" not in flat
    assert str(row.id) not in flat and str(row.workspace_id) not in flat


def test_mapping_with_absent_or_malformed_annotations() -> None:
    assert set(protocol.mcp_tool(_Row(annotations=None))) == {
        "name",
        "description",
        "inputSchema",
    }
    assert "annotations" not in protocol.mcp_tool(_Row(annotations={}))
    assert "annotations" not in protocol.mcp_tool(_Row(annotations="not-a-dict"))
    # Non-boolean hint values are dropped, not coerced — a poisoned annotation cannot smuggle
    # arbitrary payload into the wire representation.
    entry = protocol.mcp_tool(_Row(annotations={"readonly": "yes", "destructive": True}))
    assert entry["annotations"] == {"destructiveHint": True}


# ------------------------------------------------------------------------------ error objects


def test_error_and_result_envelopes() -> None:
    assert protocol.result_response(3, {"tools": []}) == {
        "jsonrpc": "2.0",
        "id": 3,
        "result": {"tools": []},
    }
    err = protocol.error_response(4, protocol.METHOD_NOT_FOUND, "Method not found.")
    assert err["error"] == {"code": -32601, "message": "Method not found."}
