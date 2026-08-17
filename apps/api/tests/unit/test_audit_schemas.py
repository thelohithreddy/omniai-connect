"""Audit Log Viewer wire contract (M1-Audit-v1): the read projection exposes only safe metadata."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.domains.audit.schemas import ToolCallLogRead


def test_read_exposes_only_safe_audit_metadata() -> None:
    fields = set(ToolCallLogRead.model_fields)
    assert fields == {
        "id",
        "connection_id",
        "tool_id",
        "request_id",
        "caller",
        "status",
        "error_code",
        "input_summary",
        "output_summary",
        "duration_ms",
        "created_at",
    }
    # The tenant boundary is never data, and no raw ciphertext/credential column can appear.
    assert "workspace_id" not in fields
    assert "ciphertext" not in fields
    assert "encrypted_dek" not in fields


def test_read_round_trips_from_attributes() -> None:
    class _Row:
        id = uuid.uuid4()
        connection_id = uuid.uuid4()
        tool_id = uuid.uuid4()
        request_id = "req_01abc"
        caller = {"interface": "rest", "kind": "api_token", "api_token_id": "t", "member_id": None}
        status = "succeeded"
        error_code = None
        input_summary = {"q": "hi"}
        output_summary = {"status_code": 200}
        duration_ms = 12
        created_at = datetime.now(UTC)

    read = ToolCallLogRead.model_validate(_Row())
    assert read.status == "succeeded"
    assert read.caller["interface"] == "rest"
