"""Domain events for the Execution Runtime (M1, AI_RUNTIME.md §2 stage 7).

`tool_call.completed` is published on the internal bus after the audit-writing transaction commits
(BACKEND_SPEC.md §4). The payload carries only non-secret identifiers a subscriber (billing metering
M3, MCP result streaming later) needs — the tool_call id, the tool/connection ids, the terminal
status, the safe error code, and the duration. Never arguments, never the response body, never a
credential. The workspace is the envelope's trusted `workspace_id`, never a payload field.
"""

from __future__ import annotations

import uuid

from app.core.events import Event

TOOL_CALL_COMPLETED = "tool_call.completed"


def tool_call_completed(
    workspace_id: uuid.UUID,
    *,
    tool_call_id: uuid.UUID,
    tool_id: uuid.UUID,
    connection_id: uuid.UUID,
    status: str,
    error_code: str | None,
    duration_ms: int,
) -> Event:
    """A Tool Call reached a terminal state and its audit row was written."""
    return Event(
        event_type=TOOL_CALL_COMPLETED,
        workspace_id=workspace_id,
        payload={
            "tool_call_id": str(tool_call_id),
            "tool_id": str(tool_id),
            "connection_id": str(connection_id),
            "status": status,
            "error_code": error_code,
            "duration_ms": duration_ms,
        },
    )


__all__ = ["TOOL_CALL_COMPLETED", "tool_call_completed"]
