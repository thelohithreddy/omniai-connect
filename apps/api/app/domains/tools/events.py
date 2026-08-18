"""Domain events for the Tools administration domain (M2.1, ADR-0034).

Published on the internal bus (BACKEND_SPEC §4) after the transaction that persists the flip
commits. These are the Tool half of the canonical MCP tools-cache eviction set (MCP_RUNTIME §3):
a subscriber (M2.2) evicts `ws:{workspace_id}:mcp:tools` when a Tool's `enabled` flag actually
changes. Emitted only on a real persisted transition — the repository's value-guarded UPDATE
matches nothing on a no-op, so `PATCH {enabled: x}` on a Tool already in state `x` stays
idempotent at the API and emits nothing (INVARIANT 1: no transition → no event).

Payloads carry only non-secret identifiers; the workspace is the envelope's trusted
`workspace_id` (tenant-match enforced by `UnitOfWork.buffer_event`, ADR-0022). Delivery is
at-most-once in-process today, at-least-once under the future broker (ADR-0023) — consumers must
be idempotent. Events grant nothing: the Runtime's policy stage remains the sole "may this Tool
execute?" decision; these merely report that the persisted answer changed.
"""

from __future__ import annotations

import uuid

from app.core.events import Event

TOOL_ENABLED = "tool.enabled"
TOOL_DISABLED = "tool.disabled"


def tool_enabled(workspace_id: uuid.UUID, *, tool_id: uuid.UUID, connector_id: uuid.UUID) -> Event:
    """A live Tool's persisted `enabled` flag transitioned false → true."""
    return Event(
        event_type=TOOL_ENABLED,
        workspace_id=workspace_id,
        payload={"tool_id": str(tool_id), "connector_id": str(connector_id)},
    )


def tool_disabled(workspace_id: uuid.UUID, *, tool_id: uuid.UUID, connector_id: uuid.UUID) -> Event:
    """A live Tool's persisted `enabled` flag transitioned true → false."""
    return Event(
        event_type=TOOL_DISABLED,
        workspace_id=workspace_id,
        payload={"tool_id": str(tool_id), "connector_id": str(connector_id)},
    )


__all__ = ["TOOL_DISABLED", "TOOL_ENABLED", "tool_disabled", "tool_enabled"]
