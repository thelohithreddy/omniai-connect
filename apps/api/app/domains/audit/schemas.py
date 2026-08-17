"""Wire contract for the Audit Log Viewer (M1-Audit-v1, API_GUIDELINES §11).

`ToolCallLogRead` exposes exactly the canonical audit metadata (PRD UJ-5.2 / FR-RT-5): the Tool and
Connection identity, the caller (Interface + Member/API-token identity), status, latency, timestamp,
`request_id`, and the **already-redacted** `input_summary` / `output_summary` (secrets never appear;
they were scrubbed at write time, SECURITY §2.3). `workspace_id` is never serialized (it is the
authenticated context, not data). An explicit schema — not raw-ORM serialization — so a new column
added to `tool_calls` cannot silently leak through this read surface.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ToolCallLogRead(BaseModel):
    """One Tool Call audit record — redacted metadata only, never a secret or a raw body."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    connection_id: uuid.UUID
    tool_id: uuid.UUID
    request_id: str
    #: {interface, kind, api_token_id | member_id} — caller identity, never a secret.
    caller: dict[str, Any]
    status: str
    error_code: str | None
    input_summary: dict[str, Any]
    output_summary: dict[str, Any] | None
    duration_ms: int
    created_at: datetime


class ToolCallLogList(BaseModel):
    """The list envelope from API_GUIDELINES §3 — `data` / `next_cursor` / `has_more`."""

    data: list[ToolCallLogRead]
    next_cursor: str | None = Field(
        default=None, description="Opaque; pass back as `?cursor=`. Null when `has_more` is false."
    )
    has_more: bool


__all__ = ["ToolCallLogList", "ToolCallLogRead"]
