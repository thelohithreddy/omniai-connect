"""Wire schemas for `/v1/tool-calls` (the OpenAPI contract, API_GUIDELINES §11).

These are the *wire* shapes (the internal `ToolCallRequest`/`ToolCallResult` in AI_RUNTIME.md §1 are
explicitly not a wire format). A caller names the Tool by its canonical `tool_name` and, when the
Connector has more than one active Connection, disambiguates with `connection_id`; arguments are a
free object validated server-side against the Tool's `input_schema`. No `workspace_id` appears —
authority is the bound context, never a body field.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ToolCallCreate(BaseModel):
    """The request body of `POST /v1/tool-calls`.

    `mode` is `sync` only in M1 — the async (job + poll/webhook) contract is deferred (AI_RUNTIME.md
    §3, ROADMAP M4), so any other value is a 422. `extra="forbid"` makes an unknown field a loud 422
    rather than a silent no-op — a caller cannot smuggle `workspace_id`, `connection`, or a
    credential field and believe it was honored.
    """

    model_config = ConfigDict(extra="forbid")

    tool_name: str = Field(min_length=1, max_length=64, description="Canonical Tool name.")
    connection_id: uuid.UUID | None = Field(
        default=None,
        description="Explicit Connection to run against; required only when the Connector has more "
        "than one active Connection.",
    )
    arguments: dict[str, Any] = Field(
        default_factory=dict, description="Tool arguments, validated against the Tool input schema."
    )
    mode: Literal["sync"] = "sync"


class CallUsage(BaseModel):
    """Non-secret usage metering for one Tool Call."""

    duration_ms: int


class ToolCallResult(BaseModel):
    """The `200` response of a *successful* `POST /v1/tool-calls`. Failures return the error
    envelope instead (with `tool_call_id` in `details`)."""

    id: uuid.UUID = Field(
        description="Tool Call id — the audit row; fetch it at GET /v1/tool-calls/{id}."
    )
    status: Literal["succeeded"]
    tool_name: str
    connection_id: uuid.UUID
    content: dict[str, Any] | None = Field(
        default=None, description="Normalized, truncation-aware payload for LLM consumption."
    )
    usage: CallUsage
    request_id: str


class ToolCallRead(BaseModel):
    """Audit-row projection returned by `GET /v1/tool-calls/{id}` — redacted metadata only, never
    the raw response body or a secret (DATABASE_DESIGN.md `tool_calls`)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    connection_id: uuid.UUID
    tool_id: uuid.UUID
    request_id: str
    status: str
    error_code: str | None
    input_summary: dict[str, Any]
    output_summary: dict[str, Any] | None
    duration_ms: int
    created_at: datetime


__all__ = ["CallUsage", "ToolCallCreate", "ToolCallRead", "ToolCallResult"]
