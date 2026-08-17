"""Wire contract for the Tools administration API (M1-Tools-v1, API_GUIDELINES §11).

`ToolRead` exposes only the canonical, LLM-facing Tool metadata (CONNECTOR_ENGINE §2): the Tool
carries no secret, no `auth_config`, no credential material, and no execution endpoint (those live
on
`connector_versions.normalized_schema` and the Connector). `workspace_id` and `deleted_at` are
internal and never serialized. `ToolUpdate` is the *only* mutable surface in M1 — `enabled` — with
`extra="forbid"` so a client cannot rewrite the description, name, input schema, connector identity,
or version (those originate from ingestion/promotion; description editing is deferred,
ADR-0031-note).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ToolRead(BaseModel):
    """The public projection of a Tool. Metadata only — never a secret or an execution detail."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    connector_id: uuid.UUID
    connector_version_id: uuid.UUID
    name: str
    description: str
    input_schema: dict[str, Any]
    output_hints: dict[str, Any] | None
    annotations: dict[str, Any]
    enabled: bool
    created_at: datetime
    updated_at: datetime


class ToolList(BaseModel):
    """The list envelope from API_GUIDELINES §3 — `data` / `next_cursor` / `has_more`."""

    data: list[ToolRead]
    next_cursor: str | None = Field(
        default=None, description="Opaque; pass back as `?cursor=`. Null when `has_more` is false."
    )
    has_more: bool


class ToolUpdate(BaseModel):
    """The mutable surface of a Tool in M1: `enabled` only.

    `extra="forbid"` is load-bearing — it turns any attempt to rewrite a canonical field
    (`name`, `description`, `input_schema`, `connector_id`, `connector_version_id`, `workspace_id`)
    into a 422 rather than a silent no-op. Those fields originate from connector ingestion/promotion
    and are immutable here; per-Tool description editing (FR-CE-4) is deferred.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(
        description="Enable (executable) or disable (blocked from execution) the Tool."
    )


__all__ = ["ToolList", "ToolRead", "ToolUpdate"]
