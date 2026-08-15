"""Pydantic request/response schemas for the connectors domain (M1.4-A).

The wire contract, and by omission part of the security boundary: `workspace_id` is never a
field, so no request can name a foreign tenant and no response leaks the tenant key.
`source_type` is server-set (`manual` in this slice), so a client cannot mint a Connector
that falsely claims to be OpenAPI-ingested.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# A URL-safe kebab slug: lowercase alphanumerics separated by single hyphens.
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class ConnectorCreate(BaseModel):
    """The client-controlled surface of creating a manual Connector.

    `extra="forbid"` so a server-owned field — `workspace_id`, `source_type`, `status`,
    `current_version_id`, `id` — is a `400`, never a silent no-op. The workspace comes from
    `X-Workspace-Id`; `source_type` is fixed to `manual` by the service; `status` starts at
    `draft`. `base_url` is SSRF-linted in the service (the single source of truth), so a
    non-HTTP caller (MCP, Celery) is guarded too, not only this endpoint.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120, description="Human-readable connector name.")
    base_url: str = Field(
        min_length=1, max_length=2048, description="The external API base URL (https only)."
    )
    auth_config: dict[str, Any] = Field(
        default_factory=dict,
        description="Auth REQUIREMENTS only (key name/location, scheme) — never secret values.",
    )
    slug: str | None = Field(
        default=None,
        max_length=64,
        description="Optional URL-safe slug, unique per workspace. Derived from name if omitted.",
    )

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("name must not be blank")
        return stripped

    @field_validator("slug")
    @classmethod
    def _slug(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if not _SLUG_RE.match(normalized):
            raise ValueError("slug must be lowercase alphanumerics separated by single hyphens")
        return normalized


class ConnectorRead(BaseModel):
    """A Connector as returned to an authorized caller. No `workspace_id`.

    `auth_config` is safe to return: it holds auth requirements, never secret values
    (CONNECTOR_ENGINE.md §8) — the secret lives in a Connection's Credential.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    source_type: str
    base_url: str
    auth_config: dict[str, Any]
    status: str
    created_at: datetime


class ConnectorList(BaseModel):
    """The list envelope from API_GUIDELINES.md §3 — `data` / `next_cursor` / `has_more`."""

    data: list[ConnectorRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque; pass back as `?cursor=`. Null when `has_more` is false.",
    )
    has_more: bool


__all__ = ["ConnectorCreate", "ConnectorList", "ConnectorRead"]
