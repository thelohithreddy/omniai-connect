"""Pydantic request/response schemas for the connections domain (M1-Connections-v1).

The wire contract, and by omission part of the security boundary: `workspace_id`, `status`, and
`credential_id` are never request fields, so no request can name a foreign tenant, forge a lifecycle
state, or attach a credential. `status` starts server-side at `pending_auth`; `credential_id` is set
only by the future Credentials module. Responses carry no secret.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ConnectionCreate(BaseModel):
    """The client-controlled surface of creating a Connection.

    `extra="forbid"` so a server-owned field — `workspace_id`, `status`, `credential_id`, `id`,
    `role`, `member_id`, `kind` — is a `400`, never a silent no-op. The workspace comes from the
    authenticated context; `connector_id` is validated to be a live connector *in that workspace*;
    `config_overrides.base_url` (if present) is SSRF-linted in the service.
    """

    model_config = ConfigDict(extra="forbid")

    connector_id: uuid.UUID = Field(description="A live Connector in this workspace to bind.")
    name: str = Field(min_length=1, max_length=120, description="Human-readable connection name.")
    config_overrides: dict[str, Any] = Field(
        default_factory=dict,
        description="Non-secret per-connection config (e.g. base_url override). Never authority.",
    )

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("name must not be blank")
        return stripped


class ConnectionUpdate(BaseModel):
    """The mutable surface of a Connection: `name` and `config_overrides` only.

    `extra="forbid"` so `status`, `credential_id`, `connector_id`, `workspace_id`, `role`, … are a
    `400` — a client cannot re-tenant a connection, reassign its connector, forge a lifecycle
    transition, or attach a credential through PATCH.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=120)
    config_overrides: dict[str, Any] | None = Field(default=None)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            raise ValueError("name must not be blank")
        return stripped


class ConnectionRead(BaseModel):
    """A Connection as returned to an authorized caller. No `workspace_id`, no secret.

    `credential_id` is a non-secret opaque id (a pointer to the future Credential, `null` until one
    is attached) — it reveals only whether a credential is bound, never any secret material.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    connector_id: uuid.UUID
    name: str
    status: str
    config_overrides: dict[str, Any]
    credential_id: uuid.UUID | None
    last_health_check_at: datetime | None
    created_at: datetime


class ConnectionList(BaseModel):
    """The list envelope from API_GUIDELINES.md §3 — `data` / `next_cursor` / `has_more`."""

    data: list[ConnectionRead]
    next_cursor: str | None = Field(
        default=None, description="Opaque; pass back as `?cursor=`. Null when `has_more` is false."
    )
    has_more: bool


__all__ = ["ConnectionCreate", "ConnectionList", "ConnectionRead", "ConnectionUpdate"]
