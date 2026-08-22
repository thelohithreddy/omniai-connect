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
    #: Derived health (M2.7-A). Never a stored column and never part of the `status` CHECK: the
    #: released lifecycle domain (`pending_auth|active|error|revoked`) is untouched, exactly as
    #: M2.5 derived `needs_reauth` rather than adding a fifth status (ADR-0038 D5).
    health: str
    #: Derived from `status == 'error'` AND an oauth2 credential. Ratified in M2.5 as
    #: "derived, never stored" and surfaced here for the first time.
    needs_reauth: bool
    created_at: datetime


class ConnectionList(BaseModel):
    """The list envelope from API_GUIDELINES.md §3 — `data` / `next_cursor` / `has_more`."""

    data: list[ConnectionRead]
    next_cursor: str | None = Field(
        default=None, description="Opaque; pass back as `?cursor=`. Null when `has_more` is false."
    )
    has_more: bool


__all__ = ["ConnectionCreate", "ConnectionList", "ConnectionRead", "ConnectionUpdate"]


class ConnectionHealthRead(BaseModel):
    """The result of one health check — classified metadata only.

    Deliberately narrow. It carries no provider response body, no headers, no credential, no
    upstream URL, no resolved address and no exception text; `reason` is a canonical Runtime error
    code from a closed vocabulary, so a hostile provider cannot use our own error path to smuggle
    content into an operator's console.
    """

    model_config = ConfigDict(from_attributes=True)

    status: str = Field(description="Derived health: healthy | unhealthy | unknown | needs_reauth.")
    reason: str | None = Field(
        default=None,
        description="Canonical failure code when the check failed, or `health_check_unavailable` "
        "when the Connector exposes no Tool that is safe to run unattended.",
    )
    checked_at: datetime | None = Field(
        default=None,
        description="When the check completed (RFC 3339 UTC). Null when nothing was executed.",
    )
    tool_call_id: uuid.UUID | None = Field(
        default=None, description="The audit row this check produced, for correlation."
    )
