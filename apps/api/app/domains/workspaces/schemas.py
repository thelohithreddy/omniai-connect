"""Pydantic request/response schemas for the workspaces domain.

These define the wire contract and, by omission, the security boundary: `token_hash` and
token plaintext have no field here, so no code path can serialize them by accident.
Omission is the design; the log redactor is only the backstop (P-16).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class WorkspaceRead(BaseModel):
    """A Workspace as returned to an authenticated caller."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    plan: str
    created_at: datetime


class ApiTokenRead(BaseModel):
    """Token metadata. Never the secret — that exists once, at creation."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    token_prefix: str = Field(description="Display-only fragment, e.g. 'omc_A1b2C3d4'.")
    scopes: list[str]
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class ApiTokenCreate(BaseModel):
    """The entire client-controlled surface of token issuance: a display name.

    `extra="forbid"` is load-bearing. Pydantic's default is to *ignore* unknown fields, so
    a client posting `{"name": "ci", "created_by_member_id": "<someone else>"}` would get
    a silent 201 and be left believing the value was honoured. Forbidding turns every
    attempt to supply a server-owned field — `workspace_id`, `token_hash`, `token_prefix`,
    `created_by_member_id`, `revoked_at` — into a 422 instead of a quiet no-op. The
    security property comes from the field's absence; this makes the absence audible.

    `scopes` is deliberately not accepted. PRD.md FR-IF-3 describes a token scope as a
    "subset of Connections", and Connections do not exist yet, so there is no vocabulary
    against which a submitted scope could be validated. Accepting free-form strings would
    manufacture a permission language by accident and mint tokens whose recorded authority
    means nothing. Tokens are issued unscoped (`[]`) until the vocabulary is defined.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        min_length=1,
        max_length=120,
        description="Human-readable label, e.g. 'ci-deploy'. Not a secret and not unique.",
    )


class ApiTokenCreated(BaseModel):
    """The creation response — the **only** place token plaintext is ever emitted.

    Deliberately not `from_attributes`: there is no `plaintext` column to read, and the
    field cannot be populated by validating an ORM row. Construction requires the caller to
    hand over the secret explicitly, so nothing can accidentally serialize a stored token.

    Separate from `ApiTokenRead` for the same reason. `ApiTokenRead` is what every list and
    detail response returns and it has no `token` field at all; if one model served both,
    a future read endpoint would only ever be one forgotten `exclude` away from emitting
    credentials it does not even possess.
    """

    id: uuid.UUID
    name: str
    token: str = Field(
        description=(
            "The plaintext token. Shown exactly once, in this response. It is stored only "
            "as a SHA-256 hash, so it cannot be recovered — issue a new token if lost."
        )
    )
    token_prefix: str
    scopes: list[str]
    created_by_member_id: uuid.UUID | None
    expires_at: datetime | None
    created_at: datetime


class ApiTokenList(BaseModel):
    """The list envelope from API_GUIDELINES.md §3 — `data` / `next_cursor` / `has_more`.

    Named fields rather than a bare array, and that is the contract's choice, not a
    preference: a top-level JSON array cannot grow a pagination field later without
    breaking every client, and it is the shape that makes "there are more" expressible at
    all.

    Items are `ApiTokenRead`, the same model every other token read uses. It has no
    `token`, `plaintext`, or `token_hash` field, so this endpoint is structurally incapable
    of emitting a credential — the guarantee comes from the model's shape, not from
    remembering to exclude something here.
    """

    data: list[ApiTokenRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque; pass back as `?cursor=`. Null when `has_more` is false.",
    )
    has_more: bool
