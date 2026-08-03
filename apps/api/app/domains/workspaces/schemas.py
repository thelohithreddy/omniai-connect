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
