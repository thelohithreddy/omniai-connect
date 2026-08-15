"""Pydantic request/response schemas for the workspaces domain.

These define the wire contract and, by omission, the security boundary: `token_hash` and
token plaintext have no field here, so no code path can serialize them by accident.
Omission is the design; the log redactor is only the backstop (P-16).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class WorkspaceRead(BaseModel):
    """A Workspace as returned to an authenticated caller."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    plan: str
    created_at: datetime


class MembershipRead(BaseModel):
    """One of the authenticated human's own workspace memberships (ADR-0016 §7).

    `id` is the Workspace id — the value the client echoes back in `X-Workspace-Id` to
    select it. `role` is the caller's persisted role there, for DISPLAY only: it is never
    an authorization input (authorization always re-resolves the role under RLS after the
    workspace binds). Deliberately narrow — no other tenant's existence, name, member
    count, or metadata is disclosed.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    role: str


class MembershipList(BaseModel):
    """The caller's workspaces. A bounded personal set, returned whole (ADR-0016 §7)."""

    data: list[MembershipRead]


def _normalize_email(value: str) -> str:
    """Lightweight email validation + normalization (ADR-0017).

    Not a full RFC validator — deliberately no `email-validator` dependency — because the
    real gate is exact equality against the accepting user's *provider-verified* Better Auth
    email, compared lower-cased. This rejects the obviously-malformed and normalizes case and
    surrounding whitespace so the stored value can match the verified claim. Anything that
    passes here but is not a real address simply never matches a verified email and can never
    be accepted.
    """
    email = value.strip().lower()
    local, sep, domain = email.partition("@")
    if not sep or not local or "." not in domain or domain.startswith(".") or domain.endswith("."):
        raise ValueError("invited_email must be a valid email address")
    if any(ch.isspace() for ch in email):
        raise ValueError("invited_email must not contain whitespace")
    return email


class InvitationCreate(BaseModel):
    """The client-controlled surface of creating an invitation: an email and a role.

    `extra="forbid"` so an attempt to supply a server-owned field — `workspace_id`,
    `invited_by`, `token`, `status`, `expires_at` — is a 400, never a silent no-op. The
    workspace is the `X-Workspace-Id` selection, the inviter is the authenticated member, and
    the token is server-generated; none of them are inputs. `role` is validated against the
    canonical domain in the service (the single source of truth), exactly as
    `MemberRoleUpdate` is.
    """

    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=320, description="The invitee's email address.")
    role: str = Field(description="The role the resulting membership will carry.")

    @field_validator("email")
    @classmethod
    def _email(cls, value: str) -> str:
        return _normalize_email(value)


class InvitationRead(BaseModel):
    """An invitation as returned to a `members:manage` holder in its workspace.

    Deliberately narrow: no `token`, no `token_hash`, no `invited_by`. The token never
    leaves the creation email; the hash is a secret at rest; provenance is omitted for the
    same reason `MemberRead` omits `invited_by`. This model is structurally incapable of
    leaking the token.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    invited_email: str
    role: str
    status: str
    expires_at: datetime
    created_at: datetime


class InvitationList(BaseModel):
    """This workspace's invitations. Envelope shape per API_GUIDELINES.md §3."""

    data: list[InvitationRead]


class InvitationAccept(BaseModel):
    """The acceptance request: the raw invitation token, in the body (never the URL/logs)."""

    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=1, description="The opaque invitation token from the email.")


class AcceptedInvitation(BaseModel):
    """What the recipient joined: the workspace and their new role. No invitation details."""

    workspace_id: uuid.UUID
    role: str


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


class MemberRead(BaseModel):
    """A Member as returned to a caller holding `members:manage`.

    Deliberately narrow. `invited_by` is omitted for the same reason `ApiTokenRead` omits
    `created_by_member_id`: exposing provenance is an information-disclosure decision no
    canonical document has made, and it is not needed to manage a Workspace's members.
    Adding it later is additive; removing it after clients depend on it is not.

    `user_id` is the Better Auth subject (DATABASE_DESIGN.md §3). It is the only handle an
    administrator has for identifying who a Member is, so a management API that withheld it
    could not be used to manage anything.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: str
    role: str
    created_at: datetime


class MemberRoleUpdate(BaseModel):
    """The entire mutable surface of a Member: its role.

    `role` is typed as a plain `str`, not an enum or `Literal`, on purpose. The canonical
    role domain already exists twice — the `members.role` CHECK constraint and
    `models.MEMBER_ROLES` — and `MemberService._require_valid_role` validates against the
    latter. Restating the four values here would create a third copy that could drift from
    the database, and the failure mode of drift is a role that validates at the door and is
    rejected by the constraint as a 500.

    `extra="forbid"` so an attempt to PATCH `user_id`, `workspace_id`, or `invited_by` is a
    400 rather than a silent no-op that leaves the caller believing it worked.
    """

    model_config = ConfigDict(extra="forbid")

    role: str = Field(description="One of the canonical member roles.")


class MemberList(BaseModel):
    """The list envelope from API_GUIDELINES.md §3 — identical in shape to `ApiTokenList`."""

    data: list[MemberRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque; pass back as `?cursor=`. Null when `has_more` is false.",
    )
    has_more: bool
