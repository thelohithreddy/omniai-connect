"""SQLAlchemy models for the workspaces domain.

`api_tokens` and `members` live here rather than in domains of their own:
BACKEND_SPEC.md §1 enumerates the eight domains, and both are properties of a Workspace
(who may act on its behalf, and who belongs to it), not bounded contexts. Inventing a
ninth domain would need an ADR (Bible §12).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.shared.models import Base, TimestampMixin, UUIDPrimaryKeyMixin, WorkspaceScopedMixin

WORKSPACE_PLANS = ("free", "pro", "team", "enterprise")

# Canonical role domain, from DATABASE_DESIGN.md §3 (the schema authority).
#
# Note a live discrepancy: SECURITY.md §4.1's capability matrix has columns for only
# owner/admin/member. `viewer` is a valid *stored* role with no capability row yet.
# Reconciling that matrix is authorization work (M1.2-D), not schema work — this module
# establishes the domain, it does not grant anything.
MEMBER_ROLES = ("owner", "admin", "member", "viewer")


class Workspace(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """The tenant root (Bible §4). The one table with no `workspace_id` of its own."""

    __tablename__ = "workspaces"

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    plan: Mapped[str] = mapped_column(String(20), nullable=False, server_default=text("'free'"))
    stripe_customer_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        # Named `plan_valid`, not `ck_workspaces_plan_valid`: the metadata naming
        # convention renders `ck_%(table_name)s_%(constraint_name)s`, so the longer name
        # would produce `ck_workspaces_workspaces_plan_valid` and never match the
        # `ck_workspaces_plan_valid` the migration created — autogenerate would then
        # propose dropping and recreating the constraint on every run.
        CheckConstraint(
            "plan IN ('free', 'pro', 'team', 'enterprise')",
            name="plan_valid",
        ),
    )


class Member(UUIDPrimaryKeyMixin, WorkspaceScopedMixin, TimestampMixin, Base):
    """A user's membership in a Workspace, with a role (Bible §4).

    Four concepts stay distinct and none of them collapse into another:

    - **User identity** lives in the Next.js/Better Auth layer (ADR-0002). It is *not* a
      row here — `user_id` is the Better Auth subject identifier, an opaque foreign
      reference with no database-level FK, because the identity table is in another
      system entirely.
    - **Membership** is this row: one user's relationship to one workspace, with a role.
    - **Workspace** is the tenant root.
    - **Machine identity** is `api_tokens`, which deliberately has no member (ADR-0002:
      "human identity and machine identity are different credential types").

    The uniqueness boundary is therefore `(workspace_id, user_id)`, never `user_id`
    alone: the same human is expected to belong to several workspaces.
    """

    __tablename__ = "members"

    # Better Auth subject identifier. Opaque to us and deliberately unconstrained by a
    # FK — the identity it names lives in a different service (ADR-0002), so a FK is not
    # merely unnecessary, it is unsatisfiable.
    user_id: Mapped[str] = mapped_column(String(255), nullable=False)

    # No server default. A membership with an unstated role is an application bug, and a
    # default would silently paper over it by minting the least-privileged plausible
    # answer — or worse, a privileged one.
    role: Mapped[str] = mapped_column(String(20), nullable=False)

    # The member who issued the invitation. NULL for a workspace's founding owner and for
    # any member whose inviter has since been removed.
    invited_by: Mapped[UUID | None] = mapped_column(postgresql.UUID(as_uuid=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "role IN ('owner', 'admin', 'member', 'viewer')",
            name="role_valid",
        ),
        # The canonical membership boundary (DATABASE_DESIGN.md §3). Leads with
        # workspace_id, so it doubles as the tenant-scoped lookup index (P-44).
        UniqueConstraint("workspace_id", "user_id"),
        # Redundant as a *uniqueness* claim — `id` is already the primary key — but
        # required as the target of the composite FK below. Postgres will not accept a
        # composite foreign key unless a matching unique constraint exists.
        UniqueConstraint("workspace_id", "id"),
        # `invited_by` is a COMPOSITE self-reference on (workspace_id, invited_by), not a
        # plain reference to members.id. This is a tenant-isolation control, not style:
        # Postgres validates referential integrity internally with RLS bypassed, so a
        # single-column FK would happily let workspace A point at a member row owned by
        # workspace B. Carrying workspace_id into the FK makes a cross-tenant reference
        # structurally impossible rather than merely unlikely.
        #
        # The column-scoped `ON DELETE SET NULL (invited_by)` (Postgres 15+) nulls only
        # the inviter. A bare SET NULL would try to null workspace_id too, which is
        # NOT NULL, and every inviter deletion would fail.
        ForeignKeyConstraint(
            ["workspace_id", "invited_by"],
            ["members.workspace_id", "members.id"],
            name="fk_members_invited_by",
            ondelete="SET NULL (invited_by)",
        ),
    )


class ApiToken(UUIDPrimaryKeyMixin, WorkspaceScopedMixin, TimestampMixin, Base):
    """A workspace-scoped machine credential (SECURITY.md §4, ADR-0002).

    `created_by_member_id` from DATABASE_DESIGN.md is deliberately still absent: wiring
    tokens to members is token-lifecycle work (M1.2-F/G/H), and adding the column plus
    its FK later is additive (P-43).
    """

    __tablename__ = "api_tokens"

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    token_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    scopes: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # Leads with workspace_id because every access path is workspace-scoped (P-44).
        # The unique index on token_hash is created separately in the migration: it is the
        # one lookup that arrives *without* workspace context (DATABASE_DESIGN.md §4).
        #
        # `created_at DESC` must be spelled out to match the migration exactly. Declared
        # ascending here, autogenerate sees drift on every run and proposes dropping and
        # recreating the index — noise that trains reviewers to ignore autogenerate output.
        Index(
            "ix_api_tokens_workspace_id_created_at",
            "workspace_id",
            text("created_at DESC"),
        ),
    )

    def is_usable(self, *, now: datetime) -> bool:
        """Domain rule, kept next to the data it constrains."""
        if self.revoked_at is not None:
            return False
        return not (self.expires_at is not None and self.expires_at <= now)


__all__ = ["MEMBER_ROLES", "WORKSPACE_PLANS", "ApiToken", "Member", "Workspace"]
