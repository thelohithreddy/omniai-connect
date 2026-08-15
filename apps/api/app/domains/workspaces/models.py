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
        # The bootstrap lookup index (migration 0004): humans are resolved by `user_id`
        # alone, before any workspace is bound (ADR-0015/0016), so this is the one members
        # index that does NOT lead with workspace_id — the same documented exception
        # `api_tokens.token_hash` embodies. Declared here so it matches the migration and
        # autogenerate stays clean; without the declaration Alembic proposes dropping it on
        # every run (the drift this fixes).
        Index("ix_members_user_id", "user_id"),
        ForeignKeyConstraint(
            ["workspace_id", "invited_by"],
            ["members.workspace_id", "members.id"],
            name="fk_members_invited_by",
            ondelete="SET NULL (invited_by)",
        ),
    )


class ApiToken(UUIDPrimaryKeyMixin, WorkspaceScopedMixin, TimestampMixin, Base):
    """A workspace-scoped machine credential (SECURITY.md §4, ADR-0002)."""

    __tablename__ = "api_tokens"

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    # Which Member issued this token (DATABASE_DESIGN.md §3). Nullable and staying that
    # way: the bootstrap script mints a workspace's first token before any Member exists,
    # and `ON DELETE SET NULL` clears the reference when a creator is removed rather than
    # taking their tokens with them — those are workspace-owned credentials, and revoking
    # them is a separate explicit act.
    created_by_member_id: Mapped[UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True), nullable=True
    )
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
        # Leads with workspace_id (P-44) and serves the FK's ON DELETE scan, which binds
        # both columns when a Member is removed.
        Index(
            "ix_api_tokens_workspace_id_created_by_member_id",
            "workspace_id",
            "created_by_member_id",
        ),
        # COMPOSITE, per the intra-tenant FK convention (DATABASE_DESIGN.md §1): FK checks
        # run with RLS bypassed, so carrying workspace_id into the key is what prevents a
        # creator reference pointing at another tenant's Member.
        ForeignKeyConstraint(
            ["workspace_id", "created_by_member_id"],
            ["members.workspace_id", "members.id"],
            name="fk_api_tokens_created_by_member_id",
            ondelete="SET NULL (created_by_member_id)",
        ),
    )

    def is_usable(self, *, now: datetime) -> bool:
        """Domain rule, kept next to the data it constrains."""
        if self.revoked_at is not None:
            return False
        return not (self.expires_at is not None and self.expires_at <= now)


INVITATION_STATUSES = ("pending", "accepted", "cancelled")


class Invitation(UUIDPrimaryKeyMixin, WorkspaceScopedMixin, Base):
    """A targeted, email-bound, single-use invitation to join a Workspace (ADR-0017).

    Not `TimestampMixin`: an invitation has no meaningful `updated_at` — its lifecycle is
    the explicit `accepted_at` / `cancelled_at` stamps — so `created_at` is declared alone.
    The token is never stored; only its `token_hash` is, and resolution runs pre-RLS through
    `auth.resolve_invitation` because an accepting user is not yet a member of the workspace.
    """

    __tablename__ = "invitations"

    # Stored lower-cased by the application; the acceptance email comparison is normalized.
    invited_email: Mapped[str] = mapped_column(String(320), nullable=False)
    # The role the resulting membership will carry. Server-set at creation; the recipient
    # never sees or chooses it (ADR-0017 §8).
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    # The inviting Member. Composite intra-tenant FK (below); nullable because the inviter
    # may later be removed (column-scoped SET NULL keeps the invitation).
    invited_by: Mapped[UUID | None] = mapped_column(postgresql.UUID(as_uuid=True), nullable=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default=text("'pending'")
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "role IN ('owner', 'admin', 'member', 'viewer')", name="invitation_role_valid"
        ),
        CheckConstraint(
            "status IN ('pending', 'accepted', 'cancelled')", name="invitation_status_valid"
        ),
        # The composite intra-tenant FK to the inviting member — a single-column reference
        # could point at another tenant's member row, since FK checks bypass RLS.
        ForeignKeyConstraint(
            ["workspace_id", "invited_by"],
            ["members.workspace_id", "members.id"],
            name="fk_invitations_invited_by",
            ondelete="SET NULL (invited_by)",
        ),
        # At most one PENDING invitation per (workspace, email): a fresh invite never lets a
        # stale one grant a different role. Partial + `lower()` — must match the migration
        # exactly or autogenerate proposes dropping and recreating it every run.
        Index(
            "uq_invitations_pending_email",
            "workspace_id",
            text("lower(invited_email)"),
            unique=True,
            postgresql_where=text("status = 'pending'"),
        ),
    )

    def is_acceptable(self, *, now: datetime) -> bool:
        """Domain rule: a pending, unexpired invitation is the only acceptable one."""
        return self.status == "pending" and self.expires_at > now


__all__ = [
    "INVITATION_STATUSES",
    "MEMBER_ROLES",
    "WORKSPACE_PLANS",
    "ApiToken",
    "Invitation",
    "Member",
    "Workspace",
]
