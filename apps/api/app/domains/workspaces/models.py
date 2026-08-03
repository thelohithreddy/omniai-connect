"""SQLAlchemy models for the workspaces domain.

`api_tokens` lives here rather than in a domain of its own: BACKEND_SPEC.md §1 enumerates
the eight domains, and a token is a property of a Workspace (who may act on its behalf),
not a bounded context. Inventing a ninth domain would need an ADR (Bible §12).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Index, String, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.shared.models import Base, TimestampMixin, UUIDPrimaryKeyMixin, WorkspaceScopedMixin

WORKSPACE_PLANS = ("free", "pro", "team", "enterprise")


class Workspace(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """The tenant root (Bible §4). The one table with no `workspace_id` of its own."""

    __tablename__ = "workspaces"

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    plan: Mapped[str] = mapped_column(String(20), nullable=False, server_default=text("'free'"))
    stripe_customer_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        # Text + CHECK rather than a native enum: adding a value to a native Postgres enum
        # cannot run inside a transaction block on older versions and complicates
        # downgrades, so additive migrations stay awkward (DATABASE_DESIGN.md §1).
        # Named `plan_valid`, not `workspaces_plan_valid`: the metadata naming convention
        # renders `ck_%(table_name)s_%(constraint_name)s`, so the longer name would
        # produce `ck_workspaces_workspaces_plan_valid` and never match the
        # `ck_workspaces_plan_valid` the migration created — autogenerate would then
        # propose dropping and recreating the constraint on every run.
        CheckConstraint(
            "plan IN ('free', 'pro', 'team', 'enterprise')",
            name="plan_valid",
        ),
    )


class ApiToken(UUIDPrimaryKeyMixin, WorkspaceScopedMixin, TimestampMixin, Base):
    """A workspace-scoped machine credential (SECURITY.md §4, ADR-0002).

    `created_by_member_id` from DATABASE_DESIGN.md is deliberately absent until the
    `members` table exists in M1.2 — adding a column plus its FK later is additive
    (P-43), whereas a dangling unconstrained UUID nothing populates is dead weight.
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


__all__ = ["WORKSPACE_PLANS", "ApiToken", "Workspace"]
