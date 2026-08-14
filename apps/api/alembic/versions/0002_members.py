"""Members: tenant-scoped human membership in a Workspace.

Revision ID: 0002_members
Revises: 0001_tenancy_foundation
Create Date: 2026-08-14
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0002_members"
down_revision: str | None = "0001_tenancy_foundation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "omniai_app"

# Identical to migration 0001. Every piece is load-bearing: `missing_ok => true` stops an
# unset GUC from raising, and NULLIF turns the empty string into NULL so the comparison
# yields NULL (treated as false) rather than erroring on ''::uuid. Fail closed to zero
# rows (DATABASE_DESIGN.md §6).
WORKSPACE_GUC_SQL = "NULLIF(current_setting('app.workspace_id', true), '')::uuid"


def upgrade() -> None:
    # ------------------------------------------------------------------ preflight
    # Re-asserted per tenant table, not just once in 0001. A tenant table created while
    # the application role holds a bypass is silently unprotected from birth, and nothing
    # downstream would notice — the policies would exist and simply never apply
    # (ADR-0008).
    op.execute(
        sa.text(f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                RAISE EXCEPTION 'Role "{APP_ROLE}" does not exist.';
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles
                       WHERE rolname = '{APP_ROLE}' AND (rolsuper OR rolbypassrls)) THEN
                RAISE EXCEPTION
                    'Role "{APP_ROLE}" is a superuser or holds BYPASSRLS. Either bypasses '
                    'Row-Level Security unconditionally, so creating a tenant table now '
                    'would produce a table whose policies never apply.';
            END IF;
        END
        $$;
        """)  # noqa: S608
    )

    # ------------------------------------------------------------------ table
    op.create_table(
        "members",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        # Better Auth subject identifier. Deliberately NOT a foreign key: the identity it
        # names lives in the Next.js layer (ADR-0002), so there is no local table to
        # reference.
        sa.Column("user_id", sa.String(length=255), nullable=False),
        # No server default — a membership with an unstated role is an application bug,
        # and defaulting would hide it behind a silently-minted privilege level.
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("invited_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        # Text + CHECK rather than a native enum: adding a value to a native Postgres enum
        # complicates additive migrations and downgrades (DATABASE_DESIGN.md §1).
        sa.CheckConstraint("role IN ('owner', 'admin', 'member', 'viewer')", name="role_valid"),
        sa.PrimaryKeyConstraint("id", name="pk_members"),
        # The canonical membership boundary (DATABASE_DESIGN.md §3): the same human may
        # belong to many workspaces, so uniqueness is per workspace, never global on
        # user_id. Leads with workspace_id, so it also serves tenant-scoped lookups (P-44).
        sa.UniqueConstraint("workspace_id", "user_id", name="uq_members_workspace_id_user_id"),
        # Redundant as uniqueness (id is already the PK) but mandatory as the target of
        # the composite self-FK below — Postgres will not accept a composite foreign key
        # without a matching unique constraint.
        sa.UniqueConstraint("workspace_id", "id", name="uq_members_workspace_id_id"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_members_workspace_id",
            ondelete="CASCADE",
        ),
        # COMPOSITE self-reference, and that is a tenant-isolation control rather than a
        # stylistic choice. Postgres validates referential integrity internally with RLS
        # bypassed, so a single-column `invited_by -> members.id` would let workspace A
        # reference a member row owned by workspace B. Carrying workspace_id into the key
        # makes a cross-tenant reference structurally impossible.
        #
        # `ON DELETE SET NULL (invited_by)` is column-scoped (Postgres 15+). A bare
        # SET NULL would also try to null workspace_id, which is NOT NULL, so every
        # inviter deletion would fail.
        sa.ForeignKeyConstraint(
            ["workspace_id", "invited_by"],
            ["members.workspace_id", "members.id"],
            name="fk_members_invited_by",
            ondelete="SET NULL (invited_by)",
        ),
    )
    # Postgres does not index foreign keys automatically, and an unindexed FK turns the
    # parent's ON DELETE CASCADE into a sequential scan per deleted row.
    op.create_index("ix_members_workspace_id", "members", ["workspace_id"])

    # ------------------------------------------------------------------ grants
    # Table privileges are granted per table, so a new table is unreadable by the
    # application until its own migration says otherwise.
    op.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON public.members TO {APP_ROLE}"))  # noqa: S608

    # ------------------------------------------------------------------ RLS
    op.execute(sa.text("ALTER TABLE public.members ENABLE ROW LEVEL SECURITY"))
    # FORCE is not optional: ENABLE alone exempts the table *owner* from its own policies.
    op.execute(sa.text("ALTER TABLE public.members FORCE ROW LEVEL SECURITY"))
    # One policy, `FOR ALL`, carrying both USING and WITH CHECK — identical in shape to
    # the tenant tables in 0001. USING filters what is visible to SELECT/UPDATE/DELETE;
    # WITH CHECK constrains what INSERT/UPDATE may write. Without WITH CHECK a bound
    # tenant could still create rows attributed to another workspace: a write-side leak
    # that read-only tests never catch.
    op.execute(
        sa.text(f"""
        CREATE POLICY tenant_isolation ON public.members
            USING (workspace_id = {WORKSPACE_GUC_SQL})
            WITH CHECK (workspace_id = {WORKSPACE_GUC_SQL});
    """)
    )


def downgrade() -> None:
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation ON public.members"))
    op.drop_index("ix_members_workspace_id", table_name="members")
    op.drop_table("members")
