"""Workspace invitations: targeted, email-bound, hashed single-use tokens (ADR-0017).

Revision ID: 0006_invitations
Revises: 0005_member_workspace_roles
Create Date: 2026-08-15
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0006_invitations"
down_revision: str | None = "0005_member_workspace_roles"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "omniai_app"
AUTH_ROLE = "omniai_auth"
WORKSPACE_GUC_SQL = "NULLIF(current_setting('app.workspace_id', true), '')::uuid"


def upgrade() -> None:
    # Preflight, re-asserted per tenant table (ADR-0008): a tenant table created while the
    # app role holds a bypass is silently unprotected from birth and nothing downstream
    # would notice.
    op.execute(
        sa.text(f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                RAISE EXCEPTION 'Role "{APP_ROLE}" does not exist.';
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles
                       WHERE rolname = '{APP_ROLE}' AND (rolsuper OR rolbypassrls)) THEN
                RAISE EXCEPTION 'Role "{APP_ROLE}" is superuser or holds BYPASSRLS.';
            END IF;
        END
        $$;
        """)  # noqa: S608
    )

    op.create_table(
        "invitations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        # The invited person, normalized to lower-case by the application before insert.
        # Not a foreign key: the identity lives in Better Auth (ADR-0002), and at creation
        # time the invitee may not be a user at all.
        sa.Column("invited_email", sa.String(length=320), nullable=False),
        # The role the membership will carry. Server-set at creation; the recipient can
        # never see or change it. CHECK against the canonical domain (DATABASE_DESIGN.md §3).
        sa.Column("role", sa.String(length=20), nullable=False),
        # Which member issued the invitation. Composite intra-tenant FK below (the M1.3
        # pattern); nullable because the bootstrap script could seed one before members exist.
        sa.Column("invited_by", postgresql.UUID(as_uuid=True), nullable=True),
        # SHA-256(token) hex. The raw 256-bit token is emailed and never stored.
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "status", sa.String(length=20), nullable=False, server_default=sa.text("'pending'")
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "role IN ('owner', 'admin', 'member', 'viewer')", name="invitation_role_valid"
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'accepted', 'cancelled')", name="invitation_status_valid"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_invitations"),
        # token_hash is globally unique: it is the pre-RLS lookup key that arrives without a
        # workspace context (the same shape as api_tokens.token_hash, DATABASE_DESIGN.md §4).
        sa.UniqueConstraint("token_hash", name="uq_invitations_token_hash"),
        # The tenant FK, `ON DELETE CASCADE` — deleting a workspace takes its invitations
        # with it (they are meaningless without it). Matches the WorkspaceScopedMixin the
        # ORM model uses, so autogenerate stays clean.
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_invitations_workspace_id",
            ondelete="CASCADE",
        ),
        # Composite self-tenant FK to the inviting member. FK checks run with RLS bypassed,
        # so carrying workspace_id into the key makes a cross-tenant inviter reference
        # structurally impossible. Column-scoped SET NULL keeps the invitation if the inviter
        # is later removed (workspace_id is NOT NULL).
        sa.ForeignKeyConstraint(
            ["workspace_id", "invited_by"],
            ["members.workspace_id", "members.id"],
            name="fk_invitations_invited_by",
            ondelete="SET NULL (invited_by)",
        ),
    )

    # Tenant-scoped listing/cancellation lead with workspace_id (P-44).
    op.create_index("ix_invitations_workspace_id", "invitations", ["workspace_id"])

    # At most ONE pending invitation per (workspace, email): a fresh invite never lets a
    # stale one grant a different role (ADR-0017 §7). Partial, so accepted/cancelled rows
    # do not block re-inviting. `lower()` because emails are compared case-insensitively.
    op.execute(
        sa.text("""
        CREATE UNIQUE INDEX uq_invitations_pending_email
            ON public.invitations (workspace_id, lower(invited_email))
            WHERE status = 'pending';
    """)
    )

    op.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON public.invitations TO {APP_ROLE}"))  # noqa: S608, E501
    op.execute(sa.text("ALTER TABLE public.invitations ENABLE ROW LEVEL SECURITY"))
    # FORCE so the table owner is not exempt from its own policy.
    op.execute(sa.text("ALTER TABLE public.invitations FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(f"""
        CREATE POLICY tenant_isolation ON public.invitations
            USING (workspace_id = {WORKSPACE_GUC_SQL})
            WITH CHECK (workspace_id = {WORKSPACE_GUC_SQL});
    """)
    )

    # Bootstrap resolution (ADR-0008/0017 §6): an accepting user is not yet a member of the
    # workspace, so the token lookup that DISCOVERS the workspace cannot run under a policy
    # that already needs one. Same SECURITY DEFINER carve-out as auth.resolve_api_token.
    op.execute(sa.text(f"GRANT SELECT ON public.invitations TO {AUTH_ROLE}"))
    op.execute(
        sa.text(f"""
        CREATE POLICY invitation_resolution ON public.invitations
            FOR SELECT TO {AUTH_ROLE}
            USING (true);
    """)
    )
    op.execute(
        sa.text("""
        CREATE FUNCTION auth.resolve_invitation(p_token_hash text)
        RETURNS TABLE (
            id uuid,
            workspace_id uuid,
            invited_email text,
            role text,
            invited_by uuid,
            status text,
            expires_at timestamptz
        )
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT i.id, i.workspace_id, i.invited_email, i.role, i.invited_by,
                   i.status, i.expires_at
            FROM public.invitations i
            WHERE i.token_hash = p_token_hash;
        $$;
    """)
    )
    op.execute(sa.text(f"ALTER FUNCTION auth.resolve_invitation(text) OWNER TO {AUTH_ROLE}"))
    op.execute(sa.text("REVOKE ALL ON FUNCTION auth.resolve_invitation(text) FROM PUBLIC"))
    op.execute(sa.text(f"GRANT EXECUTE ON FUNCTION auth.resolve_invitation(text) TO {APP_ROLE}"))


def downgrade() -> None:
    op.execute(sa.text("DROP FUNCTION IF EXISTS auth.resolve_invitation(text)"))
    op.execute(sa.text("DROP POLICY IF EXISTS invitation_resolution ON public.invitations"))
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation ON public.invitations"))
    op.execute(sa.text("DROP INDEX IF EXISTS uq_invitations_pending_email"))
    op.drop_index("ix_invitations_workspace_id", table_name="invitations")
    op.drop_table("invitations")
