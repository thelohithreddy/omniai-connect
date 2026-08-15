"""Human workspace discovery: list a subject's own memberships with role, pre-RLS.

Revision ID: 0005_member_workspace_roles
Revises: 0004_member_resolution
Create Date: 2026-08-15
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0005_member_workspace_roles"
down_revision: str | None = "0004_member_resolution"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

AUTH_ROLE = "omniai_auth"
APP_ROLE = "omniai_app"


def upgrade() -> None:
    # Backs GET /v1/workspaces — "which workspaces do I belong to, and as what" (ADR-0016 §7).
    # A human listing their own memberships is a pre-selection lookup: it cannot run under a
    # workspace policy because the caller has not yet chosen (and may belong to several)
    # workspaces. Same bootstrap carve-out as auth.resolve_member_workspaces (ADR-0008), and
    # it REUSES that function's exemption — the `member_resolution` policy and the SELECT
    # grant on public.members from migration 0004 already let AUTH_ROLE read members. No new
    # grant or policy on public.workspaces is introduced: this function reads only members,
    # so it discloses only workspace_id + the caller's own role, never workspace metadata.
    #
    # `role` is returned for DISPLAY only. Authorization never flows through this function —
    # it flows through get_workspace_context binding the selected workspace and
    # resolve_member_role reading the role under RLS (ADR-0015 §7, ADR-0016 §2/§7). Two
    # functions, because the authorization-path resolver must never return a role.
    op.execute(
        sa.text("""
        CREATE FUNCTION auth.resolve_member_workspace_roles(p_user_id text)
        RETURNS TABLE (
            workspace_id uuid,
            role text
        )
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT m.workspace_id, m.role
            FROM public.members m
            WHERE m.user_id = p_user_id
            ORDER BY m.workspace_id;
        $$;
    """)
    )
    op.execute(
        sa.text(f"ALTER FUNCTION auth.resolve_member_workspace_roles(text) OWNER TO {AUTH_ROLE}")
    )
    op.execute(
        sa.text("REVOKE ALL ON FUNCTION auth.resolve_member_workspace_roles(text) FROM PUBLIC")
    )
    op.execute(
        sa.text(
            f"GRANT EXECUTE ON FUNCTION auth.resolve_member_workspace_roles(text) TO {APP_ROLE}"
        )
    )


def downgrade() -> None:
    op.execute(sa.text("DROP FUNCTION IF EXISTS auth.resolve_member_workspace_roles(text)"))
