"""Human membership bootstrap: resolve a verified subject's workspaces pre-RLS.

Revision ID: 0004_member_resolution
Revises: 0003_api_token_creator
Create Date: 2026-08-15
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0004_member_resolution"
down_revision: str | None = "0003_api_token_creator"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

AUTH_ROLE = "omniai_auth"
APP_ROLE = "omniai_app"


def upgrade() -> None:
    # The human twin of `auth.resolve_api_token` (ADR-0008, ADR-0015 §7). A verified JWT
    # names a user; which workspace that user acts in is discovered by this lookup — and a
    # lookup that discovers the workspace cannot run under a policy that already requires
    # one. Same carve-out mechanism as migration 0001: a policy targeted at AUTH_ROLE
    # alone plus a SECURITY DEFINER function owned by it. Deliberately not BYPASSRLS,
    # which needs superuser to grant and is unavailable on managed Postgres.
    op.execute(sa.text(f"GRANT SELECT ON public.members TO {AUTH_ROLE}"))
    op.execute(
        sa.text(f"""
        CREATE POLICY member_resolution ON public.members
            FOR SELECT TO {AUTH_ROLE}
            USING (true);
    """)
    )

    # Returns member_id + workspace_id and nothing more. The role is deliberately NOT
    # returned: `resolve_member_role` reads it from the member row under RLS after the
    # workspace binds, keeping one authorization source of truth. A bootstrap function
    # that also answered "what may they do" would be a second, unaudited RBAC surface.
    #
    # `SET search_path` is load-bearing (the classic SECURITY DEFINER escalation bug):
    # without it a caller controlling search_path could shadow `public.members` and have
    # this function read their table with AUTH_ROLE's privileges.
    op.execute(
        sa.text("""
        CREATE FUNCTION auth.resolve_member_workspaces(p_user_id text)
        RETURNS TABLE (
            member_id uuid,
            workspace_id uuid
        )
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT m.id, m.workspace_id
            FROM public.members m
            WHERE m.user_id = p_user_id;
        $$;
    """)
    )
    op.execute(sa.text(f"ALTER FUNCTION auth.resolve_member_workspaces(text) OWNER TO {AUTH_ROLE}"))
    # SECURITY DEFINER functions are EXECUTE-able by PUBLIC by default. Revoke, then
    # grant to exactly one role — the same discipline as resolve_api_token.
    op.execute(sa.text("REVOKE ALL ON FUNCTION auth.resolve_member_workspaces(text) FROM PUBLIC"))
    op.execute(
        sa.text(f"GRANT EXECUTE ON FUNCTION auth.resolve_member_workspaces(text) TO {APP_ROLE}")
    )

    # A bootstrap lookup is by user_id alone — it cannot lead with workspace_id, because
    # discovering the workspace is its purpose. The same documented exception the unique
    # index on api_tokens.token_hash already embodies (DATABASE_DESIGN.md §5 convention,
    # bootstrap carve-out). The (workspace_id, user_id) unique index cannot serve this:
    # its leading column is the one value the lookup does not have.
    op.create_index("ix_members_user_id", "members", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_members_user_id", table_name="members")
    op.execute(sa.text("DROP FUNCTION IF EXISTS auth.resolve_member_workspaces(text)"))
    op.execute(sa.text("DROP POLICY IF EXISTS member_resolution ON public.members"))
    op.execute(sa.text(f"REVOKE SELECT ON public.members FROM {AUTH_ROLE}"))  # noqa: S608
