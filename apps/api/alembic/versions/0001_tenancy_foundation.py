"""Tenancy foundation: workspaces, api_tokens, RLS, token resolution.

Revision ID: 0001_tenancy_foundation
Revises:
Create Date: 2026-08-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0001_tenancy_foundation"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# The role the application connects as. Created outside Alembic (it needs a password, and
# a password in a migration is a secret in git — P-18): locally by
# infra/docker/postgres-init/01-app-role.sh, in production by the platform runbook.
APP_ROLE = "omniai_app"

# A LOGIN-less role that exists only to own the token-resolution function. No password,
# so it is safe to create here and nobody can ever connect as it.
AUTH_ROLE = "omniai_auth"

# `NULLIF(..., '')` guards the empty string: current_setting returns '' rather than NULL
# in some paths, and ''::uuid raises rather than yielding NULL — which would turn a
# missing tenant context into a 500 instead of an empty result set.
WORKSPACE_GUC_SQL = "NULLIF(current_setting('app.workspace_id', true), '')::uuid"


def upgrade() -> None:
    # ------------------------------------------------------------------ preflight
    # Fail loudly and early rather than creating tables the application cannot read.
    #
    # noqa S608 (here and below): role names cannot be bind parameters — Postgres does not
    # accept placeholders for identifiers in CREATE ROLE / GRANT / policy DDL. The
    # interpolated values are module-level constants defined above, never user input, so
    # there is no injection path. Flagged rather than blanket-ignored so the next person
    # to add DDL here has to make the same argument.
    op.execute(
        sa.text(f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                RAISE EXCEPTION
                    'Role "{APP_ROLE}" does not exist. Create it before migrating: '
                    'locally `make db-reset`, in production per the SECURITY.md runbook.';
            END IF;
            -- Two unconditional RLS bypasses exist and FORCE stops neither. Reject both.
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}' AND rolsuper) THEN
                RAISE EXCEPTION
                    'Role "{APP_ROLE}" is a superuser. Superusers bypass Row-Level Security '
                    'unconditionally, which would silently disable tenant isolation.';
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}' AND rolbypassrls) THEN
                RAISE EXCEPTION
                    'Role "{APP_ROLE}" holds BYPASSRLS. That bypasses Row-Level Security '
                    'unconditionally even for a non-superuser that owns nothing, which '
                    'would silently disable tenant isolation. Revoke it: '
                    'ALTER ROLE {APP_ROLE} NOBYPASSRLS;';
            END IF;
        END
        $$;
        """)  # noqa: S608
    )

    op.execute(
        sa.text(f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{AUTH_ROLE}') THEN
                CREATE ROLE {AUTH_ROLE} NOLOGIN;
            END IF;
        END
        $$;
    """)  # noqa: S608
    )
    # Needed so the migration role may reassign function ownership to AUTH_ROLE below.
    op.execute(sa.text(f"GRANT {AUTH_ROLE} TO CURRENT_USER"))

    # ------------------------------------------------------------------ tables
    op.create_table(
        "workspaces",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("plan", sa.String(length=20), server_default=sa.text("'free'"), nullable=False),
        sa.Column("stripe_customer_id", sa.String(length=64), nullable=True),
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
        sa.CheckConstraint(
            "plan IN ('free', 'pro', 'team', 'enterprise')", name="ck_workspaces_plan_valid"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_workspaces"),
        sa.UniqueConstraint("slug", name="uq_workspaces_slug"),
    )

    op.create_table(
        "api_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("token_prefix", sa.String(length=16), nullable=False),
        sa.Column(
            "scopes", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_api_tokens_workspace_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_api_tokens"),
        # The one lookup that arrives without workspace context (DATABASE_DESIGN.md §4).
        sa.UniqueConstraint("token_hash", name="uq_api_tokens_token_hash"),
    )
    # Postgres does not index foreign keys automatically; an unindexed FK makes the
    # parent's ON DELETE CASCADE a sequential scan per row.
    op.create_index("ix_api_tokens_workspace_id", "api_tokens", ["workspace_id"])
    # Composite leading with workspace_id — every access path is tenant-scoped (P-44).
    op.create_index(
        "ix_api_tokens_workspace_id_created_at",
        "api_tokens",
        ["workspace_id", sa.text("created_at DESC")],
    )

    # ------------------------------------------------------------------ grants
    op.execute(sa.text(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}"))
    op.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON public.workspaces TO {APP_ROLE}"))
    op.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON public.api_tokens TO {APP_ROLE}"))

    # ------------------------------------------------------------------ RLS
    for table in ("workspaces", "api_tokens"):
        op.execute(sa.text(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY"))
        # FORCE is not optional. ENABLE alone exempts the table *owner* from its own
        # policies, so any connection as the owner reads every tenant's rows while the
        # policy sits there looking correct (DATABASE_DESIGN.md §6).
        op.execute(sa.text(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY"))

    op.execute(
        sa.text(f"""
        CREATE POLICY tenant_isolation ON public.workspaces
            USING (id = {WORKSPACE_GUC_SQL})
            WITH CHECK (id = {WORKSPACE_GUC_SQL});
    """)
    )
    op.execute(
        sa.text(f"""
        CREATE POLICY tenant_isolation ON public.api_tokens
            USING (workspace_id = {WORKSPACE_GUC_SQL})
            WITH CHECK (workspace_id = {WORKSPACE_GUC_SQL});
    """)
    )

    # ------------------------------------------------ token resolution (the exemption)
    #
    # Bootstrap paradox: resolving a bearer token is what *discovers* the workspace, so
    # the lookup cannot run under a policy that already needs it. Rather than weaken the
    # policy — a `USING (... OR current_setting(...) IS NULL)` escape hatch would disable
    # isolation for every unbound query — we carve out one narrowly-scoped exemption.
    #
    # Mechanism: a policy targeted at AUTH_ROLE alone, plus a SECURITY DEFINER function
    # owned by AUTH_ROLE. Note this deliberately avoids BYPASSRLS, which needs superuser
    # to grant and is often unavailable on managed Postgres (Neon).
    #
    # `SET search_path` is load-bearing, not tidiness: without it a caller controlling
    # search_path could shadow `public.api_tokens` with their own table and make a
    # function running as another role read it. It is the classic SECURITY DEFINER
    # privilege-escalation bug.
    op.execute(sa.text("CREATE SCHEMA IF NOT EXISTS auth"))
    op.execute(sa.text(f"GRANT USAGE ON SCHEMA auth TO {APP_ROLE}, {AUTH_ROLE}"))
    op.execute(sa.text(f"GRANT SELECT ON public.api_tokens TO {AUTH_ROLE}"))
    op.execute(
        sa.text(f"""
        CREATE POLICY token_resolution ON public.api_tokens
            FOR SELECT TO {AUTH_ROLE}
            USING (true);
    """)
    )
    op.execute(
        sa.text("""
        CREATE FUNCTION auth.resolve_api_token(p_token_hash text)
        RETURNS TABLE (
            token_id uuid,
            workspace_id uuid,
            scopes jsonb,
            revoked_at timestamptz,
            expires_at timestamptz
        )
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT t.id, t.workspace_id, t.scopes, t.revoked_at, t.expires_at
            FROM public.api_tokens t
            WHERE t.token_hash = p_token_hash;
        $$;
    """)
    )
    op.execute(sa.text(f"ALTER FUNCTION auth.resolve_api_token(text) OWNER TO {AUTH_ROLE}"))
    # SECURITY DEFINER functions are EXECUTE-able by PUBLIC by default. Revoke, then grant
    # to exactly one role.
    op.execute(sa.text("REVOKE ALL ON FUNCTION auth.resolve_api_token(text) FROM PUBLIC"))
    op.execute(sa.text(f"GRANT EXECUTE ON FUNCTION auth.resolve_api_token(text) TO {APP_ROLE}"))


def downgrade() -> None:
    op.execute(sa.text("DROP FUNCTION IF EXISTS auth.resolve_api_token(text)"))
    op.execute(sa.text("DROP SCHEMA IF EXISTS auth CASCADE"))
    op.execute(sa.text("DROP POLICY IF EXISTS token_resolution ON public.api_tokens"))
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation ON public.api_tokens"))
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation ON public.workspaces"))
    op.drop_index("ix_api_tokens_workspace_id_created_at", table_name="api_tokens")
    op.drop_index("ix_api_tokens_workspace_id", table_name="api_tokens")
    op.drop_table("api_tokens")
    op.drop_table("workspaces")
    # AUTH_ROLE is dropped last: it cannot be dropped while it owns objects. APP_ROLE is
    # intentionally left in place — it is provisioned outside Alembic, and a downgrade
    # should not destroy infrastructure it did not create.
    op.execute(sa.text(f"DROP ROLE IF EXISTS {AUTH_ROLE}"))
