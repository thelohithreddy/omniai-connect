"""connections: a workspace's authenticated instance of a Connector (M1-Connections-v1, ADR-0029).

The first slice of the execution plane. A `connections` row binds a Connector to a Workspace and
carries its lifecycle (`pending_auth|active|error|revoked`) and non-secret `config_overrides`
(DATABASE_DESIGN.md §3, Bible §4). It holds **no secret** — `credential_id` is a bare nullable
placeholder for the future Credentials module (the composite FK is added additively when the
`credentials` table lands, the same P-43 pattern `connectors.current_version_id` used).

A connection may only reference a Connector in the SAME workspace: the composite intra-tenant FK
`(workspace_id, connector_id) → connectors (workspace_id, id)` makes a cross-tenant attachment
unrepresentable. RLS ENABLE + FORCE + `tenant_isolation` matches every other tenant table
(ADR-0008); grants are SELECT/INSERT/UPDATE — no DELETE, because revocation is a soft delete. A
`UNIQUE (workspace_id, id)` target is added so `credentials`/`tool_calls` can reference a connection
in the same workspace later.

Revision ID: 0010_connections
Revises: 0009_tools
Create Date: 2026-08-17
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0010_connections"
down_revision: str | None = "0009_tools"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "omniai_app"
WORKSPACE_GUC_SQL = "NULLIF(current_setting('app.workspace_id', true), '')::uuid"


def upgrade() -> None:
    # Preflight, re-asserted per tenant table (ADR-0008): a tenant table created while the app
    # role holds a bypass is silently unprotected from birth.
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
        "connections",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("connector_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        # Lifecycle (DATABASE_DESIGN.md §3). Server-controlled: a client never sets this.
        sa.Column(
            "status", sa.String(length=20), server_default=sa.text("'pending_auth'"), nullable=False
        ),
        # Placeholder for the Credentials module. Bare nullable UUID (no FK — the target table does
        # not exist yet); the composite intra-tenant FK is added additively later (P-43).
        sa.Column("credential_id", postgresql.UUID(as_uuid=True), nullable=True),
        # Non-secret per-connection config (e.g. base-URL override, per-connection tool enablement).
        # Never an authority surface (§3): tenant/role/status are never read from here.
        sa.Column(
            "config_overrides",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("last_health_check_at", sa.DateTime(timezone=True), nullable=True),
        # Soft delete = revoke (§3): retained with `deleted_at` set, name freed for reuse.
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
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
            "status IN ('pending_auth', 'active', 'error', 'revoked')", name="status_valid"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_connections"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_connections_workspace_id",
            ondelete="CASCADE",
        ),
        # Composite intra-tenant FK: a connection can only bind a connector in the same workspace.
        sa.ForeignKeyConstraint(
            ["workspace_id", "connector_id"],
            ["connectors.workspace_id", "connectors.id"],
            name="fk_connections_connector_id",
            ondelete="CASCADE",
        ),
        # Composite-FK target for the future credentials/tool_calls (workspace_id, connection_id).
        sa.UniqueConstraint("workspace_id", "id", name="uq_connections_workspace_id_id"),
    )

    # The WorkspaceScopedMixin's per-tenant index (every tenant table carries it, P-41).
    op.create_index("ix_connections_workspace_id", "connections", ["workspace_id"])
    # List a workspace's connections by connector.
    op.create_index(
        "ix_connections_workspace_id_connector_id", "connections", ["workspace_id", "connector_id"]
    )
    # One LIVE connection per (workspace, name). Partial on `deleted_at IS NULL` so a revoked name
    # frees up; the DB — not the application — is the final arbiter under concurrent creates.
    op.create_index(
        "uq_connections_workspace_id_name",
        "connections",
        ["workspace_id", "name"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )

    # Mutable lifecycle (status/config/credential_id/deleted_at) → UPDATE; no DELETE (soft-delete).
    op.execute(
        sa.text(f"GRANT SELECT, INSERT, UPDATE ON public.connections TO {APP_ROLE}")  # noqa: S608
    )
    op.execute(sa.text("ALTER TABLE public.connections ENABLE ROW LEVEL SECURITY"))
    # FORCE so the table owner is not exempt from its own policy.
    op.execute(sa.text("ALTER TABLE public.connections FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(f"""
        CREATE POLICY tenant_isolation ON public.connections
            USING (workspace_id = {WORKSPACE_GUC_SQL})
            WITH CHECK (workspace_id = {WORKSPACE_GUC_SQL});
    """)
    )


def downgrade() -> None:
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation ON public.connections"))
    op.drop_index("uq_connections_workspace_id_name", table_name="connections")
    op.drop_index("ix_connections_workspace_id_connector_id", table_name="connections")
    op.drop_index("ix_connections_workspace_id", table_name="connections")
    op.drop_table("connections")
