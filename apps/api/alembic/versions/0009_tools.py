"""tools: denormalized projection of the active version's Tool Schema set (M1.4-B1.4, ADR-0028).

The final ingestion table. Each row is one callable operation, projected from a
`connector_versions.normalized_schema` for query/export speed (DATABASE_DESIGN.md §3,
CONNECTOR_SPECIFICATION.md §3). The version's `normalized_schema` stays authoritative; this table
is a projection of the *active* (promoted) version. Promotion swaps the active set: current live
rows are soft-deleted and the new version's rows inserted (rows are never mutated in place; §3), so
grants are SELECT/INSERT/UPDATE — deprecation is a soft delete, never a physical DELETE.

Two composite intra-tenant FKs (their `UNIQUE (workspace_id, id)` targets already exist on
`connectors` and `connector_versions` from migration 0008): a tool belongs to a connector AND a
version in the same workspace — a cross-tenant tool is unrepresentable. RLS ENABLE + FORCE +
`tenant_isolation`, matching every other tenant table (ADR-0008).

Revision ID: 0009_tools
Revises: 0008_connector_versions
Create Date: 2026-08-16
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0009_tools"
down_revision: str | None = "0008_connector_versions"
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
        "tools",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("connector_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("connector_version_id", postgresql.UUID(as_uuid=True), nullable=False),
        # Canonical tool name (CONNECTOR_ENGINE.md §5); unique among LIVE rows of a version.
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        # Merged JSON Schema of the operation's arguments (CONNECTOR_SPECIFICATION.md §2).
        sa.Column("input_schema", postgresql.JSONB(), nullable=False),
        # Response shape guidance — not produced by the current importer; NULL until a later slice.
        sa.Column("output_hints", postgresql.JSONB(), nullable=True),
        # Safety metadata + tags (and rate_hints when present).
        sa.Column(
            "annotations", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        # Per-Tool user override; survives promotion by re-application on Tool identity.
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        # Soft delete = deprecation (§13): excluded from listings, retained for audit.
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
        sa.PrimaryKeyConstraint("id", name="pk_tools"),
        sa.ForeignKeyConstraint(
            ["workspace_id"], ["workspaces.id"], name="fk_tools_workspace_id", ondelete="CASCADE"
        ),
        # Composite intra-tenant FKs: a tool's connector and version live in the same workspace.
        sa.ForeignKeyConstraint(
            ["workspace_id", "connector_id"],
            ["connectors.workspace_id", "connectors.id"],
            name="fk_tools_connector_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "connector_version_id"],
            ["connector_versions.workspace_id", "connector_versions.id"],
            name="fk_tools_connector_version_id",
            ondelete="CASCADE",
        ),
    )

    # The WorkspaceScopedMixin's per-tenant index (every tenant table carries it, P-41).
    op.create_index("ix_tools_workspace_id", "tools", ["workspace_id"])
    # At most one LIVE row per (version, name); partial so re-promotion (soft-delete + re-insert)
    # never collides with soft-deleted history.
    op.create_index(
        "uq_tools_connector_version_id_name",
        "tools",
        ["connector_version_id", "name"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    # The live-set lookup leads with workspace_id (P-44).
    op.create_index("ix_tools_workspace_id_connector_id", "tools", ["workspace_id", "connector_id"])

    # Mutable lifecycle (enabled/deleted_at) → UPDATE is granted; no DELETE (soft-delete only).
    op.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON public.tools TO {APP_ROLE}"))  # noqa: S608
    op.execute(sa.text("ALTER TABLE public.tools ENABLE ROW LEVEL SECURITY"))
    # FORCE so the table owner is not exempt from its own policy.
    op.execute(sa.text("ALTER TABLE public.tools FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(f"""
        CREATE POLICY tenant_isolation ON public.tools
            USING (workspace_id = {WORKSPACE_GUC_SQL})
            WITH CHECK (workspace_id = {WORKSPACE_GUC_SQL});
    """)
    )


def downgrade() -> None:
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation ON public.tools"))
    op.drop_index("ix_tools_workspace_id_connector_id", table_name="tools")
    op.drop_index("uq_tools_connector_version_id_name", table_name="tools")
    op.drop_index("ix_tools_workspace_id", table_name="tools")
    op.drop_table("tools")
