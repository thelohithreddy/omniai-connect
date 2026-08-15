"""connector_versions: immutable ingested snapshots (M1.4-B1.1, ADR-0025).

The second slice of the Connector Engine's ingestion path. `connector_versions` stores one
immutable snapshot per successful ingestion — the canonical Tool Schema set (`normalized_schema`),
the `spec_hash` that dedupes no-op re-syncs, and the `raw_spec_ref` pointing at the original
document in R2 (DATABASE_DESIGN.md §5, CONNECTOR_SPECIFICATION.md §3). Rows are never updated or
deleted; `connectors.current_version_id` is the only moving pointer.

This migration also lands the two composite intra-tenant FKs (DATABASE_DESIGN.md §1): it adds the
`UNIQUE (workspace_id, id)` targets on both tables and wires
`connector_versions (workspace_id, connector_id) → connectors (workspace_id, id)` and the
previously-deferred `connectors (workspace_id, current_version_id) → connector_versions
(workspace_id, id)` (P-43, additive).

Revision ID: 0008_connector_versions
Revises: 0007_connectors
Create Date: 2026-08-15
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0008_connector_versions"
down_revision: str | None = "0007_connectors"
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

    # The composite-FK target on the parent: a child's (workspace_id, connector_id) can only
    # reference a connector in the SAME workspace (DATABASE_DESIGN.md §1) — a cross-tenant FK is
    # unrepresentable.
    op.create_unique_constraint(
        "uq_connectors_workspace_id_id", "connectors", ["workspace_id", "id"]
    )

    op.create_table(
        "connector_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("connector_id", postgresql.UUID(as_uuid=True), nullable=False),
        # Monotonic integer per connector (DATABASE_DESIGN.md §5); unique with connector_id.
        sa.Column("version", sa.Integer(), nullable=False),
        # SHA-256 hex of the canonical JSON of the ordered normalized Tool set (§3). Dedupes
        # no-op re-syncs: a re-ingest that normalizes identically produces no new version.
        sa.Column("spec_hash", sa.String(length=64), nullable=False),
        # R2 object key of the original document (B0.5). NULL only for non-fetched sources.
        sa.Column("raw_spec_ref", sa.String(length=1024), nullable=True),
        # The canonical Tool Schema set (CONNECTOR_SPECIFICATION.md §2).
        sa.Column("normalized_schema", postgresql.JSONB(), nullable=False),
        # added/removed/changed vs. the previous version — computed by a later slice; NULL now.
        sa.Column("diff_summary", postgresql.JSONB(), nullable=True),
        # Immutable snapshot: created_at only, never updated (no updated_at).
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name="pk_connector_versions"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_connector_versions_workspace_id",
            ondelete="CASCADE",
        ),
        # Composite intra-tenant FK: a version belongs to a connector in the same workspace.
        sa.ForeignKeyConstraint(
            ["workspace_id", "connector_id"],
            ["connectors.workspace_id", "connectors.id"],
            name="fk_connector_versions_connector_id",
            ondelete="CASCADE",
        ),
        # Monotonic, gap-tolerant, unique per connector.
        sa.UniqueConstraint("connector_id", "version", name="uq_connector_versions_connector_id_version"),
        # The composite-FK target for connectors.current_version_id.
        sa.UniqueConstraint("workspace_id", "id", name="uq_connector_versions_workspace_id_id"),
    )

    # Tenant-scoped access path leads with workspace_id (P-44).
    op.create_index("ix_connector_versions_workspace_id", "connector_versions", ["workspace_id"])

    op.execute(
        sa.text(f"GRANT SELECT, INSERT ON public.connector_versions TO {APP_ROLE}")  # noqa: S608
    )
    op.execute(sa.text("ALTER TABLE public.connector_versions ENABLE ROW LEVEL SECURITY"))
    # FORCE so the table owner is not exempt from its own policy.
    op.execute(sa.text("ALTER TABLE public.connector_versions FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(f"""
        CREATE POLICY tenant_isolation ON public.connector_versions
            USING (workspace_id = {WORKSPACE_GUC_SQL})
            WITH CHECK (workspace_id = {WORKSPACE_GUC_SQL});
    """)
    )

    # The deferred pointer FK (P-43): connectors.current_version_id now references a version in
    # the SAME workspace. Composite so it cannot point across tenants.
    op.create_foreign_key(
        "fk_connectors_current_version_id",
        "connectors",
        "connector_versions",
        ["workspace_id", "current_version_id"],
        ["workspace_id", "id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_connectors_current_version_id", "connectors", type_="foreignkey")
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation ON public.connector_versions"))
    op.drop_index("ix_connector_versions_workspace_id", table_name="connector_versions")
    op.drop_table("connector_versions")
    op.drop_constraint("uq_connectors_workspace_id_id", "connectors", type_="unique")
