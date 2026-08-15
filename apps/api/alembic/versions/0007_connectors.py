"""Connectors: tenant-owned external-API definitions (M1.4-A, Connector Engine v1).

The first slice of the Connector Engine (ROADMAP §M1, ADR-0003): the top-level Connector
record — name, base URL, auth *requirements* (never secrets), Tool-Schema status. Manual
definition only; OpenAPI/Swagger ingestion (`connector_versions`, `tools`, `source_url`,
`current_version_id` FK) lands in a later slice, which is why `current_version_id` is a bare
nullable column here — additively constrained (P-43) once `connector_versions` exists.

Unlike `api_tokens`/`invitations`, a Connector is never discovered pre-RLS: every access
arrives with a bound workspace, so there is NO SECURITY DEFINER resolver — just the tenant
table, its RLS, and the standard grant.

Revision ID: 0007_connectors
Revises: 0006_invitations
Create Date: 2026-08-15
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0007_connectors"
down_revision: str | None = "0006_invitations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "omniai_app"
WORKSPACE_GUC_SQL = "NULLIF(current_setting('app.workspace_id', true), '')::uuid"


def upgrade() -> None:
    # Preflight, re-asserted per tenant table (ADR-0008): a tenant table created while the
    # app role holds a bypass is silently unprotected from birth.
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
        "connectors",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        # Unique per workspace among live (non-deleted) rows — see the partial index below.
        sa.Column("slug", sa.String(length=64), nullable=False),
        # How the definition was produced. Only 'manual' is created by M1.4-A; the ingestion
        # source types arrive with the OpenAPI/Swagger importer. CHECK against the canonical
        # domain (DATABASE_DESIGN.md §3).
        sa.Column("source_type", sa.String(length=20), nullable=False),
        # The ingested spec's origin URL. NULL for manual connectors; populated by ingestion.
        sa.Column("source_url", sa.String(length=2048), nullable=True),
        # The external API's base URL. SSRF-linted by the service before insert
        # (CONNECTOR_SPECIFICATION.md §11, SECURITY.md §6): https only, no private/loopback/
        # link-local/metadata hosts, no embedded credentials.
        sa.Column("base_url", sa.String(length=2048), nullable=False),
        # Auth *requirements* only (key name + location, scheme) — NEVER secret values. The
        # secret lives in a Connection's Credential, decrypted only inside the runtime.
        sa.Column(
            "auth_config", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column(
            "status", sa.String(length=20), nullable=False, server_default=sa.text("'draft'")
        ),
        # FK to connector_versions once that table exists (later slice); bare nullable UUID
        # for now (P-43: the FK is an additive constraint, not a schema rewrite).
        sa.Column("current_version_id", postgresql.UUID(as_uuid=True), nullable=True),
        # Soft delete (DATABASE_DESIGN.md §3): connectors are retained with `deleted_at` set,
        # unlike credentials which are hard-deleted.
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
            "source_type IN ('openapi3', 'swagger2', 'graphql', 'manual')",
            name="source_type_valid",
        ),
        sa.CheckConstraint(
            "status IN ('draft', 'ingesting', 'active', 'failed')", name="status_valid"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_connectors"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_connectors_workspace_id",
            ondelete="CASCADE",
        ),
    )

    # Tenant-scoped access path leads with workspace_id (P-44).
    op.create_index("ix_connectors_workspace_id", "connectors", ["workspace_id"])
    # Keyset pagination (created_at DESC, id DESC) — declared DESC to match the model exactly
    # or autogenerate proposes dropping/recreating it every run.
    op.create_index(
        "ix_connectors_workspace_id_created_at",
        "connectors",
        ["workspace_id", sa.text("created_at DESC")],
    )
    # At most one LIVE connector per (workspace, slug): a soft-deleted slug can be reused,
    # so the uniqueness is partial on `deleted_at IS NULL`.
    op.execute(
        sa.text("""
        CREATE UNIQUE INDEX uq_connectors_workspace_id_slug
            ON public.connectors (workspace_id, slug)
            WHERE deleted_at IS NULL;
    """)
    )

    op.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON public.connectors TO {APP_ROLE}"))  # noqa: S608, E501
    op.execute(sa.text("ALTER TABLE public.connectors ENABLE ROW LEVEL SECURITY"))
    # FORCE so the table owner is not exempt from its own policy.
    op.execute(sa.text("ALTER TABLE public.connectors FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(f"""
        CREATE POLICY tenant_isolation ON public.connectors
            USING (workspace_id = {WORKSPACE_GUC_SQL})
            WITH CHECK (workspace_id = {WORKSPACE_GUC_SQL});
    """)
    )


def downgrade() -> None:
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation ON public.connectors"))
    op.execute(sa.text("DROP INDEX IF EXISTS uq_connectors_workspace_id_slug"))
    op.drop_index("ix_connectors_workspace_id_created_at", table_name="connectors")
    op.drop_index("ix_connectors_workspace_id", table_name="connectors")
    op.drop_table("connectors")
