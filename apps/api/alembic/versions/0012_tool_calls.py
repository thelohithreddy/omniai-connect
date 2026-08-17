"""tool_calls: append-only, partitioned audit of every Tool Call (M1-Execution-Runtime, ADR-0031).

Stage 7 of the Execution Runtime pipeline (AI_RUNTIME.md §2) writes exactly one row here per Tool
Call — "no audit row, no result". The table is **append-only and immutable** (DATABASE_DESIGN.md
§3: never deleted in-band; retention is by partition dropping), so the app role gets only
SELECT + INSERT — no UPDATE, no DELETE. There is no `updated_at`.

Partitioning: `PARTITION BY RANGE (created_at)` with the partition key in a composite PK
`(id, created_at)`, exactly as DATABASE_DESIGN.md §5 mandates ("partition-ready from day one"). A
`DEFAULT` partition catches every row so the table accepts inserts without any migration ever
assuming a specific month exists (§5); the scheduled month-ahead partition maker is later ops work.

`connection_id` / `tool_id` are plain UUID columns, **not** composite FKs. This table outlives the
operational rows it references — a soft-deleted Tool or removed Connection must never cascade-delete
or block an immutable audit record. Tenant isolation is the `workspace_id` FK (→ workspaces, CASCADE
so tenant deletion removes its own audit history) plus RLS ENABLE + FORCE + `tenant_isolation`,
identical to every other tenant table. DATABASE_DESIGN.md lists these as columns, not foreign keys.

Revision ID: 0012_tool_calls
Revises: 0011_credentials
Create Date: 2026-08-17
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0012_tool_calls"
down_revision: str | None = "0011_credentials"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "omniai_app"
WORKSPACE_GUC_SQL = "NULLIF(current_setting('app.workspace_id', true), '')::uuid"


def upgrade() -> None:
    # Preflight, re-asserted per tenant table (ADR-0008): a tenant table born while the app role
    # holds a bypass is silently unprotected for the life of the schema.
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
        "tool_calls",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        # The Connection and Tool this call resolved to. Plain UUIDs (see module docstring): an
        # immutable audit row must survive the removal of what it references.
        sa.Column("connection_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tool_id", postgresql.UUID(as_uuid=True), nullable=False),
        # Correlation id shared with structured logs and the response envelope (OBSERVABILITY §).
        sa.Column("request_id", sa.String(length=64), nullable=False),
        # {interface, api_token_id | member_id} — never a name or secret.
        sa.Column("caller", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        # Redacted/truncated argument + response *metadata* only — no raw secrets (SECURITY §2.3).
        sa.Column("input_summary", postgresql.JSONB(), nullable=False),
        sa.Column("output_summary", postgresql.JSONB(), nullable=True),
        # Stable error code (API_GUIDELINES §6.1) on a non-success row; NULL when succeeded.
        sa.Column("error_code", sa.String(length=40), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        # status is the closed set the audit log filters on (DATABASE_DESIGN.md:190).
        sa.CheckConstraint(
            "status IN ('succeeded', 'failed', 'denied', 'timeout')",
            name="ck_tool_calls_status_valid",
        ),
        # The partition key (created_at) MUST be part of every unique/primary key on a partitioned
        # table — hence the composite PK, exactly as DATABASE_DESIGN.md §5 specifies.
        sa.PrimaryKeyConstraint("id", "created_at", name="pk_tool_calls"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_tool_calls_workspace_id",
            ondelete="CASCADE",
        ),
        postgresql_partition_by="RANGE (created_at)",
    )

    # A DEFAULT partition so inserts always land somewhere. No migration ever names a specific month
    # (§5); the month-ahead maker is later ops automation and only splits rows out of DEFAULT.
    op.execute(sa.text("CREATE TABLE tool_calls_default PARTITION OF public.tool_calls DEFAULT"))

    # Log-UI index (workspace_id, created_at) and the per-connection drill-down index
    # (DATABASE_DESIGN.md:219,225). Declared on the parent → propagated to every partition. A plain
    # ascending btree serves the log's `ORDER BY created_at DESC LIMIT n` via a backward index scan,
    # so no DESC modifier is needed (and it keeps model↔DB autogenerate comparison exact).
    op.create_index(
        "ix_tool_calls_workspace_id_created_at",
        "tool_calls",
        ["workspace_id", "created_at"],
    )
    op.create_index(
        "ix_tool_calls_workspace_id_connection_id_created_at",
        "tool_calls",
        ["workspace_id", "connection_id", "created_at"],
    )

    # Append-only + immutable → SELECT and INSERT only. No UPDATE, no DELETE: an audit row is never
    # rewritten or removed in-band (DATABASE_DESIGN.md §3). Privileges on the partitioned parent
    # govern parent-routed DML, which is the only access path the app takes.
    op.execute(sa.text(f"GRANT SELECT, INSERT ON public.tool_calls TO {APP_ROLE}"))  # noqa: S608
    op.execute(sa.text("ALTER TABLE public.tool_calls ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE public.tool_calls FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(f"""
        CREATE POLICY tenant_isolation ON public.tool_calls
            USING (workspace_id = {WORKSPACE_GUC_SQL})
            WITH CHECK (workspace_id = {WORKSPACE_GUC_SQL});
    """)
    )


def downgrade() -> None:
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation ON public.tool_calls"))
    op.drop_index("ix_tool_calls_workspace_id_connection_id_created_at", table_name="tool_calls")
    op.drop_index("ix_tool_calls_workspace_id_created_at", table_name="tool_calls")
    # Dropping the partitioned parent drops its DEFAULT partition with it.
    op.drop_table("tool_calls")
