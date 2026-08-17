"""credentials: envelope-encrypted secret bound 1:1 to a Connection (M1-Credentials-v1, ADR-0030).

The radioactive table. Each row stores only ciphertext material — `ciphertext`, `encrypted_dek`
(the per-Credential DEK wrapped by the env master KEK), `nonce`, `key_version` — never plaintext
(SECURITY §2, DATABASE_DESIGN §3). Decryption happens only inside the Execution Runtime; **no soft
delete** — revocation deletes the row, so grants include DELETE (the one table that gets it).

Two composite intra-tenant FKs close the connections↔credentials cycle (P-43): a credential binds a
connection in the same workspace, and this migration additively wires the pointer
`connections.(workspace_id, credential_id) → credentials(workspace_id, id)` that Connections v1 left
open (ON DELETE SET NULL). RLS ENABLE + FORCE + `tenant_isolation`, matching every tenant table.

Revision ID: 0011_credentials
Revises: 0010_connections
Create Date: 2026-08-17
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0011_credentials"
down_revision: str | None = "0010_connections"
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
        "credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("connection_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("credential_type", sa.String(length=20), nullable=False),
        # AES-256-GCM ciphertext (+tag) of the secret; the DEK wrapped by the master KEK; the nonce.
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("encrypted_dek", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        # OAuth token expiry (M2 refresh worker); NULL for api_key/bearer/basic.
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        # Set when the secret is re-sealed (rotation); NULL on first attach.
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
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
        # The DB admits all six canonical types for forward compatibility; M1 app flows use three.
        sa.CheckConstraint(
            "credential_type IN ('api_key', 'bearer', 'basic', 'jwt', 'oauth2', 'custom_headers')",
            name="credential_type_valid",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_credentials"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_credentials_workspace_id",
            ondelete="CASCADE",
        ),
        # A credential binds a connection in the same workspace (composite intra-tenant FK).
        sa.ForeignKeyConstraint(
            ["workspace_id", "connection_id"],
            ["connections.workspace_id", "connections.id"],
            name="fk_credentials_connection_id",
            ondelete="CASCADE",
        ),
        # 1:1 — a connection has at most one credential.
        sa.UniqueConstraint("connection_id", name="uq_credentials_connection_id"),
        # Composite-FK target for connections.credential_id.
        sa.UniqueConstraint("workspace_id", "id", name="uq_credentials_workspace_id_id"),
    )

    # The WorkspaceScopedMixin's per-tenant index (every tenant table carries it, P-41).
    op.create_index("ix_credentials_workspace_id", "credentials", ["workspace_id"])

    # Mutable lifecycle + revocation → SELECT/INSERT/UPDATE/DELETE (the one table with DELETE:
    # revocation destroys the row, DATABASE_DESIGN §3).
    op.execute(
        sa.text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON public.credentials TO {APP_ROLE}")  # noqa: S608
    )
    op.execute(sa.text("ALTER TABLE public.credentials ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE public.credentials FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(f"""
        CREATE POLICY tenant_isolation ON public.credentials
            USING (workspace_id = {WORKSPACE_GUC_SQL})
            WITH CHECK (workspace_id = {WORKSPACE_GUC_SQL});
    """)
    )

    # The additive pointer FK Connections v1 left open (P-43): a connection points at its credential
    # in the same workspace. NO ACTION (the default): a composite `SET NULL` would also null the
    # NOT NULL `workspace_id`, so the service clears `credential_id` *before* deleting the row
    # (the pointer is gone before the row is removed); the check is deferred to statement end, which
    # also holds under a workspace cascade (connection + credential both go).
    op.create_foreign_key(
        "fk_connections_credential_id",
        "connections",
        "credentials",
        ["workspace_id", "credential_id"],
        ["workspace_id", "id"],
    )


def downgrade() -> None:
    op.drop_constraint("fk_connections_credential_id", "connections", type_="foreignkey")
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation ON public.credentials"))
    op.drop_index("ix_credentials_workspace_id", table_name="credentials")
    op.drop_table("credentials")
