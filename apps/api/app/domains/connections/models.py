"""SQLAlchemy model for the connections domain (M1-Connections-v1, ADR-0029).

A Connection is a tenant-owned binding of a Connector to a Workspace (Bible §4): its lifecycle
state and non-secret `config_overrides`. It carries **no secret** — the radioactive part lives in a
Credential (a later module); `credential_id` is a bare nullable placeholder here, with the composite
FK added additively when the `credentials` table lands.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

# These tables carry composite FKs to `workspaces`/`connectors`, and the additive `credential_id`
# FK to `credentials`; importing the models registers those tables in the shared MetaData so the FKs
# resolve at mapper-configure time. `credentials` is a module-style import so the connections↔
# credentials FK cycle loads cleanly (M1-Credentials-v1). Import-only.
import app.domains.credentials.models  # noqa: F401
from app.domains.connectors import models as _connectors_models  # noqa: F401
from app.shared.models import Base, TimestampMixin, UUIDPrimaryKeyMixin, WorkspaceScopedMixin

# Canonical lifecycle domain from DATABASE_DESIGN.md §3.
CONNECTION_STATUSES = ("pending_auth", "active", "error", "revoked")


class Connection(UUIDPrimaryKeyMixin, WorkspaceScopedMixin, TimestampMixin, Base):
    """A workspace's authenticated instance of a Connector (Bible §4, DATABASE_DESIGN.md §3)."""

    __tablename__ = "connections"

    connector_id: Mapped[UUID] = mapped_column(postgresql.UUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    # Lifecycle; server-controlled — a client never sets or transitions this directly.
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default=text("'pending_auth'")
    )
    # Placeholder for the Credentials module (no FK yet — the target table does not exist).
    credential_id: Mapped[UUID | None] = mapped_column(postgresql.UUID(as_uuid=True), nullable=True)
    # Non-secret per-connection config; NEVER an authority surface (tenant/role/status are never
    # read from here). A `base_url` override is SSRF-linted by the service before it is stored.
    config_overrides: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    last_health_check_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Soft delete = revoke (§3): retained with `deleted_at` set; the name frees for reuse.
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending_auth', 'active', 'error', 'revoked')", name="status_valid"
        ),
        # The WorkspaceScopedMixin index plus a list-by-connector path (P-44).
        Index("ix_connections_workspace_id_connector_id", "workspace_id", "connector_id"),
        # One LIVE connection per (workspace, name); partial so a revoked name frees up.
        Index(
            "uq_connections_workspace_id_name",
            "workspace_id",
            "name",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        # Composite-FK target for the future credentials/tool_calls (workspace_id, connection_id).
        UniqueConstraint("workspace_id", "id", name="uq_connections_workspace_id_id"),
        # A connection can only bind a connector in the same workspace (composite intra-tenant FK).
        ForeignKeyConstraint(
            ["workspace_id", "connector_id"],
            ["connectors.workspace_id", "connectors.id"],
            name="fk_connections_connector_id",
            ondelete="CASCADE",
        ),
        # The additive credential pointer (M1-Credentials-v1, P-43): a connection references its
        # Credential in the SAME workspace. `use_alter` because connections ↔ credentials reference
        # each other — the FK is added after both tables exist (migration 0011). NO ACTION (no
        # composite SET NULL, which would also null the NOT NULL workspace_id): the credentials
        # service clears `credential_id` before deleting the credential row.
        ForeignKeyConstraint(
            ["workspace_id", "credential_id"],
            ["credentials.workspace_id", "credentials.id"],
            name="fk_connections_credential_id",
            use_alter=True,
        ),
    )


__all__ = ["CONNECTION_STATUSES", "Connection"]
