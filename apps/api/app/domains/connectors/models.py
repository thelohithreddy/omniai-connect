"""SQLAlchemy model for the connectors domain (M1.4-A, ADR-0003).

A Connector is a tenant-owned *definition* of an external API — its base URL, auth
requirements, and (once ingested) its canonical Tool Schema. It carries no secrets:
`auth_config` declares *requirements* (a key's name and location, a scheme), while the
secret value lives in a Connection's Credential, decrypted only inside the runtime.
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
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

# These tables carry composite FKs to `workspaces`; importing the model registers that table in
# the shared MetaData so the FK resolves at mapper-configure time even in a process (the Celery
# worker) that imports the connectors ORM without going through `app.main`. Import-only.
from app.domains.workspaces import models as _workspaces_models  # noqa: F401
from app.shared.models import Base, TimestampMixin, UUIDPrimaryKeyMixin, WorkspaceScopedMixin

# Canonical domains from DATABASE_DESIGN.md §3 (the schema authority).
SOURCE_TYPES = ("openapi3", "swagger2", "graphql", "manual")
CONNECTOR_STATUSES = ("draft", "ingesting", "active", "failed")


class Connector(UUIDPrimaryKeyMixin, WorkspaceScopedMixin, TimestampMixin, Base):
    """A workspace's definition of an external API (Bible §4, CONNECTOR_ENGINE.md)."""

    __tablename__ = "connectors"

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    # Unique per workspace among LIVE rows only (partial index below) — a soft-deleted
    # connector's slug can be reused.
    slug: Mapped[str] = mapped_column(String(64), nullable=False)
    # How the definition was produced. M1.4-A creates only 'manual'; the ingestion source
    # types arrive with the OpenAPI/Swagger importer.
    source_type: Mapped[str] = mapped_column(String(20), nullable=False)
    # The ingested spec's origin. NULL for manual connectors; set by ingestion.
    source_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    # The external API base URL. SSRF-linted by the service before insert.
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    # Auth REQUIREMENTS, never secret values (CONNECTOR_ENGINE.md §8).
    auth_config: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default=text("'draft'"))
    # FK to connector_versions once that table exists (later slice); bare nullable UUID now.
    current_version_id: Mapped[UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True), nullable=True
    )
    # Soft delete (DATABASE_DESIGN.md §3): retained with `deleted_at` set.
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "source_type IN ('openapi3', 'swagger2', 'graphql', 'manual')",
            name="source_type_valid",
        ),
        CheckConstraint(
            "status IN ('draft', 'ingesting', 'active', 'failed')", name="status_valid"
        ),
        # Keyset pagination (created_at DESC, id DESC). `created_at DESC` spelled out to match
        # the migration exactly, or autogenerate proposes dropping/recreating it every run.
        Index(
            "ix_connectors_workspace_id_created_at",
            "workspace_id",
            text("created_at DESC"),
        ),
        # One LIVE connector per (workspace, slug). Partial on `deleted_at IS NULL` so a
        # deleted slug frees up; must match the migration's partial index exactly.
        Index(
            "uq_connectors_workspace_id_slug",
            "workspace_id",
            "slug",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        # Composite-FK target for connector_versions (workspace_id, connector_id) — a version can
        # only reference a connector in the same workspace (DATABASE_DESIGN.md §1, M1.4-B1.1).
        UniqueConstraint("workspace_id", "id", name="uq_connectors_workspace_id_id"),
        # The current-version pointer, now an additive composite intra-tenant FK (P-43). `use_alter`
        # because connectors ↔ connector_versions reference each other — the FK is added after both
        # tables exist (migration 0008). SET NULL: a dropped version clears the pointer.
        ForeignKeyConstraint(
            ["workspace_id", "current_version_id"],
            ["connector_versions.workspace_id", "connector_versions.id"],
            name="fk_connectors_current_version_id",
            ondelete="SET NULL",
            use_alter=True,
        ),
    )


class ConnectorVersion(UUIDPrimaryKeyMixin, WorkspaceScopedMixin, Base):
    """An immutable snapshot of a Connector's ingested definition (DATABASE_DESIGN.md §5,
    CONNECTOR_SPECIFICATION.md §3). Never updated or deleted — `created_at` only. Holds the
    canonical Tool Schema set, the dedup hash, and the R2 reference to the original document."""

    __tablename__ = "connector_versions"

    connector_id: Mapped[UUID] = mapped_column(postgresql.UUID(as_uuid=True), nullable=False)
    # Monotonic integer per connector.
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    # SHA-256 hex over the canonical JSON of the ordered normalized Tool set (§3).
    spec_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # R2 object key of the original document (B0.5); NULL for non-fetched sources.
    raw_spec_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # The canonical Tool Schema set (CONNECTOR_SPECIFICATION.md §2).
    normalized_schema: Mapped[Any] = mapped_column(JSONB, nullable=False)
    # added/removed/changed vs. the previous version — computed by a later slice; NULL now.
    diff_summary: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "connector_id", "version", name="uq_connector_versions_connector_id_version"
        ),
        # Composite-FK target for connectors.current_version_id.
        UniqueConstraint("workspace_id", "id", name="uq_connector_versions_workspace_id_id"),
        # A version belongs to a connector in the same workspace (composite intra-tenant FK).
        ForeignKeyConstraint(
            ["workspace_id", "connector_id"],
            ["connectors.workspace_id", "connectors.id"],
            name="fk_connector_versions_connector_id",
            ondelete="CASCADE",
        ),
    )


__all__ = ["CONNECTOR_STATUSES", "SOURCE_TYPES", "Connector", "ConnectorVersion"]
