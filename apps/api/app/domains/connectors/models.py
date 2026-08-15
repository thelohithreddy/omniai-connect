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

from sqlalchemy import CheckConstraint, DateTime, Index, String, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

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
    )


__all__ = ["CONNECTOR_STATUSES", "SOURCE_TYPES", "Connector"]
