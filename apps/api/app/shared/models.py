"""SQLAlchemy declarative base and the mixins every table inherits.

`WorkspaceScopedMixin` is the schema-level half of tenant isolation (P-41): a table that
uses it cannot exist without `workspace_id NOT NULL`. The other halves are the repository
layer (which cannot construct a query without a WorkspaceContext) and Postgres RLS.
Three independent layers, because a single missed `WHERE` is a company-ending bug.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, MetaData, func
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.core.ids import new_id

# Deterministic constraint names (DATABASE_DESIGN.md §1). Without this, Postgres invents
# names, autogenerate produces different DDL on every run, and `downgrade()` cannot drop
# a constraint it can't name.
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class UUIDPrimaryKeyMixin:
    """UUIDv7 primary key, generated application-side (DATABASE_DESIGN.md §1)."""

    id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=new_id
    )


class TimestampMixin:
    """`created_at` / `updated_at`, always timestamptz, always UTC.

    Defaults are server-side so a row written by a migration or by psql still gets them;
    `onupdate` is client-side because Postgres has no native ON UPDATE trigger without
    writing one.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class WorkspaceScopedMixin:
    """Every tenant-owned table carries this. No exceptions (P-41)."""

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
