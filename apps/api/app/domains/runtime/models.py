"""The `tool_calls` ORM row — the append-only, immutable audit of every Tool Call.

Written once, at pipeline stage 7 (AI_RUNTIME.md §2), and never updated or deleted in-band
(DATABASE_DESIGN.md §3): there is no `updated_at`, and the app role holds only SELECT + INSERT.

This is the one **partitioned** table (`PARTITION BY RANGE (created_at)`), so its primary key is the
composite `(id, created_at)` the partition key requires. That is incompatible with
`UUIDPrimaryKeyMixin` (single-column PK) and `TimestampMixin` (which also adds `updated_at`), so
`id` and `created_at` are declared here directly. It is likewise **not** `WorkspaceScopedMixin`: the
mixin's standalone `workspace_id` index would be redundant with the two composite indexes below
(both lead with `workspace_id`), and the canonical schema (DATABASE_DESIGN.md §5) names only those
two. The schema-level tenant guarantee is preserved explicitly — `workspace_id NOT NULL`, FK to
`workspaces` (CASCADE), RLS ENABLE + FORCE + `tenant_isolation` (migration 0012) — alongside the
repository layer's mandatory scoping. All three halves of tenant isolation (P-41) still hold.

`connection_id` and `tool_id` are plain UUID columns, not composite FKs: an immutable audit row must
outlive the soft-deletion of its Tool or the removal of its Connection. Referential coupling to
mutable operational tables would either cascade-delete audit history or block operational deletes —
DATABASE_DESIGN.md lists them as columns, not foreign keys.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    PrimaryKeyConstraint,
    String,
    func,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import new_id
from app.shared.models import Base

#: The closed set of terminal outcomes an audit row can record (DATABASE_DESIGN.md:190,
#: AI_RUNTIME.md §1). `pending` is async-only (deferred) and never persisted by the M1 sync path.
TOOL_CALL_STATUSES = ("succeeded", "failed", "denied", "timeout")


class ToolCall(Base):
    """One immutable audit row per Tool Call. Redacted metadata only — never a secret."""

    __tablename__ = "tool_calls"

    id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), default=new_id, nullable=False
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(postgresql.UUID(as_uuid=True), nullable=False)
    connection_id: Mapped[uuid.UUID] = mapped_column(postgresql.UUID(as_uuid=True), nullable=False)
    tool_id: Mapped[uuid.UUID] = mapped_column(postgresql.UUID(as_uuid=True), nullable=False)
    #: Correlation id shared with structured logs and the response envelope.
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    #: {interface, api_token_id | member_id} — identity, never a name or secret.
    caller: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    #: Redacted/truncated argument metadata. Never raw secrets (SECURITY.md §2.3).
    input_summary: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    #: Truncated response metadata; NULL when the call never produced one.
    output_summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    #: Stable error code (API_GUIDELINES.md §6.1) on a non-success row; NULL when succeeded.
    error_code: Mapped[str | None] = mapped_column(String(40), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('succeeded', 'failed', 'denied', 'timeout')",
            name="ck_tool_calls_status_valid",
        ),
        # Composite PK — the partition key (created_at) must be part of it.
        PrimaryKeyConstraint("id", "created_at", name="pk_tool_calls"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_tool_calls_workspace_id",
            ondelete="CASCADE",
        ),
        Index("ix_tool_calls_workspace_id_created_at", "workspace_id", "created_at"),
        Index(
            "ix_tool_calls_workspace_id_connection_id_created_at",
            "workspace_id",
            "connection_id",
            "created_at",
        ),
        {"postgresql_partition_by": "RANGE (created_at)"},
    )


__all__ = ["TOOL_CALL_STATUSES", "ToolCall"]
