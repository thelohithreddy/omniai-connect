"""API token provenance: which Member issued the token.

Revision ID: 0003_api_token_creator
Revises: 0002_members
Create Date: 2026-08-14
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0003_api_token_creator"
down_revision: str | None = "0002_members"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # `created_by_member_id` is specified in DATABASE_DESIGN.md §3 and was deliberately
    # deferred by M1.2-A, whose model comment says it lands "when tokens are wired to
    # members". Issuing a token from an authenticated membership is that moment, so this
    # is the planned additive step (P-43), not an unrelated schema change.
    op.add_column(
        "api_tokens",
        sa.Column("created_by_member_id", postgresql.UUID(as_uuid=True), nullable=True),
    )

    # Nullable, and it must stay nullable. Tokens already exist that have no creator —
    # the bootstrap script mints the first token before any Member exists, which is the
    # only way a workspace can be started today. A NOT NULL column would make that path
    # impossible and would have to be backfilled with a fabricated member.
    # Leads with workspace_id (P-44), and that ordering is also what the foreign key needs:
    # deleting a Member makes Postgres search api_tokens for rows matching
    # (workspace_id, created_by_member_id), so a composite index serves the referential
    # action directly. A single-column index would leave every member removal scanning the
    # whole table — the classic unindexed-foreign-key stall.
    op.create_index(
        "ix_api_tokens_workspace_id_created_by_member_id",
        "api_tokens",
        ["workspace_id", "created_by_member_id"],
    )

    # COMPOSITE, per the intra-tenant foreign key convention in DATABASE_DESIGN.md §1.
    # Postgres validates referential integrity with RLS bypassed, so a single-column
    # reference to members.id would let workspace A record a creator owned by workspace B
    # and no policy would ever see it. Carrying workspace_id into the key makes that
    # structurally impossible.
    #
    # `ON DELETE SET NULL (created_by_member_id)` is column-scoped (Postgres 15+): a bare
    # SET NULL would also target workspace_id, which is NOT NULL, so removing a member
    # would fail instead of orphaning their tokens. Removing a Member deliberately does
    # not revoke the tokens they issued — those are workspace-owned machine credentials,
    # and revocation is a separate, explicit operation (M1.2-H).
    op.create_foreign_key(
        "fk_api_tokens_created_by_member_id",
        "api_tokens",
        "members",
        ["workspace_id", "created_by_member_id"],
        ["workspace_id", "id"],
        ondelete="SET NULL (created_by_member_id)",
    )


def downgrade() -> None:
    op.drop_constraint("fk_api_tokens_created_by_member_id", "api_tokens", type_="foreignkey")
    op.drop_index("ix_api_tokens_workspace_id_created_by_member_id", table_name="api_tokens")
    op.drop_column("api_tokens", "created_by_member_id")
