"""Workspace notification destination (M2.10, ROADMAP §58; ADR-0042).

Architecture ratified in ADR-0041 (owner decision gate); ADR-0042 records this implementation.

One nullable column and nothing else. ROADMAP §58 asks for Connection Health *failure
notifications*, and notifying anyone requires an address the API is allowed to know. Member email
addresses live in `identity.user`, which ADR-0014 keeps unreachable from `omniai_app` —
symmetrically and on purpose — so the ratified design does not reach for them. It reuses the pattern
ADR-0017 already established for invitations: **a human supplies an address and it is stored in
`public`.** `invitations.invited_email` has done exactly that since M1.3-F; this is the same idea at
workspace scope.

Deliberate properties:

- **Nullable, no default.** A Workspace that has never configured a destination simply does not
  notify. A default would either invent an address or make "unconfigured" indistinguishable from
  "deliberately empty", and notification is opt-in.
- **`VARCHAR(320)`** — byte-identical to `invitations.invited_email`, because it holds the same kind
  of value and a second, differently-bounded email column would be a contradiction waiting to be
  discovered.
- **No foreign key, anywhere.** In particular none into `identity`: ADR-0014 clause 1 keeps rollback
  safety structural by ensuring no Alembic migration mentions that schema, and this one does not.
  The column is a plain string the workspace's owner typed, not a reference to an identity row.
- **No new policy.** `workspaces` already carries `tenant_isolation` (0001) with RLS enabled and
  forced, so the column inherits tenant protection without this migration touching RLS at all.

Downgrade drops the column and only the column. That loses configured destinations — they are
user-entered configuration, not derived state, so nothing can reconstruct them — but it destroys no
Connection, Credential, or audit data, and the feature degrades to "no notifications" rather than to
an error.

Revision ID: 0015_notification_destination
Revises: 0014_key_rotation_discovery
Create Date: 2026-08-22
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0015_notification_destination"
down_revision: str | None = "0014_key_rotation_discovery"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "workspaces",
        sa.Column("notification_email", sa.String(length=320), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("workspaces", "notification_email")
