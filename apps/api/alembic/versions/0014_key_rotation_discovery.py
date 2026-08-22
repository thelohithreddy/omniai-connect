"""Key-rotation discovery and completion proof (M2.6, ADR-0039).

Adds no table and no column: M2.6's rotation state already lives in `credentials.key_version`,
which DATABASE_DESIGN §3 created for exactly this purpose. What this migration adds is the ability
to *ask questions about it across every tenant at once*, which is impossible under normal RLS.

Two SECURITY DEFINER functions, the same sanctioned carve-out as `auth.resolve_api_token` (0001)
and `auth.due_oauth_refreshes` (0013), and deliberately minimal in the same way — both return
**identifiers and counts only, never ciphertext**, so a platform-wide scan can never become a
cross-tenant secret read:

- `auth.pending_key_rotations` — the re-wrap sweep's work list. A rotation tick runs before any
  workspace is bound (there is no "current tenant" for a cron tick), so it cannot be a scoped
  query. The per-credential task that follows binds its workspace and works under normal RLS.
- `auth.count_credentials_below_key_version` — the **retirement gate**. SECURITY.md §2.1 permits
  retiring an old KEK only when nothing still depends on it, and the ratified runbook (P1) makes
  the database the sole authority for that: not a timer, not a scheduler's opinion, not a batch
  that looked successful. This function is that authority. It must return 0 before a key is
  removed from the keyring; while it returns non-zero, retiring the key destroys data.

Both read `public.credentials`, which 0013 already made visible to `omniai_auth` through the
`refresh_discovery` policy — reused rather than duplicated, since a second identical policy would
only add a name to drop. This migration therefore depends on 0013 remaining applied.

Also indexes `key_version`. The sweep's predicate is `key_version < target` across all workspaces —
a platform-level scan, so unlike every tenant query it cannot lead with `workspace_id`.

Revision ID: 0014_key_rotation_discovery
Revises: 0013_oauth_states
Create Date: 2026-08-21
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0014_key_rotation_discovery"
down_revision: str | None = "0013_oauth_states"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "omniai_app"
AUTH_ROLE = "omniai_auth"


def upgrade() -> None:
    op.create_index("ix_credentials_key_version", "credentials", ["key_version"])

    # ------------------------------------------------------- re-wrap discovery (work list)
    op.execute(
        sa.text("""
        CREATE FUNCTION auth.pending_key_rotations(p_target_version integer, p_limit integer)
        RETURNS TABLE (workspace_id uuid, credential_id uuid)
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT c.workspace_id, c.id
            FROM public.credentials c
            WHERE c.key_version < p_target_version
            ORDER BY c.key_version, c.id
            LIMIT p_limit;
        $$;
    """)
    )
    op.execute(
        sa.text(f"ALTER FUNCTION auth.pending_key_rotations(integer, integer) OWNER TO {AUTH_ROLE}")
    )
    op.execute(
        sa.text("REVOKE ALL ON FUNCTION auth.pending_key_rotations(integer, integer) FROM PUBLIC")
    )
    op.execute(
        sa.text(
            f"GRANT EXECUTE ON FUNCTION auth.pending_key_rotations(integer, integer) TO {APP_ROLE}"
        )
    )

    # ------------------------------------------------------- retirement gate (completion proof)
    op.execute(
        sa.text("""
        CREATE FUNCTION auth.count_credentials_below_key_version(p_target_version integer)
        RETURNS bigint
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT count(*)
            FROM public.credentials c
            WHERE c.key_version < p_target_version;
        $$;
    """)
    )
    op.execute(
        sa.text(
            f"ALTER FUNCTION auth.count_credentials_below_key_version(integer) OWNER TO {AUTH_ROLE}"
        )
    )
    op.execute(
        sa.text(
            "REVOKE ALL ON FUNCTION auth.count_credentials_below_key_version(integer) FROM PUBLIC"
        )
    )
    op.execute(
        sa.text(
            "GRANT EXECUTE ON FUNCTION auth.count_credentials_below_key_version(integer)"
            f" TO {APP_ROLE}"
        )
    )


def downgrade() -> None:
    # Drops only the discovery surface. Credential rows and their `key_version` are never touched:
    # a rollback of the rotation *tooling* must never alter customer key material, and a row
    # re-wrapped to version 2 stays readable as long as version 2 is in the keyring.
    op.execute(sa.text("DROP FUNCTION IF EXISTS auth.count_credentials_below_key_version(integer)"))
    op.execute(sa.text("DROP FUNCTION IF EXISTS auth.pending_key_rotations(integer, integer)"))
    op.drop_index("ix_credentials_key_version", table_name="credentials")
