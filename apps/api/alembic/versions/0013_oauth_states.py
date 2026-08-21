"""oauth_states: single-use, tenant-bound authorization-code flow state (M2.5, ADR-0038).

The row is the **sole authority** for a callback's identity: the provider redirect carries only
`code` + `state`, both attacker-influencable, so workspace/connection are read from here and never
from the request (SECURITY §3, and the same "payload is not authority" rule as ADR-0022).

Two secrets-handling choices are load-bearing:

- **`state` is stored hashed** (SHA-256), never raw — the row is a *verifier*, so a database read
  cannot forge a callback, exactly as `api_tokens` stores only a token hash.
- **The PKCE `code_verifier` is stored sealed** by the existing credential vault (AES-256-GCM,
  AAD = workspace‖connection). It cannot be hashed because the token exchange must *present* it
  (RFC 7636 §4.5), so it is encrypted with the same envelope the Credential uses — no second
  crypto path.

`connector_id` is deliberately absent: the Connection already carries it, and a denormalized copy
could drift from the authority. RLS ENABLE + FORCE + `tenant_isolation`, composite intra-tenant FK,
least-privilege grants, and an `expires_at` index for the sweep — matching every tenant table.

Revision ID: 0013_oauth_states
Revises: 0012_tool_calls
Create Date: 2026-08-21
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0013_oauth_states"
down_revision: str | None = "0012_tool_calls"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "omniai_app"
AUTH_ROLE = "omniai_auth"
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
        "oauth_states",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("connection_id", postgresql.UUID(as_uuid=True), nullable=False),
        # SHA-256 hex of the opaque `state` the client returns. Never the raw value.
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        # The PKCE code_verifier, sealed with the credential vault's envelope (AAD ws‖conn).
        sa.Column("verifier_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("verifier_encrypted_dek", sa.LargeBinary(), nullable=False),
        sa.Column("verifier_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        # The exact redirect_uri sent to the provider; replayed verbatim at exchange (RFC 6749
        # §4.1.3 requires the token request to repeat it) and never taken from the callback.
        sa.Column("redirect_uri", sa.Text(), nullable=False),
        # The scope set requested, recorded for audit/debug. Non-secret.
        sa.Column(
            "scopes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        # Set exactly once by the atomic consume; a second callback finds it non-NULL and loses.
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_oauth_states"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_oauth_states_workspace_id",
            ondelete="CASCADE",
        ),
        # A state binds a connection in the same workspace (composite intra-tenant FK): a row can
        # never reference another tenant's connection, and revoking the connection sweeps its
        # in-flight states.
        sa.ForeignKeyConstraint(
            ["workspace_id", "connection_id"],
            ["connections.workspace_id", "connections.id"],
            name="fk_oauth_states_connection_id",
            ondelete="CASCADE",
        ),
        # Global uniqueness of the state hash: two flows can never collide, and the callback's
        # lookup is exact. Deliberately NOT scoped by workspace — the callback has no tenant
        # context before the row is found.
        sa.UniqueConstraint("state_hash", name="uq_oauth_states_state_hash"),
    )

    # The WorkspaceScopedMixin's per-tenant index (every tenant table carries it, P-41).
    op.create_index("ix_oauth_states_workspace_id", "oauth_states", ["workspace_id"])
    # Drives the expiry sweep (and keeps it index-backed as the table grows).
    op.create_index("ix_oauth_states_expires_at", "oauth_states", ["expires_at"])

    # Create (authorize) + read/consume (callback) + sweep expired rows → no UPDATE of history
    # beyond the one-time consume, which is an UPDATE; DELETE is the TTL sweep.
    op.execute(
        sa.text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON public.oauth_states TO {APP_ROLE}")  # noqa: S608
    )
    op.execute(sa.text("ALTER TABLE public.oauth_states ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE public.oauth_states FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(f"""
        CREATE POLICY tenant_isolation ON public.oauth_states
            USING (workspace_id = {WORKSPACE_GUC_SQL})
            WITH CHECK (workspace_id = {WORKSPACE_GUC_SQL});
    """)
    )

    # ------------------------------------------- state consumption (the callback exemption)
    #
    # The same bootstrap paradox M1 solved for bearer tokens (0001, `auth.resolve_api_token`):
    # a provider redirect arrives with no tenant context, and consuming the state row is what
    # *discovers* the workspace — so the consume cannot run under a policy that already needs
    # it. Rather than weaken `tenant_isolation` with an "or the GUC is NULL" escape hatch —
    # which would disable isolation for every unbound query — this reuses the identical,
    # narrowly-scoped carve-out: a policy targeted at AUTH_ROLE alone plus a SECURITY DEFINER
    # function owned by AUTH_ROLE. No BYPASSRLS (superuser-only, unavailable on managed PG).
    #
    # The function body is the atomic consume itself: one `UPDATE … WHERE consumed_at IS NULL
    # AND expires_at > now() RETURNING`, so replay and expiry are "zero rows" and two concurrent
    # callbacks produce exactly one winner. `SET search_path` is load-bearing — without it a
    # caller controlling search_path could shadow `public.oauth_states` and have a function
    # running as another role operate on their table (the classic definer escalation).
    op.execute(sa.text(f"GRANT SELECT, UPDATE ON public.oauth_states TO {AUTH_ROLE}"))
    op.execute(
        sa.text(f"""
        CREATE POLICY state_consumption ON public.oauth_states
            FOR ALL TO {AUTH_ROLE}
            USING (true)
            WITH CHECK (true);
    """)
    )
    op.execute(
        sa.text("""
        CREATE FUNCTION auth.consume_oauth_state(p_state_hash text)
        RETURNS TABLE (
            state_id uuid,
            workspace_id uuid,
            connection_id uuid,
            redirect_uri text,
            verifier_ciphertext bytea,
            verifier_encrypted_dek bytea,
            verifier_nonce bytea,
            key_version integer
        )
        LANGUAGE sql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            UPDATE public.oauth_states s
               SET consumed_at = now()
             WHERE s.state_hash = p_state_hash
               AND s.consumed_at IS NULL
               AND s.expires_at > now()
            RETURNING s.id, s.workspace_id, s.connection_id, s.redirect_uri,
                      s.verifier_ciphertext, s.verifier_encrypted_dek,
                      s.verifier_nonce, s.key_version;
        $$;
    """)
    )
    op.execute(sa.text(f"ALTER FUNCTION auth.consume_oauth_state(text) OWNER TO {AUTH_ROLE}"))
    # SECURITY DEFINER functions are EXECUTE-able by PUBLIC by default. Revoke, then grant to
    # exactly one role.
    op.execute(sa.text("REVOKE ALL ON FUNCTION auth.consume_oauth_state(text) FROM PUBLIC"))
    op.execute(sa.text(f"GRANT EXECUTE ON FUNCTION auth.consume_oauth_state(text) TO {APP_ROLE}"))

    # ------------------------------------------- refresh discovery (the scheduler exemption)
    #
    # The refresh sweep is a platform-level job: it must see every tenant's due credentials to
    # schedule them, but it runs before any workspace is bound (there is no "current tenant" for
    # a cron tick). Same carve-out, same reasoning as above — and deliberately minimal: the
    # function returns **identifiers only**, never ciphertext, so the scan cannot become a
    # cross-tenant secret read. The per-credential task that follows binds its workspace and
    # does its work under normal RLS.
    op.execute(sa.text(f"GRANT SELECT ON public.credentials TO {AUTH_ROLE}"))
    op.execute(sa.text(f"GRANT SELECT ON public.connections TO {AUTH_ROLE}"))
    op.execute(
        sa.text(f"""
        CREATE POLICY refresh_discovery ON public.credentials
            FOR SELECT TO {AUTH_ROLE}
            USING (true);
    """)
    )
    op.execute(
        sa.text(f"""
        CREATE POLICY refresh_discovery ON public.connections
            FOR SELECT TO {AUTH_ROLE}
            USING (true);
    """)
    )
    op.execute(
        sa.text("""
        CREATE FUNCTION auth.due_oauth_refreshes(p_within_seconds integer, p_limit integer)
        RETURNS TABLE (workspace_id uuid, connection_id uuid)
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT c.workspace_id, c.connection_id
            FROM public.credentials c
            JOIN public.connections n
              ON n.id = c.connection_id AND n.workspace_id = c.workspace_id
            WHERE c.credential_type = 'oauth2'
              AND c.expires_at IS NOT NULL
              AND c.expires_at < now() + make_interval(secs => p_within_seconds)
              AND n.status = 'active'
              AND n.deleted_at IS NULL
            ORDER BY c.expires_at
            LIMIT p_limit;
        $$;
    """)
    )
    op.execute(
        sa.text(f"ALTER FUNCTION auth.due_oauth_refreshes(integer, integer) OWNER TO {AUTH_ROLE}")
    )
    op.execute(
        sa.text("REVOKE ALL ON FUNCTION auth.due_oauth_refreshes(integer, integer) FROM PUBLIC")
    )
    op.execute(
        sa.text(
            f"GRANT EXECUTE ON FUNCTION auth.due_oauth_refreshes(integer, integer) TO {APP_ROLE}"
        )
    )


def downgrade() -> None:
    op.execute(sa.text("DROP FUNCTION IF EXISTS auth.due_oauth_refreshes(integer, integer)"))
    op.execute(sa.text("DROP POLICY IF EXISTS refresh_discovery ON public.connections"))
    op.execute(sa.text("DROP POLICY IF EXISTS refresh_discovery ON public.credentials"))
    op.execute(sa.text("DROP FUNCTION IF EXISTS auth.consume_oauth_state(text)"))
    op.execute(sa.text("DROP POLICY IF EXISTS state_consumption ON public.oauth_states"))
    # Drops only M2.5's own table. Credentials and connections are never touched by an OAuth
    # rollback — a rollback must never destroy customer credentials (ADR-0038).
    op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation ON public.oauth_states"))
    op.drop_index("ix_oauth_states_expires_at", table_name="oauth_states")
    op.drop_index("ix_oauth_states_workspace_id", table_name="oauth_states")
    op.drop_table("oauth_states")
