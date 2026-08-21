"""Data access for the OAuth flow (M2.5, ADR-0038) — the only layer that touches the DB.

Two access patterns with deliberately different tenancy:

- **Authorize** runs inside an authenticated, workspace-bound transaction, so `OAuthStateRepository`
  takes a `WorkspaceContext` and scopes every statement explicitly (P-14), exactly like every
  other repository.
- **Callback** is unauthenticated by necessity — the provider redirects a browser to us with only
  `code` + `state`. There is no tenant context *until the row is found*, so the consume runs
  through a dedicated admin-scoped path (`consume_state`) that resolves the row by state hash
  alone and returns the workspace it belongs to. That is the one place tenancy is *derived* from
  data rather than asserted, which is precisely why the state is unguessable, single-use, and
  short-lived: the row **is** the credential for that request.

The consume is a single atomic `UPDATE … WHERE consumed_at IS NULL AND expires_at > now()
RETURNING` — one statement, so two concurrent callbacks with the same state produce exactly one
winner; replay, expiry, and unknown state are all "zero rows", indistinguishable to the caller.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import WorkspaceContext
from app.domains.oauth.models import OAuthState


@dataclass(frozen=True, slots=True)
class ConsumedState:
    """The identity and flow material of a state row this request just claimed. Constructed only
    from a successful atomic consume — never from request input."""

    id: uuid.UUID
    workspace_id: uuid.UUID
    connection_id: uuid.UUID
    redirect_uri: str
    verifier_ciphertext: bytes
    verifier_encrypted_dek: bytes
    verifier_nonce: bytes
    key_version: int


class OAuthStateRepository:
    """Workspace-scoped writes for the authorize half of the flow."""

    def __init__(self, session: AsyncSession, ctx: WorkspaceContext) -> None:
        self._session = session
        self._ctx = ctx

    async def create(
        self,
        *,
        connection_id: uuid.UUID,
        state_hash: str,
        verifier_ciphertext: bytes,
        verifier_encrypted_dek: bytes,
        verifier_nonce: bytes,
        key_version: int,
        redirect_uri: str,
        scopes: list[str],
        expires_at: datetime,
    ) -> OAuthState:
        """Persist one in-flight flow. `workspace_id` is server-set from the bound context."""
        row = OAuthState(
            workspace_id=self._ctx.workspace_id,
            connection_id=connection_id,
            state_hash=state_hash,
            verifier_ciphertext=verifier_ciphertext,
            verifier_encrypted_dek=verifier_encrypted_dek,
            verifier_nonce=verifier_nonce,
            key_version=key_version,
            redirect_uri=redirect_uri,
            scopes=scopes,
            expires_at=expires_at,
        )
        self._session.add(row)
        await self._session.flush()
        return row

    async def delete_expired(self) -> int:
        """TTL sweep for this workspace (Postgres has no row TTL). Returns rows removed."""
        result = await self._session.execute(
            delete(OAuthState).where(
                OAuthState.workspace_id == self._ctx.workspace_id,
                OAuthState.expires_at < func.now(),
            )
        )
        # `rowcount` is defined on the DML cursor result; the base `Result` protocol does not
        # declare it, so it is read defensively rather than asserted.
        return int(getattr(result, "rowcount", 0) or 0)


async def consume_state(session: AsyncSession, state_hash: str) -> ConsumedState | None:
    """Atomically claim the unconsumed, unexpired state row for `state_hash`, or return None.

    Deliberately **not** workspace-scoped: the callback has no tenant context until this returns
    (see the module docstring). Safety comes from the statement itself — a single conditional
    UPDATE that can succeed at most once per row, so replay, expiry, and a forged/unknown state
    are all indistinguishable "no row" outcomes to the caller.

    RLS is FORCE'd on `oauth_states` and the callback has no bound workspace, so the consume runs
    through `auth.consume_oauth_state` — the same narrowly-scoped SECURITY DEFINER carve-out M1
    established for bearer-token resolution (migration 0001), never a weakened policy and never
    BYPASSRLS. The atomic UPDATE lives inside that function, so atomicity is a property of the
    database, not of this call site.
    """
    row = (
        await session.execute(
            text(
                "SELECT state_id, workspace_id, connection_id, redirect_uri,"
                " verifier_ciphertext, verifier_encrypted_dek, verifier_nonce, key_version"
                " FROM auth.consume_oauth_state(:state_hash)"
            ),
            {"state_hash": state_hash},
        )
    ).first()
    if row is None:
        return None
    return ConsumedState(
        id=row.state_id,
        workspace_id=row.workspace_id,
        connection_id=row.connection_id,
        redirect_uri=row.redirect_uri,
        verifier_ciphertext=row.verifier_ciphertext,
        verifier_encrypted_dek=row.verifier_encrypted_dek,
        verifier_nonce=row.verifier_nonce,
        key_version=row.key_version,
    )


async def state_exists(session: AsyncSession, state_hash: str) -> bool:
    """Whether any row (consumed or not) carries this hash — diagnostics only, never authority."""
    found = await session.scalar(select(OAuthState.id).where(OAuthState.state_hash == state_hash))
    return found is not None


__all__ = ["ConsumedState", "OAuthStateRepository", "consume_state", "state_exists"]
