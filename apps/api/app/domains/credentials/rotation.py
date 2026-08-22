"""KEK rotation — re-wrapping data keys behind a stable interface (M2.6, ADR-0039).

Implements the ratified runbook (SECURITY.md §2.1): **INTRODUCE → RE-WRAP → PROVE COMPLETION →
OVERLAP → RETIRE**. This module owns the middle three; introduction and retirement are operator
key-material changes, and the whole point of the design is that they are the *only* manual steps.

What rotation does, precisely: unwrap each Credential's DEK under the version that wrapped it and
re-wrap it under the target version. **The credential payload is never decrypted.** `ciphertext`
and `nonce` come out byte-identical (`vault.rewrap` enforces this); only `encrypted_dek` and
`key_version` change. That is what makes it safe for a background worker to run at scale over
material it has no business reading, and why an interrupted rotation can never corrupt a secret —
the worst case is a row still at the old version, which the next sweep picks up.

**The database is the sole authority for completion.** `count_pending` is the retirement gate, and
it is a `COUNT(key_version < target)`, not a timer, not the scheduler's opinion, and not "the batch
looked successful". A key may be removed from the keyring only while that count is 0 and the
ratified overlap has elapsed; retiring earlier makes every straggling row permanently unreadable.
`VaultKeyVersionError` exists so that failure is loud and distinguishable from tampering.
"""

from __future__ import annotations

import uuid
from enum import StrEnum

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import UnitOfWork
from app.core.security import CallerIdentity, WorkspaceContext
from app.domains.credentials import vault
from app.domains.credentials.repository import CredentialRepository

log = structlog.get_logger(__name__)


def _context(workspace_id: uuid.UUID) -> WorkspaceContext:
    """The rotation worker acts as the platform, not as a member or a token holder."""
    return WorkspaceContext(
        workspace_id=workspace_id,
        caller=CallerIdentity(kind="api_token", api_token_id=None),
        request_id="vault_rotation",
    )


class RewrapOutcome(StrEnum):
    """Why one credential's re-wrap ended the way it did — the vocabulary the worker reports."""

    REWRAPPED = "rewrapped"
    #: Already at (or above) the target. A retried task, or a credential re-sealed by an
    #: ordinary rotate/refresh mid-sweep — harmless, and why re-wrap is idempotent.
    ALREADY_CURRENT = "already_current"
    #: The row vanished between discovery and execution (revoked, or its Connection deleted).
    GONE = "gone"
    #: The version that wrapped this DEK is no longer in the keyring — a key was retired too early.
    #: Operator action, not a retry: restore the key. Never silently skipped.
    KEY_UNAVAILABLE = "key_unavailable"


async def rewrap_credential(
    uow: UnitOfWork, *, workspace_id: uuid.UUID, credential_id: uuid.UUID, to_version: int
) -> RewrapOutcome:
    """Re-wrap one Credential's DEK under `to_version`, under a row lock.

    Locked for the same reason the OAuth refresh path locks: an attach, rotate, or token refresh
    running concurrently re-seals the row with a **fresh** DEK at the active version. Without the
    lock this sweep could read that row, re-wrap the DEK it saw, and write back a stale
    `encrypted_dek` — silently orphaning the newly sealed ciphertext. The version is re-checked
    inside the lock so a row that was updated between discovery and execution is left alone.
    """
    repository = CredentialRepository(uow.session, _context(workspace_id))
    credential = await repository.credential_for_update(credential_id)
    if credential is None:
        return RewrapOutcome.GONE
    if credential.key_version >= to_version:
        return RewrapOutcome.ALREADY_CURRENT

    sealed = vault.SealedSecret(
        ciphertext=credential.ciphertext,
        encrypted_dek=credential.encrypted_dek,
        nonce=credential.nonce,
        key_version=credential.key_version,
    )
    try:
        rewrapped = vault.rewrap(
            sealed,
            workspace_id=workspace_id,
            connection_id=credential.connection_id,
            to_version=to_version,
        )
    except vault.VaultKeyVersionError:
        # The KEK that wrapped this DEK is gone. Do not touch the row: it is still recoverable the
        # moment the key is restored, and writing anything here would not make it more so.
        log.error(
            "vault.rewrap_key_unavailable",
            workspace_id=str(workspace_id),
            credential_id=str(credential_id),
            from_version=credential.key_version,
            to_version=to_version,
        )
        return RewrapOutcome.KEY_UNAVAILABLE

    # Only the wrapping changes. `ciphertext`/`nonce` are deliberately not reassigned — and
    # `rotated_at` is deliberately NOT stamped: that column means "the secret was re-sealed", and
    # a re-wrap does not change the secret. Conflating them would make an operational key rotation
    # look like a customer credential rotation in every audit view.
    credential.encrypted_dek = rewrapped.encrypted_dek
    credential.key_version = rewrapped.key_version
    log.info(
        "vault.rewrapped",
        workspace_id=str(workspace_id),
        credential_id=str(credential_id),
        from_version=sealed.key_version,
        to_version=rewrapped.key_version,
    )
    return RewrapOutcome.REWRAPPED


async def count_pending(session: AsyncSession, *, target_version: int) -> int:
    """How many Credentials across **all** tenants are still below `target_version`.

    The retirement gate. Zero is the only value that permits removing an older KEK from the
    keyring, and it is measured here — in the database — rather than inferred from a job's exit
    status. Reads through the `auth.count_credentials_below_key_version` SECURITY DEFINER carve-out
    because the question is platform-wide by nature and no workspace is bound during a rotation
    tick; it returns a count, never a row. Takes a bare session, not a UnitOfWork: the question
    has no tenant and emits no events, so implying that scope would be a lie.
    """
    result = await session.execute(
        text("SELECT auth.count_credentials_below_key_version(:target)"),
        {"target": target_version},
    )
    return int(result.scalar_one())


__all__ = ["RewrapOutcome", "count_pending", "rewrap_credential"]
