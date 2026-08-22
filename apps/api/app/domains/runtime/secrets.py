"""The runtime's private credential-decrypt boundary — the ONLY plaintext producer (SECURITY §2.1).

Credentials v1 ended at `vault._unseal`, deliberately private, "the future Execution Runtime is the
only legitimate caller" (ADR-0030). This module is that caller, nothing else: it reconstructs a
`SealedSecret` from a `Credential` row's ciphertext columns, unwraps it under the row's workspace
+ connection AAD, and returns the plaintext as a `CredentialSecret` whose `repr` is redacted so it
can never surface in a log line, traceback, or audit record.

`_unseal` is imported here and *only* here. A repository-wide search for its importers must return
exactly this file — that invariant is the runtime's decrypt encapsulation, asserted in the tests.
The returned secret lives in memory for the single outbound request that injects it, then is dropped
(no reference is persisted, buffered, or logged).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import structlog

from app.core import metrics
from app.domains.credentials.models import Credential
from app.domains.credentials.vault import (
    SealedSecret,
    VaultDecryptError,
    VaultKeyVersionError,
    _unseal,
)

log = structlog.get_logger(__name__)


@dataclass(frozen=True, repr=False, slots=True)
class CredentialSecret:
    """Decrypted credential material, in memory only. `repr` is redacted on purpose — the secret
    never renders. Fields mirror the sealed JSON: api_key/bearer carry `value`; basic carries
    `username` + `password`."""

    credential_type: str
    value: str | None = None
    username: str | None = None
    password: str | None = None
    #: oauth2 only — the bearer access token the execution path injects (M2.5).
    access_token: str | None = None
    #: oauth2 only — redeemed **exclusively** by the refresh worker on the canonical `runtime`
    #: queue (CONNECTOR_ENGINE §8). `build_auth_injection` never reads it, so an executing Tool
    #: Call holds no material that could mint a new token.
    refresh_token: str | None = None

    def __repr__(self) -> str:  # never leak the secret through repr / f-strings / tracebacks
        return f"<CredentialSecret {self.credential_type} redacted>"


def _audit(
    outcome: str,
    credential: Credential,
    *,
    workspace_id: uuid.UUID,
    connection_id: uuid.UUID,
) -> None:
    """Record one vault access (M2.6 ratified A2: structured logs + metrics, no new ledger).

    Every field here is an identifier or bounded metadata — ids, the credential *type*, the key
    *version*, the outcome. No plaintext, no ciphertext, no key material, and no exception body:
    a failure is reported as a classified outcome precisely so that nothing from the failing
    value can ride along in a message string.

    The log line is the audit record (searchable, per-event, retained by the log platform); the
    counter is the aggregate, whose labels exclude the ids so its cardinality stays bounded.
    """
    log.info(
        "vault.credential_opened" if outcome == "ok" else "vault.credential_open_failed",
        outcome=outcome,
        workspace_id=str(workspace_id),
        connection_id=str(connection_id),
        credential_id=str(credential.id),
        credential_type=credential.credential_type,
        key_version=credential.key_version,
    )
    metrics.increment(
        "vault.credential_opens",
        credential_type=credential.credential_type,
        outcome=outcome,
    )


def open_credential_secret(
    credential: Credential, *, workspace_id: uuid.UUID, connection_id: uuid.UUID
) -> CredentialSecret:
    """Decrypt one Credential row into an in-memory `CredentialSecret`. Raises `VaultDecryptError`
    if the ciphertext/tag/AAD does not verify (wrong workspace, wrong connection, or tampering).

    Every call — success or failure — is audited (M2.6). This is the only place a credential
    becomes plaintext, so it is the only place where "who opened what, when" can be recorded
    completely; auditing anywhere else would be auditing a subset and calling it the whole.
    """
    sealed = SealedSecret(
        ciphertext=credential.ciphertext,
        encrypted_dek=credential.encrypted_dek,
        nonce=credential.nonce,
        key_version=credential.key_version,
    )
    try:
        plaintext = _unseal(sealed, workspace_id=workspace_id, connection_id=connection_id)
    except VaultKeyVersionError:
        # A retired key, not a corrupt row — distinguished so an operator sees "restore the key"
        # rather than "investigate tampering". Re-raised unchanged; only the audit is added.
        _audit(
            "key_unavailable", credential, workspace_id=workspace_id, connection_id=connection_id
        )
        raise
    except VaultDecryptError:
        _audit("decrypt_failed", credential, workspace_id=workspace_id, connection_id=connection_id)
        raise
    try:
        data = json.loads(plaintext)
    except json.JSONDecodeError:
        # A successfully-decrypted secret is always the JSON the vault sealed; if it somehow is not,
        # fail closed WITHOUT echoing the plaintext (json's own error carries the raw document).
        _audit("malformed", credential, workspace_id=workspace_id, connection_id=connection_id)
        raise VaultDecryptError("decrypted credential is not well-formed") from None
    if not isinstance(data, dict):
        _audit("malformed", credential, workspace_id=workspace_id, connection_id=connection_id)
        raise VaultDecryptError("decrypted credential is not an object") from None
    _audit("ok", credential, workspace_id=workspace_id, connection_id=connection_id)
    return CredentialSecret(
        credential_type=credential.credential_type,
        value=data.get("value"),
        username=data.get("username"),
        password=data.get("password"),
        access_token=data.get("access_token"),
        refresh_token=data.get("refresh_token"),
    )


__all__ = ["CredentialSecret", "open_credential_secret"]
