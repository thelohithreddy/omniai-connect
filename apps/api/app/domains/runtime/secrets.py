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

from app.domains.credentials.models import Credential
from app.domains.credentials.vault import SealedSecret, VaultDecryptError, _unseal


@dataclass(frozen=True, repr=False, slots=True)
class CredentialSecret:
    """Decrypted credential material, in memory only. `repr` is redacted on purpose — the secret
    never renders. Fields mirror the sealed JSON: api_key/bearer carry `value`; basic carries
    `username` + `password`."""

    credential_type: str
    value: str | None = None
    username: str | None = None
    password: str | None = None
    #: oauth2 only — the bearer access token the runtime injects (M2.5). The refresh token is
    #: deliberately NOT surfaced here: the runtime never redeems it (the Celery refresh worker
    #: owns that), so the execution path holds the narrowest material that can do its job.
    access_token: str | None = None

    def __repr__(self) -> str:  # never leak the secret through repr / f-strings / tracebacks
        return f"<CredentialSecret {self.credential_type} redacted>"


def open_credential_secret(
    credential: Credential, *, workspace_id: uuid.UUID, connection_id: uuid.UUID
) -> CredentialSecret:
    """Decrypt one Credential row into an in-memory `CredentialSecret`. Raises `VaultDecryptError`
    if the ciphertext/tag/AAD does not verify (wrong workspace, wrong connection, or tampering)."""
    sealed = SealedSecret(
        ciphertext=credential.ciphertext,
        encrypted_dek=credential.encrypted_dek,
        nonce=credential.nonce,
        key_version=credential.key_version,
    )
    plaintext = _unseal(sealed, workspace_id=workspace_id, connection_id=connection_id)
    try:
        data = json.loads(plaintext)
    except json.JSONDecodeError:
        # A successfully-decrypted secret is always the JSON the vault sealed; if it somehow is not,
        # fail closed WITHOUT echoing the plaintext (json's own error carries the raw document).
        raise VaultDecryptError("decrypted credential is not well-formed") from None
    if not isinstance(data, dict):
        raise VaultDecryptError("decrypted credential is not an object") from None
    return CredentialSecret(
        credential_type=credential.credential_type,
        value=data.get("value"),
        username=data.get("username"),
        password=data.get("password"),
        access_token=data.get("access_token"),
    )


__all__ = ["CredentialSecret", "open_credential_secret"]
