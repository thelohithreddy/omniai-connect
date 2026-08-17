"""Business logic for the credentials domain (M1-Credentials-v1, ADR-0030).

Constructed from a `CredentialRepository` alone — no `WorkspaceContext`, no `workspace_id` — so no
expression here can write into another tenant. **No authorization** here: `connections:manage` is
checked at the request boundary. This layer owns: validating the target Connection, handing the
secret plaintext **straight to the vault** (`seal`) and never retaining or returning it, and the
canonical status linkage — attaching a credential moves the Connection `pending_auth → active`
(DATABASE_DESIGN §3: `credential_id` is non-null only when not `pending_auth`), revoking returns it
to `pending_auth`. Plaintext never leaves this function's local scope and never reaches a log,
response, exception, the DB (only ciphertext), Redis, or a task payload.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from app.core.exceptions import NotFoundError
from app.domains.credentials import vault
from app.domains.credentials.models import Credential
from app.domains.credentials.repository import CredentialRepository
from app.domains.credentials.schemas import CredentialWrite


def _plaintext(payload: CredentialWrite) -> bytes:
    """The canonical secret plaintext for a credential type — built, sealed, and dropped. Never
    logged or persisted (only its ciphertext is)."""
    if payload.credential_type in ("api_key", "bearer"):
        assert payload.value is not None  # guaranteed by the schema validator
        secret: dict[str, str] = {"value": payload.value.get_secret_value()}
    else:  # basic
        assert payload.username is not None and payload.password is not None
        secret = {"username": payload.username, "password": payload.password.get_secret_value()}
    return json.dumps(secret, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class CredentialService:
    def __init__(self, repository: CredentialRepository) -> None:
        self._repository = repository

    async def _seal_into(self, credential: Credential, payload: CredentialWrite) -> None:
        sealed = vault.seal(
            _plaintext(payload),
            workspace_id=credential.workspace_id,
            connection_id=credential.connection_id,
        )
        credential.credential_type = payload.credential_type
        credential.ciphertext = sealed.ciphertext
        credential.encrypted_dek = sealed.encrypted_dek
        credential.nonce = sealed.nonce
        credential.key_version = sealed.key_version

    async def attach(self, connection_id: uuid.UUID, payload: CredentialWrite) -> Credential:
        """Attach a Credential to a live Connection (→ `active`). A foreign/revoked connection is a
        uniform 404; a connection that already has a credential is a 409 (rotate instead)."""
        connection = await self._repository.connection_for_update(connection_id)
        if connection is None:
            raise NotFoundError("Connection not found.")
        credential = Credential(
            workspace_id=connection.workspace_id,
            connection_id=connection.id,
            credential_type=payload.credential_type,
            ciphertext=b"",
            encrypted_dek=b"",
            nonce=b"",
            key_version=vault.KEY_VERSION,
        )
        await self._seal_into(credential, payload)
        await self._repository.insert(credential)  # 409 if the connection already has one
        connection.credential_id = credential.id
        connection.status = "active"  # credential attached → out of pending_auth (§3)
        return credential

    async def rotate(self, connection_id: uuid.UUID, payload: CredentialWrite) -> Credential:
        """Re-seal a Connection's Credential with a **fresh DEK + nonce** and set `rotated_at`. The
        connection stays `active`. A missing connection/credential is a uniform 404."""
        connection = await self._repository.connection_for_update(connection_id)
        if connection is None:
            raise NotFoundError("Connection not found.")
        credential = await self._repository.get_by_connection(connection_id)
        if credential is None:
            raise NotFoundError("Credential not found.")
        await self._seal_into(credential, payload)
        credential.rotated_at = datetime.now(UTC)
        return credential

    async def get(self, connection_id: uuid.UUID) -> Credential:
        """A Connection's Credential **metadata**, or a uniform 404 for absent/foreign."""
        credential = await self._repository.get_by_connection(connection_id)
        if credential is None:
            raise NotFoundError("Credential not found.")
        return credential

    async def revoke(self, connection_id: uuid.UUID) -> None:
        """Hard-delete the Credential and return the Connection to `pending_auth`. A missing
        connection/credential is a uniform 404 (idempotent-safe)."""
        connection = await self._repository.connection_for_update(connection_id)
        if connection is None:
            raise NotFoundError("Connection not found.")
        credential = await self._repository.get_by_connection(connection_id)
        if credential is None:
            raise NotFoundError("Credential not found.")
        # Clear the connection's pointer and flush it BEFORE deleting the credential — the composite
        # FK has no SET NULL (which would null the NOT NULL workspace_id), so the reference must be
        # gone before the row is removed.
        connection.credential_id = None
        connection.status = "pending_auth"
        await self._repository.flush()
        await self._repository.delete(credential)


__all__ = ["CredentialService"]
