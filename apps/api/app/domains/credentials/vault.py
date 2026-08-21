"""Envelope encryption for the credential vault (SECURITY.md §2.1, ADR-0030).

The **only** code that touches credential plaintext keys. AES-256-GCM, `cryptography` primitives
only — never hand-rolled. Per-Credential model:

    plaintext ──AES-256-GCM(DEK, nonce, AAD)──▶ ciphertext(+tag)
    DEK       ──AES-256-GCM(KEK, wrap_nonce, AAD)──▶ encrypted_dek   (wrap; KEK never sees text)

- **KEK:** the env-provisioned master key `CREDENTIAL_MASTER_KEY` — base64 of exactly 32 bytes
  (`scripts/gen-key.sh`). Loaded per operation, validated, and **fail-closed** on missing / default
  `change-me` / bad base64 / wrong length (never a fallback, never a regenerated key). KMS is M2+.
- **DEK:** a fresh CSPRNG 256-bit key **per encryption** — never derived from ids/timestamps/hashes.
- **Nonce:** fresh CSPRNG per encryption, never reused with a key. The GCM tag is verified on every
  decrypt (fail-closed on mismatch).
- **AAD = workspace_id ‖ connection_id** (two raw 16-byte UUIDs, fixed length, unambiguous). Binds a
  ciphertext to its tenant + connection, so a ciphertext moved to another workspace/connection
  fails authentication.
- **key_version:** `1` in M1 (single active KEK). The column exists for the M2 rotation runbook; no
  multi-version keyring / background re-wrap here.

Decryption (`_unseal`) is **private** to this module — the future Execution Runtime is the only
legitimate caller. No router, service, repository, or worker path decrypts in M1.
"""

from __future__ import annotations

import base64
import binascii
import os
import uuid
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings

KEY_VERSION = 1
_KEK_LEN = 32
_DEK_LEN = 32
_NONCE_LEN = 12


class VaultConfigError(RuntimeError):
    """The master key is missing or invalid. Fail closed — never fall back to another key."""


class VaultDecryptError(RuntimeError):
    """Authenticated decryption failed: tampered ciphertext/tag/encrypted_dek, wrong key, or wrong
    AAD (workspace/connection mismatch). Fail closed."""


def _load_master_key() -> bytes:
    """The master KEK as 32 raw bytes, or `VaultConfigError`. Never a default/derived key."""
    raw = settings.credential_master_key.get_secret_value().strip()
    if not raw or raw.startswith("change-me"):
        raise VaultConfigError("CREDENTIAL_MASTER_KEY is not configured")
    try:
        key = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VaultConfigError("CREDENTIAL_MASTER_KEY must be valid base64") from exc
    if len(key) != _KEK_LEN:
        raise VaultConfigError("CREDENTIAL_MASTER_KEY must decode to exactly 32 bytes")
    return key


def validate_master_key_configured() -> None:
    """Startup fail-closed hook: raise `VaultConfigError` if the KEK is unusable. Called in
    production so the API refuses to boot without a valid master key."""
    _load_master_key()


def _aad(workspace_id: uuid.UUID, connection_id: uuid.UUID) -> bytes:
    """Deterministic GCM associated data: the two UUIDs as raw 16-byte values, concatenated (fixed
    length → no delimiter ambiguity). No secret; changing either id breaks authentication."""
    return workspace_id.bytes + connection_id.bytes


@dataclass(frozen=True, slots=True)
class SealedSecret:
    """The persisted, non-plaintext result of sealing a credential secret."""

    ciphertext: bytes
    encrypted_dek: bytes  # wrap_nonce ‖ AESGCM(KEK).encrypt(...)
    nonce: bytes
    key_version: int


def seal(plaintext: bytes, *, workspace_id: uuid.UUID, connection_id: uuid.UUID) -> SealedSecret:
    """Encrypt `plaintext` under a fresh per-Credential DEK, wrap the DEK with the master KEK, and
    bind both to `workspace_id ‖ connection_id` as GCM AAD. Randomized (fresh DEK + nonces) — two
    seals of the same input differ. Fails closed if the KEK is unusable."""
    kek = _load_master_key()
    dek = os.urandom(_DEK_LEN)
    nonce = os.urandom(_NONCE_LEN)
    aad = _aad(workspace_id, connection_id)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
    wrap_nonce = os.urandom(_NONCE_LEN)
    encrypted_dek = wrap_nonce + AESGCM(kek).encrypt(wrap_nonce, dek, aad)
    return SealedSecret(ciphertext, encrypted_dek, nonce, KEY_VERSION)


def _unseal(sealed: SealedSecret, *, workspace_id: uuid.UUID, connection_id: uuid.UUID) -> bytes:
    """PRIVATE — recover the plaintext. The future Execution Runtime is the only legitimate caller;
    no router/service/repository/worker path invokes this in M1. Reconstructs the exact AAD and
    fails closed (`VaultDecryptError`) on any authentication failure."""
    kek = _load_master_key()
    aad = _aad(workspace_id, connection_id)
    wrap_nonce, wrapped = sealed.encrypted_dek[:_NONCE_LEN], sealed.encrypted_dek[_NONCE_LEN:]
    try:
        dek = AESGCM(kek).decrypt(wrap_nonce, wrapped, aad)
        return AESGCM(dek).decrypt(sealed.nonce, sealed.ciphertext, aad)
    except InvalidTag as exc:
        raise VaultDecryptError("credential authentication failed") from exc


def unseal_flow_secret(
    sealed: SealedSecret, *, workspace_id: uuid.UUID, connection_id: uuid.UUID
) -> bytes:
    """Recover **ephemeral protocol material** — never a Credential (M2.5, ADR-0038).

    The credential decrypt boundary is unchanged: `_unseal` stays private and the Execution
    Runtime (`runtime/secrets.py`) remains its only importer, which is now mechanically asserted
    by a test rather than merely documented. This function exists for one narrow case that is
    *not* a customer credential: the PKCE `code_verifier`, which RFC 7636 §4.5 requires to be
    presented verbatim at the token endpoint and therefore cannot be hashed like `state`.

    It deliberately reuses the identical AES-256-GCM envelope and AAD (workspace‖connection)
    rather than introducing a second crypto path — one implementation, two labelled callers.
    The recovered value is a single-use nonce that dies with its `oauth_states` row.
    """
    return _unseal(sealed, workspace_id=workspace_id, connection_id=connection_id)


__all__ = [
    "KEY_VERSION",
    "SealedSecret",
    "VaultConfigError",
    "VaultDecryptError",
    "seal",
    "unseal_flow_secret",
    "validate_master_key_configured",
]
