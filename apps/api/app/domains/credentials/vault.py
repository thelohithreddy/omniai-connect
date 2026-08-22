"""Envelope encryption for the credential vault (SECURITY.md §2.1, ADR-0030; hardened ADR-0039).

The **only** code that touches credential plaintext keys. AES-256-GCM, `cryptography` primitives
only — never hand-rolled. Since M2.6 the key hierarchy has three levels, not two:

    plaintext ──AES-256-GCM(DEK, nonce, AAD)──────▶ ciphertext(+tag)
    DEK       ──AES-256-GCM(WK,  wrap_nonce, AAD)─▶ encrypted_dek      (wrap; WK never sees text)
    WK        ──HKDF-Expand(KEK_v, info=label‖v‖workspace_id)          (derived, never stored)

- **KEK:** an env-provisioned master key, base64 of exactly 32 bytes (`scripts/gen-key.sh`). The
  keyring may hold several *versions* at once (`CREDENTIAL_MASTER_KEY` is version 1 by definition;
  `CREDENTIAL_MASTER_KEYS` supplies 2+). Fail-closed on missing / default `change-me` / bad base64
  / wrong length / duplicate version / unknown active version — never a fallback, never a
  regenerated key, never a partial keyring. No external KMS: the provider seam below is where one
  would attach without a schema change (ADR-0030), but M2.6 deliberately ships the local keyring.
- **WK (workspace key):** derived per workspace with HKDF-Expand (RFC 5869 §3.3 — the Extract step
  is correctly skipped because the KEK is already a uniformly random 256-bit key, not a password
  or a Diffie-Hellman share). Never stored, never logged, recomputed on demand. Its `info` string
  is domain-separated and length-unambiguous, so no two contexts can derive the same key. Effect:
  a wrapped DEK from workspace A is cryptographically useless in workspace B **even if the AAD
  check were bypassed** — tenant isolation now survives a bug in the AAD layer above it.
- **DEK:** a fresh CSPRNG 256-bit key **per encryption** — never derived from ids/timestamps.
- **Nonce:** fresh CSPRNG per encryption, never reused with a key. The GCM tag is verified on every
  decrypt (fail-closed on mismatch).
- **AAD = workspace_id ‖ connection_id** (two raw 16-byte UUIDs, fixed length, unambiguous). Binds
  a ciphertext to its tenant + connection; a ciphertext moved elsewhere fails authentication.

**Why version 1 is special.** M1 wrapped DEKs with the KEK *directly*. Those rows exist in
production. Redefining version 1 to mean "workspace-derived" would make every stored credential
undecryptable — silent, total, unrecoverable data loss. So version 1 keeps its original scheme
verbatim and forever, and introducing the workspace-key hierarchy *is itself a KEK rotation*: the
re-wrap job (`credentials/rotation.py`) moves rows 1 → 2 through the ordinary runbook. The
hierarchy is not bolted onto history; history is migrated into it.

Decryption of a credential payload (`_unseal`) is **private** to this module — `runtime/secrets.py`
is its only legitimate caller, asserted mechanically by a test. Re-wrapping (`rewrap`) never touches
the payload: it re-wraps the DEK only, leaving ciphertext and nonce byte-identical.
"""

from __future__ import annotations

import base64
import binascii
import os
import uuid
from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from app.core.config import settings

_KEK_LEN = 32
_DEK_LEN = 32
_NONCE_LEN = 12

#: Version 1 predates the workspace-key hierarchy: its DEKs are wrapped by the master KEK itself.
#: Every M1-era row carries it. This constant is a historical fact, not a policy knob — changing
#: it does not migrate anything, it only makes old ciphertext unreadable.
LEGACY_DIRECT_WRAP_VERSION = 1

#: HKDF domain separation. The trailing `/v1` versions the *derivation scheme*, independently of
#: the KEK version — if the construction itself ever changed, this label would change with it.
_HKDF_LABEL = b"omniai-connect/credential-vault/workspace-key/v1"


class VaultConfigError(RuntimeError):
    """The key material is missing or invalid. Fail closed — never fall back to another key."""


class VaultDecryptError(RuntimeError):
    """Authenticated decryption failed: tampered ciphertext/tag/encrypted_dek, wrong key, or wrong
    AAD (workspace/connection mismatch). Fail closed."""


class VaultKeyVersionError(VaultDecryptError):
    """The row's `key_version` is absent from the configured keyring.

    A subclass of `VaultDecryptError` so every existing fail-closed handler already covers it,
    while rotation code can distinguish "this key was retired too early" from "this ciphertext is
    corrupt" — the two demand opposite responses (restore the key vs. investigate tampering).
    """


# ---------------------------------------------------------------------------------------------
# Key provider seam
# ---------------------------------------------------------------------------------------------


class KeyProvider(Protocol):
    """Wrap/unwrap of DEKs, behind a stable interface.

    This is the seam ADR-0030 promised: because only *wrapped DEKs* depend on the KEK, swapping the
    local keyring for a KMS is a new implementation of this protocol and a re-wrap pass — no schema
    change, no ciphertext rewrite, no downtime. M2.6 ships exactly one implementation
    (`LocalKeyringProvider`); the protocol exists so that stays true.

    Implementations must be fail-closed: an unusable or unknown version raises, never returns a
    best-effort key. No implementation may log, serialize, or return key material.
    """

    @property
    def active_version(self) -> int:
        """The version that seals new credentials."""
        ...

    @property
    def versions(self) -> frozenset[int]:
        """Every version this provider can still unwrap (the overlap window)."""
        ...

    def wrap_dek(self, dek: bytes, *, version: int, workspace_id: uuid.UUID, aad: bytes) -> bytes:
        """Wrap `dek` under `version`. Returns `wrap_nonce ‖ ciphertext(+tag)`."""
        ...

    def unwrap_dek(
        self, encrypted_dek: bytes, *, version: int, workspace_id: uuid.UUID, aad: bytes
    ) -> bytes:
        """Recover the DEK wrapped under `version`. Raises on any authentication failure."""
        ...


def _decode_kek(raw: str, source: str) -> bytes:
    """Validate one base64 KEK to 32 raw bytes. Error text names the *variable*, never the value."""
    raw = raw.strip()
    if not raw or raw.startswith("change-me"):
        raise VaultConfigError(f"{source} is not configured")
    try:
        key = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VaultConfigError(f"{source} must be valid base64") from exc
    if len(key) != _KEK_LEN:
        raise VaultConfigError(f"{source} must decode to exactly 32 bytes")
    return key


def _load_keyring() -> dict[int, bytes]:
    """Every configured KEK version. Fail-closed and total: one bad entry rejects the whole ring
    rather than silently operating with a hole in it."""
    keyring = {
        LEGACY_DIRECT_WRAP_VERSION: _decode_kek(
            settings.credential_master_key.get_secret_value(), "CREDENTIAL_MASTER_KEY"
        )
    }
    extra = settings.credential_master_keys.get_secret_value().strip()
    if not extra:
        return keyring
    for entry in extra.split(","):
        entry = entry.strip()
        if not entry:
            continue
        version_text, separator, key_text = entry.partition(":")
        if not separator:
            raise VaultConfigError("CREDENTIAL_MASTER_KEYS entries must be 'version:base64key'")
        try:
            version = int(version_text.strip())
        except ValueError as exc:
            raise VaultConfigError("CREDENTIAL_MASTER_KEYS version must be an integer") from exc
        if version <= LEGACY_DIRECT_WRAP_VERSION:
            # Version 1 already means CREDENTIAL_MASTER_KEY. A second answer for the same version
            # is how a rotation silently destroys data, so it is a boot failure, not a merge.
            raise VaultConfigError(
                "CREDENTIAL_MASTER_KEYS may only declare versions >= 2"
                " (version 1 is CREDENTIAL_MASTER_KEY)"
            )
        if version in keyring:
            raise VaultConfigError(f"CREDENTIAL_MASTER_KEYS declares version {version} twice")
        keyring[version] = _decode_kek(key_text, f"CREDENTIAL_MASTER_KEYS version {version}")
    return keyring


class LocalKeyringProvider:
    """Multi-version local KEK keyring with HKDF-derived per-workspace keys.

    Loads and validates the whole ring on construction so a misconfiguration surfaces at startup,
    not on the first tool call at 3am. Holds raw key bytes in memory only; nothing here is ever
    logged, serialized, or returned to a caller.
    """

    __slots__ = ("_active_version", "_keyring")

    def __init__(self) -> None:
        self._keyring = _load_keyring()
        active = settings.credential_key_version
        if active not in self._keyring:
            raise VaultConfigError(
                f"CREDENTIAL_KEY_VERSION={active} is not present in the configured keyring"
            )
        self._active_version = active

    @property
    def active_version(self) -> int:
        return self._active_version

    @property
    def versions(self) -> frozenset[int]:
        return frozenset(self._keyring)

    def _wrapping_key(self, *, version: int, workspace_id: uuid.UUID) -> bytes:
        """The key that wraps a DEK for this (version, workspace).

        Version 1 returns the KEK itself — its rows were written that way and must stay readable.
        Every later version returns HKDF-Expand(KEK_v, label ‖ version ‖ workspace_id): the KEK is
        already uniformly random, so RFC 5869 §3.3 permits skipping Extract, and the fixed-length
        `info` makes the derivation unambiguous across versions and workspaces.
        """
        try:
            kek = self._keyring[version]
        except KeyError as exc:
            raise VaultKeyVersionError(
                f"credential key version {version} is not in the configured keyring"
            ) from exc
        if version == LEGACY_DIRECT_WRAP_VERSION:
            return kek
        return HKDFExpand(
            algorithm=hashes.SHA256(),
            length=_KEK_LEN,
            info=_HKDF_LABEL + b"\x00" + version.to_bytes(4, "big") + workspace_id.bytes,
        ).derive(kek)

    def wrap_dek(self, dek: bytes, *, version: int, workspace_id: uuid.UUID, aad: bytes) -> bytes:
        wrapping_key = self._wrapping_key(version=version, workspace_id=workspace_id)
        wrap_nonce = os.urandom(_NONCE_LEN)
        return wrap_nonce + AESGCM(wrapping_key).encrypt(wrap_nonce, dek, aad)

    def unwrap_dek(
        self, encrypted_dek: bytes, *, version: int, workspace_id: uuid.UUID, aad: bytes
    ) -> bytes:
        wrapping_key = self._wrapping_key(version=version, workspace_id=workspace_id)
        wrap_nonce, wrapped = encrypted_dek[:_NONCE_LEN], encrypted_dek[_NONCE_LEN:]
        try:
            return AESGCM(wrapping_key).decrypt(wrap_nonce, wrapped, aad)
        except InvalidTag as exc:
            raise VaultDecryptError("credential authentication failed") from exc


def get_key_provider() -> KeyProvider:
    """The process key provider.

    Deliberately constructed per call rather than cached at import: the previous implementation
    re-read settings on every operation, and tests (plus a future hot key-reload) depend on a
    settings change taking effect without a process restart. Key derivation is one HKDF-Expand —
    a single HMAC — so this is not on any measurable hot path.
    """
    return LocalKeyringProvider()


def active_key_version() -> int:
    """The KEK version that seals new credentials."""
    return get_key_provider().active_version


def validate_master_key_configured() -> None:
    """Startup fail-closed hook: raise `VaultConfigError` if the keyring or the active version is
    unusable. Called in production so the API refuses to boot without valid key material."""
    get_key_provider()


def _aad(workspace_id: uuid.UUID, connection_id: uuid.UUID) -> bytes:
    """Deterministic GCM associated data: the two UUIDs as raw 16-byte values, concatenated (fixed
    length → no delimiter ambiguity). No secret; changing either id breaks authentication."""
    return workspace_id.bytes + connection_id.bytes


@dataclass(frozen=True, slots=True)
class SealedSecret:
    """The persisted, non-plaintext result of sealing a credential secret."""

    ciphertext: bytes
    encrypted_dek: bytes  # wrap_nonce ‖ AESGCM(workspace key).encrypt(...)
    nonce: bytes
    key_version: int


def seal(plaintext: bytes, *, workspace_id: uuid.UUID, connection_id: uuid.UUID) -> SealedSecret:
    """Encrypt `plaintext` under a fresh per-Credential DEK, wrap that DEK under the **active** key
    version for this workspace, and bind both to `workspace_id ‖ connection_id` as GCM AAD.
    Randomized (fresh DEK + nonces) — two seals of the same input differ. Fails closed if the key
    material is unusable."""
    provider = get_key_provider()
    version = provider.active_version
    dek = os.urandom(_DEK_LEN)
    nonce = os.urandom(_NONCE_LEN)
    aad = _aad(workspace_id, connection_id)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
    encrypted_dek = provider.wrap_dek(dek, version=version, workspace_id=workspace_id, aad=aad)
    return SealedSecret(ciphertext, encrypted_dek, nonce, version)


def _unseal(sealed: SealedSecret, *, workspace_id: uuid.UUID, connection_id: uuid.UUID) -> bytes:
    """PRIVATE — recover the plaintext. `runtime/secrets.py` is the only legitimate caller (asserted
    by test). Unwraps the DEK at the row's **own** key version, so a credential sealed before a
    rotation stays readable throughout the overlap window. Reconstructs the exact AAD and fails
    closed (`VaultDecryptError`) on any authentication failure."""
    provider = get_key_provider()
    aad = _aad(workspace_id, connection_id)
    dek = provider.unwrap_dek(
        sealed.encrypted_dek, version=sealed.key_version, workspace_id=workspace_id, aad=aad
    )
    try:
        return AESGCM(dek).decrypt(sealed.nonce, sealed.ciphertext, aad)
    except InvalidTag as exc:
        raise VaultDecryptError("credential authentication failed") from exc


def rewrap(
    sealed: SealedSecret, *, workspace_id: uuid.UUID, connection_id: uuid.UUID, to_version: int
) -> SealedSecret:
    """Re-wrap a sealed secret's DEK under `to_version`. **The payload is never decrypted.**

    This is the whole of what key rotation does: unwrap the DEK at its current version, wrap it
    under the target, and return a record whose `ciphertext` and `nonce` are byte-identical to the
    input. The credential plaintext is not recovered, not held, and not rewritten — which is why
    rotation is safe to run in a background worker that has no business seeing secrets, and why a
    crash mid-rotation can never corrupt a payload.

    Idempotent: re-wrapping to the version a row already carries returns it unchanged, so a retried
    task is harmless.
    """
    if sealed.key_version == to_version:
        return sealed
    provider = get_key_provider()
    if to_version not in provider.versions:
        raise VaultKeyVersionError(f"credential key version {to_version} is not in the keyring")
    aad = _aad(workspace_id, connection_id)
    dek = provider.unwrap_dek(
        sealed.encrypted_dek, version=sealed.key_version, workspace_id=workspace_id, aad=aad
    )
    encrypted_dek = provider.wrap_dek(dek, version=to_version, workspace_id=workspace_id, aad=aad)
    return SealedSecret(sealed.ciphertext, encrypted_dek, sealed.nonce, to_version)


def unseal_flow_secret(
    sealed: SealedSecret, *, workspace_id: uuid.UUID, connection_id: uuid.UUID
) -> bytes:
    """Recover **ephemeral protocol material** — never a Credential (M2.5, ADR-0038).

    The credential decrypt boundary is unchanged: the private recovery function stays private and
    the Execution Runtime (`runtime/secrets.py`) remains its only importer, which is mechanically
    asserted by a test rather than merely documented. This function exists for one narrow case that
    is *not* a customer credential: the PKCE `code_verifier`, which RFC 7636 §4.5 requires to be
    presented verbatim at the token endpoint and therefore cannot be hashed like `state`.

    It deliberately reuses the identical AES-256-GCM envelope and AAD (workspace‖connection)
    rather than introducing a second crypto path — one implementation, two labelled callers.
    The recovered value is a single-use nonce that dies with its `oauth_states` row.
    """
    return _unseal(sealed, workspace_id=workspace_id, connection_id=connection_id)


__all__ = [
    "LEGACY_DIRECT_WRAP_VERSION",
    "KeyProvider",
    "LocalKeyringProvider",
    "SealedSecret",
    "VaultConfigError",
    "VaultDecryptError",
    "VaultKeyVersionError",
    "active_key_version",
    "get_key_provider",
    "rewrap",
    "seal",
    "unseal_flow_secret",
    "validate_master_key_configured",
]
