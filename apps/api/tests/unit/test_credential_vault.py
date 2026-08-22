"""Envelope-encryption vault primitive (M1-Credentials-v1). No DB.

The real AES-256-GCM boundary (never mocked): round-trip, randomization (fresh DEK + nonce),
authenticated-decryption failure on any tamper (ciphertext / tag / encrypted_dek), AAD binding
(wrong workspace or connection fails — a transplant is rejected), wrong-KEK failure, and the
fail-closed master-key validation (default / empty / short / bad-base64 rejected). The container
with a valid disposable KEK, so `seal`/`_unseal` work by default; rejection tests override the key.
"""

from __future__ import annotations

import base64
import os
import uuid

import pytest
from pydantic import SecretStr

from app.domains.credentials import vault
from app.domains.credentials.vault import (
    VaultConfigError,
    VaultDecryptError,
    _unseal,
    seal,
)

WS = uuid.uuid4()
CONN = uuid.uuid4()


def _key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


# ------------------------------------------------------------------ round-trip / randomization


def test_seal_then_unseal_round_trips() -> None:
    sealed = seal(b"sk-live-secret", workspace_id=WS, connection_id=CONN)
    assert _unseal(sealed, workspace_id=WS, connection_id=CONN) == b"sk-live-secret"


def test_key_version_is_one() -> None:
    assert seal(b"x", workspace_id=WS, connection_id=CONN).key_version == 1


def test_two_seals_of_the_same_secret_differ_everywhere() -> None:
    a = seal(b"same", workspace_id=WS, connection_id=CONN)
    b = seal(b"same", workspace_id=WS, connection_id=CONN)
    assert a.ciphertext != b.ciphertext  # fresh nonce/DEK ⇒ different ciphertext
    assert a.encrypted_dek != b.encrypted_dek  # fresh DEK, freshly wrapped
    assert a.nonce != b.nonce
    # …yet both decrypt to the same plaintext.
    assert _unseal(a, workspace_id=WS, connection_id=CONN) == b"same"
    assert _unseal(b, workspace_id=WS, connection_id=CONN) == b"same"


def test_each_credential_gets_a_distinct_random_dek() -> None:
    # Unwrap the DEK from two seals of the same input under the same key/AAD: they must differ (a
    # fresh 256-bit DEK per encryption), not a static or derived key.
    provider = vault.get_key_provider()
    aad = WS.bytes + CONN.bytes

    def dek_of(sealed: vault.SealedSecret) -> bytes:
        return provider.unwrap_dek(
            sealed.encrypted_dek, version=sealed.key_version, workspace_id=WS, aad=aad
        )

    a = seal(b"same", workspace_id=WS, connection_id=CONN)
    b = seal(b"same", workspace_id=WS, connection_id=CONN)
    assert dek_of(a) != dek_of(b)
    assert len(dek_of(a)) == 32


# ------------------------------------------------------------------ tamper detection (fail closed)


def test_tampered_ciphertext_fails() -> None:
    sealed = seal(b"secret", workspace_id=WS, connection_id=CONN)
    bad = vault.SealedSecret(
        ciphertext=bytes(sealed.ciphertext[:-1]) + bytes([sealed.ciphertext[-1] ^ 0x01]),
        encrypted_dek=sealed.encrypted_dek,
        nonce=sealed.nonce,
        key_version=sealed.key_version,
    )
    with pytest.raises(VaultDecryptError):
        _unseal(bad, workspace_id=WS, connection_id=CONN)


def test_tampered_encrypted_dek_fails() -> None:
    sealed = seal(b"secret", workspace_id=WS, connection_id=CONN)
    bad = vault.SealedSecret(
        ciphertext=sealed.ciphertext,
        encrypted_dek=bytes(sealed.encrypted_dek[:-1]) + bytes([sealed.encrypted_dek[-1] ^ 0x01]),
        nonce=sealed.nonce,
        key_version=sealed.key_version,
    )
    with pytest.raises(VaultDecryptError):
        _unseal(bad, workspace_id=WS, connection_id=CONN)


# ------------------------------------------------------------------ AAD binding (transplant)


def test_wrong_workspace_aad_fails() -> None:
    sealed = seal(b"secret", workspace_id=WS, connection_id=CONN)
    with pytest.raises(VaultDecryptError):
        _unseal(sealed, workspace_id=uuid.uuid4(), connection_id=CONN)


def test_wrong_connection_aad_fails() -> None:
    sealed = seal(b"secret", workspace_id=WS, connection_id=CONN)
    with pytest.raises(VaultDecryptError):
        _unseal(sealed, workspace_id=WS, connection_id=uuid.uuid4())


# ------------------------------------------------------------------ wrong KEK


def test_a_different_master_key_cannot_unseal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault.settings, "credential_master_key", SecretStr(_key()))
    sealed = seal(b"secret", workspace_id=WS, connection_id=CONN)
    monkeypatch.setattr(
        vault.settings, "credential_master_key", SecretStr(_key())
    )  # rotate the KEK
    with pytest.raises(VaultDecryptError):
        _unseal(sealed, workspace_id=WS, connection_id=CONN)


# ------------------------------------------------------------------ master-key validation


@pytest.mark.parametrize(
    "bad",
    [
        "change-me",  # default placeholder
        "change-me-generate-with-scripts/gen-key.sh",  # the .env.example default
        "",  # empty
        "   ",  # whitespace
        base64.b64encode(os.urandom(16)).decode(),  # valid base64 but only 16 bytes
        base64.b64encode(os.urandom(31)).decode(),  # 31 bytes
        "not!valid!base64!!",  # malformed base64
    ],
)
def test_an_invalid_master_key_is_rejected(monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    monkeypatch.setattr(vault.settings, "credential_master_key", SecretStr(bad))
    with pytest.raises(VaultConfigError):
        vault.validate_master_key_configured()
    # And it fails closed at use, never falling back to a working key.
    with pytest.raises(VaultConfigError):
        seal(b"x", workspace_id=WS, connection_id=CONN)


def test_a_valid_master_key_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault.settings, "credential_master_key", SecretStr(_key()))
    vault.validate_master_key_configured()  # does not raise
    assert len(vault._load_keyring()[vault.LEGACY_DIRECT_WRAP_VERSION]) == 32


# ============================================================ M2.6 — keyring, derivation, rotation
#
# The three claims M2.6 rests on, each tested so that removing *only* the control fails the test:
#   1. Version 1 keeps M1's direct-KEK wrapping forever — otherwise every stored credential in
#      production becomes permanently unreadable the moment this ships.
#   2. Version 2+ wraps under an HKDF-derived per-workspace key, so a wrapped DEK is useless in
#      another workspace **even if the AAD check above it were bypassed**.
#   3. Re-wrap moves a row between versions without ever decrypting or rewriting the payload.


def _keyring(monkeypatch: pytest.MonkeyPatch, *, v1: str, v2: str | None, active: int) -> None:
    """Install a deterministic keyring for one test."""
    monkeypatch.setattr(vault.settings, "credential_master_key", SecretStr(v1))
    monkeypatch.setattr(
        vault.settings, "credential_master_keys", SecretStr(f"2:{v2}" if v2 else "")
    )
    monkeypatch.setattr(vault.settings, "credential_key_version", active)


# ------------------------------------------------------------------ 1. version 1 stays legacy


def test_version_1_ciphertext_written_by_m1_still_decrypts(monkeypatch: pytest.MonkeyPatch) -> None:
    """The backward-compatibility guarantee, proved against M1's *exact* algorithm.

    This constructs a sealed record the way M1 did — DEK wrapped by the master KEK directly, with
    no workspace derivation anywhere — and requires the hardened vault to read it. If someone
    "simplifies" the vault by making version 1 use the derived key, this test fails, and it fails
    for precisely the reason that would have destroyed every production credential.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    kek_b64 = _key()
    _keyring(monkeypatch, v1=kek_b64, v2=_key(), active=2)
    kek = base64.b64decode(kek_b64)

    aad = WS.bytes + CONN.bytes
    dek, nonce, wrap_nonce = os.urandom(32), os.urandom(12), os.urandom(12)
    legacy = vault.SealedSecret(
        ciphertext=AESGCM(dek).encrypt(nonce, b"m1-era-api-key", aad),
        encrypted_dek=wrap_nonce + AESGCM(kek).encrypt(wrap_nonce, dek, aad),
        nonce=nonce,
        key_version=1,
    )
    assert _unseal(legacy, workspace_id=WS, connection_id=CONN) == b"m1-era-api-key"


def test_version_1_wraps_with_the_kek_itself_not_a_derived_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kek_b64 = _key()
    _keyring(monkeypatch, v1=kek_b64, v2=None, active=1)
    provider = vault.get_key_provider()
    assert provider._wrapping_key(version=1, workspace_id=WS) == base64.b64decode(kek_b64)


# ------------------------------------------------------------------ 2. derived per-workspace keys


def test_version_2_does_not_wrap_with_the_raw_kek(monkeypatch: pytest.MonkeyPatch) -> None:
    """Proves derivation actually happens. Delete the HKDF branch and this fails."""
    kek2_b64 = _key()
    _keyring(monkeypatch, v1=_key(), v2=kek2_b64, active=2)
    provider = vault.get_key_provider()
    assert provider._wrapping_key(version=2, workspace_id=WS) != base64.b64decode(kek2_b64)
    assert len(provider._wrapping_key(version=2, workspace_id=WS)) == 32


def test_derived_workspace_keys_are_deterministic_and_separated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _keyring(monkeypatch, v1=_key(), v2=_key(), active=2)
    provider = vault.get_key_provider()
    other_ws = uuid.uuid4()
    # Deterministic: nothing is stored, so the same inputs must always give the same key.
    assert provider._wrapping_key(version=2, workspace_id=WS) == provider._wrapping_key(
        version=2, workspace_id=WS
    )
    # Separated by workspace…
    assert provider._wrapping_key(version=2, workspace_id=WS) != provider._wrapping_key(
        version=2, workspace_id=other_ws
    )


def test_derived_keys_are_separated_by_key_version(monkeypatch: pytest.MonkeyPatch) -> None:
    """Same KEK bytes at two versions must still derive different keys — the version is bound into
    the HKDF `info`, so a re-wrap is a real cryptographic change even in a pathological config."""
    shared = _key()
    monkeypatch.setattr(vault.settings, "credential_master_key", SecretStr(_key()))
    monkeypatch.setattr(
        vault.settings, "credential_master_keys", SecretStr(f"2:{shared},3:{shared}")
    )
    monkeypatch.setattr(vault.settings, "credential_key_version", 2)
    provider = vault.get_key_provider()
    assert provider._wrapping_key(version=2, workspace_id=WS) != provider._wrapping_key(
        version=3, workspace_id=WS
    )


def test_a_wrapped_dek_is_useless_in_another_workspace_even_with_matching_aad(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reason the workspace-key layer exists (ratified A3).

    AAD already binds a ciphertext to its tenant — but AAD is *application-supplied*, so a bug
    that passed the wrong workspace_id into `_aad` would defeat it. Here the AAD is deliberately
    held at the victim workspace's value (simulating exactly that bug) and the unwrap is attempted
    under the attacker workspace's derived key. It must still fail: with derivation, tenant
    isolation no longer depends on the AAD layer being correct.
    """
    _keyring(monkeypatch, v1=_key(), v2=_key(), active=2)
    victim, attacker = uuid.uuid4(), uuid.uuid4()
    sealed = seal(b"victim-secret", workspace_id=victim, connection_id=CONN)
    aad = victim.bytes + CONN.bytes  # AAD check bypassed / spoofed

    provider = vault.get_key_provider()
    with pytest.raises(VaultDecryptError):
        provider.unwrap_dek(sealed.encrypted_dek, version=2, workspace_id=attacker, aad=aad)


# ------------------------------------------------------------------ 3. re-wrap (rotation core)


def test_rewrap_moves_key_version_without_touching_the_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _keyring(monkeypatch, v1=_key(), v2=_key(), active=1)
    original = seal(b"rotate-me", workspace_id=WS, connection_id=CONN)
    assert original.key_version == 1

    rotated = vault.rewrap(original, workspace_id=WS, connection_id=CONN, to_version=2)

    # The payload is untouched — byte-identical. Rotation never rewrites ciphertext.
    assert rotated.ciphertext == original.ciphertext
    assert rotated.nonce == original.nonce
    # Only the wrapped DEK and the stamped version changed.
    assert rotated.encrypted_dek != original.encrypted_dek
    assert rotated.key_version == 2
    # And it still decrypts to the same plaintext, under the new version.
    assert _unseal(rotated, workspace_id=WS, connection_id=CONN) == b"rotate-me"


def test_rewrap_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    _keyring(monkeypatch, v1=_key(), v2=_key(), active=2)
    sealed = seal(b"x", workspace_id=WS, connection_id=CONN)
    assert vault.rewrap(sealed, workspace_id=WS, connection_id=CONN, to_version=2) is sealed


def test_rewrap_to_an_unconfigured_version_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _keyring(monkeypatch, v1=_key(), v2=None, active=1)
    sealed = seal(b"x", workspace_id=WS, connection_id=CONN)
    with pytest.raises(vault.VaultKeyVersionError):
        vault.rewrap(sealed, workspace_id=WS, connection_id=CONN, to_version=2)


def test_reading_a_row_whose_key_was_retired_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Retiring a key too early must be a loud, distinguishable failure — never silent corruption
    and never confusable with tampering (rotation must know to restore the key, not investigate)."""
    _keyring(monkeypatch, v1=_key(), v2=_key(), active=2)
    sealed = seal(b"x", workspace_id=WS, connection_id=CONN)
    _keyring(monkeypatch, v1=_key(), v2=None, active=1)  # version 2 retired
    with pytest.raises(vault.VaultKeyVersionError):
        _unseal(sealed, workspace_id=WS, connection_id=CONN)


def test_both_versions_decrypt_during_the_overlap_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """The runbook's overlap invariant: while both keys are configured, rows at either version
    remain readable. This is what makes a rotation non-disruptive."""
    _keyring(monkeypatch, v1=_key(), v2=_key(), active=1)
    old = seal(b"old-row", workspace_id=WS, connection_id=CONN)
    monkeypatch.setattr(vault.settings, "credential_key_version", 2)
    new = seal(b"new-row", workspace_id=WS, connection_id=CONN)
    assert (old.key_version, new.key_version) == (1, 2)
    assert _unseal(old, workspace_id=WS, connection_id=CONN) == b"old-row"
    assert _unseal(new, workspace_id=WS, connection_id=CONN) == b"new-row"


# ------------------------------------------------------------------ keyring configuration


def test_keyring_rejects_redeclaring_version_1(monkeypatch: pytest.MonkeyPatch) -> None:
    """Version 1 already means CREDENTIAL_MASTER_KEY. Two answers for one version is how a
    rotation silently destroys data, so it must be a boot failure."""
    monkeypatch.setattr(vault.settings, "credential_master_key", SecretStr(_key()))
    monkeypatch.setattr(vault.settings, "credential_master_keys", SecretStr(f"1:{_key()}"))
    monkeypatch.setattr(vault.settings, "credential_key_version", 1)
    with pytest.raises(VaultConfigError):
        vault.validate_master_key_configured()


@pytest.mark.parametrize(
    "bad_ring",
    [
        "2",  # no separator
        "two:AAAA",  # non-integer version
        "2:not!base64!!",  # malformed key
        "2:" + base64.b64encode(os.urandom(16)).decode(),  # wrong length
        "2:change-me",  # placeholder
        # Versions at or below 1 are reserved: 1 *is* CREDENTIAL_MASTER_KEY, and 0/negative are
        # not versions at all. Without this, a keyring could hold a version no row can ever carry
        # — and, worse, a second competing answer for version 1.
        "0:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "-1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    ],
)
def test_keyring_rejects_malformed_entries(monkeypatch: pytest.MonkeyPatch, bad_ring: str) -> None:
    monkeypatch.setattr(vault.settings, "credential_master_key", SecretStr(_key()))
    monkeypatch.setattr(vault.settings, "credential_master_keys", SecretStr(bad_ring))
    monkeypatch.setattr(vault.settings, "credential_key_version", 1)
    with pytest.raises(VaultConfigError):
        vault.validate_master_key_configured()


def test_keyring_rejects_a_duplicate_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault.settings, "credential_master_key", SecretStr(_key()))
    monkeypatch.setattr(
        vault.settings, "credential_master_keys", SecretStr(f"2:{_key()},2:{_key()}")
    )
    monkeypatch.setattr(vault.settings, "credential_key_version", 1)
    with pytest.raises(VaultConfigError):
        vault.validate_master_key_configured()


def test_active_version_must_exist_in_the_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    """A typo here would otherwise mint ciphertext nobody can ever read."""
    _keyring(monkeypatch, v1=_key(), v2=None, active=7)
    with pytest.raises(VaultConfigError):
        vault.validate_master_key_configured()
    with pytest.raises(VaultConfigError):
        seal(b"x", workspace_id=WS, connection_id=CONN)


def test_single_key_operation_is_the_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deployments that never rotate keep working with only CREDENTIAL_MASTER_KEY set."""
    _keyring(monkeypatch, v1=_key(), v2=None, active=1)
    provider = vault.get_key_provider()
    assert provider.versions == frozenset({1})
    assert provider.active_version == 1
