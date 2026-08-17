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
    # Unwrap the DEK from two seals of the same input under the same KEK/AAD: they must differ (a
    # fresh 256-bit DEK per encryption), not a static or derived key.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    kek = vault._load_master_key()
    aad = WS.bytes + CONN.bytes

    def dek_of(sealed: vault.SealedSecret) -> bytes:
        wrap_nonce, wrapped = sealed.encrypted_dek[:12], sealed.encrypted_dek[12:]
        return AESGCM(kek).decrypt(wrap_nonce, wrapped, aad)

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
    assert vault._load_master_key().__len__() == 32
