"""The runtime's private credential-decrypt boundary (M1 Execution Runtime, SECURITY §2.1)."""

from __future__ import annotations

import json
import pathlib
import uuid

import pytest

from app.domains.credentials.models import Credential
from app.domains.credentials.vault import VaultDecryptError, seal
from app.domains.runtime.secrets import CredentialSecret, open_credential_secret

WS = uuid.uuid4()
CONN = uuid.uuid4()


def _sealed(
    secret: dict[str, str], credential_type: str, *, ws: uuid.UUID = WS, conn: uuid.UUID = CONN
) -> Credential:
    """An in-memory Credential row carrying real sealed ciphertext (no DB)."""
    sealed = seal(json.dumps(secret).encode("utf-8"), workspace_id=ws, connection_id=conn)
    return Credential(
        ciphertext=sealed.ciphertext,
        encrypted_dek=sealed.encrypted_dek,
        nonce=sealed.nonce,
        key_version=sealed.key_version,
        credential_type=credential_type,
    )


def test_round_trips_a_bearer_value() -> None:
    secret = open_credential_secret(
        _sealed({"value": "tok-123"}, "bearer"), workspace_id=WS, connection_id=CONN
    )
    assert secret.credential_type == "bearer"
    assert secret.value == "tok-123"


def test_round_trips_basic_username_password() -> None:
    row = _sealed({"username": "u", "password": "p"}, "basic")
    secret = open_credential_secret(row, workspace_id=WS, connection_id=CONN)
    assert (secret.username, secret.password) == ("u", "p")


def test_wrong_workspace_aad_fails_closed() -> None:
    row = _sealed({"value": "x"}, "bearer")
    with pytest.raises(VaultDecryptError):
        open_credential_secret(row, workspace_id=uuid.uuid4(), connection_id=CONN)


def test_wrong_connection_aad_fails_closed() -> None:
    row = _sealed({"value": "x"}, "bearer")
    with pytest.raises(VaultDecryptError):
        open_credential_secret(row, workspace_id=WS, connection_id=uuid.uuid4())


def test_tampered_ciphertext_fails_closed() -> None:
    row = _sealed({"value": "x"}, "bearer")
    row.ciphertext = row.ciphertext[:-1] + bytes([row.ciphertext[-1] ^ 0x01])
    with pytest.raises(VaultDecryptError):
        open_credential_secret(row, workspace_id=WS, connection_id=CONN)


def test_credential_secret_repr_is_redacted() -> None:
    secret = CredentialSecret("bearer", value="super-secret-token")
    assert "super-secret-token" not in repr(secret)
    assert "redacted" in repr(secret)
    assert "super-secret-token" not in f"{secret}"


def test_unseal_is_referenced_only_by_vault_and_runtime_secrets() -> None:
    """The decrypt encapsulation invariant: nothing else may reference the private `_unseal`."""
    app_root = pathlib.Path(__file__).resolve().parents[2] / "app"
    referencing = {
        p.relative_to(app_root).as_posix()
        for p in app_root.rglob("*.py")
        if "_unseal" in p.read_text(encoding="utf-8")
    }
    # Only the vault (which defines it) and the runtime decrypt accessor may name `_unseal`.
    assert referencing <= {"domains/credentials/vault.py", "domains/runtime/secrets.py"}, (
        referencing
    )
