"""Credentials domain against real Postgres + RLS (M1-Credentials-v1).

Real tenant-bound sessions (RLS active). Proves: attach envelope-encrypts and moves the Connection
`pending_auth → active`; the stored row holds only ciphertext (no plaintext at rest) yet decrypts
back through the vault; rotate re-seals with a fresh DEK/nonce and sets `rotated_at`; revoke
hard-deletes and returns the Connection to `pending_auth`; a second attach is a 409; RLS keeps one
tenant's credential invisible and unreachable to another; concurrent attaches don't double-write.
"""

from __future__ import annotations

import asyncio
import json
import uuid

import pytest
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.exceptions import ConflictError, NotFoundError
from app.core.security import CallerIdentity, WorkspaceContext
from app.domains.credentials import vault
from app.domains.credentials.models import Credential
from app.domains.credentials.repository import CredentialRepository
from app.domains.credentials.schemas import CredentialWrite
from app.domains.credentials.service import CredentialService
from app.workers.context import worker_tenant_uow
from tests.conftest import SeededWorkspace

SECRET = "sk-live-super-secret-value"  # noqa: S105 (test secret)


def _svc(session: object, workspace_id: uuid.UUID) -> CredentialService:
    ctx = WorkspaceContext(
        workspace_id=workspace_id,
        caller=CallerIdentity(kind="api_token", api_token_id=uuid.uuid4()),
        request_id="req_test",
    )
    return CredentialService(CredentialRepository(session, ctx))  # type: ignore[arg-type]


def _api_key(secret: str = SECRET) -> CredentialWrite:
    return CredentialWrite(credential_type="api_key", value=SecretStr(secret))


async def _seed_connection(
    engine: AsyncEngine, workspace_id: uuid.UUID, *, status: str = "pending_auth"
) -> uuid.UUID:
    connector_id, connection_id = uuid.uuid4(), uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO connectors"
                " (id, workspace_id, name, slug, source_type, base_url, status)"
                " VALUES (:i,:w,'c',:s,'manual','https://api.demo.com','active')"
            ),
            {"i": connector_id, "w": workspace_id, "s": f"c-{connector_id.hex[:8]}"},
        )
        await conn.execute(
            text(
                "INSERT INTO connections (id, workspace_id, connector_id, name, status)"
                " VALUES (:i,:w,:c,:n,:st)"
            ),
            {
                "i": connection_id,
                "w": workspace_id,
                "c": connector_id,
                "n": f"conn-{connection_id.hex[:8]}",
                "st": status,
            },
        )
    return connection_id


# ------------------------------------------------------------------ attach / at-rest


async def test_attach_encrypts_activates_and_stores_no_plaintext(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    conn_id = await _seed_connection(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        cred = await _svc(uow.session, workspace_a.id).attach(conn_id, _api_key())
        cred_id = cred.id

    async with admin_engine.connect() as c:
        row = (
            await c.execute(
                text(
                    "SELECT credential_type, ciphertext, encrypted_dek, nonce, key_version,"
                    " rotated_at FROM credentials WHERE id=:i"
                ),
                {"i": cred_id},
            )
        ).one()
        connection = (
            await c.execute(
                text("SELECT status, credential_id FROM connections WHERE id=:c"), {"c": conn_id}
            )
        ).one()
    # The Connection is now active and points at the credential (§3 invariant).
    assert connection.status == "active" and connection.credential_id == cred_id
    assert row.credential_type == "api_key" and row.key_version == 1 and row.rotated_at is None
    # No plaintext at rest: the secret bytes appear nowhere in the stored material.
    for column in (row.ciphertext, row.encrypted_dek, row.nonce):
        assert SECRET.encode() not in bytes(column)
    # …yet the ciphertext decrypts back to the secret through the vault (DB round-trip).
    sealed = vault.SealedSecret(
        bytes(row.ciphertext), bytes(row.encrypted_dek), bytes(row.nonce), row.key_version
    )
    plaintext = vault._unseal(sealed, workspace_id=workspace_a.id, connection_id=conn_id)
    assert json.loads(plaintext) == {"value": SECRET}


async def test_a_second_attach_is_a_conflict(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    conn_id = await _seed_connection(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await _svc(uow.session, workspace_a.id).attach(conn_id, _api_key())
    with pytest.raises(ConflictError):
        async with worker_tenant_uow(str(workspace_a.id)) as uow:
            await _svc(uow.session, workspace_a.id).attach(conn_id, _api_key("other"))


async def test_attach_to_a_foreign_connection_is_not_found(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    a_conn = await _seed_connection(admin_engine, workspace_a.id)
    with pytest.raises(NotFoundError):
        async with worker_tenant_uow(str(workspace_b.id)) as uow:
            await _svc(uow.session, workspace_b.id).attach(a_conn, _api_key())


# ------------------------------------------------------------------ basic type


async def test_basic_credential_seals_username_and_password(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    conn_id = await _seed_connection(admin_engine, workspace_a.id)
    payload = CredentialWrite(
        credential_type="basic", username="alice", password=SecretStr("pw-123")
    )
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        cred = await _svc(uow.session, workspace_a.id).attach(conn_id, payload)
        cid = cred.id
    async with admin_engine.connect() as c:
        row = (
            await c.execute(
                text(
                    "SELECT ciphertext, encrypted_dek, nonce, key_version"
                    " FROM credentials WHERE id=:i"
                ),
                {"i": cid},
            )
        ).one()
    assert b"pw-123" not in bytes(row.ciphertext)  # password not at rest
    sealed = vault.SealedSecret(
        bytes(row.ciphertext), bytes(row.encrypted_dek), bytes(row.nonce), row.key_version
    )
    assert json.loads(
        vault._unseal(sealed, workspace_id=workspace_a.id, connection_id=conn_id)
    ) == {
        "username": "alice",
        "password": "pw-123",
    }


# ------------------------------------------------------------------ rotate / revoke


async def test_rotate_reseals_with_fresh_material(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    conn_id = await _seed_connection(admin_engine, workspace_a.id)
    async with admin_engine.connect() as c:
        pass
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await _svc(uow.session, workspace_a.id).attach(conn_id, _api_key("first"))
    async with admin_engine.connect() as c:
        before = (
            await c.execute(
                text(
                    "SELECT ciphertext, encrypted_dek, nonce"
                    " FROM credentials WHERE connection_id=:c"
                ),
                {"c": conn_id},
            )
        ).one()
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await _svc(uow.session, workspace_a.id).rotate(conn_id, _api_key("second"))
    async with admin_engine.connect() as c:
        after = (
            await c.execute(
                text(
                    "SELECT ciphertext, encrypted_dek, nonce, rotated_at FROM credentials"
                    " WHERE connection_id=:c"
                ),
                {"c": conn_id},
            )
        ).one()
        status = await c.scalar(text("SELECT status FROM connections WHERE id=:c"), {"c": conn_id})
    assert bytes(after.ciphertext) != bytes(before.ciphertext)  # fresh nonce/DEK
    assert bytes(after.encrypted_dek) != bytes(before.encrypted_dek)
    assert bytes(after.nonce) != bytes(before.nonce)
    assert after.rotated_at is not None
    assert status == "active"  # rotation keeps the connection active
    sealed = vault.SealedSecret(
        bytes(after.ciphertext), bytes(after.encrypted_dek), bytes(after.nonce), 1
    )
    assert json.loads(
        vault._unseal(sealed, workspace_id=workspace_a.id, connection_id=conn_id)
    ) == {"value": "second"}


async def test_revoke_hard_deletes_and_resets_the_connection(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    conn_id = await _seed_connection(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await _svc(uow.session, workspace_a.id).attach(conn_id, _api_key())
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        svc = _svc(uow.session, workspace_a.id)
        await svc.revoke(conn_id)
        with pytest.raises(NotFoundError):  # gone → uniform 404
            await svc.get(conn_id)
        with pytest.raises(NotFoundError):  # second revoke matches nothing
            await svc.revoke(conn_id)
    async with admin_engine.connect() as c:
        count = await c.scalar(
            text("SELECT count(*) FROM credentials WHERE connection_id=:c"), {"c": conn_id}
        )
        connection = (
            await c.execute(
                text("SELECT status, credential_id FROM connections WHERE id=:c"), {"c": conn_id}
            )
        ).one()
    assert count == 0  # hard delete — no soft-delete row retained
    assert connection.status == "pending_auth" and connection.credential_id is None


# ------------------------------------------------------------------ rollback / concurrency / RLS


async def test_rollback_persists_no_credential(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    conn_id = await _seed_connection(admin_engine, workspace_a.id)
    with pytest.raises(RuntimeError):
        async with worker_tenant_uow(str(workspace_a.id)) as uow:
            await _svc(uow.session, workspace_a.id).attach(conn_id, _api_key())
            raise RuntimeError("boom before commit")
    async with admin_engine.connect() as c:
        count = await c.scalar(
            text("SELECT count(*) FROM credentials WHERE connection_id=:c"), {"c": conn_id}
        )
        status = await c.scalar(text("SELECT status FROM connections WHERE id=:c"), {"c": conn_id})
    assert count == 0 and status == "pending_auth"  # nothing committed


async def test_concurrent_attach_never_double_writes(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    conn_id = await _seed_connection(admin_engine, workspace_a.id)

    async def attach() -> Credential:
        async with worker_tenant_uow(str(workspace_a.id)) as uow:
            return await _svc(uow.session, workspace_a.id).attach(conn_id, _api_key())

    results = await asyncio.gather(attach(), attach(), return_exceptions=True)
    ok = [r for r in results if isinstance(r, Credential)]
    conflicts = [r for r in results if isinstance(r, ConflictError)]
    assert len(ok) == 1 and len(conflicts) == 1  # the connection row lock + unique index serialize
    async with admin_engine.connect() as c:
        count = await c.scalar(
            text("SELECT count(*) FROM credentials WHERE connection_id=:c"), {"c": conn_id}
        )
    assert count == 1


async def test_rls_hides_a_foreign_tenants_credential(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    a_conn = await _seed_connection(admin_engine, workspace_a.id)
    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        await _svc(uow.session, workspace_a.id).attach(a_conn, _api_key())
    # B, under its own bound context, can neither read nor revoke A's credential.
    async with worker_tenant_uow(str(workspace_b.id)) as uow:
        b_svc = _svc(uow.session, workspace_b.id)
        with pytest.raises(NotFoundError):
            await b_svc.get(a_conn)
        with pytest.raises(NotFoundError):
            await b_svc.revoke(a_conn)
    async with admin_engine.connect() as c:
        count = await c.scalar(
            text("SELECT count(*) FROM credentials WHERE connection_id=:c"), {"c": a_conn}
        )
    assert count == 1  # A's credential untouched
