"""KEK rotation end to end (M2.6, ADR-0039). Real Postgres, real RLS, the real vault.

The runbook this proves is SECURITY.md §2.1 as ratified (P1): **INTRODUCE → RE-WRAP → PROVE
COMPLETION → OVERLAP → RETIRE**. Unit tests already cover the cryptography; what only real
infrastructure can show is the part that would actually hurt in production:

- a credential sealed under the **old** key keeps working the entire time (no window where a
  customer's Tool Call fails because an operator started a rotation);
- the payload is never rewritten — `ciphertext` and `nonce` come out of the database
  byte-identical, so an interrupted rotation cannot corrupt a secret;
- the completion count that gates retirement is measured **in the database**, across every
  tenant, and reaches zero only when the work is genuinely done;
- the discovery carve-out returns identifiers only, and the tenant boundary still holds while a
  platform-level job walks every workspace.
"""

from __future__ import annotations

import base64
import json
import os
import uuid

import pytest
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.domains.credentials import vault
from app.domains.credentials.models import Credential
from app.domains.credentials.repository import CredentialRepository
from app.domains.credentials.rotation import (
    RewrapOutcome,
    _context,
    count_pending,
    rewrap_credential,
)
from app.domains.runtime.secrets import open_credential_secret
from app.workers.context import worker_sessions, worker_tenant_uow
from tests.conftest import SeededWorkspace

SECRET = "M2_6_ROTATION_CANARY_value"  # noqa: S105 (synthetic test secret)


def _fresh_key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


async def seed_credential(
    engine: AsyncEngine, workspace_id: uuid.UUID, *, secret: str = SECRET
) -> tuple[uuid.UUID, uuid.UUID]:
    """A connector + connection + api_key credential sealed at **version 1**.

    Pinned explicitly rather than taking whatever version is active: these tests install a rotated
    keyring in a fixture, so a row sealed at "the current version" would be born already rotated
    and every assertion about the rotation would pass without a rotation ever happening. Version 1
    is also what a real pre-M2.6 row looks like, which is the case that matters.
    """
    connector_id, connection_id, credential_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    previous_active = vault.settings.credential_key_version
    vault.settings.credential_key_version = 1
    try:
        sealed = vault.seal(
            json.dumps({"value": secret}).encode(),
            workspace_id=workspace_id,
            connection_id=connection_id,
        )
    finally:
        vault.settings.credential_key_version = previous_active
    assert sealed.key_version == 1
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO connectors (id, workspace_id, name, slug, source_type, base_url,"
                " status) VALUES (:i,:w,'P',:s,'manual','https://api.example.com','active')"
            ),
            {"i": connector_id, "w": workspace_id, "s": f"r-{connector_id.hex[-12:]}"},
        )
        await conn.execute(
            text(
                "INSERT INTO connections (id, workspace_id, connector_id, name, status)"
                " VALUES (:i,:w,:c,:n,'active')"
            ),
            {
                "i": connection_id,
                "w": workspace_id,
                "c": connector_id,
                "n": f"c-{connection_id.hex[-12:]}",
            },
        )
        await conn.execute(
            text(
                "INSERT INTO credentials (id, workspace_id, connection_id, credential_type,"
                " ciphertext, encrypted_dek, nonce, key_version)"
                " VALUES (:i,:w,:c,'api_key',:ct,:d,:n,:kv)"
            ),
            {
                "i": credential_id,
                "w": workspace_id,
                "c": connection_id,
                "ct": sealed.ciphertext,
                "d": sealed.encrypted_dek,
                "n": sealed.nonce,
                "kv": sealed.key_version,
            },
        )
    return connection_id, credential_id


async def read_row(engine: AsyncEngine, credential_id: uuid.UUID) -> dict[str, object]:
    async with engine.begin() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT key_version, ciphertext, encrypted_dek, nonce, rotated_at"
                    " FROM credentials WHERE id = :i"
                ),
                {"i": credential_id},
            )
        ).one()
    return dict(row._mapping)


@pytest.fixture
def rotated_keyring(monkeypatch: pytest.MonkeyPatch) -> str:
    """INTRODUCE: add version 2 to the keyring while version 1 stays configured (the overlap)."""
    key2 = _fresh_key()
    monkeypatch.setattr(vault.settings, "credential_master_keys", SecretStr(f"2:{key2}"))
    monkeypatch.setattr(vault.settings, "credential_key_version", 2)
    return key2


async def _rewrap(workspace_id: uuid.UUID, credential_id: uuid.UUID, *, to: int) -> RewrapOutcome:
    async with worker_tenant_uow(str(workspace_id)) as uow:
        return await rewrap_credential(
            uow, workspace_id=workspace_id, credential_id=credential_id, to_version=to
        )


# ------------------------------------------------------------------ the runbook, end to end


@pytest.mark.asyncio
async def test_rotation_preserves_the_payload_and_the_secret(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, rotated_keyring: str
) -> None:
    """The central claim: a rotation re-wraps the data key and touches nothing else."""
    connection_id, credential_id = await seed_credential(admin_engine, workspace_a.id)
    before = await read_row(admin_engine, credential_id)
    assert before["key_version"] == 1

    assert await _rewrap(workspace_a.id, credential_id, to=2) is RewrapOutcome.REWRAPPED

    after = await read_row(admin_engine, credential_id)
    assert after["key_version"] == 2
    # The payload is untouched, in the database, byte for byte.
    assert after["ciphertext"] == before["ciphertext"]
    assert after["nonce"] == before["nonce"]
    assert after["encrypted_dek"] != before["encrypted_dek"]
    # `rotated_at` means "the secret was re-sealed". A re-wrap did not change the secret, so
    # stamping it would make an operational key rotation look like a customer credential rotation.
    assert after["rotated_at"] is None


@pytest.mark.asyncio
async def test_the_credential_still_decrypts_after_rotation(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, rotated_keyring: str
) -> None:
    """What the customer experiences: nothing. The same plaintext, through the same boundary."""
    connection_id, credential_id = await seed_credential(admin_engine, workspace_a.id)
    await _rewrap(workspace_a.id, credential_id, to=2)

    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        credential = await uow.session.get(Credential, credential_id)
        assert credential is not None
        secret = open_credential_secret(
            credential, workspace_id=workspace_a.id, connection_id=connection_id
        )
    assert secret.value == SECRET


@pytest.mark.asyncio
async def test_an_unrotated_credential_keeps_working_during_the_overlap(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, rotated_keyring: str
) -> None:
    """There must be no window where starting a rotation breaks live traffic. A row still at
    version 1, while version 2 is active, decrypts normally — that is what the overlap buys."""
    connection_id, credential_id = await seed_credential(admin_engine, workspace_a.id)
    assert (await read_row(admin_engine, credential_id))["key_version"] == 1

    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        credential = await uow.session.get(Credential, credential_id)
        assert credential is not None
        secret = open_credential_secret(
            credential, workspace_id=workspace_a.id, connection_id=connection_id
        )
    assert secret.value == SECRET


# ------------------------------------------------------------------ PROVE COMPLETION / discovery


@pytest.mark.asyncio
async def test_the_retirement_gate_reaches_zero_only_when_the_work_is_done(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    rotated_keyring: str,
) -> None:
    """The database is the authority for completion — never a timer, never a job's exit status.

    Two tenants, so the count is genuinely platform-wide: retiring a key while *another* tenant
    still depends on it is precisely the mistake this gate exists to prevent.
    """
    _, credential_a = await seed_credential(admin_engine, workspace_a.id)
    _, credential_b = await seed_credential(admin_engine, workspace_b.id)

    async with worker_sessions() as session:
        before = await count_pending(session, target_version=2)
    assert before >= 2  # both tenants' rows are outstanding

    await _rewrap(workspace_a.id, credential_a, to=2)
    async with worker_sessions() as session:
        # Strictly fewer, but NOT zero: one tenant is done, the other is not. An operator who
        # retired the old key here — "the job reported success" — would destroy workspace B.
        assert await count_pending(session, target_version=2) == before - 1

    # Drain everything still below the target, exactly as repeated sweeps would. The gate opens
    # only when the *database* says the work is done, not when a batch reports success.
    while True:
        async with worker_sessions() as session:
            rows = (
                await session.execute(
                    text("SELECT * FROM auth.pending_key_rotations(:t, :l)"), {"t": 2, "l": 500}
                )
            ).all()
        if not rows:
            break
        for row in rows:
            await _rewrap(row.workspace_id, row.credential_id, to=2)

    async with worker_sessions() as session:
        assert await count_pending(session, target_version=2) == 0
    assert (await read_row(admin_engine, credential_b))["key_version"] == 2


@pytest.mark.asyncio
async def test_discovery_returns_identifiers_only(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, rotated_keyring: str
) -> None:
    """The carve-out runs before any workspace is bound, so it must not be able to become a
    cross-tenant secret read. It returns two ids and nothing else."""
    _, credential_id = await seed_credential(admin_engine, workspace_a.id)
    async with worker_sessions() as session:
        rows = (
            await session.execute(
                text("SELECT * FROM auth.pending_key_rotations(:t, :l)"), {"t": 2, "l": 500}
            )
        ).all()
    assert set(rows[0]._mapping) == {"workspace_id", "credential_id"}
    assert credential_id in {row.credential_id for row in rows}


# ------------------------------------------------------------------ safety properties


@pytest.mark.asyncio
async def test_rewrap_is_idempotent_across_repeated_runs(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, rotated_keyring: str
) -> None:
    """A retried task, or two sweeps overlapping, must not corrupt anything."""
    _, credential_id = await seed_credential(admin_engine, workspace_a.id)
    assert await _rewrap(workspace_a.id, credential_id, to=2) is RewrapOutcome.REWRAPPED
    first = await read_row(admin_engine, credential_id)
    assert await _rewrap(workspace_a.id, credential_id, to=2) is RewrapOutcome.ALREADY_CURRENT
    assert await read_row(admin_engine, credential_id) == first


@pytest.mark.asyncio
async def test_rewrap_cannot_reach_another_tenants_credential(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    workspace_b: SeededWorkspace,
    rotated_keyring: str,
) -> None:
    """A platform-level job still runs each unit of work under one tenant. Asking workspace A's
    context to re-wrap workspace B's credential finds nothing — RLS plus explicit scoping, not
    the job's good manners."""
    _, credential_b = await seed_credential(admin_engine, workspace_b.id)
    assert await _rewrap(workspace_a.id, credential_b, to=2) is RewrapOutcome.GONE
    assert (await read_row(admin_engine, credential_b))["key_version"] == 1


@pytest.mark.asyncio
async def test_a_deleted_credential_is_reported_gone_not_crashed(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, rotated_keyring: str
) -> None:
    """Discovery and execution are separated by a queue, so the row can be revoked in between."""
    _, credential_id = await seed_credential(admin_engine, workspace_a.id)
    async with admin_engine.begin() as conn:
        await conn.execute(text("DELETE FROM credentials WHERE id = :i"), {"i": credential_id})
    assert await _rewrap(workspace_a.id, credential_id, to=2) is RewrapOutcome.GONE


@pytest.mark.asyncio
async def test_repository_scoping_holds_even_without_rls(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace, workspace_b: SeededWorkspace
) -> None:
    """Isolates the repository's own `workspace_id` filter from RLS (P-14, defense in depth).

    The cross-tenant test above passes on RLS alone — deleting the repository's explicit predicate
    would not fail it, which a mutation audit confirmed. So this asks the same question on a
    connection RLS does not constrain, leaving the repository filter as the only thing standing.
    Two independent controls are only two controls if each is tested without the other.
    """
    _, credential_b = await seed_credential(admin_engine, workspace_b.id)
    async with AsyncSession(admin_engine) as session:
        # The premise: this connection really can see the row. Without it the assertion below
        # would pass for the wrong reason — an invisible row and a filtered row look identical.
        visible = (
            await session.execute(
                text("SELECT count(*) FROM credentials WHERE id = :i"), {"i": credential_b}
            )
        ).scalar_one()
        assert visible == 1, "premise failed: the admin connection is subject to RLS here"

        repository = CredentialRepository(session, _context(workspace_a.id))
        assert await repository.credential_for_update(credential_b) is None
