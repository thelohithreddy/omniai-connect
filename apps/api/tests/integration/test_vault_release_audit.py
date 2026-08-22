"""M2.6 release audit — the deliberate red-team pass (EC3, ADR-0039).

Not a unit test of a control. This drives a credential through its **entire** life — sealed,
executed, key-rotated, re-read — with a canary secret, and then goes looking for that canary
everywhere it could plausibly have escaped: every column of every table in the database, the
structured log stream, and the arguments handed to Celery. EC3 is satisfied only if the answer is
zero, everywhere.

The sweep is deliberately blunt rather than targeted. A test that checks the three places the
author *expected* a leak proves only that the author's imagination is intact; casting every row of
every table to text and searching for the canary finds the place nobody thought of. That is the
whole point of a red-team pass, and it is why the scan enumerates `information_schema` instead of
a hand-written list of tables that would silently go stale the next time someone adds one.
"""

from __future__ import annotations

import base64
import inspect
import json
import os
import uuid

import pytest
import structlog
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.logging import configure_logging
from app.domains.credentials import vault
from app.domains.credentials.models import Credential
from app.domains.credentials.rotation import RewrapOutcome, rewrap_credential
from app.domains.runtime import secrets as secrets_module
from app.domains.runtime.secrets import open_credential_secret
from app.workers.context import worker_tenant_uow
from tests.conftest import SeededWorkspace
from tests.integration.test_vault_key_rotation import read_row, seed_credential

#: Distinctive enough that a match cannot be coincidence, and shaped like a real key.
CANARY = "M2_6_REDTEAM_CANARY_0f3a9d7c"  # noqa: S105 (synthetic test secret)


@pytest.fixture
def emitted_logs(monkeypatch: pytest.MonkeyPatch):
    """Capture the log stream without depending on structlog's logger cache — see the note in
    tests/unit/test_vault_audit.py. A red-team scan that silently captured nothing would report a
    clean bill of health for an empty haystack."""
    captured: list[dict] = []

    def capture(_logger, _method, event_dict):
        captured.append(dict(event_dict))
        return event_dict

    structlog.configure(
        processors=[capture],
        wrapper_class=structlog.make_filtering_bound_logger(10),
        logger_factory=structlog.ReturnLoggerFactory(),
        cache_logger_on_first_use=False,
    )
    # Reconfiguring is not enough on its own: `secrets.log` is a module-level lazy proxy and
    # `cache_logger_on_first_use=True` means it binds its processors once, on first use, and keeps
    # them. If any earlier test opened a credential, that proxy is already bound to the production
    # chain and would ignore the capture entirely — which is exactly how these assertions passed
    # alone and failed in a full run. Swapping in a fresh, unbound proxy is what makes the capture
    # actually observe the boundary; monkeypatch restores the original afterwards.
    monkeypatch.setattr(secrets_module, "log", structlog.get_logger("m26-audit-capture"))
    try:
        yield captured
    finally:
        configure_logging()


@pytest.fixture
def rotated_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        vault.settings,
        "credential_master_keys",
        SecretStr(f"2:{base64.b64encode(os.urandom(32)).decode()}"),
    )
    monkeypatch.setattr(vault.settings, "credential_key_version", 2)


async def scan_database_for(engine: AsyncEngine, needle: str) -> list[str]:
    """Every row of every public table, cast to text, searched for `needle`.

    `bytea` renders as `\\x…` hex under this cast, so ciphertext cannot produce a false positive —
    and equally, a *plaintext* secret mistakenly stored in a bytea column would still be invisible
    here, which is why the hex form is searched too.
    """
    hits: list[str] = []
    encoded = needle.encode().hex()
    async with engine.connect() as conn:
        tables = [
            row[0]
            for row in (
                await conn.execute(
                    text(
                        "SELECT table_name FROM information_schema.tables"
                        " WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
                    )
                )
            ).all()
        ]
        assert tables, "table discovery returned nothing — the scan would vacuously pass"
        for table in tables:
            found = (
                await conn.execute(
                    text(
                        # Identifier comes from information_schema, never from user input.
                        f'SELECT count(*) FROM public."{table}" t'  # noqa: S608
                        " WHERE t::text ILIKE :needle OR t::text ILIKE :hex"
                    ),
                    {"needle": f"%{needle}%", "hex": f"%{encoded}%"},
                )
            ).scalar_one()
            if found:
                hits.append(f"{table} ({found} row(s))")
    return hits


@pytest.mark.asyncio
async def test_no_plaintext_anywhere_after_a_full_lifecycle(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    rotated_keyring: None,
    emitted_logs: list,
) -> None:
    """Seal → read → rotate → read again, then hunt the canary through the whole database."""
    connection_id, credential_id = await seed_credential(
        admin_engine, workspace_a.id, secret=CANARY
    )

    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        credential = await uow.session.get(Credential, credential_id)
        assert credential is not None
        assert (
            open_credential_secret(
                credential, workspace_id=workspace_a.id, connection_id=connection_id
            ).value
            == CANARY
        )

    assert (
        await rewrap_credential_in_context(workspace_a.id, credential_id) is RewrapOutcome.REWRAPPED
    )

    async with worker_tenant_uow(str(workspace_a.id)) as uow:
        credential = await uow.session.get(Credential, credential_id)
        assert credential is not None
        # Still the same secret after rotation — the lifecycle really did complete.
        assert (
            open_credential_secret(
                credential, workspace_id=workspace_a.id, connection_id=connection_id
            ).value
            == CANARY
        )

    assert (await read_row(admin_engine, credential_id))["key_version"] == 2

    hits = await scan_database_for(admin_engine, CANARY)
    assert hits == [], f"plaintext canary found in: {hits}"

    rendered = json.dumps(emitted_logs, default=str)
    assert CANARY not in rendered, "canary reached the log stream"


async def rewrap_credential_in_context(
    workspace_id: uuid.UUID, credential_id: uuid.UUID
) -> RewrapOutcome:
    async with worker_tenant_uow(str(workspace_id)) as uow:
        return await rewrap_credential(
            uow, workspace_id=workspace_id, credential_id=credential_id, to_version=2
        )


@pytest.mark.asyncio
async def test_the_scan_would_actually_catch_a_leak(
    admin_engine: AsyncEngine, workspace_a: SeededWorkspace
) -> None:
    """A negative result is worthless without evidence the instrument works.

    Plants the canary in a real column, confirms the sweep finds it, then removes it. Without
    this, `assert hits == []` above would pass just as happily if the scan were broken.
    """
    connection_id, _ = await seed_credential(
        admin_engine,
        workspace_a.id,
        secret="unrelated",  # noqa: S106 (synthetic test secret)
    )
    async with admin_engine.begin() as conn:
        await conn.execute(
            text("UPDATE connections SET name = :n WHERE id = :i"),
            {"n": CANARY, "i": connection_id},
        )
    try:
        assert await scan_database_for(admin_engine, CANARY) != []
    finally:
        async with admin_engine.begin() as conn:
            await conn.execute(
                text("UPDATE connections SET name = :n WHERE id = :i"),
                {"n": f"c-{connection_id.hex[-12:]}", "i": connection_id},
            )
    assert await scan_database_for(admin_engine, CANARY) == []


# ------------------------------------------------------------------ Celery payload discipline


def test_rotation_task_signatures_accept_only_identifiers() -> None:
    """Task arguments are JSON at rest in the broker, so key material in a signature would be a
    plaintext secret in Redis. Asserted structurally, not by inspecting one call site."""
    from app.workers import vault_tasks

    assert list(inspect.signature(vault_tasks.rewrap_credential_key).parameters) == [
        "workspace_id",
        "credential_id",
    ]
    source = inspect.getsource(vault_tasks)
    for forbidden in ("dek=", "kek=", "ciphertext=", "plaintext=", "secret=", "master_key="):
        assert forbidden not in source, f"{forbidden} appears in a task module"


@pytest.mark.asyncio
async def test_the_sweep_enqueues_identifiers_and_nothing_else(
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    rotated_keyring: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The signature test proves what the task *accepts*; this proves what the sweep *sends*.

    A future change could pass an extra positional argument at the call site without touching the
    signature, so the actual dispatch is captured and every argument is required to be a UUID.
    """
    await seed_credential(admin_engine, workspace_a.id, secret=CANARY)
    from app.workers import vault_tasks

    captured: list[dict[str, object]] = []
    monkeypatch.setattr(
        vault_tasks.rewrap_credential_key,
        "apply_async",
        lambda **kwargs: captured.append(kwargs),
    )
    await vault_tasks._sweep()

    assert captured, "the sweep discovered nothing — the assertion below would be vacuous"
    for call in captured:
        for argument in call["args"]:
            uuid.UUID(str(argument))  # raises unless every argument is an identifier
        assert CANARY not in json.dumps(call, default=str)


# ------------------------------------------------------------------ encapsulation still holds


def test_the_decrypt_boundary_did_not_widen() -> None:
    """M2.6 added a re-wrap path that handles data keys, so the obvious regression is a second
    module learning to decrypt payloads. The private recovery function must still be referenced by
    exactly the vault and the runtime's secrets module — rotation re-wraps, it does not unseal."""
    from pathlib import Path

    root = Path(inspect.getfile(vault)).parents[2]  # apps/api/app
    referencing = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*.py")
        if "_unseal" in path.read_text()
    )
    assert referencing == ["domains/credentials/vault.py", "domains/runtime/secrets.py"]
