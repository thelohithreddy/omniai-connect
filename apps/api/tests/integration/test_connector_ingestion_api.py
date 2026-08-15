"""Ingestion endpoint through the real app (M1.4-B1.1): POST /v1/connectors/{id}/versions.

Real HTTP, real Postgres with RLS, real centralized RBAC, the real event bus. The Celery enqueue
(the post-commit handoff to the worker) is captured rather than sent to Redis, so the test asserts
*that* the pipeline is enqueued — with the trusted workspace, connector, and source_url — after the
`ingesting` transition commits, and never before. Authorization, tenant isolation, and the
server-established workspace are not mocked.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine

import app.workers.tasks as tasks
from app.core.object_store import TenantObjectKey, get_object_store
from tests.conftest import FakeJWKSEndpoint, SeededWorkspace, SigningAuthority, bearer
from tests.integration.test_human_auth import seed_member

WS_HEADER = "X-Workspace-Id"
SOURCE_URL = "https://api.example.com/openapi.json"


def hx(token: str, workspace_id: uuid.UUID) -> dict[str, str]:
    return {**bearer(token), WS_HEADER: str(workspace_id)}


@pytest.fixture
def captured_enqueue(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    """Capture ingest_connector_spec.apply_async instead of sending to Redis."""
    calls: list[dict[str, object]] = []

    def _capture(*, args: list[object], queue: str) -> None:
        calls.append({"args": args, "queue": queue})

    monkeypatch.setattr(tasks.ingest_connector_spec, "apply_async", _capture)
    return calls


@pytest.fixture
async def owner(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
) -> AsyncIterator[dict[str, object]]:
    client, _ = human_client
    await seed_member(admin_engine, workspace_a.id, user_id="ing-owner", role="owner")
    yield {"client": client, "ws": workspace_a.id, "token": authority.sign("ing-owner")}


async def _make_connector(owner: dict[str, object], slug: str = "demo") -> str:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    resp = await client.post(
        "/v1/connectors",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
        json={"name": "Demo", "base_url": "https://api.example.com/v1", "slug": slug},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def test_ingest_returns_202_marks_ingesting_and_enqueues(
    owner: dict[str, object], captured_enqueue: list[dict[str, object]]
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    cid = await _make_connector(owner)

    resp = await client.post(
        f"/v1/connectors/{cid}/versions",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
        data={"source_url": SOURCE_URL},
    )
    assert resp.status_code == 202, resp.text
    assert resp.json()["status"] == "ingesting"

    # The task was enqueued post-commit with the trusted workspace + connector + url (+ empty
    # upload_ref, since this is URL ingestion).
    assert len(captured_enqueue) == 1
    assert captured_enqueue[0]["args"] == [str(owner["ws"]), cid, SOURCE_URL, ""]
    assert captured_enqueue[0]["queue"] == "ingestion"


@pytest.mark.parametrize(("role", "expected"), [("member", 403), ("viewer", 403)])
async def test_ingest_requires_connectors_manage(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    owner: dict[str, object],
    captured_enqueue: list[dict[str, object]],
    role: str,
    expected: int,
) -> None:
    client, _ = human_client
    cid = await _make_connector(owner)  # created by the owner
    await seed_member(admin_engine, workspace_a.id, user_id=f"ing-{role}", role=role)
    resp = await client.post(
        f"/v1/connectors/{cid}/versions",
        headers=hx(authority.sign(f"ing-{role}"), workspace_a.id),
        data={"source_url": SOURCE_URL},
    )
    assert resp.status_code == expected
    assert captured_enqueue == []  # denied → nothing enqueued


async def test_ingest_unknown_connector_is_404(
    owner: dict[str, object], captured_enqueue: list[dict[str, object]]
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    resp = await client.post(
        f"/v1/connectors/{uuid.uuid4()}/versions",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
        data={"source_url": SOURCE_URL},
    )
    assert resp.status_code == 404
    assert captured_enqueue == []


async def test_ingest_already_ingesting_is_409(
    owner: dict[str, object], captured_enqueue: list[dict[str, object]]
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    cid = await _make_connector(owner)
    first = await client.post(
        f"/v1/connectors/{cid}/versions",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
        data={"source_url": SOURCE_URL},
    )
    assert first.status_code == 202
    second = await client.post(
        f"/v1/connectors/{cid}/versions",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
        data={"source_url": SOURCE_URL},
    )
    assert second.status_code == 409


async def test_ingest_rejects_non_https_source_url(
    owner: dict[str, object], captured_enqueue: list[dict[str, object]]
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    cid = await _make_connector(owner)
    resp = await client.post(
        f"/v1/connectors/{cid}/versions",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
        data={"source_url": "http://api.example.com/openapi.json"},
    )
    assert resp.status_code == 400  # validation → standard 400 envelope
    assert captured_enqueue == []


async def test_ingest_rejects_a_smuggled_workspace_id(
    owner: dict[str, object], captured_enqueue: list[dict[str, object]]
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    cid = await _make_connector(owner)
    resp = await client.post(
        f"/v1/connectors/{cid}/versions",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
        data={"source_url": SOURCE_URL, "workspace_id": str(uuid.uuid4())},
    )
    assert resp.status_code == 400  # extra="forbid" → 400 envelope
    assert captured_enqueue == []


async def test_ingest_a_foreign_workspaces_connector_is_404(
    owner: dict[str, object],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_b: SeededWorkspace,
    captured_enqueue: list[dict[str, object]],
) -> None:
    """An owner of B cannot ingest A's connector — a uniform 404, and nothing enqueued."""
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    a_cid = await _make_connector(owner)  # belongs to workspace A
    await seed_member(admin_engine, workspace_b.id, user_id="b-owner", role="owner")
    resp = await client.post(
        f"/v1/connectors/{a_cid}/versions",
        headers=hx(authority.sign("b-owner"), workspace_b.id),  # acting in B
        data={"source_url": SOURCE_URL},
    )
    assert resp.status_code == 404
    assert captured_enqueue == []


# ------------------------------------------------------------------ file upload (M1.4-B1.2)
#
# The upload path stages the raw bytes to the real ObjectStore (MinIO) before enqueuing, so these
# assert both the 202/enqueue contract AND that the staged object lands under the tenant key.

SPEC_JSON = json.dumps(
    {"openapi": "3.0.0", "paths": {"/x": {"get": {"operationId": "x"}}}}
).encode()
SPEC_YAML = b"openapi: '3.0.0'\npaths:\n  /x:\n    get:\n      operationId: x\n"


async def test_upload_json_returns_202_stages_and_enqueues(
    owner: dict[str, object], captured_enqueue: list[dict[str, object]]
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    cid = await _make_connector(owner)
    resp = await client.post(
        f"/v1/connectors/{cid}/versions",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
        files={"file": ("openapi.json", SPEC_JSON, "application/json")},
    )
    assert resp.status_code == 202, resp.text
    assert resp.json()["status"] == "ingesting"

    # Enqueued with an upload_ref (not a URL), workspace-relative under this connector.
    assert len(captured_enqueue) == 1
    ws, connector, source_url, upload_ref = captured_enqueue[0]["args"]  # type: ignore[misc]
    assert ws == str(owner["ws"]) and connector == cid and source_url == ""
    assert upload_ref.startswith(f"connectors/{cid}/uploads/") and upload_ref.endswith(".json")

    # The staged object exists under the tenant key with the exact bytes.
    body = await get_object_store().get(
        TenantObjectKey.for_workspace(owner["ws"], upload_ref)  # type: ignore[arg-type]
    )
    assert body == SPEC_JSON


async def test_upload_yaml_is_accepted(
    owner: dict[str, object], captured_enqueue: list[dict[str, object]]
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    cid = await _make_connector(owner)
    resp = await client.post(
        f"/v1/connectors/{cid}/versions",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
        files={"file": ("openapi.yaml", SPEC_YAML, "application/x-yaml")},
    )
    assert resp.status_code == 202, resp.text
    assert len(captured_enqueue) == 1


async def test_upload_empty_file_is_400(
    owner: dict[str, object], captured_enqueue: list[dict[str, object]]
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    cid = await _make_connector(owner)
    resp = await client.post(
        f"/v1/connectors/{cid}/versions",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
        files={"file": ("empty.json", b"", "application/json")},
    )
    assert resp.status_code == 400
    assert captured_enqueue == []


async def test_upload_oversized_is_rejected(
    owner: dict[str, object], captured_enqueue: list[dict[str, object]]
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    cid = await _make_connector(owner)
    big = b"x" * (10 * 1024 * 1024 + 1)  # > 10 MB
    resp = await client.post(
        f"/v1/connectors/{cid}/versions",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
        files={"file": ("big.json", big, "application/json")},
    )
    assert resp.status_code == 400  # rejected at the bounded multipart parse / size check
    assert captured_enqueue == []


async def test_both_url_and_file_is_400(
    owner: dict[str, object], captured_enqueue: list[dict[str, object]]
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    cid = await _make_connector(owner)
    resp = await client.post(
        f"/v1/connectors/{cid}/versions",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
        data={"source_url": SOURCE_URL},
        files={"file": ("openapi.json", SPEC_JSON, "application/json")},
    )
    assert resp.status_code == 400
    assert captured_enqueue == []


async def test_neither_url_nor_file_is_400(
    owner: dict[str, object], captured_enqueue: list[dict[str, object]]
) -> None:
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    cid = await _make_connector(owner)
    resp = await client.post(
        f"/v1/connectors/{cid}/versions",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
        data={"other": "x"},
    )
    assert resp.status_code == 400
    assert captured_enqueue == []


async def test_upload_requires_connectors_manage(
    human_client: tuple[AsyncClient, FakeJWKSEndpoint],
    authority: SigningAuthority,
    admin_engine: AsyncEngine,
    workspace_a: SeededWorkspace,
    owner: dict[str, object],
    captured_enqueue: list[dict[str, object]],
) -> None:
    client, _ = human_client
    cid = await _make_connector(owner)
    await seed_member(admin_engine, workspace_a.id, user_id="up-viewer", role="viewer")
    resp = await client.post(
        f"/v1/connectors/{cid}/versions",
        headers=hx(authority.sign("up-viewer"), workspace_a.id),
        files={"file": ("openapi.json", SPEC_JSON, "application/json")},
    )
    assert resp.status_code == 403
    assert captured_enqueue == []


async def test_a_malicious_upload_filename_never_reaches_the_storage_key(
    owner: dict[str, object], captured_enqueue: list[dict[str, object]]
) -> None:
    """The filename is discarded — the staged key is a fresh uuid under the tenant prefix, so a
    traversal/absolute filename cannot influence the key."""
    client: AsyncClient = owner["client"]  # type: ignore[assignment]
    cid = await _make_connector(owner)
    resp = await client.post(
        f"/v1/connectors/{cid}/versions",
        headers=hx(owner["token"], owner["ws"]),  # type: ignore[arg-type]
        files={"file": ("../../../../etc/passwd", SPEC_JSON, "application/json")},
    )
    assert resp.status_code == 202, resp.text
    upload_ref = captured_enqueue[0]["args"][3]  # type: ignore[misc]
    assert ".." not in upload_ref and upload_ref.startswith(f"connectors/{cid}/uploads/")
