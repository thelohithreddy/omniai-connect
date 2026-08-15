"""ObjectStore against real MinIO (M1.4-B0.5, ADR-0024).

The unit suites prove the key grammar and config resolution without a provider. This suite talks
to the real S3-compatible MinIO the compose/CI stack runs, proving the parts that only a real
provider can: PUT/GET/HEAD/DELETE, missing-object handling, tenant isolation, real concurrency
(A×8/B×8/C×8), the per-operation client lifecycle, and predictable failure when the endpoint or
credentials are wrong. No S3 SDK is mocked.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator

import pytest
from pydantic import SecretStr

from app.core.object_store import (
    ObjectNotFoundError,
    ObjectStore,
    ObjectStoreConfig,
    StorageProviderError,
    TenantObjectKey,
    get_object_store,
    resolve_object_store_config,
)


@pytest.fixture(scope="module")
async def store() -> AsyncIterator[ObjectStore]:
    """The real ObjectStore pointed at the compose/CI MinIO, bucket ensured. Skips cleanly if
    storage is not configured in this environment (so unit-only runs are unaffected)."""
    try:
        resolve_object_store_config()
    except Exception as exc:  # StorageConfigError: no MinIO/R2 here
        pytest.skip(f"object storage not configured: {exc}")
    s = get_object_store()
    # Startup resilience: MinIO may still be coming up in CI. Bounded wait, no infinite retry.
    last: Exception | None = None
    for _ in range(20):
        try:
            await s.ensure_bucket()
            break
        except Exception as exc:  # noqa: BLE001
            last = exc
            await asyncio.sleep(0.5)
    else:
        pytest.skip(f"MinIO not reachable: {last}")
    yield s


def _key(ws: uuid.UUID, path: str = "specs/openapi.json") -> TenantObjectKey:
    return TenantObjectKey.for_workspace(ws, path)


# ------------------------------------------------------------------ lifecycle


async def test_put_get_head_delete_roundtrip(store: ObjectStore) -> None:
    key = _key(uuid.uuid4())
    body = b'{"openapi":"3.0.0","info":{"title":"x"}}'
    await store.put(key, body, content_type="application/json")

    head = await store.head(key)
    assert head.size == len(body)
    assert head.content_type == "application/json"
    assert head.etag  # provider returns an etag

    assert await store.get(key) == body

    await store.delete(key)
    with pytest.raises(ObjectNotFoundError):
        await store.get(key)


async def test_get_missing_object_raises_not_found(store: ObjectStore) -> None:
    with pytest.raises(ObjectNotFoundError) as exc:
        await store.get(_key(uuid.uuid4(), "does/not/exist.json"))
    # The error carries the tenant key but never the bucket name or raw SDK internals (§20/§23).
    assert resolve_object_store_config().bucket not in str(exc.value)


async def test_head_missing_object_raises_not_found(store: ObjectStore) -> None:
    with pytest.raises(ObjectNotFoundError):
        await store.head(_key(uuid.uuid4(), "missing.json"))


async def test_delete_is_idempotent(store: ObjectStore) -> None:
    # Deleting an absent object is storage-idempotent (no error) — not an authorization statement.
    await store.delete(_key(uuid.uuid4(), "never/created.json"))


async def test_put_overwrites_last_writer_wins(store: ObjectStore) -> None:
    key = _key(uuid.uuid4())
    await store.put(key, b"first")
    await store.put(key, b"second")
    assert await store.get(key) == b"second"
    await store.delete(key)


async def test_many_sequential_operations_do_not_leak_clients(store: ObjectStore) -> None:
    """Each operation opens and closes its own client; a run of them must not exhaust sockets."""
    ws = uuid.uuid4()
    for i in range(15):
        key = _key(ws, f"n/{i}.txt")
        await store.put(key, str(i).encode())
        assert await store.get(key) == str(i).encode()
        await store.delete(key)


# ------------------------------------------------------------------ tenant isolation


async def test_a_workspace_cannot_read_another_workspaces_object(store: ObjectStore) -> None:
    """B stores a secret; A — using its own trusted context — cannot form B's key, so the same
    relative path resolves under A's prefix and A gets NotFound while B's object is untouched."""
    a, b = uuid.uuid4(), uuid.uuid4()
    b_key = _key(b, "secret.json")
    await store.put(b_key, b"B-only-secret")

    a_key = _key(a, "secret.json")  # same relative path, A's context
    assert a_key.full_key != b_key.full_key
    assert a_key.full_key.startswith(f"ws/{a}/")

    with pytest.raises(ObjectNotFoundError):
        await store.get(a_key)  # A cannot see B's object
    assert await store.get(b_key) == b"B-only-secret"  # B's object intact

    await store.delete(b_key)


async def test_each_workspace_reads_only_its_own_bytes(store: ObjectStore) -> None:
    a, b = uuid.uuid4(), uuid.uuid4()
    await store.put(_key(a), b"A-body")
    await store.put(_key(b), b"B-body")
    assert await store.get(_key(a)) == b"A-body"
    assert await store.get(_key(b)) == b"B-body"
    await store.delete(_key(a))
    await store.delete(_key(b))


# ------------------------------------------------------------------ concurrency A×8 / B×8 / C×8


async def test_concurrent_tenants_never_cross(store: ObjectStore) -> None:
    """24 interleaved PUT→HEAD→GET→DELETE cycles across three tenants. Each writes a body carrying
    its own workspace id and must read back exactly that — no key crossover, no client state
    bleed between concurrent operations."""
    a, b, c = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()

    async def cycle(ws: uuid.UUID, n: int) -> tuple[uuid.UUID, bytes]:
        await asyncio.sleep(0)  # force interleaving
        key = _key(ws, f"concurrent/{n}.bin")
        body = f"{ws}:{n}".encode()
        await store.put(key, body)
        head = await store.head(key)
        assert head.size == len(body)
        got = await store.get(key)
        await store.delete(key)
        return ws, got

    jobs = [cycle(w, i) for w in (a, b, c) for i in range(8)]
    results = await asyncio.gather(*jobs)

    assert len(results) == 24
    for ws, got in results:
        assert got.startswith(f"{ws}:".encode()), f"tenant crossover: {ws} read {got!r}"


# ------------------------------------------------------------------ failure modes


async def test_an_unreachable_endpoint_fails_predictably(store: ObjectStore) -> None:
    """A store pointed at a dead endpoint raises a safe StorageProviderError — no crash, no retry
    storm, no secret in the message."""
    base = resolve_object_store_config()
    dead = ObjectStore(
        ObjectStoreConfig(
            endpoint_url="http://127.0.0.1:1",  # nothing listening
            bucket=base.bucket,
            access_key_id=base.access_key_id,
            secret_access_key=base.secret_access_key,
            region=base.region,
        )
    )
    with pytest.raises(StorageProviderError) as exc:
        await dead.get(_key(uuid.uuid4()))
    assert "secret" not in str(exc.value).lower()


async def test_a_provider_error_never_leaks_the_bucket_or_raw_sdk_string(
    store: ObjectStore,
) -> None:
    """A put to a non-existent bucket raises `NoSuchBucket`, whose raw SDK message contains the
    bucket name — the translated error must surface only the S3 code, never that raw string."""
    base = resolve_object_store_config()
    absent_bucket = f"no-such-bucket-{uuid.uuid4().hex}"
    misconfigured = ObjectStore(
        ObjectStoreConfig(
            endpoint_url=base.endpoint_url,
            bucket=absent_bucket,
            access_key_id=base.access_key_id,
            secret_access_key=base.secret_access_key,
            region=base.region,
        )
    )
    with pytest.raises(StorageProviderError) as exc:
        await misconfigured.put(_key(uuid.uuid4()), b"x")
    message = str(exc.value)
    # Only the tight, safe format ("<op> failed (<S3 code>)") — never the raw SDK string.
    assert message.startswith("put failed (")
    assert "An error occurred" not in message  # the botocore exception text is not surfaced
    assert absent_bucket not in message  # nor the bucket name


async def test_wrong_credentials_fail_without_leaking_the_secret(store: ObjectStore) -> None:
    base = resolve_object_store_config()
    bad = ObjectStore(
        ObjectStoreConfig(
            endpoint_url=base.endpoint_url,
            bucket=base.bucket,
            access_key_id="wrong-access-key",
            secret_access_key=SecretStr("wrong-secret-value"),
            region=base.region,
        )
    )
    with pytest.raises(StorageProviderError) as exc:
        await bad.put(_key(uuid.uuid4()), b"x")
    message = str(exc.value)
    assert "wrong-secret-value" not in message  # the secret never appears
    assert base.bucket not in message  # nor the bucket / raw SDK string (§23)
