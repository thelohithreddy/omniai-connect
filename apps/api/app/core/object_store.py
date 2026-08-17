"""Object storage — the tenant-isolated boundary to S3-compatible storage (M1.4-B0.5, ADR-0024).

Cloudflare R2 in production, MinIO in local/CI — one S3 API selected by `r2_endpoint`. Canon
(SYSTEM_ARCHITECTURE, CONNECTOR_ENGINE) stores spec files, export artifacts, and oversized/binary
runtime payloads in R2, referenced by a server-constructed object key (`raw_spec_ref`). This
module builds only that storage boundary; it persists nothing to the database and exposes no API.

The security model, in one line:

    trusted WorkspaceContext / worker tenant context
        → TenantObjectKey.for_workspace(workspace_id, path)   (validated, ws/<uuid>/... )
        → ObjectStore.{put,get,head,delete}
        → one private bucket
        → ws/<workspace_id>/...

The single bucket is infrastructure; **tenant isolation is the object key**. A key is built only
by `TenantObjectKey` from a *trusted* workspace id and an explicit key grammar, so one workspace
can never address another's object — the provider is never the authorization system, and R2/MinIO
credentials are never tenant credentials. No application code calls boto3/botocore directly; the
untyped SDK is confined to this module.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Any

import aioboto3
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError

from app.core.config import Settings, settings
from app.core.logging import get_logger

log = get_logger(__name__)

# The tenant prefix. Every key produced by this module begins with `ws/<validated_workspace_id>/`.
_WORKSPACE_PREFIX = "ws"
# S3 caps a key at 1024 bytes; enforce it so a pathological path fails here, not at the provider.
_MAX_KEY_BYTES = 1024
# A key segment allowlist (NOT a denylist, NOT pathlib): a segment is one or more of these ASCII
# characters and is never "." or "..". This rejects traversal, backslashes, encoded traversal
# (`%2e` has `%`), null bytes, control characters, whitespace, and unicode by construction — the
# only things that can appear are safe object-path characters.
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class ObjectStoreError(Exception):
    """Base for storage failures. Messages never carry a credential, endpoint secret, or the
    raw SDK exception string."""


class ObjectKeyError(ObjectStoreError):
    """A relative path or workspace id failed the tenant-key grammar — rejected before any
    provider access, so a malformed or hostile key never reaches the bucket."""


class ObjectNotFoundError(ObjectStoreError):
    """The object does not exist (provider 404 / NoSuchKey). Carries the tenant key, never the
    bucket name or provider internals."""


class StorageConfigError(ObjectStoreError):
    """Object storage is required but not (correctly) configured — fail closed. Names the missing
    settings, never their values."""


class StorageProviderError(ObjectStoreError):
    """The provider failed (network, auth, 5xx). Carries the S3 error *code* and the operation,
    never the raw SDK string (which can embed the endpoint or a signed request)."""


@dataclass(frozen=True, slots=True)
class TenantObjectKey:
    """A validated, tenant-scoped object key. The only constructor that yields a usable key is
    `for_workspace`, so an unvalidated or cross-tenant key is unrepresentable.

    `full_key` is always `ws/<workspace_id>/<relative_path>` — the workspace prefix is applied by
    this type, never assembled by hand elsewhere, so no caller can address a foreign tenant."""

    workspace_id: uuid.UUID
    relative_path: str

    @classmethod
    def for_workspace(cls, workspace_id: uuid.UUID, relative_path: str) -> TenantObjectKey:
        """Build a key for a workspace from a trusted context. Fail closed on anything that is
        not a UUID workspace id and a grammar-valid relative path (see `_SEGMENT_RE`)."""
        if not isinstance(workspace_id, uuid.UUID):
            # A str/None/foreign type is refused: the workspace id must come from a resolved
            # WorkspaceContext / worker tenant context, which is always a uuid.UUID.
            raise ObjectKeyError("workspace_id must be a UUID from a trusted context")
        if not isinstance(relative_path, str):
            raise ObjectKeyError("object path must be a string")
        # Explicit allowlist grammar (never pathlib): each "/"-separated segment is one or more
        # allowed characters and is never "." or "..". The regex's `+` is also the single guard
        # that rejects an *empty* segment, which is exactly how an empty path, a leading/trailing
        # slash, and a double slash fail — every check below is individually load-bearing.
        for segment in relative_path.split("/"):
            if segment in (".", ".."):
                raise ObjectKeyError("object path contains a traversal component")
            if not _SEGMENT_RE.match(segment):
                raise ObjectKeyError(
                    "object path segment is empty or contains an illegal character"
                )
        key = cls(workspace_id=workspace_id, relative_path=relative_path)
        if len(key.full_key.encode("utf-8")) > _MAX_KEY_BYTES:
            raise ObjectKeyError("object key exceeds the maximum length")
        return key

    @property
    def full_key(self) -> str:
        return f"{_WORKSPACE_PREFIX}/{self.workspace_id}/{self.relative_path}"


@dataclass(frozen=True, slots=True)
class ObjectHead:
    """Metadata for an object (from HEAD), never its content."""

    size: int
    content_type: str | None
    etag: str | None


@dataclass(frozen=True, slots=True)
class ObjectStoreConfig:
    """Resolved, validated storage configuration. The secret stays wrapped so a stray repr or log
    cannot leak it (its `__repr__` is `**********`)."""

    endpoint_url: str
    bucket: str
    access_key_id: str = field(repr=False)
    secret_access_key: Any = field(repr=False)  # pydantic SecretStr; unwrapped only at the SDK
    region: str


def resolve_object_store_config(source: Settings = settings) -> ObjectStoreConfig:
    """Read storage config from settings, fail closed if incomplete, and enforce TLS in
    production. Returns a validated config or raises `StorageConfigError` naming (not valuing) the
    problem — never a silent MinIO fallback in production."""
    required = {
        "R2_ENDPOINT": source.r2_endpoint,
        "R2_BUCKET": source.r2_bucket,
        "R2_ACCESS_KEY_ID": source.r2_access_key_id,
        "R2_SECRET_ACCESS_KEY": source.r2_secret_access_key.get_secret_value(),
    }
    missing = sorted(name for name, value in required.items() if not value)
    if missing:
        raise StorageConfigError(f"object storage is not configured: missing {missing}")
    # Production must speak TLS to a real endpoint; only local/CI may use a plaintext MinIO.
    if source.is_production and not source.r2_endpoint.startswith("https://"):
        raise StorageConfigError("production object storage endpoint must use https")
    return ObjectStoreConfig(
        endpoint_url=source.r2_endpoint,
        bucket=source.r2_bucket,
        access_key_id=source.r2_access_key_id,
        secret_access_key=source.r2_secret_access_key,
        region=source.r2_region,
    )


class ObjectStore:
    """The narrow S3-compatible boundary. Every operation takes a `TenantObjectKey`, so a caller
    can never present a raw, unvalidated, or cross-tenant key.

    A client is opened per operation via `async with` (aioboto3 clients are async context managers
    bound to the current event loop). That is deliberate and correct here: the ingestion worker
    runs each task on a fresh `asyncio.run` loop (ADR-0022), so a long-lived shared client would be
    bound to the wrong loop — exactly the reason B0.3 uses a per-task DB connection. Ingestion is
    not a hot path, so per-operation setup is acceptable; a lifespan-shared client is a future
    optimisation once a hot storage path exists. The `async with` also guarantees the client's
    sockets are closed after every operation — no leak.
    """

    def __init__(self, config: ObjectStoreConfig) -> None:
        self._config = config
        self._session = aioboto3.Session()
        # s3v4 signing; path-style addressing (MinIO requires it, R2 accepts it); bounded standard
        # retries (idempotent ops only — put overwrites, delete is idempotent); explicit timeouts.
        # botocore owns the retry loop — the store never becomes a second scheduler (Celery owns
        # task retries, ADR-0021).
        self._botocore_config = Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            retries={"max_attempts": 3, "mode": "standard"},
            connect_timeout=5,
            read_timeout=30,
        )

    def _client(self) -> Any:
        return self._session.client(
            "s3",
            endpoint_url=self._config.endpoint_url,
            aws_access_key_id=self._config.access_key_id,
            aws_secret_access_key=self._config.secret_access_key.get_secret_value(),
            region_name=self._config.region,
            config=self._botocore_config,
        )

    async def put(
        self, key: TenantObjectKey, data: bytes, *, content_type: str | None = None
    ) -> None:
        """Store bytes at the tenant key (overwrites — S3 PUT is last-writer-wins; B0.5 makes no
        write-once claim). Content is bytes: spec files are small and bounded by the fetcher's
        ≤10 MB (CONNECTOR_SPECIFICATION §18); a streaming interface is a future concern the
        upload/ingestion module owns, not this primitive."""
        extra: dict[str, str] = {"ContentType": content_type} if content_type else {}
        async with self._client() as s3:
            try:
                await s3.put_object(
                    Bucket=self._config.bucket, Key=key.full_key, Body=data, **extra
                )
            except ClientError as exc:
                raise self._provider_error("put", key, exc) from None
            except EndpointConnectionError as exc:
                raise self._unreachable("put", exc) from None

    async def get(self, key: TenantObjectKey) -> bytes:
        """Read the object's bytes, or raise `ObjectNotFoundError`."""
        async with self._client() as s3:
            try:
                response = await s3.get_object(Bucket=self._config.bucket, Key=key.full_key)
                async with response["Body"] as body:
                    data: bytes = await body.read()
                    return data
            except ClientError as exc:
                raise self._map_client_error("get", key, exc) from None
            except EndpointConnectionError as exc:
                raise self._unreachable("get", exc) from None

    async def head(self, key: TenantObjectKey) -> ObjectHead:
        """Return object metadata (size/content-type/etag) without downloading content, or raise
        `ObjectNotFoundError`."""
        async with self._client() as s3:
            try:
                response = await s3.head_object(Bucket=self._config.bucket, Key=key.full_key)
            except ClientError as exc:
                raise self._map_client_error("head", key, exc) from None
            except EndpointConnectionError as exc:
                raise self._unreachable("head", exc) from None
        etag = response.get("ETag")
        return ObjectHead(
            size=int(response["ContentLength"]),
            content_type=response.get("ContentType"),
            etag=etag.strip('"') if isinstance(etag, str) else None,
        )

    async def delete(self, key: TenantObjectKey) -> None:
        """Delete the object. Idempotent: S3 DELETE succeeds whether or not the object existed —
        this is storage idempotency, not tenant authorization (the key is still tenant-scoped)."""
        async with self._client() as s3:
            try:
                await s3.delete_object(Bucket=self._config.bucket, Key=key.full_key)
            except ClientError as exc:
                raise self._provider_error("delete", key, exc) from None
            except EndpointConnectionError as exc:
                raise self._unreachable("delete", exc) from None

    async def ensure_bucket(self) -> None:
        """Create the bucket if absent — a **local/CI/test** convenience only. Production buckets
        are pre-provisioned infrastructure; nothing calls this on the request or worker path."""
        async with self._client() as s3:
            try:
                await s3.head_bucket(Bucket=self._config.bucket)
            except ClientError:
                await s3.create_bucket(Bucket=self._config.bucket)

    # ----------------------------------------------------------------- safe error translation

    @staticmethod
    def _error_code(exc: Any) -> str:
        code = ""
        response = getattr(exc, "response", None)
        if isinstance(response, dict):
            code = str(response.get("Error", {}).get("Code", ""))
        return code

    def _map_client_error(self, op: str, key: TenantObjectKey, exc: Any) -> ObjectStoreError:
        """404 / NoSuchKey → not-found; anything else → a safe provider error."""
        if self._error_code(exc) in ("404", "NoSuchKey", "NotFound"):
            return ObjectNotFoundError(f"{op}: object not found: {key.full_key}")
        return self._provider_error(op, key, exc)

    def _provider_error(self, op: str, key: TenantObjectKey, exc: Any) -> StorageProviderError:
        # Only the S3 error code and the (tenant-scoped) key — never the raw SDK string, which can
        # embed the endpoint or a signed request. The key contains workspace_id, which the logging
        # policy already treats as a non-secret correlation id (core/logging.py).
        code = self._error_code(exc) or "provider_error"
        log.warning("object_store.provider_error", op=op, code=code, key=key.full_key)
        return StorageProviderError(f"{op} failed ({code})")

    def _unreachable(self, op: str, exc: Any) -> StorageProviderError:  # noqa: ARG002
        log.warning("object_store.unreachable", op=op)
        return StorageProviderError(f"{op} failed (endpoint_unreachable)")


def get_object_store() -> ObjectStore:
    """Build an `ObjectStore` from the resolved (fail-closed) config. Cheap — holds no open
    socket until an operation runs."""
    return ObjectStore(resolve_object_store_config())


__all__ = [
    "ObjectHead",
    "ObjectKeyError",
    "ObjectNotFoundError",
    "ObjectStore",
    "ObjectStoreConfig",
    "ObjectStoreError",
    "StorageConfigError",
    "StorageProviderError",
    "TenantObjectKey",
    "get_object_store",
    "resolve_object_store_config",
]
