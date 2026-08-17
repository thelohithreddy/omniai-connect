"""Idempotency-Key handling for Tool Call execution (API_GUIDELINES §5, AI_RUNTIME.md §2).

Executing a Tool Call is a side-effecting POST, so it accepts an `Idempotency-Key` header (a
client-generated UUID). Unlike creating a Connection — where a partial-unique index is the true
correctness arbiter — a Tool Call has *no* database uniqueness backstop, so this Redis layer is the
whole duplicate-suppression mechanism: it must reserve the key **before** the outbound call so a
retry that races the original cannot fire a second egress or write a second audit row.

- First request: reserve the key (`SET NX`, short TTL); on completion, store the response (24 h).
- Retry, same key + same body: the stored `ToolCallResult` is replayed verbatim (no re-execution).
- Same key + different body: `409` (`validation_error`) — API_GUIDELINES §5.
- Concurrent same-key request that finds the reservation still pending: `409` (retry).

Keys are always workspace-scoped, so one tenant's Idempotency-Key can never collide with another's.
The stored response contains only what the API already returned (redacted result) — never a secret.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any

from app.core.exceptions import ConflictError, ValidationFailedError
from app.core.redis import redis_client

HEADER = "Idempotency-Key"
_PENDING_TTL = 60  # seconds a reservation may sit un-completed — a stuck key frees itself
_DONE_TTL = 24 * 60 * 60  # 24 h replay window (§5)


def validate_key(raw: str) -> str:
    """The key must be a client-generated UUID (§5); anything else is a `400`."""
    try:
        return str(uuid.UUID(raw.strip()))
    except ValueError as exc:
        raise ValidationFailedError("Idempotency-Key must be a UUID.") from exc


def body_digest(payload: dict[str, Any]) -> str:
    """A stable hash of the request body (canonical JSON) — same body ⇒ same digest."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _redis_key(workspace_id: uuid.UUID, key: str) -> str:
    return f"ws:{workspace_id}:idem:tool-calls:create:{key}"


@dataclass(frozen=True, slots=True)
class Replay:
    """A previously-stored response to replay verbatim."""

    status_code: int
    body: dict[str, Any]


async def begin(workspace_id: uuid.UUID, key: str, digest: str) -> Replay | None:
    """Reserve the key (caller proceeds, returns None) or resolve an existing entry.

    Raises `ConflictError` (409) on a body mismatch or an in-flight reservation.
    """
    rkey = _redis_key(workspace_id, key)
    async with redis_client() as redis:
        reserved = await redis.set(
            rkey, json.dumps({"body_hash": digest, "response": None}), nx=True, ex=_PENDING_TTL
        )
        if reserved:
            return None  # we own the key — proceed to execute
        existing = await redis.get(rkey)
    if existing is None:  # the reservation expired between SET NX and GET — ask the client to retry
        raise ConflictError("A request with this Idempotency-Key is in progress; retry.")
    record = json.loads(existing)
    if record.get("body_hash") != digest:
        raise ConflictError("Idempotency-Key reused with a different request body.")
    response = record.get("response")
    if response is None:  # a concurrent request holds the reservation but has not completed yet
        raise ConflictError("A request with this Idempotency-Key is in progress; retry.")
    return Replay(status_code=int(response["status_code"]), body=response["body"])


async def complete(
    workspace_id: uuid.UUID, key: str, digest: str, status_code: int, body: dict[str, Any]
) -> None:
    """Store the response so a later retry with the same key + body replays it (24 h)."""
    rkey = _redis_key(workspace_id, key)
    async with redis_client() as redis:
        await redis.set(
            rkey,
            json.dumps(
                {"body_hash": digest, "response": {"status_code": status_code, "body": body}}
            ),
            ex=_DONE_TTL,
        )


async def release(workspace_id: uuid.UUID, key: str) -> None:
    """Drop a reservation that never completed (the call raised before a response was stored), so a
    genuine retry is not blocked for the full pending TTL. Best-effort."""
    async with redis_client() as redis:
        await redis.delete(_redis_key(workspace_id, key))


__all__ = ["HEADER", "Replay", "begin", "body_digest", "complete", "release", "validate_key"]
