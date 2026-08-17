"""Idempotency-Key handling for connection creation (API_GUIDELINES §5, M1-Connections-v1).

A minimal, connections-scoped mechanism — there is no platform idempotency subsystem yet, and this
slice must not invent a speculative one. Keyed per **workspace + endpoint + client key** in Redis:

- First request: reserve the key (`SET NX`, short TTL); on success, store the response (24 h TTL).
- Retry, same key + same body: the stored response is replayed.
- Same key + different body: `409` (`validation_error`) — API_GUIDELINES §5.
- Concurrent same-key request that finds the reservation still pending: `409` (retry).

The Redis layer is a UX optimization (replay the response) *on top of* the real correctness
guarantee: the partial-unique index `(workspace_id, name) WHERE deleted_at IS NULL` means the DB —
not Redis — is the final arbiter, so even a Redis/DB split can never produce a duplicate connection.
Keys are always workspace-scoped, so one tenant's Idempotency-Key can never collide with another's.
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
_PENDING_TTL = 60  # seconds a reservation may sit un-completed — crash-safety, so a stuck key frees
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
    return f"ws:{workspace_id}:idem:connections:create:{key}"


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
            return None  # we own the key — proceed to create
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


__all__ = ["HEADER", "Replay", "begin", "body_digest", "complete", "validate_key"]
