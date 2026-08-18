"""Workspace MCP tools-discovery cache (M2.2, ADR-0035).

Redis is an **optimization layer only** — PostgreSQL + RLS + the workspace-bound request
context remain authoritative, and the cache is never consulted for authorization. Three
properties make the cached listing safe:

- the key embeds the **server-derived** workspace identity (`ws:{workspace_id}:mcp:tools`,
  MCP_RUNTIME §3) — callers never influence the namespace;
- the value is the metadata-only MCP projection (protocol.py's strict allowlist) inside a
  versioned envelope, so a shape change across deploys reads as a miss, never as poison;
- every entry carries the **TTL backstop** (`settings.mcp_tools_cache_ttl_seconds`,
  founder-ratified 300 s): the internal bus is at-most-once (ADR-0023 — a crash between COMMIT
  and dispatch loses the eviction), so the TTL, not event delivery, is the guaranteed staleness
  bound. Stale discovery is bounded; stale *execution* is impossible — the Runtime re-authorizes
  every call against the database.

Every Redis failure here degrades to the authoritative path: a read error is a miss, a write
error skips caching, an eviction error is logged (the TTL recovers it). None of them can turn
into "the workspace has no tools" or bypass authorization. Logs carry identifiers only.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Final

from app.core.config import settings
from app.core.logging import get_logger
from app.core.redis import redis_client

log = get_logger(__name__)

# The canonical key (MCP_RUNTIME §3). The workspace_id is always the trusted server-side value:
# the authenticated context on reads/writes, the trusted event envelope on eviction.
CACHE_KEY_TEMPLATE: Final[str] = "ws:{workspace_id}:mcp:tools"

# Envelope schema version — bumped when the cached representation changes shape, so entries
# written by an older deploy read as a miss instead of serving a drifted payload.
ENVELOPE_VERSION: Final[int] = 1


def cache_key(workspace_id: uuid.UUID) -> str:
    return CACHE_KEY_TEMPLATE.format(workspace_id=workspace_id)


async def read_tools_cache(workspace_id: uuid.UUID) -> list[dict[str, Any]] | None:
    """The cached MCP tools projection, or None on miss — where 'miss' includes an absent key,
    a malformed/foreign-shaped value, and any Redis failure (the caller falls back to the
    authoritative database; Redis can never fabricate an empty listing)."""
    key = cache_key(workspace_id)
    try:
        async with redis_client() as redis:
            raw = await redis.get(key)
    except Exception:
        log.warning("mcp.cache_read_failed", workspace_id=str(workspace_id))
        return None
    if raw is None:
        return None
    try:
        envelope = json.loads(raw)
        if (
            isinstance(envelope, dict)
            and envelope.get("v") == ENVELOPE_VERSION
            and isinstance(tools := envelope.get("tools"), list)
        ):
            return tools
    except ValueError:
        pass
    # Unparseable or wrong-shaped entry: treat as a miss (the next write repairs it).
    log.warning("mcp.cache_envelope_invalid", workspace_id=str(workspace_id))
    return None


async def write_tools_cache(workspace_id: uuid.UUID, tools: list[dict[str, Any]]) -> None:
    """Store the projection with the TTL backstop. A write failure is logged and swallowed —
    the response was already computed from the authoritative database."""
    payload = json.dumps({"v": ENVELOPE_VERSION, "tools": tools}, separators=(",", ":"))
    try:
        async with redis_client() as redis:
            await redis.set(
                cache_key(workspace_id), payload, ex=settings.mcp_tools_cache_ttl_seconds
            )
    except Exception:
        log.warning("mcp.cache_write_failed", workspace_id=str(workspace_id))


async def evict_tools_cache(workspace_id: uuid.UUID) -> None:
    """Delete the workspace's cached listing. Idempotent — deleting an absent key is a no-op —
    and fail-safe: an eviction failure is logged and bounded by the TTL backstop."""
    try:
        async with redis_client() as redis:
            await redis.delete(cache_key(workspace_id))
    except Exception:
        log.warning("mcp.cache_evict_failed", workspace_id=str(workspace_id))


__all__ = [
    "CACHE_KEY_TEMPLATE",
    "ENVELOPE_VERSION",
    "cache_key",
    "evict_tools_cache",
    "read_tools_cache",
    "write_tools_cache",
]
