"""Async Redis access for the request path (M1-Connections-v1).

`redis_client()` returns a fresh `redis.asyncio` client to be used as an async context manager, so
its connection pool is opened and **closed within one request** (`async with redis_client() as r:`).
It is deliberately not a long-lived cached singleton: a cached async client binds its pool to the
event loop it was created on, which breaks across the per-test loops (and would leak on shutdown).
The one consumer today is the connections idempotency store; readiness keeps its own probe client.
"""

from __future__ import annotations

import redis.asyncio as aioredis

from app.core.config import settings


def redis_client() -> aioredis.Redis:
    """A fresh async Redis client; use with `async with` so its pool is closed after the request."""
    return aioredis.from_url(settings.redis_url, decode_responses=True)


__all__ = ["redis_client"]
