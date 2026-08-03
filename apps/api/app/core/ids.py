"""Identifier generation.

UUIDv7 for every primary key (DATABASE_DESIGN.md §1). v7 embeds a millisecond timestamp
in its high bits, so generated IDs sort in creation order and B-tree inserts append to the
rightmost page instead of scattering random writes across the index — the property UUIDv4
lacks and the reason v4 primary keys degrade write throughput as tables grow. v7 keeps
v4's unguessability, so IDs remain safe to expose in URLs and API responses.

Isolated in one module so the source can be swapped for `uuid.uuid7()` when we move to
Python 3.14 without touching a single call site.
"""

import uuid

import uuid6


def new_id() -> uuid.UUID:
    """A time-ordered UUIDv7."""
    return uuid6.uuid7()


def new_request_id() -> str:
    """Correlation id for one unit of work (API_GUIDELINES.md §1).

    Prefixed and hyphen-free so it survives log greps and URL query params intact.
    """
    return f"req_{new_id().hex}"
