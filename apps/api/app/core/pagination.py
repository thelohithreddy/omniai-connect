"""Cursor pagination, per API_GUIDELINES.md §3.

§3 is unambiguous: *"Cursor-based, on every list endpoint. Offset pagination is
forbidden — it breaks under concurrent writes and invites table scans."* Both halves of
that reasoning matter here.

**Concurrent writes.** `OFFSET 50` means "skip the first 50 rows of the answer computed
right now". If a row is inserted between two page requests — and this is a list of API
tokens, where inserting is precisely what the neighbouring endpoint does — every
subsequent row shifts by one, so the client silently re-reads an item it already saw and
never sees another. Keyset pagination asks "the rows after *this specific row*", which is
stable no matter what happens either side of it.

**Table scans.** `OFFSET n` makes Postgres produce and discard n rows; cost grows with
depth. A keyset predicate is a range scan the index can start directly.

**The cursor is a position, never an authority.** It encodes only the sort key of the last
row the client was already served. It carries no `workspace_id`, so a forged or replayed
cursor cannot move a caller outside their own tenant — the workspace comes from the
authenticated context, and the cursor is applied as an *additional* predicate on top of it.
That is the property that makes it safe to leave unsigned; see `decode_cursor`.
"""

from __future__ import annotations

import base64
import binascii
import uuid
from dataclasses import dataclass
from datetime import datetime

from app.core.exceptions import ValidationFailedError

#: §3: "`limit` defaults to 50, max 100."
DEFAULT_LIMIT = 50
MAX_LIMIT = 100

_SEPARATOR = "|"


@dataclass(frozen=True, slots=True)
class CursorPosition:
    """The sort key of the last row already delivered: `(created_at, id)`.

    Both halves are required. `created_at` alone is not a unique ordering — two tokens
    minted in the same microsecond would tie, and a keyset predicate on a non-unique key
    either skips rows or repeats them forever. `id` breaks the tie, and because ids are
    UUIDv7 (time-ordered), ordering by id agrees with ordering by creation time instead of
    scrambling rows that share a timestamp.
    """

    created_at: datetime
    id: uuid.UUID


def encode_cursor(position: CursorPosition) -> str:
    """Opaque token marking where the next page starts.

    Base64url so it survives a query string unescaped, and so it *looks* opaque: §3 tells
    clients not to construct or decode cursors, and a bare `2026-08-14T10:00:00Z|019f…`
    would be an open invitation to do exactly that. This is encoding, not encryption, and
    is not relied on for any security property.
    """
    raw = f"{position.created_at.isoformat()}{_SEPARATOR}{position.id}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def decode_cursor(cursor: str) -> CursorPosition:
    """Parse a cursor, or raise `ValidationFailedError`.

    §3: *"Cursors may expire; an expired cursor yields `validation_error`."* Every way a
    cursor can be unusable — expired, truncated, hand-written, base64 of something else,
    from a different endpoint — lands on that same outcome. There is no path where a
    malformed cursor is silently ignored and the client is quietly served page one while
    believing it received page nine.

    **Deliberately unsigned.** §3 says cursors are *"encoded internally, signed if they
    ever carry state"*. This one carries no state: only the sort key of a row the client
    was already shown. Forging it lets a caller resume from an arbitrary point **inside
    their own workspace** — which is not a privilege, since they may already page through
    all of it — and cannot reach another tenant, because the tenant predicate comes from
    the authenticated context and is applied independently. Signing would require choosing
    a key, an algorithm, and a rotation policy, none of which any canonical document
    decides; that is recorded as a deferred question rather than invented here.

    The error message deliberately does not distinguish "malformed" from "expired". The
    client's action is identical in both cases — restart the listing — and a more specific
    message would only describe the encoding to someone probing it.
    """
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
        encoded_at, _, encoded_id = raw.partition(_SEPARATOR)
        return CursorPosition(
            created_at=datetime.fromisoformat(encoded_at),
            id=uuid.UUID(encoded_id),
        )
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise ValidationFailedError(
            "The cursor is invalid or has expired. Restart the listing without a cursor."
        ) from exc


def resolve_limit(limit: int) -> int:
    """Clamp a page size to the canonical bounds.

    FastAPI's `Query(ge=1, le=100)` already rejects out-of-range values at the HTTP door,
    so this exists for the service's non-HTTP callers (BACKEND_SPEC.md §2) — a Celery task
    or an MCP adapter reaching the same operation must not be able to ask for a million
    rows in one query and turn a paginated endpoint into a full table read.
    """
    if limit < 1:
        raise ValidationFailedError("limit must be at least 1.", details={"limit": limit})
    if limit > MAX_LIMIT:
        raise ValidationFailedError(
            "limit exceeds the maximum page size.",
            details={"limit": limit, "max": MAX_LIMIT},
        )
    return limit


__all__ = [
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "CursorPosition",
    "decode_cursor",
    "encode_cursor",
    "resolve_limit",
]
