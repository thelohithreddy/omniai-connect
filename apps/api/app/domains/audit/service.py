"""Audit Log Viewer business logic (M1-Audit-Viewer-v1).

Thin over the repository: one paginated, filtered read of the Tool Call ledger. Cursor pagination
(API_GUIDELINES §3) and filter validation live here — an invalid `status` value is a
`validation_error`
(a closed enum, DATABASE_DESIGN `tool_calls`), never a silent empty page. No execution, no decrypt,
no
mutation.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.exceptions import ValidationFailedError
from app.core.pagination import (
    DEFAULT_LIMIT,
    CursorPosition,
    decode_cursor,
    encode_cursor,
    resolve_limit,
)
from app.domains.audit.repository import LogFilters, ToolCallLogRepository
from app.domains.runtime.models import TOOL_CALL_STATUSES, ToolCall


@dataclass(frozen=True, slots=True)
class ToolCallLogPage:
    """One page of audit rows plus the pagination signals (API_GUIDELINES §3)."""

    rows: list[ToolCall]
    next_cursor: str | None
    has_more: bool


class ToolCallLogService:
    def __init__(self, repository: ToolCallLogRepository) -> None:
        self._repository = repository

    async def list_page(
        self, *, limit: int = DEFAULT_LIMIT, cursor: str | None = None, filters: LogFilters
    ) -> ToolCallLogPage:
        """One page of this Workspace's Tool Call audit log, newest first."""
        if filters.status is not None and filters.status not in TOOL_CALL_STATUSES:
            raise ValidationFailedError(
                "Unknown status filter.",
                details={"status": filters.status, "allowed": list(TOOL_CALL_STATUSES)},
            )
        position = decode_cursor(cursor) if cursor is not None else None
        page_size = resolve_limit(limit)
        rows = await self._repository.list_page(
            limit=page_size + 1, after=position, filters=filters
        )
        has_more = len(rows) > page_size
        page = rows[:page_size]
        next_cursor = (
            encode_cursor(CursorPosition(created_at=page[-1].created_at, id=page[-1].id))
            if has_more and page
            else None
        )
        return ToolCallLogPage(rows=page, next_cursor=next_cursor, has_more=has_more)


__all__ = ["ToolCallLogPage", "ToolCallLogService"]
