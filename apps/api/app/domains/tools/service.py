"""Tools administration business logic (M1-Tools-v1).

Thin over the repository: list / get / enable-disable, with cursor pagination and
uniform not-found (a foreign or deprecated Tool is a 404, never an existence oracle).
No execution, no decrypt, no Connection/Credential access — it manipulates Tool metadata and
the `enabled` flag only. The Runtime already refuses to resolve a disabled or deleted Tool,
so flipping `enabled` here is the single source of the "may this Tool execute?" decision.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.core.events import event_bus
from app.core.exceptions import NotFoundError
from app.core.pagination import (
    DEFAULT_LIMIT,
    CursorPosition,
    decode_cursor,
    encode_cursor,
    resolve_limit,
)
from app.domains.connectors.models import Tool
from app.domains.tools.events import tool_disabled, tool_enabled
from app.domains.tools.repository import ToolRepository


@dataclass(frozen=True, slots=True)
class ToolPage:
    """One page of tools plus the pagination signals (API_GUIDELINES §3)."""

    tools: list[Tool]
    next_cursor: str | None
    has_more: bool


class ToolService:
    def __init__(self, repository: ToolRepository) -> None:
        self._repository = repository

    async def list_page(
        self,
        *,
        limit: int = DEFAULT_LIMIT,
        cursor: str | None = None,
        connector_id: uuid.UUID | None = None,
    ) -> ToolPage:
        """One page of this Workspace's live tools (enabled and disabled), newest first."""
        position = decode_cursor(cursor) if cursor is not None else None
        page_size = resolve_limit(limit)
        rows = await self._repository.list_page(
            limit=page_size + 1, after=position, connector_id=connector_id
        )
        has_more = len(rows) > page_size
        tools = rows[:page_size]
        next_cursor = (
            encode_cursor(CursorPosition(created_at=tools[-1].created_at, id=tools[-1].id))
            if has_more and tools
            else None
        )
        return ToolPage(tools=tools, next_cursor=next_cursor, has_more=has_more)

    async def get(self, tool_id: uuid.UUID) -> Tool:
        """One live Tool by id, or a uniform 404 (foreign / deprecated / missing all look alike)."""
        tool = await self._repository.get(tool_id)
        if tool is None:
            raise NotFoundError("Tool not found.")
        return tool

    async def set_enabled(self, tool_id: uuid.UUID, *, enabled: bool) -> Tool:
        """Enable or disable a live Tool (idempotent, race-safe). A foreign / deprecated / missing
        Tool is a uniform 404 — the same response whether it never existed or belongs to another
        tenant — so the endpoint is not an oracle and a deprecated Tool cannot be revived.

        Buffers `tool.enabled`/`tool.disabled` (M2.1, ADR-0034) exactly when the repository's
        value-guarded UPDATE actually flipped the persisted flag — a no-op PATCH emits nothing —
        dispatched only after this transaction commits. The tenant is the row's own workspace_id;
        the UoW refuses a mismatch with the transaction's bound tenant (ADR-0022).
        """
        tool, changed = await self._repository.set_enabled(tool_id, enabled=enabled)
        if tool is None:
            raise NotFoundError("Tool not found.")
        if changed:
            factory = tool_enabled if enabled else tool_disabled
            event_bus.publish(
                factory(tool.workspace_id, tool_id=tool.id, connector_id=tool.connector_id)
            )
        return tool


__all__ = ["ToolPage", "ToolService"]
