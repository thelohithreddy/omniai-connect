"""Data access for the Execution Runtime — the only layer that touches the DB.

Scoped exactly like every other repository (P-14): `ctx` is a required constructor argument, and
every statement filters on `workspace_id` explicitly even though RLS enforces the same boundary. The
runtime reads across four owning domains (tools, connections, connectors + versions, credentials) to
assemble one Tool Call, and appends exactly one immutable `tool_calls` row. It never updates or
deletes — the audit table has no such grant.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import WorkspaceContext
from app.domains.connections.models import Connection
from app.domains.connectors.models import Connector, ConnectorVersion, Tool
from app.domains.credentials.models import Credential
from app.domains.runtime.models import ToolCall
from app.domains.workspaces.models import Workspace


class RuntimeRepository:
    def __init__(self, session: AsyncSession, ctx: WorkspaceContext) -> None:
        self._session = session
        self._ctx = ctx

    async def get_workspace_plan(self) -> str:
        """The bound Workspace's plan (M2.4 limit selector). `workspaces.plan` is authoritative
        (NOT NULL, CHECK-constrained); read per call so a plan change takes effect immediately.
        Scoped to the context's own workspace — there is no expression here that can read
        another tenant's plan."""
        plan: str | None = await self._session.scalar(
            select(Workspace.plan).where(Workspace.id == self._ctx.workspace_id)
        )
        # The workspace row always exists for an authenticated context; `free` is the safe
        # (most-restrictive) fallback if it were ever absent mid-transaction.
        return plan if plan is not None else "free"

    async def resolve_tool(self, tool_name: str) -> Tool | None:
        """The one live, enabled Tool with this canonical name in the current Workspace, or None.

        Live + enabled = `deleted_at IS NULL AND enabled` — a removed or user-disabled Tool is not
        executable and is indistinguishable from a missing one (no existence oracle). Canonical
        names
        are unique per Workspace (CONNECTOR_ENGINE.md §5); `limit(1)` on a deterministic order is a
        belt over that guarantee.
        """
        stmt = (
            select(Tool)
            .where(
                Tool.name == tool_name,
                Tool.workspace_id == self._ctx.workspace_id,
                Tool.deleted_at.is_(None),
                Tool.enabled.is_(True),
            )
            .order_by(Tool.created_at.desc(), Tool.id.desc())
            .limit(1)
        )
        tool: Tool | None = await self._session.scalar(stmt)
        return tool

    async def get_connection(self, connection_id: uuid.UUID) -> Connection | None:
        """One live Connection by id in the current Workspace (revoked = soft-deleted = gone)."""
        stmt = select(Connection).where(
            Connection.id == connection_id,
            Connection.workspace_id == self._ctx.workspace_id,
            Connection.deleted_at.is_(None),
        )
        connection: Connection | None = await self._session.scalar(stmt)
        return connection

    async def active_connections_for_connector(self, connector_id: uuid.UUID) -> list[Connection]:
        """Every live, `active` Connection binding this Connector — used to bind implicitly when the
        caller gave no `connection_id` (ambiguity is an error, never a guess — AI_RUNTIME §2.2)."""
        stmt = select(Connection).where(
            Connection.workspace_id == self._ctx.workspace_id,
            Connection.connector_id == connector_id,
            Connection.status == "active",
            Connection.deleted_at.is_(None),
        )
        return list((await self._session.scalars(stmt)).all())

    async def get_connector(self, connector_id: uuid.UUID) -> Connector | None:
        """The live Connector (for `base_url` + `auth_config`), scoped to the Workspace."""
        stmt = select(Connector).where(
            Connector.id == connector_id,
            Connector.workspace_id == self._ctx.workspace_id,
            Connector.deleted_at.is_(None),
        )
        connector: Connector | None = await self._session.scalar(stmt)
        return connector

    async def get_connector_version(
        self, connector_version_id: uuid.UUID
    ) -> ConnectorVersion | None:
        """The immutable ConnectorVersion holding the executable `normalized_schema`, scoped."""
        stmt = select(ConnectorVersion).where(
            ConnectorVersion.id == connector_version_id,
            ConnectorVersion.workspace_id == self._ctx.workspace_id,
        )
        version: ConnectorVersion | None = await self._session.scalar(stmt)
        return version

    async def get_credential(self, connection_id: uuid.UUID) -> Credential | None:
        """The Credential bound to this Connection (ciphertext columns the runtime decrypts)."""
        stmt = select(Credential).where(
            Credential.connection_id == connection_id,
            Credential.workspace_id == self._ctx.workspace_id,
        )
        credential: Credential | None = await self._session.scalar(stmt)
        return credential

    async def insert_tool_call(
        self,
        *,
        connection_id: uuid.UUID,
        tool_id: uuid.UUID,
        request_id: str,
        caller: dict[str, Any],
        status: str,
        input_summary: dict[str, Any],
        output_summary: dict[str, Any] | None,
        error_code: str | None,
        duration_ms: int,
    ) -> ToolCall:
        """Append one immutable audit row to the current Workspace. `workspace_id` is server-set."""
        row = ToolCall(
            workspace_id=self._ctx.workspace_id,
            connection_id=connection_id,
            tool_id=tool_id,
            request_id=request_id,
            caller=caller,
            status=status,
            input_summary=input_summary,
            output_summary=output_summary,
            error_code=error_code,
            duration_ms=duration_ms,
        )
        self._session.add(row)
        await self._session.flush()
        return row

    async def get_tool_call(self, tool_call_id: uuid.UUID) -> ToolCall | None:
        """One audit row by id, within the current Workspace (for `GET /v1/tool-calls/{id}`)."""
        stmt = select(ToolCall).where(
            ToolCall.id == tool_call_id,
            ToolCall.workspace_id == self._ctx.workspace_id,
        )
        row: ToolCall | None = await self._session.scalar(stmt)
        return row


__all__ = ["RuntimeRepository"]
