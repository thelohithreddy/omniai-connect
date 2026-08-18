"""Business logic for the connections domain (M1-Connections-v1, ADR-0029).

Constructed from a `ConnectionRepository` alone — no `WorkspaceContext`, no `workspace_id` — so
there is no expression this class can form that writes into another tenant. **This layer performs
no authorization**: whether the caller may manage connections is decided at the request boundary by
`require_permission(Permission.CONNECTIONS_MANAGE)`. What it *does* own is: proving the referenced
Connector is live in this Workspace, and SSRF-linting a `base_url` override in `config_overrides` —
reusing the connectors domain's `validate_base_url`, never a second SSRF validator.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from app.core.events import event_bus
from app.core.exceptions import NotFoundError, ValidationFailedError
from app.core.pagination import (
    DEFAULT_LIMIT,
    CursorPosition,
    decode_cursor,
    encode_cursor,
    resolve_limit,
)
from app.domains.connections.events import connection_revoked
from app.domains.connections.models import Connection
from app.domains.connections.repository import ConnectionRepository
from app.domains.connectors.service import validate_base_url


def _validate_config_overrides(config_overrides: dict[str, Any]) -> dict[str, Any]:
    """`config_overrides` is data, never authority. The only field with a security contract is a
    `base_url` override, which must pass the same SSRF lint a Connector's base URL does (https-only,
    no credentials, no private/loopback/link-local/metadata host) — reused, not reimplemented. Every
    other key is stored opaquely and is never read as tenant/role/status."""
    if not isinstance(config_overrides, dict):
        raise ValidationFailedError("config_overrides must be an object.")
    base_url = config_overrides.get("base_url")
    if base_url is not None:
        if not isinstance(base_url, str):
            raise ValidationFailedError("config_overrides.base_url must be a string.")
        validate_base_url(base_url)  # SSRF lint; raises ValidationFailedError on an unsafe override
    return config_overrides


@dataclass(frozen=True, slots=True)
class ConnectionPage:
    """One page of connections plus the pagination signals (API_GUIDELINES.md §3)."""

    connections: list[Connection]
    next_cursor: str | None
    has_more: bool


class ConnectionService:
    def __init__(self, repository: ConnectionRepository) -> None:
        self._repository = repository

    async def create(
        self, *, connector_id: uuid.UUID, name: str, config_overrides: dict[str, Any]
    ) -> Connection:
        """Create a `pending_auth` Connection bound to a live Connector in this Workspace.

        The connector must exist and be live *in this Workspace* — a foreign or deleted connector is
        a uniform 404, so a cross-tenant binding is not a request this API can express. Credential
        attachment (→ `active`) belongs to the future Credentials module and is not performed here.
        """
        config = _validate_config_overrides(config_overrides)
        if not await self._repository.live_connector_exists(connector_id):
            raise NotFoundError("Connector not found.")
        return await self._repository.create(
            connector_id=connector_id, name=name, config_overrides=config
        )

    async def list_page(
        self, *, limit: int = DEFAULT_LIMIT, cursor: str | None = None
    ) -> ConnectionPage:
        """One page of this Workspace's live connections, newest first."""
        position = decode_cursor(cursor) if cursor is not None else None
        page_size = resolve_limit(limit)
        rows = await self._repository.list_page(limit=page_size + 1, after=position)
        has_more = len(rows) > page_size
        connections = rows[:page_size]
        next_cursor = (
            encode_cursor(
                CursorPosition(created_at=connections[-1].created_at, id=connections[-1].id)
            )
            if has_more and connections
            else None
        )
        return ConnectionPage(connections=connections, next_cursor=next_cursor, has_more=has_more)

    async def get(self, connection_id: uuid.UUID) -> Connection:
        """One live Connection, or a 404 that is byte-identical for absent and foreign ids."""
        connection = await self._repository.get(connection_id)
        if connection is None:
            raise NotFoundError("Connection not found.")
        return connection

    async def update(
        self,
        connection_id: uuid.UUID,
        *,
        name: str | None,
        config_overrides: dict[str, Any] | None,
    ) -> Connection:
        """Update a Connection's `name`/`config_overrides` (only). Re-lints a `base_url` override
        and re-checks live-name uniqueness at the DB. `status`/`credential_id`/`connector_id` are
        immutable here — a client cannot forge a lifecycle transition or re-tenant the row."""
        if config_overrides is not None:
            config_overrides = _validate_config_overrides(config_overrides)
        connection = await self._repository.update(
            connection_id, name=name, config_overrides=config_overrides
        )
        if connection is None:
            raise NotFoundError("Connection not found.")
        return connection

    async def revoke(self, connection_id: uuid.UUID) -> None:
        """Revoke a live Connection (soft delete → `revoked`). A foreign or already-revoked id is a
        uniform 404 — the second revoke matches nothing (idempotent at the repository).

        Buffers `connection.revoked` (M2.1, ADR-0034) exactly when the row actually moved, stamped
        from the RETURNING identifiers — dispatched only after this transaction commits, so a
        rolled-back revoke emits nothing and the second revoke (no-op) emits nothing.
        """
        revoked = await self._repository.revoke(connection_id)
        if revoked is None:
            raise NotFoundError("Connection not found.")
        event_bus.publish(
            connection_revoked(
                revoked.workspace_id,
                connection_id=revoked.id,
                connector_id=revoked.connector_id,
            )
        )


__all__ = ["ConnectionPage", "ConnectionService"]
