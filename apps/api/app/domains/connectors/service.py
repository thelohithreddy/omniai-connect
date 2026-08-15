"""Business logic for the connectors domain (M1.4-A).

Constructed from a `ConnectorRepository` alone — no `WorkspaceContext`, no `workspace_id` —
so there is no expression this class can form that writes into another tenant. **This layer
performs no authorization**: whether the caller may manage connectors is decided at the
request boundary by `require_permission(Permission.CONNECTORS_MANAGE)`. What it *does* own is
the SSRF lint on `base_url` and slug derivation, here rather than in the router so a non-HTTP
caller (MCP adapter, Celery task) is guarded identically (BACKEND_SPEC §2).
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from app.core.db import UnitOfWork
from app.core.exceptions import ConflictError, NotFoundError, ValidationFailedError
from app.core.pagination import (
    DEFAULT_LIMIT,
    CursorPosition,
    decode_cursor,
    encode_cursor,
    resolve_limit,
)
from app.domains.connectors import promotion
from app.domains.connectors.events import connector_ingestion_requested
from app.domains.connectors.models import Connector
from app.domains.connectors.repository import ConnectorRepository

_NON_SLUG = re.compile(r"[^a-z0-9]+")


def _slugify(name: str) -> str:
    """A URL-safe slug from a display name: lowercase, non-alphanumerics collapse to hyphens."""
    return _NON_SLUG.sub("-", name.strip().lower()).strip("-")[:64]


def validate_base_url(raw: str) -> str:
    """SSRF lint for a Connector's base URL (CONNECTOR_SPECIFICATION.md §11, SECURITY.md §6).

    Applies to spec-declared URLs *before any Tool exists* — a stored `base_url` is a wire
    destination the runtime will later call, so a private/loopback/link-local/metadata host or
    an embedded credential must be refused at definition time, not discovered at egress.
    `http` is rejected outright: the dev-flagged-connector exception is out of scope for M1.4-A.

    Hostname → IP resolution is deliberately NOT done here (DNS rebinding is an egress-time
    concern the Execution Runtime owns); this refuses literal private addresses and obvious
    local hostnames, which is exactly what §11 requires of the declared URL.
    """
    value = raw.strip()
    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise ValidationFailedError("base_url is not a valid URL.") from exc

    if parts.scheme != "https":
        raise ValidationFailedError("base_url must use https.")
    if parts.username or parts.password or "@" in parts.netloc:
        raise ValidationFailedError("base_url must not embed credentials.")

    host = parts.hostname
    if not host:
        raise ValidationFailedError("base_url must include a host.")

    lowered = host.lower()
    if lowered == "localhost" or lowered.endswith((".localhost", ".local")):
        raise ValidationFailedError("base_url must not point at a local or internal host.")

    try:
        address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_unspecified
        or address.is_multicast
    ):
        raise ValidationFailedError(
            "base_url must not point at a private, loopback, link-local, or reserved address."
        )
    return value


@dataclass(frozen=True, slots=True)
class ConnectorPage:
    """One page of connectors plus the pagination signals (API_GUIDELINES.md §3)."""

    connectors: list[Connector]
    next_cursor: str | None
    has_more: bool


class ConnectorService:
    def __init__(self, repository: ConnectorRepository) -> None:
        self._repository = repository

    async def create(
        self,
        *,
        name: str,
        base_url: str,
        auth_config: dict[str, Any],
        slug: str | None = None,
    ) -> Connector:
        """Create a manual Connector. `source_type` is server-set to `manual`; `status` starts
        at `draft`; `base_url` is SSRF-linted; the slug is derived from the name when absent."""
        clean_base_url = validate_base_url(base_url)
        connector_slug = slug or _slugify(name)
        if not connector_slug:
            raise ValidationFailedError(
                "Could not derive a slug from the name; provide an explicit slug.",
                details={"name": name},
            )
        return await self._repository.create(
            name=name,
            slug=connector_slug,
            source_type="manual",
            base_url=clean_base_url,
            auth_config=auth_config,
            status="draft",
        )

    async def list_page(
        self, *, limit: int = DEFAULT_LIMIT, cursor: str | None = None
    ) -> ConnectorPage:
        """One page of this Workspace's live connectors, newest first.

        `has_more` is computed by over-fetching one row, not by counting — the same snapshot
        answers the page and "is there more". The cursor is decoded before the query, so a
        malformed one is a `ValidationFailedError` rather than a silently empty page.
        """
        position = decode_cursor(cursor) if cursor is not None else None
        page_size = resolve_limit(limit)
        rows = await self._repository.list_page(limit=page_size + 1, after=position)
        has_more = len(rows) > page_size
        connectors = rows[:page_size]
        next_cursor = (
            encode_cursor(
                CursorPosition(created_at=connectors[-1].created_at, id=connectors[-1].id)
            )
            if has_more and connectors
            else None
        )
        return ConnectorPage(connectors=connectors, next_cursor=next_cursor, has_more=has_more)

    async def get(self, connector_id: uuid.UUID) -> Connector:
        """One live Connector, or a 404 that is byte-identical for absent and foreign ids."""
        connector = await self._repository.get(connector_id)
        if connector is None:
            raise NotFoundError("Connector not found.")
        return connector

    async def delete(self, connector_id: uuid.UUID) -> None:
        """Soft-delete a live Connector. A foreign or already-deleted id is a uniform 404."""
        if not await self._repository.soft_delete(connector_id):
            raise NotFoundError("Connector not found.")

    async def request_ingestion(
        self,
        uow: UnitOfWork,
        *,
        workspace_id: uuid.UUID,
        connector_id: uuid.UUID,
        source_url: str = "",
        upload_ref: str = "",
    ) -> Connector:
        """Start asynchronous OpenAPI ingestion for a live Connector (M1.4-B1.1/B1.2).

        The source is either a `source_url` (URL ingestion) or an `upload_ref` — a
        workspace-relative ObjectStore key the router already staged the uploaded bytes to (the
        worker cannot re-fetch an upload, §18). Exactly one must be non-empty. Both are *where*, not
        *who*: the connector's tenant is `workspace_id` from the request's trusted context.

        Transitions the Connector to `ingesting` and buffers a post-commit trigger that enqueues the
        Celery pipeline — so the worker never sees the Connector before the transition is durable,
        and a rolled-back request enqueues nothing. The trigger is buffered directly on the request
        `uow` (not the ambient-sink `event_bus.publish`, whose contextvar does not cross FastAPI's
        DI boundary); `uow.buffer_event` still enforces the workspace-match (ADR-0022).

        A Connector already `ingesting` is a 409 (its run is the concurrency lock); a foreign or
        deleted id is a uniform 404.
        """
        if bool(source_url) == bool(upload_ref):
            raise ValidationFailedError("Provide exactly one of a source URL or an uploaded file.")
        connector = await self._repository.get(connector_id)
        if connector is None:
            raise NotFoundError("Connector not found.")
        if not await self._repository.mark_ingesting(connector_id):
            raise ConflictError(
                "Connector is already ingesting.", details={"status": connector.status}
            )
        uow.buffer_event(
            connector_ingestion_requested(
                workspace_id, connector_id, source_url=source_url, upload_ref=upload_ref
            )
        )
        connector.status = "ingesting"
        return connector

    async def promote(self, uow: UnitOfWork, *, connector_id: uuid.UUID, version: int) -> Connector:
        """Promote a persisted version to the connector's active definition (M1.4-B1.4).

        The explicit half of the promotion gate: a first/purely-additive version auto-promotes
        during ingestion, but a **breaking** version is persisted un-promoted and activated here by
        an owner/admin (authorization is enforced at the request boundary, `connectors:manage`).

        The connector is row-locked (`SELECT … FOR UPDATE`) so concurrent promotions — and a
        promotion racing the worker's auto-promote — serialize on the row: the winner projects the
        tools and advances the pointer, the loser sees the version already current and no-ops.
        Idempotent (promoting the current version changes nothing). A connector mid-ingestion is a
        409 (its run owns the transition); a foreign/deleted connector or an unknown version is a
        uniform 404. `promotion.promote` swaps the active tool set and buffers `connector.ingested`.
        """
        connector = await self._repository.get_for_update(connector_id)
        if connector is None:
            raise NotFoundError("Connector not found.")
        if connector.status == "ingesting":
            raise ConflictError(
                "Connector is ingesting; promote after it settles.",
                details={"status": connector.status},
            )
        version_row = await self._repository.get_version(connector_id, version)
        if version_row is None:
            raise NotFoundError("Connector version not found.")
        await promotion.promote(uow, connector.workspace_id, connector, version_row)
        return connector


__all__ = ["ConnectorPage", "ConnectorService", "validate_base_url"]
