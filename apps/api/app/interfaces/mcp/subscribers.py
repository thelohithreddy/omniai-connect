"""MCP cache-eviction subscribers (M2.2, ADR-0035) — the consumer M2.1 built its events for.

Startup-registered handlers (BACKEND_SPEC §4): each of the six canonical lifecycle events that
can change a workspace's discoverable Tool set evicts `ws:{workspace_id}:mcp:tools`. The
workspace is derived **only from the trusted event envelope** — never from the payload, never
from any caller-supplied value — and the envelope's tenant was already fail-closed-matched
against the publishing transaction's bound workspace (ADR-0022), so an event can never evict
another tenant's namespace.

Handlers run post-commit and are idempotent: duplicate delivery deletes an already-absent key
(a no-op), and a lost delivery (the bus is at-most-once, ADR-0023) is bounded by the cache's
TTL backstop. Eviction failures are logged, never raised — the bus isolates handler errors, and
the TTL recovers the staleness either way. The dependency direction is one-way: this interface
module imports the domains' event names; no domain imports MCP.
"""

from __future__ import annotations

from typing import Final

from app.core.events import Event, EventBus, event_bus
from app.core.logging import get_logger
from app.domains.connections.events import (
    CONNECTION_ACTIVATED,
    CONNECTION_DEACTIVATED,
    CONNECTION_REVOKED,
)
from app.domains.connectors.events import CONNECTOR_INGESTED
from app.domains.tools.events import TOOL_DISABLED, TOOL_ENABLED
from app.interfaces.mcp.cache import evict_tools_cache

log = get_logger(__name__)

#: Every event after which a workspace's discoverable Tool set may differ (MCP_RUNTIME §3).
MCP_EVICTION_EVENTS: Final[tuple[str, ...]] = (
    CONNECTOR_INGESTED,
    CONNECTION_ACTIVATED,
    CONNECTION_DEACTIVATED,
    CONNECTION_REVOKED,
    TOOL_ENABLED,
    TOOL_DISABLED,
)


async def _evict_workspace_tools(event: Event) -> None:
    # The envelope's workspace_id is the trusted tenant (typed uuid.UUID by construction) —
    # payload fields are never consulted for the cache namespace.
    await evict_tools_cache(event.workspace_id)
    log.info(
        "mcp.tools_cache_evicted",
        event_type=event.event_type,
        event_id=str(event.event_id),
        workspace_id=str(event.workspace_id),
    )


def register_mcp_subscribers(bus: EventBus = event_bus) -> None:
    """Register the MCP eviction handlers. Called once at startup (composition root)."""
    for event_type in MCP_EVICTION_EVENTS:
        bus.subscribe(event_type, _evict_workspace_tools)


__all__ = ["MCP_EVICTION_EVENTS", "register_mcp_subscribers"]
