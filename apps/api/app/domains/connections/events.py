"""Domain events for the connections domain (M2.1, ADR-0034).

Published on the internal bus (BACKEND_SPEC §4) after the transaction that persists the state
transition commits — a rolled-back request emits nothing. These are the Connection half of the
canonical MCP tools-cache eviction set (MCP_RUNTIME §3): a subscriber (M2.2) evicts
`ws:{workspace_id}:mcp:tools` when a Connection enters or leaves the active set. Delivery is
at-most-once in-process today and at-least-once under the future broker (ADR-0023), so consumers
must be idempotent — evicting an already-evicted cache is a no-op by construction.

Every payload carries only non-secret identifiers; the workspace is the envelope's trusted
`workspace_id`, never a payload field, and `UnitOfWork.buffer_event` refuses an event whose tenant
differs from the transaction's bound workspace (ADR-0022). Events state WHERE and WHAT — never WHO
may act (they are not an authorization surface) and never credential material.

Emission sites are the persisted transitions themselves, not method names:

- `connection.activated` — `pending_auth → active`, the credential-attach transition
  (credentials domain owns it; DATABASE_DESIGN §3 links `credential_id` to non-`pending_auth`).
- `connection.deactivated` — the Connection *left* the active set without being revoked:
  `active → pending_auth` on credential revoke today; `active → error` when the M2 OAuth refresh
  worker lands (founder-ratified 2026-08-18 as the 5th eviction event; ADR-0034).
- `connection.revoked` — `* → revoked`, the terminal soft delete (connections domain owns it).
"""

from __future__ import annotations

import uuid

from app.core.events import Event

CONNECTION_ACTIVATED = "connection.activated"
CONNECTION_DEACTIVATED = "connection.deactivated"
CONNECTION_REVOKED = "connection.revoked"

#: M2.10 (ADR-0041). A completed health check found the Connection unusable. Like every event here
#: it is tied to a persisted change — the check stamped `last_health_check_at` — not to a method
#: call, so a refused or unevaluated check (no stamp) emits nothing. It is deliberately **not** an
#: MCP cache-eviction event: a failing provider does not change which Tools are discoverable, and
#: adding it to the eviction set would flush a workspace's listing on every transient upstream blip.
CONNECTION_HEALTH_CHECK_FAILED = "connection.health_check_failed"


def connection_activated(
    workspace_id: uuid.UUID, *, connection_id: uuid.UUID, connector_id: uuid.UUID
) -> Event:
    """A Connection's persisted status became `active` (credential attached)."""
    return Event(
        event_type=CONNECTION_ACTIVATED,
        workspace_id=workspace_id,
        payload={"connection_id": str(connection_id), "connector_id": str(connector_id)},
    )


def connection_deactivated(
    workspace_id: uuid.UUID,
    *,
    connection_id: uuid.UUID,
    connector_id: uuid.UUID,
    status: str,
) -> Event:
    """A Connection left the active set without being revoked. `status` is the new persisted
    status (`pending_auth` on credential revoke; `error` once the OAuth refresh worker exists) —
    a closed-vocabulary state word, never free text and never secret."""
    return Event(
        event_type=CONNECTION_DEACTIVATED,
        workspace_id=workspace_id,
        payload={
            "connection_id": str(connection_id),
            "connector_id": str(connector_id),
            "status": status,
        },
    )


def connection_revoked(
    workspace_id: uuid.UUID, *, connection_id: uuid.UUID, connector_id: uuid.UUID
) -> Event:
    """A Connection was revoked (terminal soft delete — it can never re-enter the active set)."""
    return Event(
        event_type=CONNECTION_REVOKED,
        workspace_id=workspace_id,
        payload={"connection_id": str(connection_id), "connector_id": str(connector_id)},
    )


def connection_health_check_failed(
    workspace_id: uuid.UUID,
    *,
    connection_id: uuid.UUID,
    reason: str,
) -> Event:
    """A completed health check found this Connection unusable (M2.10).

    `reason` is the Runtime's **stable error code** — an enumerated token such as `upstream_error`
    or `timeout` — never `str(exception)`, which for an upstream failure can carry provider text and
    with it a leaked secret. It rides in the payload so the notification can name a cause without
    the subscriber re-reading the audit ledger.
    """
    return Event(
        event_type=CONNECTION_HEALTH_CHECK_FAILED,
        workspace_id=workspace_id,
        payload={"connection_id": str(connection_id), "reason": reason},
    )


__all__ = [
    "CONNECTION_ACTIVATED",
    "CONNECTION_DEACTIVATED",
    "CONNECTION_HEALTH_CHECK_FAILED",
    "CONNECTION_REVOKED",
    "connection_activated",
    "connection_deactivated",
    "connection_health_check_failed",
    "connection_revoked",
]
