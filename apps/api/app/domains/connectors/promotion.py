"""Version promotion + tools projection (M1.4-B1.4, ADR-0028).

Promotion is the single act that makes a `connector_versions` row the connector's *active*
definition. It is shared by two callers: the worker auto-promotes a first/purely-additive version
inside the ingestion transaction (`ingestion._persist`), and an owner/admin explicitly promotes a
breaking version through the synchronous endpoint (`ConnectorService.promote`). Both converge here,
so the projection and the activation event have exactly one implementation.

Promotion **swaps the active set** (CONNECTOR_SPECIFICATION §3): the connector's current live tool
rows are soft-deleted and the new version's rows inserted — rows are never mutated in place. Each
Tool's `enabled` override is re-applied on Tool identity (the canonical name, which encodes source
identity, §5). The live set is `deleted_at IS NULL`; a removed Tool simply has no new row and stays
soft-deleted (retained for audit, §13). On success `connectors.current_version_id` advances and a
`connector.ingested` event is buffered (post-commit) to invalidate tool-list caches (§12.2). The
whole thing runs in the caller's transaction — version pointer, tools, and event are atomic.

Idempotent: promoting the already-current version is a no-op (returns False). The caller holds the
connector row lock (`SELECT … FOR UPDATE`) so concurrent promotions serialize.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select, update

from app.core.db import UnitOfWork
from app.domains.connectors.events import connector_ingested
from app.domains.connectors.models import Connector, ConnectorVersion, Tool


def _annotations(tool: dict[str, Any]) -> dict[str, Any]:
    """The tools-row `annotations`: safety flags plus `tags` (DATABASE_DESIGN.md / §2)."""
    base = tool.get("annotations")
    annotations: dict[str, Any] = dict(base) if isinstance(base, dict) else {}
    tags = tool.get("tags")
    annotations["tags"] = tags if isinstance(tags, list) else []
    return annotations


async def _live_enabled_by_name(
    uow: UnitOfWork, workspace_id: uuid.UUID, connector_id: uuid.UUID
) -> dict[str, bool]:
    """The `enabled` override of every live tool row, keyed by Tool name (identity)."""
    stmt = select(Tool.name, Tool.enabled).where(
        Tool.workspace_id == workspace_id,
        Tool.connector_id == connector_id,
        Tool.deleted_at.is_(None),
    )
    rows = (await uow.session.execute(stmt)).all()
    return {str(name): bool(enabled) for name, enabled in rows}


async def promote(
    uow: UnitOfWork,
    workspace_id: uuid.UUID,
    connector: Connector,
    version_row: ConnectorVersion,
) -> bool:
    """Make `version_row` the connector's active version. Returns whether a change was made.

    Idempotent: if the version is already current, nothing happens and False is returned. Otherwise
    the current live tool rows are soft-deleted, the version's tools are projected (carrying each
    Tool's `enabled` override on identity), the version pointer advances, and `connector.ingested`
    is buffered for post-commit dispatch. Runs entirely in `uow`'s transaction.
    """
    if connector.current_version_id == version_row.id:
        return False  # already promoted — idempotent no-op

    prior_enabled = await _live_enabled_by_name(uow, workspace_id, connector.id)

    # Soft-delete the outgoing active set (a scoped Core UPDATE; sets updated_at explicitly because
    # the ORM onupdate does not fire on a Core statement).
    await uow.session.execute(
        update(Tool)
        .where(
            Tool.workspace_id == workspace_id,
            Tool.connector_id == connector.id,
            Tool.deleted_at.is_(None),
        )
        .values(deleted_at=func.now(), updated_at=func.now())
    )

    normalized: Any = version_row.normalized_schema
    tools: list[dict[str, Any]] = normalized if isinstance(normalized, list) else []
    for tool in tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
            continue
        uow.session.add(
            Tool(
                workspace_id=workspace_id,
                connector_id=connector.id,
                connector_version_id=version_row.id,
                name=tool["name"],
                description=str(tool.get("description", "")),
                input_schema=tool.get("input_schema") or {},
                output_hints=tool.get("output_hints"),
                annotations=_annotations(tool),
                enabled=prior_enabled.get(tool["name"], True),
            )
        )

    connector.current_version_id = version_row.id
    connector.status = "active"
    # Buffered on the held UoW; dispatches only after COMMIT (B0.4) and enforces event-tenant ==
    # bound-tenant. Invalidates tool-list caches on version activation (§12.2).
    uow.buffer_event(
        connector_ingested(workspace_id, connector.id, version_row.version, version_row.spec_hash)
    )
    return True


__all__ = ["promote"]
