"""Business logic for the workspaces domain. Framework-free by design.

No FastAPI imports here: the service is what an MCP adapter, a Celery task, or a test
calls directly, and each of those would otherwise have to fake an HTTP request to reach
the logic (BACKEND_SPEC.md §2).
"""

from __future__ import annotations

from app.core.exceptions import NotFoundError
from app.domains.workspaces.models import Workspace
from app.domains.workspaces.repository import WorkspaceRepository


class WorkspaceService:
    def __init__(self, repository: WorkspaceRepository) -> None:
        self._repository = repository

    async def get_current(self) -> Workspace:
        """The Workspace the caller's token belongs to.

        A miss here means the token resolved but its Workspace row is gone — a deleted
        tenant whose tokens were not cascaded, or an RLS misconfiguration. `not_found`
        rather than `internal` because the caller cannot act on the distinction, and it
        keeps the cross-tenant response shape identical (P-17).
        """
        workspace = await self._repository.get_current()
        if workspace is None:
            raise NotFoundError("Workspace not found.")
        return workspace
