"""HTTP surface for the workspaces domain. Thin: parse, delegate, shape.

No business logic, no DB access, no hand-built error responses (P-9, P-50). If a handler
here grows an `if` about domain state, it belongs in the service.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.core.db import UnitOfWork, get_uow
from app.core.security import CurrentWorkspace, WorkspaceContext
from app.domains.workspaces.repository import WorkspaceRepository
from app.domains.workspaces.schemas import WorkspaceRead
from app.domains.workspaces.service import WorkspaceService

router = APIRouter(prefix="/v1/workspaces", tags=["workspaces"])


def get_workspace_service(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    ctx: CurrentWorkspace,
) -> WorkspaceService:
    """Composition root for the domain (BACKEND_SPEC.md §3).

    Depending on `CurrentWorkspace` here — not inside the repository — is what guarantees
    the tenant is bound before any query runs, since FastAPI resolves dependencies before
    invoking the handler.
    """
    return WorkspaceService(WorkspaceRepository(uow.session, ctx))


@router.get("/me", response_model=WorkspaceRead, summary="Get the caller's Workspace")
async def get_current_workspace(
    service: Annotated[WorkspaceService, Depends(get_workspace_service)],
) -> WorkspaceRead:
    """Resolve the Workspace bound to the presented API token.

    The canonical "does my token work?" probe: it exercises token resolution, tenant
    binding, RLS, and the response envelope in one call.
    """
    return WorkspaceRead.model_validate(await service.get_current())


__all__ = ["WorkspaceContext", "router"]
