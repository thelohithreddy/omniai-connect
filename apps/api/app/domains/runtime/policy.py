"""Tool-execution authorization — the human/machine fork (AI_RUNTIME.md §2 stage 3, ADR-0031).

`require_permission` cannot gate Tool Calls: it resolves a *membership* role, and a machine API
token has no membership by design (ADR-0002), so it would deny every machine caller — yet machine
tokens are the primary Tool-Call caller (the curl-from-token demo, ROADMAP.md:45). Tool execution is
therefore authorized on **two planes**, exactly as ADR-0002 keeps them:

- **Human (`kind="member"`)** → the RBAC matrix: must hold `Permission.TOOLS_EXECUTE`
  (OWNER/ADMIN/MEMBER; VIEWER denied). Same policy source (`authz.is_allowed`) as every other
  human-gated endpoint — no duplicated matrix here.
- **Machine (`kind="api_token"`)** → a valid, non-revoked, non-expired, workspace-bound token (which
  `get_workspace_context` has already proven) authorizes execution within its own workspace. Tokens
  are canonically issued unscoped (`[]`) pending a scope vocabulary that does not exist yet, so an
  unscoped token carries full machine authority; per-token scope-narrowing (restricting a token to a
  subset of Connections/Tools) is deferred to when that vocabulary lands. This is the founder-
  ratified
  M1 posture, not an implicit grant.

Depending on `CurrentWorkspace` orders the pipeline: authentication + tenant binding have already
run (or raised 401) before this gate evaluates.
"""

from __future__ import annotations

from typing import Annotated, Final

from fastapi import Depends

from app.core.authorization import resolve_member_role
from app.core.authz import Permission, is_allowed
from app.core.db import UnitOfWork, get_uow
from app.core.exceptions import PermissionDeniedError
from app.core.security import CurrentWorkspace, WorkspaceContext
from app.domains.workspaces.repository import MemberRepository

_DENIED = "You do not have permission to perform this action."
_HUMAN_IDENTITY_KIND: Final = "member"


async def require_tool_execution(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    ctx: CurrentWorkspace,
) -> WorkspaceContext:
    """Admit a caller allowed to execute Tool Calls in the bound workspace, else 403."""
    if ctx.caller.kind != _HUMAN_IDENTITY_KIND:
        # Machine plane: the authenticated, workspace-bound token is the authority (see module
        # docs).
        return ctx
    role = await resolve_member_role(ctx, MemberRepository(uow.session, ctx))
    if role is None or not is_allowed(role, Permission.TOOLS_EXECUTE):
        raise PermissionDeniedError(_DENIED)
    return ctx


__all__ = ["require_tool_execution"]
