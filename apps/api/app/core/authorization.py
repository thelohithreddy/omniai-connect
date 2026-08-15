"""Request authorization boundary: enforce a required Permission on an endpoint.

This is **enforcement**. `core/authz.py` is the policy — a pure function over a static
table — and it is the only place role→permission grants are decided. Nothing here
compares a role to a literal or reimplements the matrix; it resolves *which* role the
authenticated caller actually holds in *this* workspace and asks the policy.

    Request
      → authentication            (get_workspace_context: Bearer token → WorkspaceContext)
      → tenant context bound      (SET LOCAL app.workspace_id, RLS armed)
      → membership resolution     (MemberRepository, workspace-scoped by construction)
      → role from the DB row      (never from the request)
      → authz.is_allowed(role, permission)
      → allow, or PermissionDeniedError → 403

**The permission is declared by the endpoint, not chosen by the caller.** It is captured
in a closure when the route is defined, at import time, and no request field can reach it.
A caller can influence *whether* they satisfy a requirement; never *which* requirement
applies.

**Machine identity has no membership, and therefore no permissions.** ADR-0002 establishes
two identity planes that are "never mixed": humans authenticate via Better Auth and map to
a Member (`kind="member"`, since M1.3-B/C), while workspace-scoped API tokens are machine
credentials that DATABASE_DESIGN.md §3 states explicitly "do not" map to a Member. A machine
request (`kind="api_token"`) resolves to no membership, so every permission check denies it.

That is the correct behaviour, not a bug to work around. The tempting shortcuts —
treating a token as its workspace's owner, or granting a token the strongest role in the
workspace — are exactly the confused-deputy patterns this boundary exists to prevent, and
they would silently merge two identity planes the architecture keeps apart. Machine
authorization is the token's own `scopes` field, a separate mechanism (M1.2-I).

Human authentication landed in M1.3-B/C, so this dependency is now **live and attached** to
every protected endpoint (`members:manage` on `/v1/members`, `api_tokens:manage` on
`/v1/api-tokens`). A human's role is resolved from `members.role` for the workspace they
selected with `X-Workspace-Id` (ADR-0016), and it is that persisted role — never a JWT,
header, or request field — that the policy below is asked about.

**Layering.** This module imports `MemberRepository` from the workspaces domain. That
follows the precedent set by `core/security.py`, which already reads the `api_tokens`
table to authenticate; the request-security boundary necessarily touches tenancy data.
It goes through the repository rather than SQL so the workspace scoping and RLS
guarantees proven in M1.2-B apply unchanged.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated, Final

from fastapi import Depends

from app.core.authz import Permission, Role, is_allowed
from app.core.db import UnitOfWork, get_uow
from app.core.exceptions import PermissionDeniedError
from app.core.security import CurrentWorkspace, WorkspaceContext
from app.domains.workspaces.repository import MemberRepository

# One message for every denial. Distinguishing "you are not a member here" from "your role
# lacks this permission" would turn a 403 into a membership-enumeration primitive: an
# attacker holding a token could probe which workspaces a subject belongs to by reading
# the difference. The endpoint's own requirement is not echoed back either.
_DENIED = "You do not have permission to perform this action."

# `CallerIdentity.kind` and `Role` unfortunately share the spelling "member" for two
# unrelated ideas: the *human identity plane* versus the *ordinary-participant role*. Named
# here so the check below reads as an identity-plane test and can never be misread — or
# mechanically mistaken — for a role comparison, which is what a duplicated RBAC matrix
# would look like. Renaming the `kind` value itself would mean editing M1.1's authenticated
# context, which is out of scope for this module.
_HUMAN_IDENTITY_KIND: Final = "member"


async def resolve_member_role(ctx: WorkspaceContext, repository: MemberRepository) -> Role | None:
    """The authenticated caller's role **in the currently bound workspace**, or `None`.

    `None` means "no role could be established" and is always a denial. It covers four
    distinct situations deliberately collapsed into one outcome:

    1. The caller is a machine identity, which has no membership by design (ADR-0002).
    2. The caller claims a membership that does not exist in this workspace — including
       one that exists in a *different* workspace, because the repository is scoped to
       this one and simply returns nothing.
    3. The membership exists but carries a role outside the canonical domain, which would
       mean the CHECK constraint was bypassed.
    4. There is no member id to look up at all.

    Case 2 is the cross-workspace guarantee, and it holds without any comparison here: the
    lookup is workspace-scoped by construction (M1.2-B) and RLS is armed on the same
    transaction. A user who is an owner in workspace A and a viewer in workspace B gets
    viewer's permissions when authenticated against B — not because this function checks,
    but because A's membership row is unreachable from B's context.
    """
    if ctx.caller.kind != _HUMAN_IDENTITY_KIND or ctx.caller.member_id is None:
        return None

    member = await repository.get(ctx.caller.member_id)
    if member is None:
        return None

    # The role is read from the persisted row, never from the request. A value outside the
    # domain denies rather than raising: authorization must not be convertible into a
    # crash by corrupting one row.
    try:
        return Role(member.role)
    except ValueError:
        return None


def require_permission(
    permission: Permission,
) -> Callable[[UnitOfWork, WorkspaceContext], Awaitable[WorkspaceContext]]:
    """Build a FastAPI dependency that admits only callers holding `permission`.

        @router.delete("/members/{member_id}")
        async def remove(ctx: Annotated[WorkspaceContext,
                                        Depends(require_permission(Permission.MEMBERS_MANAGE))]):
            ...

    `permission` is bound when the route is declared and is not a parameter of the
    returned dependency, so it never appears in the request signature and cannot be
    supplied, overridden, or guessed by a caller.

    Depending on `CurrentWorkspace` is what orders the pipeline: FastAPI resolves it
    first, so authentication has already succeeded (or raised `UnauthorizedError` → 401)
    and the tenant is already bound before any membership lookup runs. Authorization
    cannot execute on an unauthenticated or unbound request.

    Read-only. It resolves a role and evaluates policy; it writes nothing, commits
    nothing, and opens no transaction of its own — the UnitOfWork it receives is the
    request's existing one.
    """

    async def dependency(
        uow: Annotated[UnitOfWork, Depends(get_uow)],
        ctx: CurrentWorkspace,
    ) -> WorkspaceContext:
        role = await resolve_member_role(ctx, MemberRepository(uow.session, ctx))
        if role is None or not is_allowed(role, permission):
            raise PermissionDeniedError(_DENIED)
        return ctx

    return dependency


__all__ = ["require_permission", "resolve_member_role"]
