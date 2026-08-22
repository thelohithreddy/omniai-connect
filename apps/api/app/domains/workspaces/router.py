"""HTTP surface for the workspaces domain. Thin: parse, delegate, shape.

No business logic, no DB access, no hand-built error responses (P-9, P-50). If a handler
here grows an `if` about domain state, it belongs in the service.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Query, Request, Response, status

from app.core.authorization import require_permission
from app.core.authz import Permission
from app.core.db import UnitOfWork, get_uow
from app.core.email import EmailSender, get_email_sender
from app.core.exceptions import ValidationFailedError
from app.core.pagination import DEFAULT_LIMIT, MAX_LIMIT
from app.core.security import (
    CurrentHumanIdentity,
    CurrentHumanSubject,
    CurrentWorkspace,
    WorkspaceContext,
    resolve_human_memberships,
)
from app.domains.workspaces.acceptance import InvitationAcceptanceService
from app.domains.workspaces.repository import (
    ApiTokenRepository,
    InvitationRepository,
    MemberRepository,
    WorkspaceRepository,
)
from app.domains.workspaces.schemas import (
    AcceptedInvitation,
    ApiTokenCreate,
    ApiTokenCreated,
    ApiTokenList,
    ApiTokenRead,
    InvitationAccept,
    InvitationCreate,
    InvitationList,
    InvitationRead,
    MemberList,
    MemberRead,
    MemberRoleUpdate,
    MembershipList,
    MembershipRead,
    WorkspaceNotificationSettings,
    WorkspaceNotificationUpdate,
    WorkspaceRead,
)
from app.domains.workspaces.service import (
    ApiTokenService,
    InvitationService,
    MemberService,
    WorkspaceService,
)

router = APIRouter(prefix="/v1/workspaces", tags=["workspaces"])
api_tokens_router = APIRouter(prefix="/v1/api-tokens", tags=["api-tokens"])
members_router = APIRouter(prefix="/v1/members", tags=["members"])

# Built **once**, at import time, and reused. `require_permission` returns a fresh closure
# per call, and FastAPI's per-request dependency cache is keyed on the callable object — so
# writing `Depends(require_permission(...))` in both the service factory and the handler
# would create two distinct dependencies and run the whole membership lookup twice per
# request. One module-level instance makes it exactly one lookup.
#
# It also means the required Permission is fixed at import time: it is captured in a
# closure with no request in scope, so no header, body field, or query parameter can reach
# it. A caller can fail the requirement; never choose a different one.
#: The only query parameters this endpoint accepts. Anything else is a validation error
#: rather than a silent no-op (API_GUIDELINES.md §4).
_ALLOWED_LIST_PARAMS: Final = frozenset({"limit", "cursor"})

AuthorizedTokenAdmin = Annotated[
    WorkspaceContext, Depends(require_permission(Permission.API_TOKENS_MANAGE))
]

#: Built once for the same reason as `AuthorizedTokenAdmin`: `require_permission` returns a
#: fresh closure per call and FastAPI's per-request dependency cache is keyed on the
#: callable, so a second construction would run the membership lookup twice per request.
AuthorizedMemberAdmin = Annotated[
    WorkspaceContext, Depends(require_permission(Permission.MEMBERS_MANAGE))
]

#: `workspace:manage` — OWNER only (authz.py's matrix, transcribed from SECURITY.md §4.1). Built
#: once for the same dependency-cache reason as the two above. This is the permission's **first**
#: enforcement anywhere in the API: it was transcribed in M1.2-D and, until M2.10, guarded nothing.
AuthorizedWorkspaceAdmin = Annotated[
    WorkspaceContext, Depends(require_permission(Permission.WORKSPACE_MANAGE))
]


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


@router.get(
    "",
    response_model=MembershipList,
    summary="List the authenticated human's own workspace memberships",
)
async def list_my_workspaces(
    subject: CurrentHumanSubject,
    uow: Annotated[UnitOfWork, Depends(get_uow)],
) -> MembershipList:
    """The workspaces the authenticated human belongs to, with their role in each (ADR-0016 §7).

    Human-only and pre-selection: a human calls this to discover what they may put in
    `X-Workspace-Id` before selecting a workspace, so it authenticates via the verified JWT
    subject **without** binding a workspace. It reads only the caller's own memberships
    through the `auth.resolve_member_workspace_roles` bootstrap function — no other tenant's
    existence, name, members, or metadata is reachable, and `role` is display-only (never an
    authorization input). A machine token is not a human credential and fails the human
    verifier uniformly.
    """
    memberships = await resolve_human_memberships(subject, uow.session)
    return MembershipList(
        data=[MembershipRead(id=m.workspace_id, role=m.role) for m in memberships]
    )


@router.get("/me", response_model=WorkspaceRead, summary="Get the caller's Workspace")
async def get_current_workspace(
    service: Annotated[WorkspaceService, Depends(get_workspace_service)],
) -> WorkspaceRead:
    """Resolve the Workspace bound to the presented API token.

    The canonical "does my token work?" probe: it exercises token resolution, tenant
    binding, RLS, and the response envelope in one call.

    Deliberately does **not** carry `notification_email`. This endpoint authenticates with
    `CurrentWorkspace`, which every machine token satisfies, so a field added here is a field
    handed to every MCP client holding a workspace token. The destination is read through the
    `workspace:manage` endpoint below instead (M2.10, ADR-0041).
    """
    return WorkspaceRead.model_validate(await service.get_current())


def get_workspace_admin_service(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    ctx: AuthorizedWorkspaceAdmin,
) -> WorkspaceService:
    """Composition root for the OWNER-only workspace-configuration endpoints.

    Identical to `get_workspace_service` except for the dependency that produces the context:
    resolving `AuthorizedWorkspaceAdmin` here means authorization runs *before* the service — and
    therefore before any query — rather than inside a handler that could forget to ask.
    """
    return WorkspaceService(WorkspaceRepository(uow.session, ctx))


@router.get(
    "/me/notification-settings",
    response_model=WorkspaceNotificationSettings,
    summary="Read the Workspace's notification destination",
    responses={
        403: {"description": "The caller does not hold workspace:manage (OWNER only)."},
        404: {"description": "Workspace not found."},
    },
)
async def get_notification_settings(
    service: Annotated[WorkspaceService, Depends(get_workspace_admin_service)],
) -> WorkspaceNotificationSettings:
    """Where this Workspace's Connection Health failure notifications are sent (M2.10).

    OWNER-only on both read and write: the value is an address a human typed, so exposing it to
    ADMIN — let alone to a machine token — would widen PII for no operational gain.
    """
    return WorkspaceNotificationSettings(notification_email=await service.get_notification_email())


@router.patch(
    "/me",
    response_model=WorkspaceNotificationSettings,
    summary="Set the Workspace's notification destination",
    responses={
        403: {"description": "The caller does not hold workspace:manage (OWNER only)."},
        404: {"description": "Workspace not found."},
        400: {"description": "The destination is not a valid email address."},
    },
)
async def update_current_workspace(
    payload: WorkspaceNotificationUpdate,
    service: Annotated[WorkspaceService, Depends(get_workspace_admin_service)],
) -> WorkspaceNotificationSettings:
    """Configure Connection Health failure notifications for the caller's own Workspace.

    The Workspace is the one the caller is already authenticated against — there is no
    `workspace_id` in the path or the body, so this endpoint is structurally incapable of being
    aimed at another tenant. `notification_email: null` (or an emptied field) disables
    notifications; the Connection Health path then simply has nowhere to send and does not send.

    `extra="forbid"` on the payload means this cannot become a general workspace mutator by
    accident: an attempt to set `plan`, `slug`, or `name` here is a 422, not a silent no-op.
    """
    stored = await service.set_notification_email(payload.notification_email)
    return WorkspaceNotificationSettings(notification_email=stored)


def get_member_service(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    ctx: AuthorizedMemberAdmin,
) -> MemberService:
    """Composition root for member management.

    Depending on `AuthorizedMemberAdmin` rather than `CurrentWorkspace` is what puts
    authorization *before* construction: FastAPI resolves dependencies before the handler
    runs, so a caller lacking `members:manage` gets a 403 and the service is never built.
    """
    return MemberService(MemberRepository(uow.session, ctx))


@members_router.get(
    "",
    response_model=MemberList,
    summary="List the Workspace's Members",
    responses={
        200: {"description": "A page of Members, newest first."},
        400: {"description": "Unknown query parameter, bad limit, or an invalid cursor."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `members:manage` in this Workspace."},
    },
)
async def list_members(
    service: Annotated[MemberService, Depends(get_member_service)],
    _: Annotated[None, Depends(reject_unknown_query_params)],
    limit: Annotated[
        int, Query(ge=1, le=MAX_LIMIT, description="Page size. Defaults to 50, maximum 100.")
    ] = DEFAULT_LIMIT,
    cursor: Annotated[str | None, Query(description="Opaque cursor from a prior page.")] = None,
) -> MemberList:
    """Page through this Workspace's Members, newest first.

    The Workspace comes from the authenticated context and appears in no parameter of this
    function, so listing another tenant's members is not a request this API can express.

    Requires `members:manage` (SECURITY.md §4.1), which owner and admin hold. A machine
    token resolves to no membership and is therefore denied — a leaked credential cannot
    enumerate who works at the customer.
    """
    page = await service.list_members_page(limit=limit, cursor=cursor)
    return MemberList(
        data=[MemberRead.model_validate(member) for member in page.members],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )


@members_router.patch(
    "/{member_id}",
    response_model=MemberRead,
    summary="Change a Member's role",
    responses={
        200: {"description": "The updated Member."},
        400: {"description": "Malformed id, unknown field, or a role outside the domain."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `members:manage` in this Workspace."},
        404: {"description": "No such Member in this Workspace."},
    },
)
async def change_member_role(
    member_id: uuid.UUID,
    payload: MemberRoleUpdate,
    service: Annotated[MemberService, Depends(get_member_service)],
) -> MemberRead:
    """Set a Member's role. Takes effect on that member's very next request.

    The role is read from the persisted row on every authorization check (M1.2-E), so a
    demotion binds immediately — there is no cached role and nothing to invalidate.

    **No role-transition rules are enforced**, and that is deliberate rather than an
    oversight: no canonical document defines whether an admin may re-role an owner, or
    whether the last owner may be demoted. `MemberService` records both as open questions.
    Inventing them here would place authorization policy in an HTTP adapter and prejudge a
    decision that belongs in SECURITY.md §4.1.
    """
    member = await service.change_member_role(member_id, payload.role)
    return MemberRead.model_validate(member)


@members_router.delete(
    "/{member_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove a Member from the Workspace",
    responses={
        204: {"description": "Removed."},
        400: {"description": "Malformed member id."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `members:manage` in this Workspace."},
        404: {"description": "No such Member in this Workspace."},
    },
)
async def remove_member(
    member_id: uuid.UUID,
    service: Annotated[MemberService, Depends(get_member_service)],
) -> None:
    """Remove a Member. Their membership, and the authority it carried, ends immediately.

    **404 for a Member that is absent *or* belongs to another Workspace**, byte-identical in
    both cases. API_GUIDELINES.md §2 also says "deleting a deleted resource is 204", but the
    same section requires cross-tenant access to answer 404 — and for a hard-deleted row,
    "already deleted", "never existed" and "not yours" are indistinguishable. Answering 204
    for absence would therefore mean answering 204 for another tenant's id too, or
    distinguishing them and becoming the existence oracle SECURITY.md §3 forbids. Security
    wins, matching ADR-0012's treatment of the analogous token endpoint.

    Removing a Member does **not** revoke the API tokens they created: those are
    workspace-owned credentials whose provenance is simply cleared (M1.2-A's composite FK
    with `ON DELETE SET NULL`). Revoking them is a separate, explicit act.
    """
    await service.remove_member(member_id)


def get_api_token_service(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    ctx: AuthorizedTokenAdmin,
) -> ApiTokenService:
    """Composition root for token issuance.

    Depending on `AuthorizedTokenAdmin` rather than `CurrentWorkspace` is what puts
    authorization *before* construction: FastAPI resolves dependencies before the handler
    runs, so a caller lacking `api_tokens:manage` gets a 403 and the service is never
    built. The permission check is not a line inside the handler that a future edit could
    reorder below the write.
    """
    return ApiTokenService(ApiTokenRepository(uow.session, ctx))


def reject_unknown_query_params(request: Request) -> None:
    """API_GUIDELINES.md §4: *"Unknown filter/sort fields are a `validation_error`, not
    silently ignored."*

    FastAPI's default is the opposite — unrecognised query parameters are dropped without
    comment. That default is quietly dangerous for a listing endpoint: a client that asks
    for `?revoked=false`, or misspells `limit` as `limlt`, receives a perfectly valid 200
    containing *everything*, and believes it received a filtered page. For a credential
    inventory that is a correctness bug the caller cannot detect.

    This endpoint documents its sortable fields as *none* — the order is fixed at
    `-created_at` (§4's default) — so `sort` is unknown here too and is refused rather than
    accepted and ignored, which would be the more misleading of the two failures.
    """
    unknown = sorted(set(request.query_params) - _ALLOWED_LIST_PARAMS)
    if unknown:
        raise ValidationFailedError(
            "Unknown query parameters.",
            details={"unknown": unknown, "allowed": sorted(_ALLOWED_LIST_PARAMS)},
        )


@api_tokens_router.get(
    "",
    response_model=ApiTokenList,
    summary="List the Workspace's API tokens",
    responses={
        200: {"description": "A page of token metadata. Never contains a secret."},
        400: {"description": "Unknown query parameter, bad limit, or an invalid cursor."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `api_tokens:manage` in this Workspace."},
    },
)
async def list_api_tokens(
    service: Annotated[ApiTokenService, Depends(get_api_token_service)],
    _: Annotated[None, Depends(reject_unknown_query_params)],
    limit: Annotated[
        int,
        Query(ge=1, le=MAX_LIMIT, description="Page size. Defaults to 50, maximum 100."),
    ] = DEFAULT_LIMIT,
    cursor: Annotated[str | None, Query(description="Opaque cursor from a prior page.")] = None,
) -> ApiTokenList:
    """Page through this Workspace's tokens, newest first.

    **Metadata only, always.** The response carries `token_prefix` — the public fragment
    that lets a human recognise a credential in a revocation UI, exactly as GitHub shows
    `ghp_…` — and never the secret or its hash. That is not enforced by a filter here: the
    plaintext was never stored, and `ApiTokenRead` has no field able to carry either value.

    The Workspace comes from the authenticated context and appears in no parameter of this
    function. There is no request field — query, path, body, or header — through which a
    caller could name a different tenant, so cross-workspace listing is not a request this
    API can express.

    Requires `api_tokens:manage`, the same capability as issuance (SECURITY.md §4.1). A
    machine token therefore cannot enumerate the Workspace's credentials, for the same
    reason it cannot mint one: it resolves to no membership (ADR-0002).
    """
    page = await service.list_tokens(limit=limit, cursor=cursor)
    return ApiTokenList(
        data=[ApiTokenRead.model_validate(token) for token in page.tokens],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )


@api_tokens_router.delete(
    "/{token_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a workspace API token",
    responses={
        204: {"description": "Revoked. Also returned if it was already revoked."},
        400: {"description": "Malformed token id."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `api_tokens:manage` in this Workspace."},
        404: {"description": "No such token in this Workspace."},
    },
)
async def revoke_api_token(
    token_id: uuid.UUID,
    service: Annotated[ApiTokenService, Depends(get_api_token_service)],
) -> None:
    """Stop a credential from working, immediately and permanently.

    **`DELETE` on a state transition.** The row is not removed — `revoked_at` is set, and
    the token stays visible in listings with that field populated, which is how an operator
    later sees that a credential existed and when it was cut off. From the client's side the
    credential ceases to exist, which is what `DELETE` means; retention is an audit
    implementation detail. There is no un-revoke: the guidelines define no such operation
    and inventing one would let a compromised credential be restored (ADR-0012).

    **Effective immediately**, with no cache to wait for. `get_workspace_context` re-reads
    the token row on every request and rejects a revoked one (MCP_RUNTIME.md §5: revoking
    "severs every client using it immediately"). Nothing here duplicates that check — this
    endpoint only writes the state that the single existing resolver already enforces.

    Requires `api_tokens:manage`. A machine token cannot revoke anything, including itself,
    because it resolves to no membership (ADR-0002) — which also means a stolen credential
    cannot be used to revoke the *other* tokens an operator would need during a response.
    """
    await service.revoke(token_id)


@api_tokens_router.post(
    "",
    response_model=ApiTokenCreated,
    status_code=status.HTTP_201_CREATED,
    summary="Create a workspace API token",
    responses={
        201: {"description": "Created. Contains the plaintext token, shown once."},
        # The app converts `RequestValidationError` into the canonical 400 envelope
        # (API_GUIDELINES.md §6), so 400 — not FastAPI's default 422 — is what a client
        # actually receives for a malformed body or an unknown field.
        400: {"description": "Invalid name, or an attempt to set a server-owned field."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `api_tokens:manage` in this Workspace."},
    },
)
async def create_api_token(
    payload: ApiTokenCreate,
    service: Annotated[ApiTokenService, Depends(get_api_token_service)],
    ctx: AuthorizedTokenAdmin,
    response: Response,
) -> ApiTokenCreated:
    """Mint a machine credential for the caller's Workspace.

    The response body carries the plaintext token, and it is the only time it will ever
    exist outside the client. It is stored as a SHA-256 hash; there is no read-back
    endpoint and no recovery path.

    **Provenance comes from the authenticated context, never the request.**
    `created_by_member_id` is taken from `ctx.caller.member_id` — a value produced by token
    resolution and membership lookup — and `ApiTokenCreate` forbids extra fields, so a
    client attempting to supply it is rejected rather than ignored. Reaching this line at
    all proves the caller is a human-plane member of this Workspace holding
    `api_tokens:manage`: `resolve_member_role` returns `None` for any other identity, and
    `None` denies. The attribution therefore cannot be forged or absent.

    `Cache-Control: no-store` per RFC 6749 §5.1, which governs exactly this shape of
    response — a bearer credential in a JSON body. Without it a proxy, a browser cache, or
    a logging middleware that records response bodies for cacheable 2xx replies is free to
    retain the secret.
    """
    response.headers["Cache-Control"] = "no-store"
    issued = await service.issue(
        name=payload.name,
        created_by_member_id=ctx.caller.member_id,
    )
    return ApiTokenCreated(
        id=issued.token.id,
        name=issued.token.name,
        token=issued.plaintext,
        token_prefix=issued.token.token_prefix,
        scopes=list(issued.token.scopes),
        created_by_member_id=issued.token.created_by_member_id,
        expires_at=issued.token.expires_at,
        created_at=issued.token.created_at,
    )


invitations_router = APIRouter(prefix="/v1/invitations", tags=["invitations"])


def get_invitation_service(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    ctx: AuthorizedMemberAdmin,
    email_sender: Annotated[EmailSender, Depends(get_email_sender)],
) -> InvitationService:
    """Composition root for invitation management (ADR-0017 §8).

    Gated by `AuthorizedMemberAdmin` (`members:manage`) exactly like member management —
    creating, listing, and cancelling invitations is managing who belongs to the workspace.
    The permission is checked before the service is built, so an unauthorized caller never
    reaches the logic.
    """
    return InvitationService(InvitationRepository(uow.session, ctx), email_sender)


@invitations_router.post(
    "",
    response_model=InvitationRead,
    status_code=status.HTTP_201_CREATED,
    summary="Invite a person to the Workspace by email",
    responses={
        201: {"description": "Created and emailed. The token is never in the response."},
        400: {"description": "Invalid email, unknown role, or a server-owned field."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `members:manage` in this Workspace."},
        409: {"description": "A pending invitation already exists for that email here."},
    },
)
async def create_invitation(
    payload: InvitationCreate,
    ctx: AuthorizedMemberAdmin,
    service: Annotated[InvitationService, Depends(get_invitation_service)],
) -> InvitationRead:
    """Create a targeted invitation and email it (ADR-0017).

    The Workspace is the `X-Workspace-Id` selection, the inviter is the authenticated
    member (`ctx.caller.member_id`, never a request field), and the role is server-persisted
    at creation — the recipient can neither see nor change it. The response is the invitation
    record **without** the token: the raw token exists only in the email and is never
    returned or logged.
    """
    issued = await service.invite(
        email=payload.email, role=payload.role, invited_by=ctx.caller.member_id
    )
    return InvitationRead.model_validate(issued.invitation)


@invitations_router.get(
    "",
    response_model=InvitationList,
    summary="List this Workspace's pending invitations",
    responses={
        200: {"description": "Pending invitations for the selected Workspace, newest first."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `members:manage` in this Workspace."},
    },
)
async def list_invitations(
    service: Annotated[InvitationService, Depends(get_invitation_service)],
    _: Annotated[None, Depends(reject_unknown_query_params)],
) -> InvitationList:
    """Pending invitations for the selected Workspace only.

    Workspace-scoped by the same context every management endpoint uses, so another
    tenant's invitations are not a request this API can express. Tokens and hashes are
    absent from `InvitationRead` by construction.
    """
    invitations = await service.list_pending()
    return InvitationList(data=[InvitationRead.model_validate(i) for i in invitations])


@invitations_router.delete(
    "/{invitation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Cancel a pending invitation",
    responses={
        204: {"description": "Cancelled. It can never be accepted."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `members:manage` in this Workspace."},
        404: {"description": "No such pending invitation in this Workspace."},
    },
)
async def cancel_invitation(
    invitation_id: uuid.UUID,
    service: Annotated[InvitationService, Depends(get_invitation_service)],
) -> Response:
    """Cancel a pending invitation. Workspace-scoped: a foreign id is simply not found.

    A cancelled invitation can never be accepted — its status leaves `pending`, so the
    acceptance guard fails.
    """
    await service.cancel(invitation_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@invitations_router.post(
    "/accept",
    response_model=AcceptedInvitation,
    summary="Accept an invitation and join the Workspace",
    responses={
        200: {"description": "Joined. Returns the workspace and the granted role."},
        401: {"description": "Missing or invalid human credential."},
        404: {"description": "Invitation not found or not acceptable (uniform, no oracle)."},
        409: {"description": "You are already a member of this Workspace."},
    },
)
async def accept_invitation(
    payload: InvitationAccept,
    identity: CurrentHumanIdentity,
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    request: Request,
) -> AcceptedInvitation:
    """Accept an invitation with the token from its email (ADR-0017 §8).

    Not workspace-scoped and not RBAC-gated: the invitation, resolved from its token,
    establishes the Workspace, and the gate is the verified-email binding, not a permission.
    The token is in the body — never the URL — so it stays out of access logs. The whole
    sequence (resolve, verify email, bind, consume, create membership) is one transaction;
    any failure rolls all of it back. Every unacceptable case returns the one uniform 404.
    """
    request_id: str = getattr(request.state, "request_id", "")
    result = await InvitationAcceptanceService(uow).accept(
        token=payload.token, identity=identity, request_id=request_id
    )
    return AcceptedInvitation(workspace_id=result.workspace_id, role=result.role)


__all__ = [
    "WorkspaceContext",
    "api_tokens_router",
    "invitations_router",
    "members_router",
    "router",
]
