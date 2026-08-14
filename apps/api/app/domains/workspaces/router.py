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
from app.core.exceptions import ValidationFailedError
from app.core.pagination import DEFAULT_LIMIT, MAX_LIMIT
from app.core.security import CurrentWorkspace, WorkspaceContext
from app.domains.workspaces.repository import ApiTokenRepository, WorkspaceRepository
from app.domains.workspaces.schemas import (
    ApiTokenCreate,
    ApiTokenCreated,
    ApiTokenList,
    ApiTokenRead,
    WorkspaceRead,
)
from app.domains.workspaces.service import ApiTokenService, WorkspaceService

router = APIRouter(prefix="/v1/workspaces", tags=["workspaces"])
api_tokens_router = APIRouter(prefix="/v1/api-tokens", tags=["api-tokens"])

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


__all__ = ["WorkspaceContext", "api_tokens_router", "router"]
