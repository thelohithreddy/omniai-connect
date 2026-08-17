"""HTTP surface for the connections domain (M1-Connections-v1). Thin: parse, delegate, shape.

No business logic, no DB access, no hand-built error responses (P-9, P-50). Every endpoint is gated
by `connections:manage` (owner/admin) — checked before the service is constructed, so an
unauthorized caller never reaches the logic. The workspace is the authenticated context
(`X-Workspace-Id` + membership for humans; the token's own workspace for machines) and appears in no
field, so a cross-workspace request is not one this API can express.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Query, Request, Response, status
from fastapi.responses import JSONResponse

from app.core.authorization import require_permission
from app.core.authz import Permission
from app.core.db import UnitOfWork, get_uow
from app.core.exceptions import ValidationFailedError
from app.core.pagination import DEFAULT_LIMIT, MAX_LIMIT
from app.core.security import WorkspaceContext
from app.domains.connections import idempotency
from app.domains.connections.repository import ConnectionRepository
from app.domains.connections.schemas import (
    ConnectionCreate,
    ConnectionList,
    ConnectionRead,
    ConnectionUpdate,
)
from app.domains.connections.service import ConnectionService

connections_router = APIRouter(prefix="/v1/connections", tags=["connections"])

#: Managing Connections (and, later, their Credentials) is `connections:manage` (owner/admin).
AuthorizedConnectionAdmin = Annotated[
    WorkspaceContext, Depends(require_permission(Permission.CONNECTIONS_MANAGE))
]

_ALLOWED_LIST_PARAMS: Final = frozenset({"limit", "cursor"})


def get_connection_service(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    ctx: AuthorizedConnectionAdmin,
) -> ConnectionService:
    """Composition root: `connections:manage` is checked before this runs, so the repository is
    always scoped to a tenant the caller may manage. The service never sees the raw request."""
    return ConnectionService(ConnectionRepository(uow.session, ctx))


def reject_unknown_query_params(request: Request) -> None:
    """API_GUIDELINES.md §4: unknown filter/sort fields are a `validation_error`, not silently
    ignored. This endpoint's only parameters are `limit` and `cursor`."""
    unknown = sorted(set(request.query_params) - _ALLOWED_LIST_PARAMS)
    if unknown:
        raise ValidationFailedError(
            "Unknown query parameters.",
            details={"unknown": unknown, "allowed": sorted(_ALLOWED_LIST_PARAMS)},
        )


@connections_router.post(
    "",
    response_model=ConnectionRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a Connection to a Connector",
    responses={
        201: {"description": "The created Connection (status=pending_auth). No credential yet."},
        400: {
            "description": "Invalid body, an unsafe base_url override, or a bad Idempotency-Key."
        },
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `connections:manage` in this Workspace."},
        404: {"description": "No such live Connector in this Workspace."},
        409: {
            "description": "A live connection with that name exists, or an Idempotency-Key clash."
        },
    },
)
async def create_connection(
    payload: ConnectionCreate,
    request: Request,
    service: Annotated[ConnectionService, Depends(get_connection_service)],
    ctx: AuthorizedConnectionAdmin,
) -> Response:
    """Create a `pending_auth` Connection binding a live Connector in the selected Workspace.

    `connector_id` is validated to be a live Connector *in this Workspace* — a foreign or deleted
    connector is a uniform 404, so a cross-tenant binding cannot be expressed. `status` and
    `credential_id` are server-controlled (never body fields); credential attachment (→ `active`)
    is a later module. `config_overrides.base_url`, if present, is SSRF-linted. An optional
    `Idempotency-Key` header (a UUID, API_GUIDELINES §5) makes retries safe: the same key + body
    replays the original response; the same key + a different body is a 409.
    """
    idem_key = request.headers.get(idempotency.HEADER)
    digest = ""
    if idem_key is not None:
        idem_key = idempotency.validate_key(idem_key)
        digest = idempotency.body_digest(payload.model_dump(mode="json"))
        replay = await idempotency.begin(ctx.workspace_id, idem_key, digest)
        if replay is not None:
            return JSONResponse(status_code=replay.status_code, content=replay.body)

    connection = await service.create(
        connector_id=payload.connector_id,
        name=payload.name,
        config_overrides=payload.config_overrides,
    )
    body = ConnectionRead.model_validate(connection).model_dump(mode="json")
    if idem_key is not None:
        await idempotency.complete(
            ctx.workspace_id, idem_key, digest, status.HTTP_201_CREATED, body
        )
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=body)


@connections_router.get(
    "",
    response_model=ConnectionList,
    summary="List the Workspace's Connections",
    responses={
        200: {"description": "A page of this Workspace's live connections, newest first."},
        400: {"description": "Unknown query parameter, bad limit, or an invalid cursor."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `connections:manage` in this Workspace."},
    },
)
async def list_connections(
    service: Annotated[ConnectionService, Depends(get_connection_service)],
    _: Annotated[None, Depends(reject_unknown_query_params)],
    limit: Annotated[
        int, Query(ge=1, le=MAX_LIMIT, description="Page size. Defaults to 50, maximum 100.")
    ] = DEFAULT_LIMIT,
    cursor: Annotated[str | None, Query(description="Opaque cursor from a prior page.")] = None,
) -> ConnectionList:
    """Page through this Workspace's live connections, newest first. The Workspace comes from the
    authenticated context and appears in no parameter, so a cross-workspace listing is not a request
    this API can express."""
    page = await service.list_page(limit=limit, cursor=cursor)
    return ConnectionList(
        data=[ConnectionRead.model_validate(c) for c in page.connections],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )


@connections_router.get(
    "/{connection_id}",
    response_model=ConnectionRead,
    summary="Get one Connection",
    responses={
        200: {"description": "The Connection."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `connections:manage` in this Workspace."},
        404: {"description": "No such live connection in this Workspace."},
    },
)
async def get_connection(
    connection_id: uuid.UUID,
    service: Annotated[ConnectionService, Depends(get_connection_service)],
) -> ConnectionRead:
    """One Connection by id. Workspace-scoped: a foreign or revoked id is a uniform 404, byte-
    identical to one that never existed, so the endpoint is not a cross-tenant oracle."""
    return ConnectionRead.model_validate(await service.get(connection_id))


@connections_router.patch(
    "/{connection_id}",
    response_model=ConnectionRead,
    summary="Update a Connection's name / config",
    responses={
        200: {"description": "The updated Connection."},
        400: {"description": "Invalid body or an unsafe base_url override."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `connections:manage` in this Workspace."},
        404: {"description": "No such live connection in this Workspace."},
        409: {"description": "The new name collides with another live connection."},
    },
)
async def update_connection(
    connection_id: uuid.UUID,
    payload: ConnectionUpdate,
    service: Annotated[ConnectionService, Depends(get_connection_service)],
) -> ConnectionRead:
    """Update a Connection's `name`/`config_overrides` only. `status`, `credential_id`, and
    `connector_id` are immutable here — a client cannot forge a lifecycle transition, attach a
    credential, or re-tenant/re-target the connection through PATCH. A `base_url` override is
    re-linted; a foreign id is a uniform 404."""
    connection = await service.update(
        connection_id, name=payload.name, config_overrides=payload.config_overrides
    )
    return ConnectionRead.model_validate(connection)


@connections_router.delete(
    "/{connection_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a Connection",
    responses={
        204: {"description": "Revoked (soft delete → `revoked`). Its name is free to reuse."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `connections:manage` in this Workspace."},
        404: {"description": "No such live connection in this Workspace."},
    },
)
async def revoke_connection(
    connection_id: uuid.UUID,
    service: Annotated[ConnectionService, Depends(get_connection_service)],
) -> Response:
    """Revoke a Connection (soft delete → `revoked`, retained for audit). Workspace-scoped: a
    foreign id is simply not found. A second revoke is a uniform 404 (the row is no longer live)."""
    await service.revoke(connection_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


__all__ = ["connections_router"]
