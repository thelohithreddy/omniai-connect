"""HTTP surface for the connectors domain (M1.4-A). Thin: parse, delegate, shape.

No business logic, no DB access, no hand-built error responses (P-9, P-50). Every endpoint
is gated by `connectors:manage` (owner/admin) — the permission is checked before the service
is constructed, so an unauthorized caller never reaches the logic.
"""

from __future__ import annotations

import contextlib
import uuid
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Query, Request, Response, status
from starlette.datastructures import UploadFile

from app.core.authorization import require_permission
from app.core.authz import Permission
from app.core.db import UnitOfWork, get_uow
from app.core.exceptions import ValidationFailedError
from app.core.ids import new_id
from app.core.object_store import ObjectStoreError, TenantObjectKey, get_object_store
from app.core.pagination import DEFAULT_LIMIT, MAX_LIMIT
from app.core.security import WorkspaceContext
from app.domains.connectors.repository import ConnectorRepository
from app.domains.connectors.schemas import ConnectorCreate, ConnectorList, ConnectorRead
from app.domains.connectors.service import ConnectorService

connectors_router = APIRouter(prefix="/v1/connectors", tags=["connectors"])

# The canonical document cap (CONNECTOR_SPECIFICATION §11: "≤ 10 MB raw"). Applied to uploads by
# bounding the multipart part size explicitly — never trusting the framework default (1 MB).
_MAX_UPLOAD_BYTES: Final = 10 * 1024 * 1024

#: Managing Connectors is `connectors:manage` (owner/admin). Built once at import time and
#: reused — `require_permission` returns a fresh closure each call, so building it inline in
#: every handler would be one dependency object per endpoint for no benefit.
AuthorizedConnectorAdmin = Annotated[
    WorkspaceContext, Depends(require_permission(Permission.CONNECTORS_MANAGE))
]

_ALLOWED_LIST_PARAMS: Final = frozenset({"limit", "cursor"})


def get_connector_service(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    ctx: AuthorizedConnectorAdmin,
) -> ConnectorService:
    """Composition root for connector management.

    `AuthorizedConnectorAdmin` resolves the authenticated caller into a workspace-bound
    context *and* checks `connectors:manage` before this runs, so the repository is always
    scoped to a tenant the caller may manage. The service never sees the raw request.
    """
    return ConnectorService(ConnectorRepository(uow.session, ctx))


def reject_unknown_query_params(request: Request) -> None:
    """API_GUIDELINES.md §4: unknown filter/sort fields are a `validation_error`, not silently
    ignored. This endpoint's only parameters are `limit` and `cursor`; the order is fixed at
    `-created_at`, so any other query key (a misspelled `limit`, a `sort`) is refused rather
    than accepted and quietly ignored — the more misleading of the two failures."""
    unknown = sorted(set(request.query_params) - _ALLOWED_LIST_PARAMS)
    if unknown:
        raise ValidationFailedError(
            "Unknown query parameters.",
            details={"unknown": unknown, "allowed": sorted(_ALLOWED_LIST_PARAMS)},
        )


@connectors_router.post(
    "",
    response_model=ConnectorRead,
    status_code=status.HTTP_201_CREATED,
    summary="Define a manual Connector",
    responses={
        201: {"description": "The created Connector (source_type=manual, status=draft)."},
        400: {"description": "Invalid name/slug, or a base_url that fails the SSRF lint."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `connectors:manage` in this Workspace."},
        409: {"description": "A live connector with that slug already exists here."},
    },
)
async def create_connector(
    payload: ConnectorCreate,
    service: Annotated[ConnectorService, Depends(get_connector_service)],
) -> ConnectorRead:
    """Create a manual Connector in the selected Workspace.

    `source_type` is server-set to `manual` and `status` to `draft` — neither is a request
    field, so a client cannot mint a Connector that falsely claims to be OpenAPI-ingested.
    `base_url` is SSRF-linted (https only; no private/loopback/link-local/metadata hosts; no
    embedded credentials) before it is stored, because it is a wire destination the runtime
    will later call. `auth_config` carries auth *requirements* only, never secrets.
    """
    connector = await service.create(
        name=payload.name,
        base_url=payload.base_url,
        auth_config=payload.auth_config,
        slug=payload.slug,
    )
    return ConnectorRead.model_validate(connector)


@connectors_router.get(
    "",
    response_model=ConnectorList,
    summary="List the Workspace's Connectors",
    responses={
        200: {"description": "A page of this Workspace's live connectors, newest first."},
        400: {"description": "Unknown query parameter, bad limit, or an invalid cursor."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `connectors:manage` in this Workspace."},
    },
)
async def list_connectors(
    service: Annotated[ConnectorService, Depends(get_connector_service)],
    _: Annotated[None, Depends(reject_unknown_query_params)],
    limit: Annotated[
        int, Query(ge=1, le=MAX_LIMIT, description="Page size. Defaults to 50, maximum 100.")
    ] = DEFAULT_LIMIT,
    cursor: Annotated[str | None, Query(description="Opaque cursor from a prior page.")] = None,
) -> ConnectorList:
    """Page through this Workspace's live connectors, newest first.

    The Workspace comes from the authenticated context and appears in no parameter here, so a
    cross-workspace listing is not a request this API can express. Soft-deleted connectors are
    absent by construction (the repository filters `deleted_at IS NULL`).
    """
    page = await service.list_page(limit=limit, cursor=cursor)
    return ConnectorList(
        data=[ConnectorRead.model_validate(connector) for connector in page.connectors],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
    )


@connectors_router.post(
    "/{connector_id}/versions",
    response_model=ConnectorRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest an OpenAPI spec (async) — by URL or file upload",
    responses={
        202: {
            "description": "Accepted; the Connector is now `ingesting`. The Celery pipeline gets "
            "the bytes (guarded fetch of the URL, or the staged upload), normalizes, persists an "
            "immutable version, and publishes `connector.ingested`. Poll for `active`/`failed`."
        },
        400: {
            "description": "Not exactly one of `source_url`/`file`; a non-https URL; an empty, "
            "oversized, or malformed upload."
        },
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `connectors:manage` in this Workspace."},
        404: {"description": "No such live connector in this Workspace."},
        409: {"description": "The Connector is already ingesting."},
    },
)
async def ingest_connector_version(
    connector_id: uuid.UUID,
    request: Request,
    service: Annotated[ConnectorService, Depends(get_connector_service)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    ctx: AuthorizedConnectorAdmin,
) -> ConnectorRead:
    """Start asynchronous OpenAPI ingestion for a Connector (M1.4-B1.1/B1.2).

    `multipart/form-data` with **exactly one** of a `source_url` field (URL ingestion) or a `file`
    upload. The Connector transitions to `ingesting` and a post-commit trigger enqueues the Celery
    pipeline. The workspace is the authenticated context — the URL/upload names only *where* the
    spec is, never *which tenant* — so a client cannot ingest into another Workspace. Returns 202
    with the Connector in `ingesting`; the terminal state is the worker's.

    An uploaded file is validated (bounded size, non-empty) and staged to the tenant ObjectStore
    here (the worker cannot re-fetch it, §18); the filename is discarded — never trusted for type,
    path, or logging. The multipart part size is bounded explicitly (never the 1 MB framework
    default) so an oversized upload fails at parse time.
    """
    try:
        form = await request.form(max_part_size=_MAX_UPLOAD_BYTES + 4096, max_files=1, max_fields=3)
    except Exception as exc:  # oversized part / malformed multipart
        raise ValidationFailedError("Malformed or oversized multipart body.") from exc

    unknown = set(form) - {"source_url", "file"}
    if unknown:  # a client cannot smuggle a server-owned field (workspace_id, status, …)
        raise ValidationFailedError("Unknown form fields.", details={"unknown": sorted(unknown)})

    raw_url = form.get("source_url")
    upload = form.get("file")
    has_url = isinstance(raw_url, str) and bool(raw_url.strip())
    has_file = isinstance(upload, UploadFile)
    if has_url == has_file:  # both or neither
        raise ValidationFailedError("Provide exactly one of a `source_url` field or a `file`.")

    if has_file:
        assert isinstance(upload, UploadFile)
        data = await upload.read()
        if not data:
            raise ValidationFailedError("Uploaded file is empty.")
        if len(data) > _MAX_UPLOAD_BYTES:
            raise ValidationFailedError("Uploaded file exceeds the size limit.")
        # Stage under the tenant prefix with a fresh uuid key — the client filename is never used
        # for the key, the type, or a log line. The worker reads it back through the same boundary.
        store = get_object_store()
        upload_ref = f"connectors/{connector_id}/uploads/{new_id().hex}.json"
        key = TenantObjectKey.for_workspace(ctx.workspace_id, upload_ref)
        await store.put(key, data, content_type="application/json")
        try:
            connector = await service.request_ingestion(
                uow, workspace_id=ctx.workspace_id, connector_id=connector_id, upload_ref=upload_ref
            )
        except Exception:
            # A rejected request (404/409/…) must not leave the staged upload behind.
            with contextlib.suppress(ObjectStoreError):
                await store.delete(key)
            raise
    else:
        assert isinstance(raw_url, str)
        source_url = raw_url.strip()
        if not source_url.lower().startswith("https://") or len(source_url) > 2048:
            raise ValidationFailedError("source_url must be an https URL within the length limit.")
        connector = await service.request_ingestion(
            uow, workspace_id=ctx.workspace_id, connector_id=connector_id, source_url=source_url
        )

    return ConnectorRead.model_validate(connector)


@connectors_router.get(
    "/{connector_id}",
    response_model=ConnectorRead,
    summary="Get one Connector",
    responses={
        200: {"description": "The Connector."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `connectors:manage` in this Workspace."},
        404: {"description": "No such live connector in this Workspace."},
    },
)
async def get_connector(
    connector_id: uuid.UUID,
    service: Annotated[ConnectorService, Depends(get_connector_service)],
) -> ConnectorRead:
    """One Connector by id. Workspace-scoped: a foreign or soft-deleted id is a uniform 404,
    byte-identical to one that never existed, so the endpoint is not a cross-tenant oracle."""
    return ConnectorRead.model_validate(await service.get(connector_id))


@connectors_router.delete(
    "/{connector_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a Connector",
    responses={
        204: {"description": "Soft-deleted. Its slug is free to reuse."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `connectors:manage` in this Workspace."},
        404: {"description": "No such live connector in this Workspace."},
    },
)
async def delete_connector(
    connector_id: uuid.UUID,
    service: Annotated[ConnectorService, Depends(get_connector_service)],
) -> Response:
    """Soft-delete a Connector (retained with `deleted_at` set). Workspace-scoped: a foreign id
    is simply not found. A second delete is a uniform 404 (the row is no longer live)."""
    await service.delete(connector_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


__all__ = ["connectors_router"]
