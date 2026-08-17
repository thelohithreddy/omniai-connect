"""HTTP surface for the credentials domain (M1-Credentials-v1). Thin: parse, delegate, shape.

The Credential is a **1:1 sub-resource of a Connection** (API_GUIDELINES §2 lists no top-level
`/v1/credentials`; a Credential is bound to a Connection, Bible §4), so it lives at
`/v1/connections/{connection_id}/credential`. Every endpoint is gated by `connections:manage`
(owner/admin — the permission whose remit is "manage Credentials", SECURITY §4.1). Responses carry
**metadata only** — never the secret. The workspace is the authenticated context; `connection_id`
is a path parameter validated to a live connection in that workspace.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Response, status

from app.core.authorization import require_permission
from app.core.authz import Permission
from app.core.db import UnitOfWork, get_uow
from app.core.security import WorkspaceContext
from app.domains.credentials.repository import CredentialRepository
from app.domains.credentials.schemas import CredentialRead, CredentialWrite
from app.domains.credentials.service import CredentialService

credentials_router = APIRouter(prefix="/v1/connections", tags=["credentials"])

AuthorizedConnectionAdmin = Annotated[
    WorkspaceContext, Depends(require_permission(Permission.CONNECTIONS_MANAGE))
]


def get_credential_service(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    ctx: AuthorizedConnectionAdmin,
) -> CredentialService:
    """Composition root: `connections:manage` is checked before this runs, so the repository is
    always scoped to a tenant the caller may manage."""
    return CredentialService(CredentialRepository(uow.session, ctx))


_ATTACH_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"description": "Missing or invalid credentials."},
    403: {"description": "Caller does not hold `connections:manage` in this Workspace."},
    404: {"description": "No such live connection (or credential) in this Workspace."},
}


@credentials_router.post(
    "/{connection_id}/credential",
    response_model=CredentialRead,
    status_code=status.HTTP_201_CREATED,
    summary="Attach an encrypted Credential to a Connection",
    responses={
        201: {
            "description": "The Credential metadata (no secret). The Connection is now `active`."
        },
        400: {"description": "Invalid body for the credential type."},
        409: {"description": "This connection already has a credential; rotate it instead."},
        **_ATTACH_RESPONSES,
    },
)
async def attach_credential(
    connection_id: uuid.UUID,
    payload: CredentialWrite,
    service: Annotated[CredentialService, Depends(get_credential_service)],
) -> CredentialRead:
    """Attach a Credential (api_key/bearer/basic). The secret enters over TLS once, is
    envelope-encrypted (AES-256-GCM, per-Credential DEK, workspace‖connection AAD), and is **never**
    returned, logged, or persisted in plaintext. The Connection transitions `pending_auth → active`.
    A foreign/revoked connection is a uniform 404; an already-credentialed connection is a 409."""
    return CredentialRead.model_validate(await service.attach(connection_id, payload))


@credentials_router.get(
    "/{connection_id}/credential",
    response_model=CredentialRead,
    summary="Get a Connection's Credential metadata",
    responses={200: {"description": "The Credential metadata (no secret)."}, **_ATTACH_RESPONSES},
)
async def get_credential(
    connection_id: uuid.UUID,
    service: Annotated[CredentialService, Depends(get_credential_service)],
) -> CredentialRead:
    """The Credential's **metadata** (type, key_version, timestamps) — never the secret. Absent or
    foreign is a uniform 404, so the endpoint is not a cross-tenant oracle."""
    return CredentialRead.model_validate(await service.get(connection_id))


@credentials_router.put(
    "/{connection_id}/credential",
    response_model=CredentialRead,
    summary="Rotate a Connection's Credential",
    responses={
        200: {
            "description": "The rotated Credential metadata (fresh DEK + nonce, `rotated_at` set)."
        },
        400: {"description": "Invalid body for the credential type."},
        **_ATTACH_RESPONSES,
    },
)
async def rotate_credential(
    connection_id: uuid.UUID,
    payload: CredentialWrite,
    service: Annotated[CredentialService, Depends(get_credential_service)],
) -> CredentialRead:
    """Re-seal the Credential with a fresh DEK + nonce and new secret material; `rotated_at` is set.
    The old ciphertext is replaced atomically. A missing connection/credential is a uniform 404."""
    return CredentialRead.model_validate(await service.rotate(connection_id, payload))


@credentials_router.delete(
    "/{connection_id}/credential",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke (hard-delete) a Connection's Credential",
    responses={
        204: {
            "description": "Revoked; the row is destroyed, the Connection returns to pending_auth."
        },
        **_ATTACH_RESPONSES,
    },
)
async def revoke_credential(
    connection_id: uuid.UUID,
    service: Annotated[CredentialService, Depends(get_credential_service)],
) -> Response:
    """Hard-delete the Credential (revocation destroys the material — no soft delete) and return the
    Connection to `pending_auth`. A missing connection/credential is a uniform 404."""
    await service.revoke(connection_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


__all__ = ["credentials_router"]
