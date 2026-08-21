"""HTTP surface for the OAuth authorization-code flow (M2.5, ADR-0038). Thin: parse, delegate.

Two endpoints with deliberately different authentication, which is the whole security design:

- **`POST /v1/connections/{connection_id}/oauth/authorize`** — a human control-plane action,
  gated by `connections:manage` exactly like attaching a credential. The workspace comes from the
  authenticated context; nothing in the request can name a tenant.
- **`GET /v1/oauth/callback`** — **unauthenticated by necessity**: a provider redirects a browser
  here, and browsers carry no OmniAI credential. Its authority is the single-use `oauth_states`
  row, which is why that row is unguessable, tenant-bound, and consumable exactly once. The
  response is terminal and carries no token, no code, and no state.

The callback deliberately returns a small HTML page rather than JSON: a human is looking at it.
It is `no-store` (the URL in the address bar contains a spent authorization code) and contains no
attacker-controlled interpolation — only static text plus the outcome.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import HTMLResponse

from app.core.authorization import require_permission
from app.core.authz import Permission
from app.core.db import UnitOfWork, get_uow
from app.core.exceptions import DomainError
from app.core.logging import get_logger
from app.core.security import WorkspaceContext
from app.domains.oauth.schemas import AuthorizeStartRead
from app.domains.oauth.service import OAuthAuthorizationService, complete_callback

log = get_logger(__name__)

oauth_router = APIRouter(tags=["oauth"])

#: Starting an authorization is Connection configuration — the same gate as credential attach.
AuthorizedConnectionManager = Annotated[
    WorkspaceContext, Depends(require_permission(Permission.CONNECTIONS_MANAGE))
]

_SUCCESS_HTML: Final = (
    "<!doctype html><html><head><title>Connection authorized</title>"
    '<meta name="robots" content="noindex"></head><body>'
    "<h1>Connection authorized</h1>"
    "<p>You can close this window and return to OmniAI Connect.</p>"
    "</body></html>"
)
_FAILURE_HTML: Final = (
    "<!doctype html><html><head><title>Authorization failed</title>"
    '<meta name="robots" content="noindex"></head><body>'
    "<h1>Authorization failed</h1>"
    "<p>This authorization link is invalid or has expired. "
    "Start the connection again from OmniAI Connect.</p>"
    "</body></html>"
)
#: The address bar holds a spent code; never let an intermediary or the browser cache this page.
_NO_STORE: Final = {"Cache-Control": "no-store", "Pragma": "no-cache"}


@oauth_router.post(
    "/v1/connections/{connection_id}/oauth/authorize",
    response_model=AuthorizeStartRead,
    summary="Begin an OAuth authorization for a Connection",
    responses={
        200: {"description": "Where to send the user agent, and when the link expires."},
        400: {"description": "The Connector does not use the oauth2 auth model."},
        401: {"description": "Missing or invalid credentials."},
        403: {"description": "Caller does not hold `connections:manage` in this Workspace."},
        404: {"description": "No such live Connection in this Workspace."},
        409: {"description": "OAuth is disabled, or the Connection is revoked."},
    },
)
async def start_authorization(
    connection_id: uuid.UUID,
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    ctx: AuthorizedConnectionManager,
) -> AuthorizeStartRead:
    """Start the dance. The response carries the provider URL and its expiry — never the `state`
    as a separate field, never the PKCE verifier, never a token."""
    result = await OAuthAuthorizationService(uow, ctx).start(connection_id)
    return AuthorizeStartRead(authorize_url=result.authorize_url, expires_at=result.expires_at)


@oauth_router.get(
    "/v1/oauth/callback",
    summary="OAuth provider redirect target (unauthenticated by design)",
    response_class=HTMLResponse,
    include_in_schema=True,
    responses={
        200: {"description": "The authorization completed; the Connection is now active."},
        400: {"description": "The provider reported an error, or the link is invalid/expired."},
    },
)
async def oauth_callback(
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    code: Annotated[str | None, Query(description="Authorization code from the provider.")] = None,
    state: Annotated[
        str | None, Query(description="Opaque state issued at authorize time.")
    ] = None,
    error: Annotated[str | None, Query(description="Provider-reported error code.")] = None,
) -> Response:
    """Complete the dance.

    Authority is the state row alone: `code` and `state` are attacker-influencable, so the
    workspace and connection are read from the row this request atomically consumes. Every
    failure — provider error, missing parameters, unknown/expired/replayed state, a refused
    token exchange — renders the same terminal page, so the endpoint is not an oracle.
    """
    if error is not None or not code or not state:
        # RFC 6749 §4.1.2.1: the user denied consent, or the redirect is malformed. Log the
        # provider's error *code* only (never its description, which can echo request data).
        log.info("oauth.callback_rejected", provider_error=error or "missing_parameters")
        return HTMLResponse(_FAILURE_HTML, status_code=400, headers=_NO_STORE)

    try:
        await complete_callback(uow, code=code, state=state)
    except DomainError:
        # Uniform terminal page. The specific cause is in the structured log under this
        # request_id; the browser learns nothing about which states exist.
        #
        # Swallowing here is deliberate and security-relevant: the request transaction commits,
        # so the state row stays CONSUMED even though the flow failed. Letting the error
        # propagate would roll the consume back and hand an attacker a replay window on a state
        # that has already been presented. Nothing partial is committed with it — the only write
        # after the consume is the credential seal, which happens after a successful exchange.
        return HTMLResponse(_FAILURE_HTML, status_code=400, headers=_NO_STORE)
    return HTMLResponse(_SUCCESS_HTML, status_code=200, headers=_NO_STORE)


__all__ = ["oauth_router"]
