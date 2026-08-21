"""OAuth authorization-code orchestration (M2.5, ADR-0038).

Two halves with deliberately different trust:

**Authorize** runs under an authenticated, workspace-bound transaction. It proves the Connection
is this workspace's and is OAuth-eligible, generates the flow secrets, seals the PKCE verifier,
persists the state row, and returns the provider URL. It performs no egress.

**Callback** is unauthenticated by necessity. It trusts exactly one thing: a state row it can
atomically consume. Identity (`workspace_id`, `connection_id`) comes from that row and never from
the request, so a provider — or anyone who can reach the callback — cannot name a tenant. Once the
row is claimed, the transaction is bound to its workspace and the rest of the work proceeds under
normal RLS, using the credentials domain to seal tokens (PRD §74) and the connections domain's
existing lifecycle event.

Failures are uniform: an unknown, expired, replayed, or foreign state are one indistinguishable
error, so the endpoint is not an oracle for which states exist.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.core.config import settings
from app.core.db import UnitOfWork
from app.core.exceptions import ConflictError, NotFoundError, ValidationFailedError
from app.core.logging import get_logger
from app.core.security import CallerIdentity, WorkspaceContext
from app.domains.connections.repository import ConnectionRepository
from app.domains.connectors.oauth_config import OAuthConfig, is_oauth2, parse_oauth_config
from app.domains.connectors.repository import ConnectorRepository
from app.domains.credentials.repository import CredentialRepository
from app.domains.credentials.service import CredentialService
from app.domains.credentials.vault import SealedSecret, VaultDecryptError, seal, unseal_flow_secret
from app.domains.oauth import provider
from app.domains.oauth.repository import OAuthStateRepository, consume_state
from app.domains.oauth.state import hash_state, new_flow_secrets

log = get_logger(__name__)

#: One uniform refusal for every unusable state: unknown, expired, replayed, or tampered.
INVALID_STATE_MESSAGE = "The authorization link is invalid or has expired."


@dataclass(frozen=True, slots=True)
class AuthorizeStart:
    authorize_url: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class CallbackOutcome:
    """What the callback accomplished. Carries identifiers only — never a token."""

    workspace_id: uuid.UUID
    connection_id: uuid.UUID


class OAuthAuthorizationService:
    """The authenticated half: start an authorization for one of this workspace's Connections."""

    def __init__(self, uow: UnitOfWork, ctx: WorkspaceContext) -> None:
        self._uow = uow
        self._ctx = ctx
        self._states = OAuthStateRepository(uow.session, ctx)
        self._connections = ConnectionRepository(uow.session, ctx)
        self._connectors = ConnectorRepository(uow.session, ctx)

    async def start(self, connection_id: uuid.UUID) -> AuthorizeStart:
        """Begin an authorization-code flow. Everything is server-derived: the workspace from the
        authenticated context, the Connector from the Connection, the redirect URI from config."""
        if not settings.oauth_enabled:
            raise ConflictError("OAuth is not enabled.")

        connection = await self._connections.get(connection_id)
        if connection is None:
            # Uniform with every other tenant-scoped 404: absent and foreign look identical.
            raise NotFoundError("Connection not found.")
        if connection.status == "revoked":
            raise ConflictError("Connection is revoked.")

        connector = await self._connectors.get(connection.connector_id)
        if connector is None or not is_oauth2(connector.auth_config):
            raise ValidationFailedError("Connector does not use the oauth2 auth model.")
        config = parse_oauth_config(connector.auth_config)

        secrets_ = new_flow_secrets()
        # The verifier must be presented verbatim at the token endpoint (RFC 7636 §4.5), so it is
        # sealed — not hashed — under the same envelope and AAD the Credential uses.
        sealed = seal(
            secrets_.code_verifier.encode("ascii"),
            workspace_id=self._ctx.workspace_id,
            connection_id=connection.id,
        )
        expires_at = datetime.now(UTC) + timedelta(seconds=settings.oauth_state_ttl_seconds)
        await self._states.create(
            connection_id=connection.id,
            state_hash=hash_state(secrets_.state),
            verifier_ciphertext=sealed.ciphertext,
            verifier_encrypted_dek=sealed.encrypted_dek,
            verifier_nonce=sealed.nonce,
            key_version=sealed.key_version,
            redirect_uri=settings.oauth_redirect_uri,
            scopes=list(config.scopes),
            expires_at=expires_at,
        )
        log.info(
            "oauth.authorization_initiated",
            workspace_id=str(self._ctx.workspace_id),
            connection_id=str(connection.id),
        )
        return AuthorizeStart(
            authorize_url=provider.build_authorize_url(
                config,
                state=secrets_.state,
                code_challenge=secrets_.code_challenge,
                redirect_uri=settings.oauth_redirect_uri,
            ),
            expires_at=expires_at,
        )


async def _load_config_for_connection(
    uow: UnitOfWork, ctx: WorkspaceContext, connection_id: uuid.UUID
) -> tuple[OAuthConfig, uuid.UUID]:
    """The Connector's validated OAuth config for a Connection, plus the connector id."""
    connections = ConnectionRepository(uow.session, ctx)
    connection = await connections.get(connection_id)
    if connection is None:
        raise ValidationFailedError(INVALID_STATE_MESSAGE)
    connector = await ConnectorRepository(uow.session, ctx).get(connection.connector_id)
    if connector is None:
        raise ValidationFailedError(INVALID_STATE_MESSAGE)
    return parse_oauth_config(connector.auth_config), connection.connector_id


async def complete_callback(uow: UnitOfWork, *, code: str, state: str) -> CallbackOutcome:
    """Finish an authorization-code flow from a provider redirect.

    Order is load-bearing: the state row is consumed **first** (atomically, once), because that
    single act both authenticates the request and reveals the tenant. Only then is the
    transaction bound to that workspace and tenant-scoped work performed.
    """
    if not settings.oauth_enabled:
        raise ConflictError("OAuth is not enabled.")

    claimed = await consume_state(uow.session, hash_state(state))
    if claimed is None:
        # Unknown, expired, already-consumed, or forged — one uniform refusal, no oracle.
        log.warning("oauth.callback_state_rejected")
        raise ValidationFailedError(INVALID_STATE_MESSAGE)

    # From here the request has a proven tenant. Bind it so RLS governs everything that follows.
    await uow.bind_workspace(claimed.workspace_id)
    ctx = WorkspaceContext(
        workspace_id=claimed.workspace_id,
        caller=_callback_caller(),
        request_id="oauth_callback",
    )

    try:
        verifier = unseal_flow_secret(
            SealedSecret(
                ciphertext=claimed.verifier_ciphertext,
                encrypted_dek=claimed.verifier_encrypted_dek,
                nonce=claimed.verifier_nonce,
                key_version=claimed.key_version,
            ),
            workspace_id=claimed.workspace_id,
            connection_id=claimed.connection_id,
        ).decode("ascii")
    except VaultDecryptError:
        log.warning(
            "oauth.verifier_unusable",
            workspace_id=str(claimed.workspace_id),
            connection_id=str(claimed.connection_id),
        )
        raise ValidationFailedError(INVALID_STATE_MESSAGE) from None

    config, connector_id = await _load_config_for_connection(uow, ctx, claimed.connection_id)
    token_set = await provider.exchange_authorization_code(
        config,
        code=code,
        code_verifier=verifier,
        # Replayed from the stored row, never from the request (RFC 6749 §4.1.3).
        redirect_uri=claimed.redirect_uri,
    )

    credentials = CredentialService(CredentialRepository(uow.session, ctx))
    await credentials.store_oauth_tokens(
        claimed.connection_id,
        access_token=token_set.access_token,
        refresh_token=token_set.refresh_token,
        token_type=token_set.token_type,
        scope=token_set.scope,
        expires_at=datetime.now(UTC) + timedelta(seconds=token_set.expires_in),
    )
    log.info(
        "oauth.authorization_succeeded",
        workspace_id=str(claimed.workspace_id),
        connection_id=str(claimed.connection_id),
        connector_id=str(connector_id),
    )
    return CallbackOutcome(workspace_id=claimed.workspace_id, connection_id=claimed.connection_id)


def _callback_caller() -> CallerIdentity:
    """The callback acts as the platform itself, not as a member or a machine token: the browser
    presented no OmniAI credential. Modeled as a machine caller with **no** token id, so nothing
    downstream can mistake it for an authenticated principal."""
    return CallerIdentity(kind="api_token", api_token_id=None)


__all__ = [
    "INVALID_STATE_MESSAGE",
    "AuthorizeStart",
    "CallbackOutcome",
    "OAuthAuthorizationService",
    "complete_callback",
]
