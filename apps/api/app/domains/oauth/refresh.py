"""OAuth token refresh (M2.5, ADR-0038) — the credential-lifecycle half of the flow.

Canon puts this on the Celery **`runtime` queue**, refreshing *ahead of* `credentials.expires_at`
with jittered scheduling; a terminal failure flips the Connection to `error`
(CONNECTOR_SPECIFICATION §215, CONNECTOR_ENGINE §8).

The concurrency design is the load-bearing part. Two workers, a racing runtime execution, and a
provider that rotates refresh tokens can all collide on one credential, and losing a rotated
refresh token would permanently orphan the Connection. The resolution is PostgreSQL, consistent
with the rest of this codebase: the refresh **claims the Connection row with `SELECT … FOR
UPDATE`** (credentials are 1:1 with connections, so that lock serializes the credential too),
then **re-checks expiry inside the lock**. The loser wakes to a freshly-refreshed credential and
no-ops rather than performing a second exchange with a refresh token the provider has already
invalidated.

Decryption stays at the single boundary: this module reads plaintext only through
`runtime.secrets.open_credential_secret`, which remains the sole accessor of the vault's private
decrypt primitive. Task arguments carry identifiers only — never a token.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from app.core.config import settings
from app.core.db import UnitOfWork
from app.core.events import event_bus
from app.core.exceptions import DomainError
from app.core.logging import get_logger
from app.core.security import CallerIdentity, WorkspaceContext
from app.domains.connections.events import connection_deactivated
from app.domains.connectors.oauth_config import parse_oauth_config
from app.domains.connectors.repository import ConnectorRepository
from app.domains.credentials.repository import CredentialRepository
from app.domains.credentials.service import CredentialService
from app.domains.credentials.vault import VaultDecryptError
from app.domains.oauth import provider
from app.domains.runtime.secrets import open_credential_secret

log = get_logger(__name__)


class RefreshOutcome(StrEnum):
    """What a refresh attempt did. Every value is safe to log and to use as a metric label."""

    REFRESHED = "refreshed"
    NOT_DUE = "not_due"  # another worker won the race, or it simply is not time yet
    SKIPPED = "skipped"  # not an OAuth connection, not active, or already gone
    RETRYABLE = "retryable"  # provider outage / transport — try again with backoff
    TERMINAL = "terminal"  # unrecoverable: the Connection is now `error`


@dataclass(frozen=True, slots=True)
class RefreshResult:
    outcome: RefreshOutcome
    connection_id: uuid.UUID


def is_due(expires_at: datetime | None, *, now: datetime | None = None) -> bool:
    """Whether a credential should be refreshed now: inside the last `threshold_ratio` of its
    remaining life, or already expired. A credential with no expiry is never due."""
    if expires_at is None:
        return False
    moment = now or datetime.now(UTC)
    remaining = (expires_at - moment).total_seconds()
    if remaining <= 0:
        return True
    # Refresh once the remaining life drops under the configured share of a full token lifetime.
    return remaining <= settings.oauth_refresh_threshold_ratio * _assumed_lifetime()


def _assumed_lifetime() -> float:
    """The lifetime a token is assumed to have when judging 'due'. Providers vary, so this uses
    the RFC default rather than storing a per-credential lifetime we were never told."""
    return float(provider.DEFAULT_EXPIRES_IN_SECONDS)


def _context(workspace_id: uuid.UUID) -> WorkspaceContext:
    """The worker acts as the platform, not as a member or a token holder."""
    return WorkspaceContext(
        workspace_id=workspace_id,
        caller=CallerIdentity(kind="api_token", api_token_id=None),
        request_id="oauth_refresh",
    )


async def _fail_terminally(
    uow: UnitOfWork, connection: object, *, reason: str, workspace_id: uuid.UUID
) -> RefreshResult:
    """Transition the Connection to `error` and emit `connection.deactivated` (D2/D5).

    No `webhooks_outbox` here — customer-facing delivery belongs to Connection Health (D2). The
    derived `needs_reauth` follows from `status == 'error'` + an oauth2 credential (D5).
    """
    previous = connection.status  # type: ignore[attr-defined]
    connection.status = "error"  # type: ignore[attr-defined]
    if previous == "active":
        event_bus.publish(
            connection_deactivated(
                workspace_id,
                connection_id=connection.id,  # type: ignore[attr-defined]
                connector_id=connection.connector_id,  # type: ignore[attr-defined]
                status="error",
            )
        )
    log.warning(
        "oauth.refresh_failed_terminally",
        workspace_id=str(workspace_id),
        connection_id=str(connection.id),  # type: ignore[attr-defined]
        reason=reason,
    )
    return RefreshResult(RefreshOutcome.TERMINAL, connection.id)  # type: ignore[attr-defined]


async def refresh_connection(
    uow: UnitOfWork, *, workspace_id: uuid.UUID, connection_id: uuid.UUID, force: bool = False
) -> RefreshResult:
    """Refresh one Connection's OAuth credential, exactly once, under a row lock."""
    if not settings.oauth_enabled:
        return RefreshResult(RefreshOutcome.SKIPPED, connection_id)

    ctx = _context(workspace_id)
    credentials_repo = CredentialRepository(uow.session, ctx)

    # The claim: everything below runs while this row is locked, so a second worker blocks here
    # and then re-evaluates against our committed result instead of racing us.
    connection = await credentials_repo.connection_for_update(connection_id)
    if connection is None or connection.status not in ("active", "error"):
        return RefreshResult(RefreshOutcome.SKIPPED, connection_id)

    credential = await credentials_repo.get_by_connection(connection_id)
    if credential is None or credential.credential_type != "oauth2":
        return RefreshResult(RefreshOutcome.SKIPPED, connection_id)

    # Re-check inside the lock: the worker we queued behind may already have refreshed this.
    if not force and not is_due(credential.expires_at):
        return RefreshResult(RefreshOutcome.NOT_DUE, connection_id)

    try:
        secret = open_credential_secret(
            credential, workspace_id=workspace_id, connection_id=connection_id
        )
    except VaultDecryptError:
        return await _fail_terminally(
            uow, connection, reason="credential_unreadable", workspace_id=workspace_id
        )
    if not secret.refresh_token:
        # A provider that never issued a refresh token cannot be renewed without the user.
        return await _fail_terminally(
            uow, connection, reason="no_refresh_token", workspace_id=workspace_id
        )

    connector = await ConnectorRepository(uow.session, ctx).get(connection.connector_id)
    if connector is None:
        return RefreshResult(RefreshOutcome.SKIPPED, connection_id)
    try:
        config = parse_oauth_config(connector.auth_config)
    except DomainError:
        return await _fail_terminally(
            uow, connection, reason="connector_config_invalid", workspace_id=workspace_id
        )

    try:
        token_set = await provider.refresh_access_token(config, refresh_token=secret.refresh_token)
    except DomainError as exc:
        # A provider outage is retryable; a refusal of the grant is not. `connector_error`
        # covers both here, so the task's bounded retry decides — and the caller transitions to
        # `error` only after the retry budget is exhausted.
        log.warning(
            "oauth.refresh_attempt_failed",
            workspace_id=str(workspace_id),
            connection_id=str(connection_id),
            code=exc.code,
        )
        return RefreshResult(RefreshOutcome.RETRYABLE, connection_id)

    await CredentialService(credentials_repo).store_oauth_tokens(
        connection_id,
        access_token=token_set.access_token,
        # RFC 6749 §6: when the response omits a refresh token the existing one remains valid,
        # so it is preserved. When the provider ROTATES, the new one replaces it — losing it
        # here would orphan the Connection forever, which is why this runs under the lock.
        refresh_token=token_set.refresh_token or secret.refresh_token,
        token_type=token_set.token_type,
        scope=token_set.scope,
        expires_at=datetime.now(UTC) + timedelta(seconds=token_set.expires_in),
    )
    log.info(
        "oauth.refresh_succeeded",
        workspace_id=str(workspace_id),
        connection_id=str(connection_id),
        rotated=token_set.refresh_token is not None,
    )
    return RefreshResult(RefreshOutcome.REFRESHED, connection_id)


async def mark_refresh_exhausted(
    uow: UnitOfWork, *, workspace_id: uuid.UUID, connection_id: uuid.UUID
) -> RefreshResult:
    """Called when the bounded retry budget is spent: the Connection becomes `error`."""
    ctx = _context(workspace_id)
    connection = await CredentialRepository(uow.session, ctx).connection_for_update(connection_id)
    if connection is None:
        return RefreshResult(RefreshOutcome.SKIPPED, connection_id)
    return await _fail_terminally(
        uow, connection, reason="retries_exhausted", workspace_id=workspace_id
    )


__all__ = [
    "RefreshOutcome",
    "RefreshResult",
    "is_due",
    "mark_refresh_exhausted",
    "refresh_connection",
]
