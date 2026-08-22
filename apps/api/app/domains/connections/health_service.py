"""Connection Health orchestration — a thin door onto the Execution Runtime (ROADMAP §58, M2.7-A).

This module contains no execution. It selects a safe probe Tool, hands a canonical
`ToolCallCreate` to `RuntimeService.execute`, records that a check completed, and translates the
outcome into classified metadata. Every security-relevant step — authorization, rate limits and
quota, argument validation, credential decrypt-at-use, SSRF and egress, timeout, audit — happens
inside the Runtime, unchanged and unduplicated, because AI_RUNTIME §4 is explicit that there is
one runtime behind many doors.

What that buys, concretely: a health check cannot become a privileged probe. It cannot reach an
endpoint a Tool Call could not reach, cannot skip a quota a Tool Call would pay, and cannot
produce a result that never appeared in the audit ledger.

**Notifications (M2.10, ADR-0041).** ROADMAP §58's Resend clause is delivered, and this module's
part in it is one line: when a completed check finds the Connection unhealthy, it publishes
`connection.health_check_failed` on the internal bus. It sends nothing. It does not know an address,
does not touch Redis, and does not import the notifications domain — the event is a fact about
committed state, and everything downstream of it (destination lookup, deduplication, delivery,
retry) belongs to a subscriber and a Celery task.

Publishing rather than sending is what keeps the two concerns separable: the bus buffers on the
UnitOfWork and dispatches only after COMMIT, so a rolled-back check notifies nobody, and a failing
mail provider cannot reach back into a health verdict that has already been written.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

import structlog

from app.core.config import settings
from app.core.db import UnitOfWork
from app.core.events import event_bus
from app.core.exceptions import (
    ConflictError,
    NotFoundError,
    QuotaExceededError,
    RateLimitedError,
)
from app.core.security import WorkspaceContext
from app.domains.connections.events import connection_health_check_failed
from app.domains.connections.health import HealthState, select_probe_tool
from app.domains.connections.repository import ConnectionRepository
from app.domains.runtime.schemas import ToolCallCreate
from app.domains.runtime.service import RuntimeService

log = structlog.get_logger(__name__)

#: Returned when the Connector offers no Tool that is safe to run unattended. A first-class
#: outcome, not an error: refusing to probe is the correct behaviour, and the caller needs to be
#: able to tell it apart from a provider failure.
UNAVAILABLE_REASON = "health_check_unavailable"

#: Stage-3 policy refusals (M2.4). These are **platform** decisions taken before any
#: Connection-specific work happens — no credential is decrypted and nothing is sent upstream — so
#: they say nothing whatsoever about whether the Connection is usable. They are audited (the denial
#: really occurred and the Runtime owns that record), but they are deliberately **not** treated as
#: a completed health check: doing so let an exhausted weekly quota, or a Redis outage failing
#: closed, flip every Connection in a Workspace to `unhealthy` and overwrite a known-good
#: `last_health_check_at` — a verdict that then outlived the incident until someone re-checked.
#:
#: Note the contrast with the denials that *are* health facts: `EgressBlockedError` means this
#: Connector's own base URL resolves somewhere forbidden, and `ConflictError` means the Connection
#: is inactive or has no credential. Both are properties of the Connection and stay `unhealthy`.
_POLICY_REFUSALS = (RateLimitedError, QuotaExceededError)


@dataclass(frozen=True, slots=True)
class HealthCheckResult:
    """The classified outcome of one health check. Carries metadata only — never a provider body,
    never a credential, never an exception message from the upstream."""

    status: HealthState
    checked_at: datetime | None
    reason: str | None = None
    tool_call_id: uuid.UUID | None = None
    duration_ms: int | None = None


class ConnectionHealthService:
    """Orchestrates a health check. Constructed per request, scoped to one Workspace."""

    def __init__(self, uow: UnitOfWork, ctx: WorkspaceContext) -> None:
        self._uow = uow
        self._ctx = ctx
        self._repository = ConnectionRepository(uow.session, ctx)
        self._runtime = RuntimeService(uow, ctx)

    async def check(self, connection_id: uuid.UUID) -> HealthCheckResult:
        """Run one health check against a Connection.

        The feature flag is evaluated before anything else so that a disabled deployment performs
        no lookup, no execution, no credential access and no state mutation — an operational
        rollback lever has to be total to be worth having.
        """
        if not settings.connection_health_enabled:
            raise ConflictError("Connection health checks are not enabled.")

        connection = await self._repository.get(connection_id)
        if connection is None:
            # Foreign, revoked and never-existed are one uniform 404 — the same non-oracle the rest
            # of the connections API presents.
            raise NotFoundError("Connection not found.")

        candidates = await self._repository.probe_candidates(connection.connector_id)
        probe = select_probe_tool(candidates)
        if probe is None:
            # No execution, and therefore no completed check: `last_health_check_at` is untouched
            # and the projection stays at whatever the last real check said.
            log.info(
                "connection.health_check_unavailable",
                workspace_id=str(self._ctx.workspace_id),
                connection_id=str(connection_id),
                candidates=len(candidates),
            )
            return HealthCheckResult(
                status=HealthState.UNKNOWN, checked_at=None, reason=UNAVAILABLE_REASON
            )

        outcome = await self._runtime.execute(
            ToolCallCreate(tool_name=probe.name, connection_id=connection.id, arguments={})
        )

        # An `ExecutionOutcome` exists only for an audited call, so reaching here means the Runtime
        # wrote exactly one `tool_calls` row. That is the canonical definition of "a health check
        # completed" — pre-audit failures (unknown Tool, unbindable Connection) raise instead, and
        # correctly leave the timestamp alone because nothing was actually attempted upstream.
        if outcome.error is not None and isinstance(outcome.error, _POLICY_REFUSALS):
            # The Connection was never evaluated. Report that honestly and leave the previous
            # verdict — and its timestamp — untouched.
            log.info(
                "connection.health_check_not_evaluated",
                workspace_id=str(self._ctx.workspace_id),
                connection_id=str(connection_id),
                reason=outcome.error.code,
                tool_call_id=str(outcome.tool_call_id),
            )
            return HealthCheckResult(
                status=HealthState.UNKNOWN,
                checked_at=None,
                reason=outcome.error.code,
                tool_call_id=outcome.tool_call_id,
            )

        row = await self._repository.audit_row(outcome.tool_call_id)
        checked_at = row.created_at if row is not None else None
        if checked_at is not None:
            await self._repository.stamp_health_check(connection, checked_at)

        if outcome.error is not None:
            log.info(
                "connection.health_check_failed",
                workspace_id=str(self._ctx.workspace_id),
                connection_id=str(connection_id),
                reason=outcome.error.code,
                tool_call_id=str(outcome.tool_call_id),
            )
            # M2.10: the notifiable fact. Buffered on the UnitOfWork and dispatched only after this
            # request's transaction commits, so a rolled-back check emits nothing and the
            # notification can never observe a health verdict that was not durably written.
            #
            # Reached only on this branch, which is the whole ratified matrix for the health path:
            # a policy refusal returned `unknown` above without stamping, a refused probe returned
            # `unknown` earlier still, and success falls through below. `needs_reauth` is not
            # produced here at all — it arrives on the OAuth worker's `connection.deactivated`.
            event_bus.publish(
                connection_health_check_failed(
                    self._ctx.workspace_id,
                    connection_id=connection.id,
                    # The stable, enumerated Runtime code. Never `str(exception)`, which for an
                    # upstream failure can carry a provider message and with it a leaked secret.
                    reason=outcome.error.code,
                )
            )
            return HealthCheckResult(
                status=HealthState.UNHEALTHY,
                checked_at=checked_at,
                # The canonical Runtime error *code* — a stable, enumerated token. Never
                # `str(exception)`, which for an upstream failure can carry a provider message.
                reason=outcome.error.code,
                tool_call_id=outcome.tool_call_id,
            )

        log.info(
            "connection.health_check_succeeded",
            workspace_id=str(self._ctx.workspace_id),
            connection_id=str(connection_id),
            tool_call_id=str(outcome.tool_call_id),
        )
        return HealthCheckResult(
            status=HealthState.HEALTHY,
            checked_at=checked_at,
            tool_call_id=outcome.tool_call_id,
        )


__all__ = ["ConnectionHealthService", "HealthCheckResult", "UNAVAILABLE_REASON"]
