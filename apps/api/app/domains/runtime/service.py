"""The Execution Runtime pipeline (AI_RUNTIME.md §2) — resolve → policy → decrypt → egress → audit.

One synchronous path per Tool Call (M1). The pipeline has two regions:

- **Pre-audit** (resolve the Tool + the Connection): a failure here has no Tool/Connection to
  attribute an audit row to, so it raises a `DomainError` the router surfaces as a normal error
  envelope, and the request transaction rolls back. These are `not_found` (unknown/soft-deleted/
  disabled Tool, wrong-Connector or missing Connection) and `validation_error` (ambiguous one).

- **Audited** (from the moment Tool + Connection are both bound): *every* outcome — success or any
  failure — writes exactly one immutable `tool_calls` row and publishes `tool_call.completed`. To
  keep that row (the transaction rolls back on a raised exception), audited failures are **not
  raised**; the pipeline records them and returns an `ExecutionOutcome` the router renders as the
  canonical error envelope while the transaction commits normally. This is what makes "no audit row,
  no result" hold for failed/denied/timeout calls, not just successes.

Credential plaintext lives only inside `_run_authenticated_call`, only for the outbound request, and
is never returned, logged, buffered, or written to the audit row.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any

from app.core.db import UnitOfWork
from app.core.events import event_bus
from app.core.exceptions import (
    ConflictError,
    DomainError,
    EgressBlockedError,
    NotFoundError,
    QuotaExceededError,
    RateLimitedError,
    UpstreamAPIError,
    UpstreamTimeoutError,
    ValidationFailedError,
)
from app.core.security import WorkspaceContext
from app.domains.credentials.vault import VaultDecryptError
from app.domains.runtime.build import build_request
from app.domains.runtime.egress import execute_outbound
from app.domains.runtime.events import tool_call_completed
from app.domains.runtime.injection import build_auth_injection
from app.domains.runtime.limits import enforce_tool_call_limits, record_executed_call
from app.domains.runtime.normalization import normalize_response
from app.domains.runtime.redaction import redact_arguments
from app.domains.runtime.repository import RuntimeRepository
from app.domains.runtime.schemas import CallUsage, ToolCallCreate, ToolCallResult
from app.domains.runtime.secrets import open_credential_secret
from app.domains.runtime.validation import validate_arguments


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    """The rendered outcome of an audited Tool Call. Exactly one of `result` / `error` is set; both
    carry `tool_call_id` (the persisted audit row). A set `error` is *returned*, not raised, so the
    audit row it references survives the request commit."""

    tool_call_id: uuid.UUID
    result: ToolCallResult | None = None
    error: DomainError | None = None


def _status_for(exc: DomainError) -> str:
    """Terminal Tool Call status for an audited failure (DATABASE_DESIGN:190, AI_RUNTIME §6)."""
    if isinstance(exc, UpstreamTimeoutError):
        return "timeout"
    if isinstance(exc, (EgressBlockedError, ConflictError, RateLimitedError, QuotaExceededError)):
        # Policy/state denial: blocked egress, inactive connection, no credential, and the M2.4
        # stage-3 limit denials — all audited as `denied` and, per D2, never quota-consuming.
        return "denied"
    return "failed"  # bad arguments, connector config, upstream error, decrypt failure


class RuntimeService:
    def __init__(self, uow: UnitOfWork, ctx: WorkspaceContext, *, interface: str = "rest") -> None:
        self._uow = uow
        self._ctx = ctx
        self._repo = RuntimeRepository(uow.session, ctx)
        # Which Interface adapter invoked the runtime — recorded in the audit `caller` (the
        # canonical UJ-5.3 `interface` filter distinguishes surfaces). Server-set by the calling
        # adapter (M2.3: "mcp"), never a client value; defaults keep every M1 call "rest".
        self._interface = interface
        # The Workspace plan, resolved once per execute() (M2.4 limit selector). `free` is the
        # most-restrictive default until the per-call read replaces it.
        self._plan = "free"

    async def execute(self, payload: ToolCallCreate) -> ExecutionOutcome:
        """Run one Tool Call end to end. Pre-audit failures raise; audited outcomes return."""
        started = time.perf_counter()

        # --- Pre-audit: resolve Tool + Connection (raises; no audit row without both) ---
        tool = await self._repo.resolve_tool(payload.tool_name)
        if tool is None:
            raise NotFoundError("Tool not found.")
        connection = await self._bind_connection(tool.connector_id, payload.connection_id)

        # --- Audited region: one row + one event for every outcome ---
        input_summary = redact_arguments(payload.arguments)
        # The workspace plan selects the enforced limits (M2.4); read per call, RLS-scoped.
        self._plan = await self._repo.get_workspace_plan()
        try:
            # Stage 3 (AI_RUNTIME §2): rate limits + quota, the canonical policy point — after
            # resolve/bind (so the denial is audited with real tool/connection ids), before
            # validation, decrypt, and egress. Raises RateLimitedError / QuotaExceededError,
            # which the shared handler below records as `denied` — one audit path, no new one.
            await enforce_tool_call_limits(
                workspace_id=self._ctx.workspace_id,
                plan=self._plan,
                connection_id=connection.id,
                tool_annotations=tool.annotations,
            )
            content, output_summary, status_code = await self._run_authenticated_call(
                tool, connection, payload
            )
        except DomainError as exc:
            # Pre-egress / egress failure — no upstream response, so no output metadata.
            return await self._record_failure(
                tool_id=tool.id,
                connection_id=connection.id,
                input_summary=input_summary,
                output_summary=None,
                exc=exc,
                started=started,
            )
        if not 200 <= status_code < 300:
            # The call reached the upstream and got a response; record the failure WITH its
            # metadata.
            failure = UpstreamAPIError(
                "The upstream API returned an error.",
                details={"upstream_status": status_code},
            )
            return await self._record_failure(
                tool_id=tool.id,
                connection_id=connection.id,
                input_summary=input_summary,
                output_summary=output_summary,
                exc=failure,
                started=started,
            )
        return await self._record_success(
            tool_id=tool.id,
            tool_name=tool.name,
            connection_id=connection.id,
            input_summary=input_summary,
            output_summary=output_summary,
            content=content,
            started=started,
        )

    async def get_tool_call(self, tool_call_id: uuid.UUID) -> Any:
        """One audit row by id in the bound Workspace (GET /v1/tool-calls/{id}). A foreign id is
        a uniform 404, byte-identical to a missing one — never a cross-tenant oracle."""
        row = await self._repo.get_tool_call(tool_call_id)
        if row is None:
            raise NotFoundError("Tool call not found.")
        return row

    async def _bind_connection(
        self, connector_id: uuid.UUID, connection_id: uuid.UUID | None
    ) -> Any:
        """Resolve the Connection to run against (explicit, or the single active one). Ambiguity is
        an error, never a guess (AI_RUNTIME.md §2.2). Pre-audit: raises on failure."""
        if connection_id is not None:
            connection = await self._repo.get_connection(connection_id)
            if connection is None or connection.connector_id != connector_id:
                # A foreign or wrong-Connector Connection is indistinguishable from a missing one.
                raise NotFoundError("Connection not found.")
            return connection
        actives = await self._repo.active_connections_for_connector(connector_id)
        if not actives:
            raise NotFoundError("No active connection for this tool.")
        if len(actives) > 1:
            raise ValidationFailedError(
                "Multiple active connections; specify connection_id.",
                details={"connection_ids": [str(c.id) for c in actives]},
            )
        return actives[0]

    async def _run_authenticated_call(
        self, tool: Any, connection: Any, payload: ToolCallCreate
    ) -> tuple[dict[str, Any], dict[str, Any], int]:
        """Stages 3–6 for a bound Tool + Connection. Returns (content, output_summary, status_code).
        Raises a `DomainError` for any pre-egress or egress failure; an upstream non-2xx is NOT a
        raise — the response reached us, so the caller records it (with metadata) as a failure."""
        if connection.status != "active":
            raise ConflictError("Connection is not active.")

        connector = await self._repo.get_connector(tool.connector_id)
        if connector is None:
            raise UpstreamAPIError("Connector is not available.")
        version = await self._repo.get_connector_version(tool.connector_version_id)
        endpoint = _endpoint_for(version, tool.name)
        if endpoint is None:
            raise UpstreamAPIError("Tool endpoint is not available.")

        validate_arguments(payload.arguments, tool.input_schema)

        if connection.credential_id is None:
            raise ConflictError("Connection has no credential.")
        credential = await self._repo.get_credential(connection.id)
        if credential is None:
            raise ConflictError("Connection has no credential.")

        base_url = _base_url(connector, connection)
        try:
            secret = open_credential_secret(
                credential, workspace_id=self._ctx.workspace_id, connection_id=connection.id
            )
            injected = build_auth_injection(secret, connector.auth_config)
            built = build_request(
                endpoint, base_url=base_url, arguments=payload.arguments, injected=injected
            )
        except VaultDecryptError as exc:
            raise UpstreamAPIError("Credential could not be used.") from exc

        response = await execute_outbound(built)
        content, output_summary = normalize_response(response)
        return content, output_summary, response.status_code

    async def _record_success(
        self,
        *,
        tool_id: uuid.UUID,
        tool_name: str,
        connection_id: uuid.UUID,
        input_summary: dict[str, Any],
        output_summary: dict[str, Any] | None,
        content: dict[str, Any],
        started: float,
    ) -> ExecutionOutcome:
        duration_ms = _elapsed_ms(started)
        row_id = await self._append_audit(
            tool_id=tool_id,
            connection_id=connection_id,
            status="succeeded",
            input_summary=input_summary,
            output_summary=output_summary,
            error_code=None,
            duration_ms=duration_ms,
        )
        result = ToolCallResult(
            id=row_id,
            status="succeeded",
            tool_name=tool_name,
            connection_id=connection_id,
            content=content,
            usage=CallUsage(duration_ms=duration_ms),
            request_id=self._ctx.request_id,
        )
        return ExecutionOutcome(tool_call_id=row_id, result=result)

    async def _record_failure(
        self,
        *,
        tool_id: uuid.UUID,
        connection_id: uuid.UUID,
        input_summary: dict[str, Any],
        output_summary: dict[str, Any] | None,
        exc: DomainError,
        started: float,
    ) -> ExecutionOutcome:
        status = _status_for(exc)
        duration_ms = _elapsed_ms(started)
        row_id = await self._append_audit(
            tool_id=tool_id,
            connection_id=connection_id,
            status=status,
            input_summary=input_summary,
            output_summary=output_summary,
            error_code=exc.code,
            duration_ms=duration_ms,
        )
        # Give the caller the audit id without leaking anything else into the envelope.
        exc.details = {**(exc.details or {}), "tool_call_id": str(row_id)}
        return ExecutionOutcome(tool_call_id=row_id, error=exc)

    async def _append_audit(
        self,
        *,
        tool_id: uuid.UUID,
        connection_id: uuid.UUID,
        status: str,
        input_summary: dict[str, Any],
        output_summary: dict[str, Any] | None,
        error_code: str | None,
        duration_ms: int,
    ) -> uuid.UUID:
        """Insert the audit row and buffer `tool_call.completed` (dispatched post-commit)."""
        caller = {
            "interface": self._interface,
            "kind": self._ctx.caller.kind,
            "api_token_id": _opt_str(self._ctx.caller.api_token_id),
            "member_id": _opt_str(self._ctx.caller.member_id),
        }
        row = await self._repo.insert_tool_call(
            connection_id=connection_id,
            tool_id=tool_id,
            request_id=self._ctx.request_id,
            caller=caller,
            status=status,
            input_summary=input_summary,
            output_summary=output_summary,
            error_code=error_code,
            duration_ms=duration_ms,
        )
        event_bus.publish(
            tool_call_completed(
                self._ctx.workspace_id,
                tool_call_id=row.id,
                tool_id=tool_id,
                connection_id=connection_id,
                status=status,
                error_code=error_code,
                duration_ms=duration_ms,
            )
        )
        # M2.4 D2: quota consumption happens HERE — exactly once per audited call, and only for
        # executed statuses (succeeded/failed/timeout). Denied calls consume nothing; an
        # idempotency replay never reaches execute(), so it can never re-consume.
        await record_executed_call(
            workspace_id=self._ctx.workspace_id, plan=self._plan, status=status
        )
        return row.id


def _endpoint_for(version: Any, tool_name: str) -> dict[str, Any] | None:
    """The executable `endpoint` for `tool_name` inside a ConnectorVersion.normalized_schema."""
    if version is None:
        return None
    schema = version.normalized_schema
    tools = schema.get("tools") if isinstance(schema, dict) else schema
    if not isinstance(tools, list):
        return None
    for entry in tools:
        if isinstance(entry, dict) and entry.get("name") == tool_name:
            endpoint = entry.get("endpoint")
            return endpoint if isinstance(endpoint, dict) else None
    return None


def _base_url(connector: Any, connection: Any) -> str:
    """The Connection's `base_url` override if present and non-empty, else the Connector's."""
    overrides = connection.config_overrides if isinstance(connection.config_overrides, dict) else {}
    override = overrides.get("base_url")
    if isinstance(override, str) and override.strip():
        return override
    return str(connector.base_url)


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.perf_counter() - started) * 1000))


def _opt_str(value: uuid.UUID | None) -> str | None:
    return str(value) if value is not None else None


__all__ = ["ExecutionOutcome", "RuntimeService"]
