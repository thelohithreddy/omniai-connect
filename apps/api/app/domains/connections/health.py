"""Connection Health — the derived projection and the safe probe-Tool selector (ROADMAP §58).

Connection Health is **not a new execution engine**. A health check is an ordinary Tool Call:
AI_RUNTIME §2 stage 1 authenticates "the workspace-scoped api token **or the session Member for
dashboard 'test call'**", and stage 2 resolves Tool + Connection. So the whole of this module is
two pure decisions and a projection; the execution itself belongs to `RuntimeService` and nothing
here performs HTTP, decrypts a credential, validates egress, or writes an audit row.

Two rules in here are load-bearing and both are **fail-closed**:

1. **Probe selection** (`select_probe_tool`). A health check runs a Tool against a real third-party
   API with real credentials, so choosing the wrong one is not a cosmetic bug — it is an
   unattended destructive call the user never asked for. A Tool is eligible only when it is
   enabled, live, annotated `readonly: true`, **and** needs no arguments. Anything else, including
   a Tool whose annotations are simply absent, is refused. `tools.annotations` is `NOT NULL
   DEFAULT '{}'`, so "absent" is the common case for manually-created Connectors — treating it as
   safe would be exactly backwards.

2. **Health projection** (`project_health`). Derived, never stored. The released
   `connections.status` CHECK (`pending_auth|active|error|revoked`) is untouched, for the same
   reason M2.5 derived `needs_reauth` instead of adding a fifth status (ADR-0038 D5): a status
   column is a contract, and widening it to carry an operational signal conflates two lifetimes.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

#: Audit statuses (`tool_calls.status`, DATABASE_DESIGN §3) that mean the probe actually worked.
_SUCCEEDED = "succeeded"

#: The credential type whose failure is recoverable only by a human re-authorizing (M2.5).
_OAUTH2 = "oauth2"

#: The Connection lifecycle status that, for an OAuth credential, means the refresh budget is spent
#: and the Connection needs a human (ADR-0038 D2/D5).
_ERROR = "error"


class HealthState(StrEnum):
    """The derived health of a Connection. Never persisted, never a database enum."""

    #: No health check has ever completed for this Connection.
    UNKNOWN = "unknown"
    #: The most recent completed health check succeeded.
    HEALTHY = "healthy"
    #: The most recent completed health check failed.
    UNHEALTHY = "unhealthy"
    #: The Connection's OAuth credential is exhausted; only re-authorization recovers it. Takes
    #: precedence over a stale check result: a Connection in this state cannot succeed, so
    #: reporting `healthy` from an older probe would be actively misleading.
    NEEDS_REAUTH = "needs_reauth"


def needs_reauth(*, connection_status: str, credential_type: str | None) -> bool:
    """The M2.5 D5 derivation, surfaced at last.

    `needs_reauth` was ratified in ADR-0038 as **derived, never stored** — and then existed only in
    docstrings, surfaced by no endpoint. This is that contract, finally evaluated: an OAuth
    Connection whose refresh budget is spent transitions to `error` (D2), and that combination is
    the signal. An `error` on an api_key Connection is not re-authorizable, so it is not this.
    """
    return connection_status == _ERROR and credential_type == _OAUTH2


def project_health(
    *,
    connection_status: str,
    credential_type: str | None,
    last_health_check_at: object | None,
    last_check_status: str | None,
) -> HealthState:
    """Derive a Connection's health. Pure — every input is authoritative database state.

    `last_check_status` is the `tool_calls.status` of the audit row that *this* Connection's most
    recent health check produced. It is bound to that specific check rather than to "the newest
    Tool Call on this Connection", so ordinary traffic can neither manufacture a green light nor
    poison one: a Connection whose last *health check* passed stays `healthy` even if an unrelated
    Tool Call failed afterwards for its own reasons.
    """
    if needs_reauth(connection_status=connection_status, credential_type=credential_type):
        return HealthState.NEEDS_REAUTH
    if last_health_check_at is None or last_check_status is None:
        return HealthState.UNKNOWN
    return HealthState.HEALTHY if last_check_status == _SUCCEEDED else HealthState.UNHEALTHY


def _requires_arguments(input_schema: Any) -> bool:
    """True unless the Tool can be called with `{}`.

    The Runtime validates `input_schema.required` before egress, so a probe that needs arguments
    could only be executed by **inventing** them — which would mean sending fabricated data to a
    customer's live API. Anything not provably argument-free is refused, including a malformed or
    non-dict schema.
    """
    if not isinstance(input_schema, dict):
        return True  # unparseable schema → cannot prove it is argument-free
    required = input_schema.get("required")
    if required is None:
        return False
    if not isinstance(required, list):
        return True  # malformed → refuse rather than guess
    return len(required) > 0


def is_probe_eligible(tool: Any) -> bool:
    """Whether one Tool may be executed as an unattended health probe. Fail-closed on every axis.

    `annotations.readonly` must be exactly the boolean `True`. The stored annotation is the only
    authority: the HTTP method is deliberately **not** consulted here even though ingestion infers
    `readonly` from GET/HEAD, because re-deriving it at execution time would silently overrule a
    user who edited the annotation (CONNECTOR_ENGINE §151 permits per-Tool overrides).
    """
    if not getattr(tool, "enabled", False):
        return False
    if getattr(tool, "deleted_at", None) is not None:
        return False
    annotations = getattr(tool, "annotations", None)
    if not isinstance(annotations, dict) or annotations.get("readonly") is not True:
        return False
    return not _requires_arguments(getattr(tool, "input_schema", None))


def select_probe_tool(tools: list[Any]) -> Any | None:
    """The one Tool to probe with, or None when the Connector offers no safe option.

    Deterministic by design: eligible Tools are ordered by canonical `name` and the first is taken.
    Name is unique among a Workspace's live Tools (CONNECTOR_ENGINE §5), so the ordering is total
    and the same Connector yields the same probe on every check — which is what makes a health
    result comparable over time, and what stops a re-ingestion from silently changing which
    third-party endpoint gets called.

    Returning None is a supported outcome (`health_check_unavailable`), not an error to work
    around. A Connector whose read operations all take required parameters genuinely has no
    zero-argument probe, and inventing one would mean fabricating a request.
    """
    eligible = [tool for tool in tools if is_probe_eligible(tool)]
    if not eligible:
        return None
    return min(eligible, key=lambda tool: str(tool.name))


__all__ = [
    "HealthState",
    "is_probe_eligible",
    "needs_reauth",
    "project_health",
    "select_probe_tool",
]
