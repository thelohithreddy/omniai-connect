"""Domain exception hierarchy and its mapping to the API error envelope.

Services raise these; one handler in main.py maps them (BACKEND_SPEC.md §6, P-50).
Routers never build an error response by hand, so the envelope in API_GUIDELINES.md §6
stays uniform across every endpoint and every Interface.

`code` values come from the taxonomy in API_GUIDELINES.md §6.1 and are part of the public
API contract: clients branch on them, so they are stable even when `message` is reworded.
"""

from __future__ import annotations

from typing import Any


class DomainError(Exception):
    """Base for every expected failure. Unexpected ones become `internal`."""

    code: str = "internal"
    http_status: int = 500

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class ValidationFailedError(DomainError):
    code = "validation_error"
    http_status = 400


class UnauthorizedError(DomainError):
    """Missing, malformed, revoked, or expired credential."""

    code = "unauthorized"
    http_status = 401


class PermissionDeniedError(DomainError):
    """Authenticated, but the role lacks the capability (SECURITY.md §4.1)."""

    code = "forbidden"
    http_status = 403


class NotFoundError(DomainError):
    """Absent — or outside the caller's Workspace.

    Cross-tenant access returns this, never `forbidden` (P-17): a 403 confirms the object
    exists, which turns the endpoint into an existence oracle an attacker can enumerate.
    """

    code = "not_found"
    http_status = 404


class ConflictError(DomainError):
    """State conflict: duplicate slug, idempotency-key body mismatch."""

    code = "validation_error"
    http_status = 409


class QuotaExceededError(DomainError):
    code = "rate_limited"
    http_status = 429


class UpstreamAPIError(DomainError):
    """A third-party API failed in a way the runtime could not normalize."""

    code = "connector_error"
    http_status = 502


class UpstreamTimeoutError(DomainError):
    """The upstream API exceeded the runtime timeout (default 30s, Architecture §7)."""

    code = "upstream_timeout"
    http_status = 504


class EgressBlockedError(DomainError):
    """The runtime refused an outbound request on egress policy — a target that resolves to a
    private/link-local address, an off-allowlist redirect, or a rebinding answer (SECURITY.md §6,
    AI_RUNTIME.md §7). A policy *denial*, distinct from an upstream failure: it is our layer saying
    no. Surfaced as the `ssrf_blocked` code (API_GUIDELINES.md §6.1); the message never carries the
    raw URL or resolved address."""

    code = "ssrf_blocked"
    http_status = 403
