"""Machine identity: workspace-scoped API token generation, hashing, and resolution.

Per ADR-0002 there are two identity planes and they never mix. This module owns the
*machine* plane — the tokens AI clients and Interfaces present (MCP_RUNTIME.md §2,
AI_RUNTIME.md §2.1). Human identity is Better Auth's, lands in M1.2, and gets its own
resolver.

**Why SHA-256 and not bcrypt/argon2.** Password hashes are deliberately slow because
passwords are low-entropy and guessable; the work factor is what makes a dictionary attack
uneconomic. An API token here is 32 bytes from `secrets.token_urlsafe` — 256 bits of
uniform entropy, with no dictionary to attack. Slow hashing would buy nothing and would
add its cost to *every* Tool Call, on the hot path we are budgeting to p95 < 400 ms
(PRD.md §6). A single SHA-256 over a high-entropy secret is the correct primitive, and the
same reasoning is why GitHub and Stripe hash their tokens rather than password-hash them.

**Why the plaintext is never stored.** `token_hash` is one-way, so a database disclosure
does not yield working credentials. The plaintext exists exactly once, in the creation
response; losing it means issuing a new token.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Literal

import structlog
from fastapi import Depends, Request
from sqlalchemy import text

from app.core.db import UnitOfWork, get_uow
from app.core.exceptions import UnauthorizedError

# noqa S105: this is a public, non-secret marker deliberately printed in dashboards and
# logs so a leaked credential is greppable (the pattern GitHub uses with `ghp_`). It is a
# constant prefix, not key material.
TOKEN_PREFIX = "omc_"  # noqa: S105
_TOKEN_ENTROPY_BYTES = 32
# `omc_` + 8 random chars. Enough to disambiguate tokens in a list UI without being
# enough to attack; lookup is always by full hash (DATABASE_DESIGN.md `api_tokens`).
PREFIX_DISPLAY_LEN = 12

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class GeneratedToken:
    """The only object that ever holds token plaintext. Never persist or log it."""

    plaintext: str
    token_hash: str
    token_prefix: str


@dataclass(frozen=True, slots=True)
class CallerIdentity:
    """Who is making this call (AI_RUNTIME.md §1 `ToolCallRequest.caller`)."""

    kind: Literal["api_token", "member"]
    api_token_id: uuid.UUID | None = None
    member_id: uuid.UUID | None = None


@dataclass(frozen=True, slots=True)
class WorkspaceContext:
    """Resolved tenant + caller for one request.

    Repositories require one of these to be constructed, which is what makes an unscoped
    tenant query unrepresentable rather than merely discouraged (P-14).
    """

    workspace_id: uuid.UUID
    caller: CallerIdentity
    request_id: str
    scopes: tuple[str, ...] = ()


def generate_token() -> GeneratedToken:
    """Mint a new workspace-scoped API token."""
    plaintext = f"{TOKEN_PREFIX}{secrets.token_urlsafe(_TOKEN_ENTROPY_BYTES)}"
    return GeneratedToken(
        plaintext=plaintext,
        token_hash=hash_token(plaintext),
        token_prefix=plaintext[:PREFIX_DISPLAY_LEN],
    )


def hash_token(plaintext: str) -> str:
    """SHA-256 hex digest — the only form ever persisted."""
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def extract_bearer_token(request: Request) -> str:
    header = request.headers.get("Authorization")
    if not header:
        raise UnauthorizedError("Missing Authorization header.")
    scheme, _, credential = header.partition(" ")
    if scheme.lower() != "bearer" or not credential.strip():
        raise UnauthorizedError("Authorization header must be 'Bearer <token>'.")
    return credential.strip()


# Resolution has to happen *before* a workspace is bound — the lookup is what discovers
# the workspace — so it cannot run under RLS, whose policy needs the very value being
# looked up. `auth.resolve_api_token` is a SECURITY DEFINER function created in migration
# 0001: it is the single, narrowly-granted, search_path-pinned exemption in the schema
# (DATABASE_DESIGN.md §6). Everything after this line is fully scoped.
_RESOLVE_TOKEN_SQL = text(
    "SELECT token_id, workspace_id, scopes, revoked_at, expires_at "
    "FROM auth.resolve_api_token(:token_hash)"
)


async def get_workspace_context(
    request: Request,
    uow: Annotated[UnitOfWork, Depends(get_uow)],
) -> WorkspaceContext:
    """FastAPI dependency: Bearer token → bound, tenant-scoped request context."""
    presented = extract_bearer_token(request)
    row = (
        await uow.session.execute(_RESOLVE_TOKEN_SQL, {"token_hash": hash_token(presented)})
    ).first()

    # Unknown, revoked, and expired all produce the same response and the same message.
    # Distinguishing them tells an attacker which of their guesses was once real.
    if row is None:
        raise UnauthorizedError("Invalid or revoked API token.")
    if row.revoked_at is not None:
        raise UnauthorizedError("Invalid or revoked API token.")
    if row.expires_at is not None and row.expires_at <= datetime.now(UTC):
        raise UnauthorizedError("Invalid or revoked API token.")

    await uow.bind_workspace(row.workspace_id)
    structlog.contextvars.bind_contextvars(workspace_id=str(row.workspace_id))

    request_id: str = getattr(request.state, "request_id", "")
    return WorkspaceContext(
        workspace_id=row.workspace_id,
        caller=CallerIdentity(kind="api_token", api_token_id=row.token_id),
        request_id=request_id,
        scopes=tuple(row.scopes or ()),
    )


CurrentWorkspace = Annotated[WorkspaceContext, Depends(get_workspace_context)]
