"""Caller identity resolution: machine API tokens, and human JWTs via `core.human_auth`.

Per ADR-0002 there are two identity planes and they never mix. This module owns the
*machine* plane — the tokens AI clients and Interfaces present (MCP_RUNTIME.md §2,
AI_RUNTIME.md §2.1) — and hosts the single composite resolver BACKEND_SPEC §3 defines:
`get_workspace_context` accepts either credential type and dispatches by shape. Machine
tokens carry the `omc_` prefix; anything else is treated as a human JWT and verified by
`core.human_auth` (ADR-0015). Neither path ever falls through to the other — a failed JWT
is never retried as an API token, nor the reverse, so a defect in one plane cannot become
an authentication path through the other.

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
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Literal

import structlog
from fastapi import Depends, Request
from sqlalchemy import text

from app.core.db import UnitOfWork, get_uow
from app.core.exceptions import UnauthorizedError
from app.core.human_auth import (
    HUMAN_AUTH_FAILED,
    JWKSCache,
    get_jwks_cache,
    resolve_human_subject,
)

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
    """The only object that ever holds token plaintext. Never persist or log it.

    `repr=False` on `plaintext` is not cosmetic. A dataclass's generated `__repr__` prints
    every field, so `log.info("issued", token=generated)`, an f-string in an exception
    message, or a traceback frame rendering local variables would each emit a live
    credential — and structlog calls `repr()` on non-primitive values. Excluding the field
    means the accident is not available: the object renders as
    `GeneratedToken(token_hash='...', token_prefix='omc_...')`, and reaching the secret
    requires naming `.plaintext` deliberately.
    """

    plaintext: str = field(repr=False)
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


# The human bootstrap twin of `auth.resolve_api_token` (migration 0004, ADR-0015 §7): a
# verified JWT names a user, not a workspace, so discovering the workspace cannot itself
# run under the policy that needs one. Same SECURITY DEFINER mechanism, same owner role.
_RESOLVE_MEMBER_SQL = text(
    "SELECT member_id, workspace_id FROM auth.resolve_member_workspaces(:user_id)"
)


async def get_workspace_context(
    request: Request,
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    jwks_cache: Annotated[JWKSCache, Depends(get_jwks_cache)],
) -> WorkspaceContext:
    """FastAPI dependency: Bearer credential → bound, tenant-scoped request context.

    The composite resolver of BACKEND_SPEC §3. Dispatch is by credential shape and is
    exclusive: the `omc_` prefix is reserved by `generate_token`, so a machine token can
    never parse as a JWT and a JWT can never carry the prefix. There is no retry of one
    plane's credential against the other.
    """
    presented = extract_bearer_token(request)
    if presented.startswith(TOKEN_PREFIX):
        return await _machine_context(request, uow, presented)
    return await _human_context(request, uow, presented, jwks_cache)


async def _machine_context(request: Request, uow: UnitOfWork, presented: str) -> WorkspaceContext:
    """API token → context. The M1.2 path, byte-for-byte."""
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


async def _human_context(
    request: Request, uow: UnitOfWork, presented: str, jwks_cache: JWKSCache
) -> WorkspaceContext:
    """Verified human JWT → membership → context (ADR-0015 §§8–11).

    `resolve_human_subject` owns every cryptographic and claim check; by the time it
    returns, `sub` is proven to come from our issuer. What remains is pure membership:

    - zero memberships   → uniform 401. The subject is real but has no tenant context;
      distinguishing this from a forged token would let a stolen-JWT holder probe which
      accounts have workspaces.
    - one membership     → that workspace, the degenerate case where no selection exists.
    - many memberships   → uniform 401, fail closed. Selecting among workspaces is an
      undecided public-API-shape question (the Open Question in PROJECT_STATUS.md), and
      guessing here would invent the answer. Deny-by-default is the only safe interim.

    The role is deliberately NOT read here. `resolve_member_role` reads it from the
    member row under RLS after binding — one source of truth, already tested, and a
    bootstrap function that returned roles would be a second authorization surface.
    """
    sub = await resolve_human_subject(presented, jwks_cache)

    rows = (await uow.session.execute(_RESOLVE_MEMBER_SQL, {"user_id": sub})).all()
    if len(rows) != 1:
        log.debug(
            "human_auth.membership_unresolved",
            membership_count=len(rows),
        )
        raise UnauthorizedError(HUMAN_AUTH_FAILED)

    member_id, workspace_id = rows[0].member_id, rows[0].workspace_id
    await uow.bind_workspace(workspace_id)
    structlog.contextvars.bind_contextvars(workspace_id=str(workspace_id), member_id=str(member_id))

    request_id: str = getattr(request.state, "request_id", "")
    return WorkspaceContext(
        workspace_id=workspace_id,
        caller=CallerIdentity(kind="member", member_id=member_id),
        request_id=request_id,
        # Humans carry no token scopes; their authorization is the RBAC matrix, resolved
        # from the persisted role by require_permission. An empty tuple here is a fact,
        # not a placeholder.
        scopes=(),
    )


CurrentWorkspace = Annotated[WorkspaceContext, Depends(get_workspace_context)]
