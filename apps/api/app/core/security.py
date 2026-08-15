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
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import UnitOfWork, get_uow
from app.core.exceptions import UnauthorizedError
from app.core.human_auth import (
    HUMAN_AUTH_FAILED,
    HumanIdentity,
    JWKSCache,
    get_jwks_cache,
    resolve_human_identity,
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


def generate_invitation_token() -> str:
    """A fresh 256-bit opaque invitation token (ADR-0017 §4).

    `secrets.token_urlsafe(32)` is 32 CSPRNG bytes — 256 bits — URL-safe so it can ride in
    the invite link. No prefix (unlike `omc_` machine tokens): an invitation token is never
    a bearer credential for the API, only the one-time key that establishes a membership.
    Only its `hash_token` is ever stored; the raw value exists during creation, delivery,
    and acceptance and is never logged.
    """
    return secrets.token_urlsafe(_TOKEN_ENTROPY_BYTES)


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

# The listing twin (migration 0005, ADR-0016 §7): the subject's workspaces + display role,
# for GET /v1/workspaces. Distinct from the resolver above precisely because it returns
# `role` — a value used only for display, never for authorization, so it must never sit on
# the binding path that get_workspace_context takes.
_RESOLVE_MEMBER_WORKSPACE_ROLES_SQL = text(
    "SELECT workspace_id, role FROM auth.resolve_member_workspace_roles(:user_id)"
)


@dataclass(frozen=True, slots=True)
class HumanMembership:
    """One membership row for the listing endpoint: a Workspace id and the caller's role."""

    workspace_id: uuid.UUID
    role: str


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


# The canonical human workspace-selection header (ADR-0016). A *selection signal*, never
# authority: it names which membership to bind, and binding happens only after the row is
# found among the subject's own memberships.
WORKSPACE_SELECTION_HEADER = "X-Workspace-Id"


def _read_selected_workspace(request: Request) -> uuid.UUID | None:
    """Parse `X-Workspace-Id` as an untrusted selection, or None if absent.

    Returns None when the header is not present at all (the no-selector case). Raises the
    uniform human 401 when the header is present but unusable:

    - *Duplicate/ambiguous.* `Headers.get()` silently returns only the FIRST of repeated
      headers, so relying on it would let `X-Workspace-Id: <mine>, X-Workspace-Id: <theirs>`
      quietly bind the first — the directive's forbidden "silently reconciled" case. We take
      the full list instead and reject anything that is not exactly one value; a single
      comma-joined header (`"A, B"`) also fails, on the UUID parse below. Ambiguity denies.
    - *Malformed.* Anything that is not one canonical UUID. Whitespace is stripped so a
      padded but otherwise valid id still works.
    """
    values = request.headers.getlist(WORKSPACE_SELECTION_HEADER)
    if not values:
        return None
    if len(values) > 1:
        log.debug("human_auth.workspace_selection_rejected", reason="ambiguous_selector")
        raise UnauthorizedError(HUMAN_AUTH_FAILED)
    try:
        return uuid.UUID(values[0].strip())
    except (ValueError, AttributeError):
        log.debug("human_auth.workspace_selection_rejected", reason="malformed_selector")
        raise UnauthorizedError(HUMAN_AUTH_FAILED) from None


async def _human_context(
    request: Request, uow: UnitOfWork, presented: str, jwks_cache: JWKSCache
) -> WorkspaceContext:
    """Verified human JWT + `X-Workspace-Id` selection → membership-bound context (ADR-0016).

    `resolve_human_subject` owns every cryptographic and claim check; by the time it
    returns, `sub` is proven to come from our issuer. What remains is binding the requested
    workspace to a *verified* membership — the header says where the human wants to act, the
    membership set says where they may:

    - zero memberships                → fail closed. Header or not, there is no tenant to
      bind, and distinguishing this from a forged token would let a stolen JWT probe which
      accounts have workspaces.
    - one membership, no header        → bind it (the M1.3-B auto-bind, preserved).
    - a header naming an own membership → bind that one; role and permissions follow it.
    - a header naming any other        → fail closed, indistinguishable from an invalid JWT.
      No existence oracle: "not a member of X" reads exactly like "bad token".
    - many memberships, no header       → fail closed; the header is required and the server
      never picks first/newest/arbitrary.

    Role is deliberately NOT read here. `resolve_member_role` reads it from the bound
    member row under RLS — one authorization source of truth (ADR-0015 §7, ADR-0016 §2).
    """
    sub = await resolve_human_subject(presented, jwks_cache)
    selected = _read_selected_workspace(request)

    rows = (await uow.session.execute(_RESOLVE_MEMBER_SQL, {"user_id": sub})).all()
    # workspace_id → member_id over the subject's OWN memberships. Membership is unique per
    # (workspace, user), so this map is the complete, authoritative set of bindable targets.
    memberships = {row.workspace_id: row.member_id for row in rows}

    member_id, workspace_id = _select_membership(selected, memberships)
    if member_id is None or workspace_id is None:
        raise UnauthorizedError(HUMAN_AUTH_FAILED)

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


def _select_membership(
    selected: uuid.UUID | None, memberships: dict[uuid.UUID, uuid.UUID]
) -> tuple[uuid.UUID | None, uuid.UUID | None]:
    """Resolve (member_id, workspace_id) to bind, or (None, None) to fail closed.

    Pure function over the requested workspace and the subject's own membership map, so the
    whole selection policy (ADR-0016 §3) is auditable in one place with no IO. Every deny
    path returns the same sentinel; the caller maps it to the single uniform 401.
    """
    if selected is not None:
        # An explicit selection binds only if it is one of the caller's OWN memberships.
        # A foreign/random/deleted id is simply absent from the map → deny, no disclosure.
        member_id = memberships.get(selected)
        if member_id is None:
            log.debug("human_auth.workspace_selection_rejected", reason="not_a_member")
            return None, None
        return member_id, selected

    # No selector supplied.
    if len(memberships) == 1:
        # The degenerate case: exactly one membership, nothing to choose. Preserve the
        # M1.3-B auto-bind so single-workspace humans need not send the header.
        (workspace_id, member_id) = next(iter(memberships.items()))
        return member_id, workspace_id

    # Zero memberships, or many without a selection: both fail closed.
    log.debug(
        "human_auth.workspace_selection_rejected",
        reason="no_membership" if not memberships else "selector_required",
        membership_count=len(memberships),
    )
    return None, None


CurrentWorkspace = Annotated[WorkspaceContext, Depends(get_workspace_context)]


async def require_human_subject(
    request: Request,
    jwks_cache: Annotated[JWKSCache, Depends(get_jwks_cache)],
) -> str:
    """FastAPI dependency: a verified human JWT → its `sub`, with NO workspace bound.

    The pre-selection identity dependency for `GET /v1/workspaces` (ADR-0016 §7): a human
    lists the workspaces they may select *before* selecting one, so binding a single
    workspace is impossible here by definition. This reuses the M1.3-B verifier —
    `resolve_human_subject` — and stops at the verified subject; it is not a second resolver.

    Human-only. A machine `omc_` credential is fed to the JWT verifier like anything else,
    where it fails as a malformed token with the uniform human 401. There is deliberately no
    early `omc_` branch and no fallthrough to the machine plane: a machine token is simply
    not a valid credential for a human-identity endpoint, and saying so with a distinct
    message would be a plane oracle.
    """
    presented = extract_bearer_token(request)
    return await resolve_human_subject(presented, jwks_cache)


CurrentHumanSubject = Annotated[str, Depends(require_human_subject)]


async def require_human_identity(
    request: Request,
    jwks_cache: Annotated[JWKSCache, Depends(get_jwks_cache)],
) -> HumanIdentity:
    """FastAPI dependency: a verified human JWT → its identity (sub + email-binding claims).

    Used only by invitation acceptance (ADR-0017 §3), which needs the provider-verified
    email to bind an invitation to the accepting person. Like `require_human_subject` it is
    human-only and binds no workspace — the invitation, resolved from its token, establishes
    the workspace. A machine `omc_` credential is fed to the JWT verifier and fails as a
    malformed token, with no fallthrough to the machine plane.
    """
    presented = extract_bearer_token(request)
    return await resolve_human_identity(presented, jwks_cache)


CurrentHumanIdentity = Annotated[HumanIdentity, Depends(require_human_identity)]


async def resolve_human_memberships(subject: str, session: AsyncSession) -> list[HumanMembership]:
    """The verified subject's own workspaces + display role (ADR-0016 §7).

    Reads only the caller's memberships via the `auth.resolve_member_workspace_roles`
    bootstrap function, which reuses migration 0004's `members` exemption — so it discloses
    a workspace id and the caller's own role, and nothing about any other tenant. The role
    is for display; it never authorizes anything.
    """
    rows = (await session.execute(_RESOLVE_MEMBER_WORKSPACE_ROLES_SQL, {"user_id": subject})).all()
    return [HumanMembership(workspace_id=row.workspace_id, role=row.role) for row in rows]
