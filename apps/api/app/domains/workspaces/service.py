"""Business logic for the workspaces domain. Framework-free by design.

No FastAPI imports here: the service is what an MCP adapter, a Celery task, or a test
calls directly, and each of those would otherwise have to fake an HTTP request to reach
the logic (BACKEND_SPEC.md §2).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from app.core.exceptions import NotFoundError, ValidationFailedError
from app.core.security import generate_token
from app.domains.workspaces.models import MEMBER_ROLES, ApiToken, Member, Workspace
from app.domains.workspaces.repository import (
    ApiTokenRepository,
    MemberRepository,
    WorkspaceRepository,
)


class WorkspaceService:
    def __init__(self, repository: WorkspaceRepository) -> None:
        self._repository = repository

    async def get_current(self) -> Workspace:
        """The Workspace the caller's token belongs to.

        A miss here means the token resolved but its Workspace row is gone — a deleted
        tenant whose tokens were not cascaded, or an RLS misconfiguration. `not_found`
        rather than `internal` because the caller cannot act on the distinction, and it
        keeps the cross-tenant response shape identical (P-17).
        """
        workspace = await self._repository.get_current()
        if workspace is None:
            raise NotFoundError("Workspace not found.")
        return workspace


class MemberService:
    """Application operations over Members of one Workspace.

    Constructed from a `MemberRepository`, exactly as `WorkspaceService` is — and that
    choice carries the tenancy guarantee. The service holds no `WorkspaceContext` and no
    `workspace_id` of its own, so there is nothing here for a caller to override and no
    expression this class can form that reaches another tenant. The repository it was
    handed already decided which Workspace this is.

    Where the repository answers "how do I safely persist and retrieve members", this
    layer answers "what application operation is being performed" — turning absent rows
    into domain errors, validating inputs against the domain, and leaving persistence
    semantics alone.

    **This layer performs no authorization.** It stores, reads and changes `role` as
    data; it never asks whether *the caller* is entitled to do so. Validating that a role
    is one of the four canonical values is a data-domain check, not a permission check —
    the distinction is that nothing here branches on who is asking. Caller authorization
    is M1.2-D/E and is deliberately absent, not forgotten.

    Transactions belong to the UnitOfWork (BACKEND_SPEC.md §3): nothing here commits or
    rolls back, so a caller's request-scoped transaction stays the single boundary.
    """

    def __init__(self, repository: MemberRepository) -> None:
        self._repository = repository

    # ---------------------------------------------------------------- reads

    async def get_member(self, member_id: uuid.UUID) -> Member:
        """One Member of this Workspace. Raises `NotFoundError` if absent.

        A member belonging to another Workspace is indistinguishable from one that does
        not exist, because the repository already returned `None` for both. That is
        deliberate: a distinct error would confirm the row exists somewhere and turn this
        into an existence oracle (P-17).
        """
        member = await self._repository.get(member_id)
        if member is None:
            raise NotFoundError("Member not found.")
        return member

    async def get_member_by_user_id(self, user_id: str) -> Member:
        """This Workspace's membership for a user. Raises `NotFoundError` if absent.

        Resolves within the Workspace only. `user_id` is an external Better Auth subject
        and is not globally unique across Workspaces (ADR-0002), so there is deliberately
        no operation here that answers "which Workspaces does this user belong to" — that
        query cannot run under RLS and needs its own architectural decision.
        """
        member = await self._repository.get_by_user_id(_require_user_id(user_id))
        if member is None:
            raise NotFoundError("Member not found.")
        return member

    async def list_members(self) -> list[Member]:
        """Every Member of this Workspace.

        There is no cross-Workspace listing operation and none should be added here; that
        would be a new tenancy exemption requiring an ADR (ADR-0008), not a service method.
        """
        return await self._repository.list_for_workspace()

    # ---------------------------------------------------------------- writes

    async def add_member(
        self,
        *,
        user_id: str,
        role: str,
        invited_by: uuid.UUID | None = None,
    ) -> Member:
        """Add a user to this Workspace with a role.

        Raises `ValidationFailedError` for an empty user identity or a role outside the
        canonical domain, and `ConflictError` if the user is already a member.

        **Deliberately does not pre-check for an existing membership.** A
        `SELECT`-then-`INSERT` would be a race: two concurrent requests for the same user
        can both observe "not a member" and both proceed, and the second insert then fails
        anyway. Since the losing request must handle the constraint violation regardless,
        the pre-check buys nothing and would create the illusion that the application is
        what guarantees uniqueness. The `(workspace_id, user_id)` unique constraint is
        authoritative; the repository translates its violation into `ConflictError`, and
        this method simply lets that surface.
        """
        return await self._repository.create(
            user_id=_require_user_id(user_id),
            role=_require_valid_role(role),
            invited_by=invited_by,
        )

    async def change_member_role(self, member_id: uuid.UUID, role: str) -> Member:
        """Set a Member's role. Raises `NotFoundError` if the Member is not in this Workspace.

        Validates the value against the canonical domain. It does **not** evaluate whether
        the change is permitted — no last-owner protection, no "admins cannot modify
        owners", no role-transition rules. None of those appear in any canonical document,
        and inventing them here would place authorization in the wrong layer and prejudge
        M1.2-D.
        """
        member = await self._repository.update_role(member_id, _require_valid_role(role))
        if member is None:
            raise NotFoundError("Member not found.")
        return member

    async def remove_member(self, member_id: uuid.UUID) -> None:
        """Remove a Member from this Workspace. Raises `NotFoundError` if absent.

        Removing the Workspace's last owner is not prevented, because no canonical source
        defines that rule. Recorded as a deferred question for M1.2-D rather than decided
        here by default.
        """
        if not await self._repository.delete(member_id):
            raise NotFoundError("Member not found.")


def _require_user_id(user_id: str) -> str:
    """Reject an absent identity before it reaches persistence.

    `user_id` is `NOT NULL` in the schema but an empty or whitespace-only string would
    satisfy that and create a membership pointing at nobody.
    """
    cleaned = user_id.strip()
    if not cleaned:
        raise ValidationFailedError("A member requires a user identity.")
    return cleaned


def _require_valid_role(role: str) -> str:
    """Reject a role outside the canonical domain.

    The database CHECK constraint remains authoritative and is not being replaced — this
    exists because a CHECK violation arrives as a raw `IntegrityError`, which the
    repository translates only for the duplicate-membership case. Without this the service
    would leak a SQLAlchemy exception to its caller (BACKEND_SPEC.md §6).

    Not an authorization check: it validates a *value*, and branches on nothing about the
    caller.
    """
    if role not in MEMBER_ROLES:
        raise ValidationFailedError(
            "Unknown member role.",
            details={"role": role, "allowed": list(MEMBER_ROLES)},
        )
    return role


@dataclass(frozen=True, slots=True)
class IssuedApiToken:
    """A newly created token *plus* its plaintext — a return value, never a stored one.

    The plaintext lives in this object for the width of a single request: minted in
    `ApiTokenService.issue`, carried to the router, serialized into the response, and then
    unreachable. It is not written to the row, not cached, not held in module state.

    `repr=False` mirrors `GeneratedToken`: a dataclass repr would print the secret into any
    log line, exception message, or traceback frame that happens to render this object.
    """

    token: ApiToken
    plaintext: str = field(repr=False)


class ApiTokenService:
    """Issuance of workspace-scoped machine credentials (SECURITY.md §4, ADR-0002).

    Constructed from an `ApiTokenRepository` alone, like the other services here: it holds
    no `WorkspaceContext` and no `workspace_id`, so there is no expression this class can
    form that writes a token into another tenant.

    **This layer performs no authorization.** Whether the caller may mint credentials is
    decided at the request boundary by `require_permission(Permission.API_TOKENS_MANAGE)`
    (M1.2-E). Nothing here branches on who is asking — which is exactly why the endpoint
    must not be the only guard for anything this class does not itself enforce.
    """

    def __init__(self, repository: ApiTokenRepository) -> None:
        self._repository = repository

    async def issue(
        self,
        *,
        name: str,
        created_by_member_id: uuid.UUID | None,
    ) -> IssuedApiToken:
        """Mint a token for this Workspace and return it with its one-time plaintext.

        The secret is generated here and hashed immediately; only the hash and the display
        prefix travel onward to persistence. `ApiTokenRepository.create` has no parameter
        capable of accepting a plaintext, so "forgot to hash it" is not a mistake this
        codebase can make — the plaintext leaves this method only in the return value.

        There is no second read-back path: nothing in the domain can reconstruct the secret
        from the stored row, because SHA-256 is one-way and the prefix is 8 random
        characters of a 43-character secret. If the caller loses the response, the token is
        gone and a new one must be issued.

        `created_by_member_id` is a **required** keyword argument even though it is
        nullable. A default of `None` would let a future call site omit provenance silently
        and record an unattributed credential; making it required forces every caller to
        state, in the code, whose authority the token was minted under. The endpoint passes
        the authenticated member; the bootstrap script — which mints a workspace's first
        token before any Member exists — passes `None` explicitly.
        """
        # Validate *before* minting. Generating first would create a live secret for a
        # request that is about to fail, leaving it in a stack frame that a traceback
        # renderer can walk. Nothing high-entropy exists until the request is known good.
        validated_name = _require_token_name(name)
        generated = generate_token()
        token = await self._repository.create(
            name=validated_name,
            token_hash=generated.token_hash,
            token_prefix=generated.token_prefix,
            created_by_member_id=created_by_member_id,
        )
        return IssuedApiToken(token=token, plaintext=generated.plaintext)


def _require_token_name(name: str) -> str:
    """Reject a nameless token before it reaches persistence.

    Duplicated from the Pydantic schema on purpose. The schema guards the HTTP door; this
    guards the service, which an MCP adapter, a Celery task, or a script calls directly
    (BACKEND_SPEC.md §2). A token labelled `"   "` is unidentifiable in a revocation UI,
    which is a real operational hazard for a credential you can only revoke by picking it
    out of a list.

    Names are deliberately **not** unique. Two CI runners may both be called "ci", and a
    uniqueness constraint would make the failure mode of issuance a confusing 409 rather
    than a second working credential.
    """
    cleaned = name.strip()
    if not cleaned:
        raise ValidationFailedError("An API token requires a name.")
    if len(cleaned) > _TOKEN_NAME_MAX_LEN:
        raise ValidationFailedError(
            "API token name is too long.",
            details={"max_length": _TOKEN_NAME_MAX_LEN},
        )
    return cleaned


#: Matches `api_tokens.name` (String(120)). Over-length input is a domain error here rather
#: than a `DataError` surfacing from the driver (BACKEND_SPEC.md §6).
_TOKEN_NAME_MAX_LEN = 120
