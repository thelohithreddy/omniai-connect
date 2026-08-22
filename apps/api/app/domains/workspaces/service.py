"""Business logic for the workspaces domain. Framework-free by design.

No FastAPI imports here: the service is what an MCP adapter, a Celery task, or a test
calls directly, and each of those would otherwise have to fake an HTTP request to reach
the logic (BACKEND_SPEC.md §2).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import structlog

from app.core.config import settings
from app.core.email import EmailMessage, EmailSender
from app.core.exceptions import NotFoundError, ValidationFailedError
from app.core.pagination import (
    DEFAULT_LIMIT,
    CursorPosition,
    decode_cursor,
    encode_cursor,
    resolve_limit,
)
from app.core.security import generate_invitation_token, generate_token, hash_token
from app.domains.workspaces.models import MEMBER_ROLES, ApiToken, Invitation, Member, Workspace
from app.domains.workspaces.repository import (
    ApiTokenRepository,
    InvitationRepository,
    MemberRepository,
    RevocationOutcome,
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

    async def get_notification_email(self) -> str | None:
        """The Workspace's Connection Health notification destination, or None if unset."""
        return (await self.get_current()).notification_email

    async def set_notification_email(self, email: str | None) -> str | None:
        """Set or clear the notification destination (M2.10, ADR-0041).

        The value is already normalized and validated by the schema (`strip().lower()`, the same
        treatment `invited_email` gets), so this layer only persists it. A missed row is the same
        `not_found` `get_current` raises, for the same reason: the caller cannot act on the
        difference between a deleted tenant and an RLS misconfiguration, and reporting success for
        an UPDATE that changed nothing would be a lie the caller would act on.
        """
        matched, stored = await self._repository.set_notification_email(email)
        if not matched:
            raise NotFoundError("Workspace not found.")
        return stored


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

    async def list_members_page(
        self, *, limit: int = DEFAULT_LIMIT, cursor: str | None = None
    ) -> MemberPage:
        """One page of this Workspace's Members, newest first.

        Mirrors `ApiTokenService.list_tokens` exactly, including the over-fetch: asking for
        `limit + 1` and discarding the extra answers "is there another page?" from the same
        snapshot as the page itself, which a separate `count(*)` cannot do — it would be a
        second scan taken at a different instant, and a member added between the two makes
        them disagree.

        The cursor is decoded before the query runs, so an unusable one is a
        `ValidationFailedError` rather than a silently empty page (§3).
        """
        position = decode_cursor(cursor) if cursor is not None else None
        page_size = resolve_limit(limit)

        rows = await self._repository.list_page(limit=page_size + 1, after=position)

        has_more = len(rows) > page_size
        members = rows[:page_size]
        next_cursor = (
            encode_cursor(CursorPosition(created_at=members[-1].created_at, id=members[-1].id))
            if has_more and members
            else None
        )
        return MemberPage(members=members, next_cursor=next_cursor, has_more=has_more)

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
class MemberPage:
    """One page of Members plus the cursor that continues it (API_GUIDELINES.md §3)."""

    members: list[Member]
    next_cursor: str | None
    has_more: bool


@dataclass(frozen=True, slots=True)
class TokenPage:
    """One page of token metadata plus the cursor that continues it.

    `next_cursor` is `None` exactly when `has_more` is `False` (API_GUIDELINES.md §3), so
    a client loops until the cursor is null without needing to interpret the rows.
    """

    tokens: list[ApiToken]
    next_cursor: str | None
    has_more: bool


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

    async def list_tokens(
        self, *, limit: int = DEFAULT_LIMIT, cursor: str | None = None
    ) -> TokenPage:
        """One page of this Workspace's token *metadata*, newest first.

        Returns metadata only. There is no secret to withhold here and no code path that
        could produce one: the plaintext was never stored (M1.2-F), and `ApiToken` has no
        attribute holding it. Listing cannot recover a credential because the credential
        does not exist anywhere to be recovered — not because this method remembers to
        filter it out.

        **`has_more` is computed by over-fetching one row, not by counting.** A
        `SELECT count(*)` would be a second query over the whole tenant's tokens on every
        page, and it would still be wrong — the count is taken at a different instant from
        the page, so a concurrent issuance makes them disagree. Asking for `limit + 1` and
        discarding the extra answers exactly the question "is there anything after this
        page?" using the same snapshot as the page itself.

        The cursor is decoded before the query runs, so a malformed one is a
        `ValidationFailedError` rather than a silently empty page (API_GUIDELINES.md §3).
        """
        position = decode_cursor(cursor) if cursor is not None else None
        page_size = resolve_limit(limit)

        rows = await self._repository.list_page(limit=page_size + 1, after=position)

        has_more = len(rows) > page_size
        tokens = rows[:page_size]
        next_cursor = (
            encode_cursor(CursorPosition(created_at=tokens[-1].created_at, id=tokens[-1].id))
            if has_more and tokens
            else None
        )
        return TokenPage(tokens=tokens, next_cursor=next_cursor, has_more=has_more)

    async def revoke(self, token_id: uuid.UUID) -> None:
        """Revoke one of this Workspace's tokens. Idempotent.

        Raises `NotFoundError` when the token does not exist **or belongs to another
        Workspace** — deliberately the same outcome for both. SECURITY.md §3 requires
        cross-tenant access to answer `not_found` rather than `forbidden`, because a
        distinct response would confirm that a guessed id is real somewhere and turn this
        endpoint into an existence oracle across tenants.

        Revoking an already-revoked token succeeds silently, per API_GUIDELINES.md §2:
        *"Idempotent: deleting a deleted resource is 204."* That is not laxity. Revocation
        is what an operator reaches for during an incident, frequently through a retried
        request or a script run twice, and an error on the second attempt would suggest the
        credential is somehow still live at exactly the moment certainty matters most. The
        original `revoked_at` is preserved by the repository, so the audit trail still
        records when the credential actually stopped working.

        Returns nothing. There is no post-revocation state worth reporting that the listing
        does not already show, and returning the row would mean serializing a credential
        record in response to a destructive call for no reason.
        """
        outcome = await self._repository.revoke(token_id)
        if outcome is RevocationOutcome.NOT_FOUND:
            raise NotFoundError("API token not found.")

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

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class IssuedInvitation:
    """The created invitation plus its raw token — the token exists only here and in the
    email, never in a response body or a log."""

    invitation: Invitation
    raw_token: str


class InvitationService:
    """Create, list, and cancel invitations for one Workspace (ADR-0017).

    Framework-free like its siblings. It owns invitation *policy* — role validity, token
    generation, expiry, and handing the message to the email sender — while the repository
    owns persistence and the UnitOfWork owns the transaction. It never sees an HTTP request.
    """

    def __init__(self, repository: InvitationRepository, email_sender: EmailSender) -> None:
        self._repository = repository
        self._email_sender = email_sender

    async def invite(
        self, *, email: str, role: str, invited_by: uuid.UUID | None
    ) -> IssuedInvitation:
        """Mint a pending invitation and deliver it, or fail without persisting either.

        The token is generated here, stored only as its hash, and delivered by email inside
        the request's transaction: if delivery fails, the exception rolls the whole request
        back and no dangling, undeliverable invitation is left behind. The role is validated
        against the canonical domain (the same `_require_valid_role` every write uses).

        The email is normalized (stripped, lower-cased) HERE, not only in the request
        schema, so the stored value matches the normalized verified email the acceptance
        path compares against — regardless of how the service is reached. The pending-email
        unique index keys on `lower(invited_email)`, so this also keeps that invariant
        honest for a caller that bypasses the schema.
        """
        now = datetime.now(UTC)
        raw_token = generate_invitation_token()
        invitation = await self._repository.create(
            invited_email=email.strip().lower(),
            role=_require_valid_role(role),
            token_hash=hash_token(raw_token),
            expires_at=now + timedelta(days=settings.invitation_expiry_days),
            invited_by=invited_by,
        )
        await self._deliver(invitation.invited_email, raw_token)
        return IssuedInvitation(invitation=invitation, raw_token=raw_token)

    async def _deliver(self, email: str, raw_token: str) -> None:
        """Send the invite email. The URL and token appear only in the message, never a log."""
        accept_url = f"{settings.next_public_app_url}/accept-invite?token={raw_token}"
        await self._email_sender.send(
            EmailMessage(
                to=email,
                subject="You've been invited to a workspace on OmniAI Connect",
                html=(
                    "<p>You've been invited to join a workspace on OmniAI Connect.</p>"
                    f'<p><a href="{accept_url}">Accept the invitation</a></p>'
                    "<p>This link expires in "
                    f"{settings.invitation_expiry_days} days and can be used once.</p>"
                ),
            )
        )

    async def list_pending(self) -> list[Invitation]:
        return await self._repository.list_pending()

    async def cancel(self, invitation_id: uuid.UUID) -> None:
        """Cancel a pending invitation. `NotFoundError` if absent, foreign, or not pending.

        Workspace-scoped in the repository, so a foreign invitation id is simply not found —
        the 404 an unauthorized cancellation and a genuinely-absent one share, no oracle.
        """
        if not await self._repository.cancel(invitation_id):
            raise NotFoundError("Invitation not found.")
