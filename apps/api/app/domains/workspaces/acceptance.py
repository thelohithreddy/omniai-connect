"""Invitation acceptance — a bootstrap flow that establishes a membership (ADR-0017 §8).

Deliberately separate from `service.py`, which is framework- and infrastructure-free (it
reaches the database only through repositories). Acceptance is different: an accepting human
is not yet a member of the invitation's workspace, so it cannot go through a
`require_permission`/`CurrentWorkspace` pipeline — the invitation, resolved from its token,
*is* what establishes the workspace. It therefore holds the `UnitOfWork` directly and binds
tenant context itself, exactly like `get_workspace_context`'s token resolution. Keeping it
here preserves service.py's "no session layer" invariant.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import NoReturn

import structlog

from app.core.db import UnitOfWork
from app.core.exceptions import NotFoundError
from app.core.human_auth import HumanIdentity
from app.core.security import CallerIdentity, WorkspaceContext, hash_token
from app.domains.workspaces.repository import (
    InvitationRepository,
    MemberRepository,
    ResolvedInvitation,
)

log = structlog.get_logger(__name__)

# One uniform failure for every unacceptable invitation (ADR-0017 §11). Bad/random token,
# expired, cancelled, already-consumed, wrong email, and unverified email are
# indistinguishable — none reveals whether an invitation exists, for whom, or in which
# workspace. `NotFoundError` maps to 404 with the standard envelope; there is no oracle.
_INVITATION_NOT_ACCEPTABLE = "Invitation not found or not acceptable."


@dataclass(frozen=True, slots=True)
class Acceptance:
    """The outcome of accepting: which workspace the human joined, and as what role."""

    workspace_id: uuid.UUID
    role: str


class InvitationAcceptanceService:
    """Resolve a token, verify the email binding, and atomically establish the membership."""

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def accept(self, *, token: str, identity: HumanIdentity, request_id: str) -> Acceptance:
        resolved = await InvitationRepository.resolve(self._uow.session, hash_token(token))

        # Every rejection below is the SAME uniform failure — no caller can tell a bad token
        # from an expired one, a foreign one, or one addressed to someone else (ADR-0017 §11).
        now = datetime.now(UTC)
        if (
            resolved is None
            or not identity.email_verified
            or identity.email is None
            or identity.email != resolved.invited_email
            or resolved.status != "pending"
            or resolved.expires_at <= now
        ):
            _reject_acceptance(resolved, identity)

        # The invitation is valid and this verified human is its intended recipient. Bind the
        # workspace the invitation established (never a request value) and operate under its
        # RLS. `member_id` is None in the context because the caller is *becoming* a member;
        # the context is a scoping vehicle here, not an authorization subject — acceptance is
        # gated by the email binding above, not by RBAC.
        await self._uow.bind_workspace(resolved.workspace_id)
        ctx = WorkspaceContext(
            workspace_id=resolved.workspace_id,
            caller=CallerIdentity(kind="member", member_id=None),
            request_id=request_id,
        )

        # Consume first, guarded by `status = 'pending'`: if a concurrent acceptance already
        # took it, this updates zero rows and we fail uniformly rather than create a second
        # membership. The row lock serializes the two, so exactly one wins.
        if not await InvitationRepository(self._uow.session, ctx).consume(resolved.id):
            raise NotFoundError(_INVITATION_NOT_ACCEPTABLE)

        # Establish the permanent authority: a membership keyed by the VERIFIED sub, with the
        # invitation's server-set role. Already-member surfaces as the repository's
        # ConflictError (409); the transaction then rolls back, so the invitation is not
        # consumed and the existing membership stays authoritative (ADR-0017 §9).
        await MemberRepository(self._uow.session, ctx).create(
            user_id=identity.sub,
            role=resolved.role,
            invited_by=resolved.invited_by,
        )
        return Acceptance(workspace_id=resolved.workspace_id, role=resolved.role)


def _reject_acceptance(resolved: ResolvedInvitation | None, identity: HumanIdentity) -> NoReturn:
    """Log the *reason* (never the token or the invited email) and raise the uniform 404."""
    if resolved is None:
        reason = "unknown_token"
    elif not identity.email_verified:
        reason = "email_unverified"
    elif identity.email != resolved.invited_email:
        reason = "email_mismatch"
    elif resolved.status != "pending":
        reason = f"status_{resolved.status}"
    else:
        reason = "expired"
    log.debug("invitation.rejected", reason=reason)
    raise NotFoundError(_INVITATION_NOT_ACCEPTABLE)
