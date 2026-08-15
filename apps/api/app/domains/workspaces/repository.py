"""Data access for the workspaces domain. The only layer that touches the DB.

Every repository takes a `WorkspaceContext` in its constructor. That is the point: there
is no way to build one without a tenant, so "I forgot the WHERE clause" is not a mistake
this code can express (P-14). RLS is the second net, not the first.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from sqlalchemy import delete, func, select, text, tuple_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictError
from app.core.pagination import CursorPosition
from app.core.security import WorkspaceContext
from app.domains.workspaces.models import ApiToken, Invitation, Member, Workspace


class RevocationOutcome(StrEnum):
    """What a revocation attempt actually did.

    Three outcomes rather than a boolean, because the HTTP layer must distinguish
    idempotent success from a token that is not the caller's. A boolean would force the
    service to guess, and the natural guess — "False means not found" — would turn a second
    revocation into a 404 and break the idempotency API_GUIDELINES.md §2 requires.
    """

    REVOKED = "revoked"
    ALREADY_REVOKED = "already_revoked"
    NOT_FOUND = "not_found"


class WorkspaceRepository:
    def __init__(self, session: AsyncSession, ctx: WorkspaceContext) -> None:
        self._session = session
        self._ctx = ctx

    async def get_current(self) -> Workspace | None:
        """The caller's own Workspace.

        Filtered on `id` explicitly even though RLS also constrains it — the application
        scoping is the primary control and must stand on its own if RLS is ever misapplied
        (DATABASE_DESIGN.md §6: RLS is defense-in-depth, not the mechanism).
        """
        stmt = select(Workspace).where(Workspace.id == self._ctx.workspace_id)
        # Annotated because AsyncSession.scalar() is typed as returning Any; under mypy
        # strict an unannotated return would silently widen the domain's contract.
        workspace: Workspace | None = await self._session.scalar(stmt)
        return workspace


class ApiTokenRepository:
    def __init__(self, session: AsyncSession, ctx: WorkspaceContext) -> None:
        self._session = session
        self._ctx = ctx

    async def list_for_workspace(self) -> list[ApiToken]:
        stmt = (
            select(ApiToken)
            .where(ApiToken.workspace_id == self._ctx.workspace_id)
            .order_by(ApiToken.created_at.desc())
        )
        return list((await self._session.scalars(stmt)).all())

    async def list_page(self, *, limit: int, after: CursorPosition | None = None) -> list[ApiToken]:
        """One page of this Workspace's tokens, newest first.

        `workspace_id` is taken from the context and is not a parameter — there is no
        argument here through which a caller could name another tenant, which is the same
        guarantee `create` provides for writes.

        **Ordering is `(created_at DESC, id DESC)`, and the second key is not decorative.**
        `created_at` alone is not unique: two tokens minted in the same microsecond tie,
        and a keyset predicate over a non-unique key either skips rows or serves one
        forever. `id` is UUIDv7, so ordering by it agrees with creation order rather than
        scrambling tied rows, and the pair is unique because `id` is the primary key.

        The keyset predicate is written as a row comparison — `(created_at, id) < (…, …)`
        — rather than the expanded `created_at < x OR (created_at = x AND id < y)`. Both
        are correct; the row form is what Postgres can satisfy as a single index range
        scan on `ix_api_tokens_workspace_id_created_at` instead of evaluating a disjunction.

        Returns at most `limit` rows and knows nothing about pages: deciding whether more
        exist is the service's job, because it requires fetching one extra row and that is
        a pagination decision, not a persistence one.
        """
        stmt = select(ApiToken).where(ApiToken.workspace_id == self._ctx.workspace_id)
        if after is not None:
            stmt = stmt.where(
                tuple_(ApiToken.created_at, ApiToken.id) < (after.created_at, after.id)
            )
        stmt = stmt.order_by(ApiToken.created_at.desc(), ApiToken.id.desc()).limit(limit)
        return list((await self._session.scalars(stmt)).all())

    async def get(self, token_id: uuid.UUID) -> ApiToken | None:
        stmt = select(ApiToken).where(
            ApiToken.id == token_id,
            ApiToken.workspace_id == self._ctx.workspace_id,
        )
        token: ApiToken | None = await self._session.scalar(stmt)
        return token

    async def revoke(self, token_id: uuid.UUID) -> RevocationOutcome:
        """Mark one of this Workspace's tokens revoked. Reports what actually happened.

        Revocation is a **state transition, not a row deletion**: the row is retained with
        `revoked_at` set (DATABASE_DESIGN.md §3). The credential stops working —
        `auth.resolve_api_token`'s caller rejects a revoked row — while the record of it
        having existed survives, which is what makes an audit trail possible after an
        incident. (The line in DATABASE_DESIGN.md §3 that says "revocation deletes the row"
        governs `credentials`, a different table with different requirements.)

        **`WHERE revoked_at IS NULL` is what makes this concurrency-safe.** Two requests
        revoking the same token both reach the UPDATE; Postgres serialises them on the row
        lock, and the second re-evaluates the predicate after the first commits, matches
        nothing, and leaves the original `revoked_at` intact. Without that predicate the
        second would overwrite the timestamp, and the audit record would say the token was
        revoked at the moment of the *retry* rather than of the incident.

        `updated_at` is set explicitly because this is a Core UPDATE: `TimestampMixin`
        declares `onupdate` client-side (app/shared/models.py), so it only fires through the
        ORM flush path and a Core statement would silently leave the column stale.

        The follow-up SELECT is what separates "already revoked" from "not yours". Both
        cases produce zero updated rows, and collapsing them would make repeated revocation
        indistinguishable from targeting another tenant's token — one is a 204, the other a
        404, and confusing them either breaks idempotency or turns this endpoint into an
        existence oracle.
        """
        revoked = await self._session.scalar(
            update(ApiToken)
            .where(
                ApiToken.id == token_id,
                ApiToken.workspace_id == self._ctx.workspace_id,
                ApiToken.revoked_at.is_(None),
            )
            .values(revoked_at=func.now(), updated_at=func.now())
            .returning(ApiToken.id)
        )
        if revoked is not None:
            return RevocationOutcome.REVOKED

        # Zero rows updated: either the token is already revoked, or it is not this
        # Workspace's to revoke. The distinction is scoped exactly like every other read
        # here, so a token belonging to another tenant is simply invisible.
        exists = await self._session.scalar(
            select(ApiToken.id).where(
                ApiToken.id == token_id,
                ApiToken.workspace_id == self._ctx.workspace_id,
            )
        )
        return (
            RevocationOutcome.ALREADY_REVOKED if exists is not None else RevocationOutcome.NOT_FOUND
        )

    async def create(
        self,
        *,
        name: str,
        token_hash: str,
        token_prefix: str,
        created_by_member_id: uuid.UUID | None = None,
    ) -> ApiToken:
        """Persist a token's hash and metadata into the current Workspace.

        Takes `token_hash`, never the plaintext — the secret is generated and hashed one
        layer up and this method has no parameter that could accept it, so there is no
        path by which persistence code could store a usable credential.

        `workspace_id` is taken from the context and is not a parameter, exactly as
        `MemberRepository.create` works: a caller cannot supply a foreign tenant because
        there is nowhere to put one.
        """
        token = ApiToken(
            workspace_id=self._ctx.workspace_id,
            name=name,
            token_hash=token_hash,
            token_prefix=token_prefix,
            created_by_member_id=created_by_member_id,
        )
        self._session.add(token)
        await self._session.flush()
        return token


class MemberRepository:
    """Data access for Members, scoped to one Workspace by construction.

    `ctx` is a required positional argument, so `MemberRepository(session)` is a
    `TypeError` — an unscoped instance is not merely discouraged, it cannot be built.
    Every method then filters on `workspace_id` explicitly even though RLS enforces the
    same boundary in the database: application scoping is the primary control and has to
    stand on its own if a policy is ever misapplied (DATABASE_DESIGN.md §6, P-14).

    Note what this class deliberately does **not** contain: no role authorization, no
    "a workspace must keep one owner" rule, no invitation policy. Those are service-layer
    concerns (M1.2-C/D). The only question answered here is "how do I safely persist and
    retrieve members *for this workspace*".

    Transactions belong to the UnitOfWork (BACKEND_SPEC.md §3). Nothing here commits.
    Writes `flush()` — which pushes SQL inside the caller's open transaction and is not a
    commit — so server defaults and constraint violations surface at the call site rather
    than at an unrelated commit boundary much later.
    """

    def __init__(self, session: AsyncSession, ctx: WorkspaceContext) -> None:
        self._session = session
        self._ctx = ctx

    # ---------------------------------------------------------------- reads

    async def get(self, member_id: uuid.UUID) -> Member | None:
        """One Member by its id, within the current Workspace.

        The `workspace_id` predicate is not redundant just because `member_id` is a UUID
        and globally unique: dropping it would turn a leaked or guessed id into a
        cross-tenant read the moment RLS were misconfigured.
        """
        stmt = select(Member).where(
            Member.id == member_id,
            Member.workspace_id == self._ctx.workspace_id,
        )
        member: Member | None = await self._session.scalar(stmt)
        return member

    async def get_by_user_id(self, user_id: str) -> Member | None:
        """The current Workspace's membership for a given user.

        `user_id` is a Better Auth subject and is emphatically **not** globally unique
        across workspaces — the same human is expected to belong to several. The lookup is
        therefore keyed on `(workspace_id, user_id)`, matching both the canonical
        uniqueness boundary and the unique index that serves it.
        """
        stmt = select(Member).where(
            Member.workspace_id == self._ctx.workspace_id,
            Member.user_id == user_id,
        )
        member: Member | None = await self._session.scalar(stmt)
        return member

    async def list_page(self, *, limit: int, after: CursorPosition | None = None) -> list[Member]:
        """One page of this Workspace's Members, newest first.

        Added rather than paginating `list_for_workspace`, which stays exactly as M1.2-B
        shipped it: that method is unpaginated and ascending, other code depends on it, and
        API_GUIDELINES.md §3 governs *endpoints*, not every internal read.

        Ordered `(created_at DESC, id DESC)` per §4's default sort, with `id` as the
        tiebreak because a keyset predicate over a non-unique key skips or repeats rows —
        two members added in the same microsecond would tie. `id` is UUIDv7, so it orders in
        agreement with creation time, and `(workspace_id, id)` is already unique.

        `ix_members_workspace_id` narrows to the tenant; no `(workspace_id, created_at)`
        composite is added because members-per-workspace is bounded by team size, and an
        index chosen for a table that will hold tens of rows is speculative (P-44 is
        satisfied by the existing workspace-leading index).
        """
        stmt = select(Member).where(Member.workspace_id == self._ctx.workspace_id)
        if after is not None:
            stmt = stmt.where(tuple_(Member.created_at, Member.id) < (after.created_at, after.id))
        stmt = stmt.order_by(Member.created_at.desc(), Member.id.desc()).limit(limit)
        return list((await self._session.scalars(stmt)).all())

    async def list_for_workspace(self) -> list[Member]:
        """Every Member of the current Workspace.

        There is deliberately no `list_all()` spanning workspaces. A cross-workspace
        administrative read is a separate architectural decision requiring its own
        exemption (ADR-0008 governs how those are granted), not a flag on this method.
        """
        stmt = (
            select(Member)
            .where(Member.workspace_id == self._ctx.workspace_id)
            .order_by(Member.created_at.asc())
        )
        return list((await self._session.scalars(stmt)).all())

    # ---------------------------------------------------------------- writes

    async def create(
        self,
        *,
        user_id: str,
        role: str,
        invited_by: uuid.UUID | None = None,
    ) -> Member:
        """Add a Member to the current Workspace.

        `workspace_id` is taken from the context and is **not** a parameter. That is the
        whole design: a caller cannot supply a foreign tenant id because there is nowhere
        to put one. Role validity is enforced by the database CHECK constraint; deciding
        *who may assign which role* is authorization and belongs to M1.2-D.
        """
        member = Member(
            workspace_id=self._ctx.workspace_id,
            user_id=user_id,
            role=role,
            invited_by=invited_by,
        )
        self._session.add(member)
        try:
            await self._session.flush()
        except IntegrityError as err:
            # Translate only the one violation a well-behaved caller can trip, so the
            # service layer never has to import SQLAlchemy to interpret it (BACKEND_SPEC
            # §6). Everything else propagates untouched rather than being flattened into
            # a misleading domain error.
            if _is_duplicate_membership(err):
                raise ConflictError(
                    "That user is already a member of this workspace.",
                    details={"user_id": user_id},
                ) from err
            raise
        return member

    async def update_role(self, member_id: uuid.UUID, role: str) -> Member | None:
        """Change a Member's role. Returns None if the Member is not in this Workspace.

        Reads through `get()` first, so the workspace predicate applies to the write as
        well, and mutates the ORM object rather than issuing a Core `UPDATE` — the
        `updated_at` `onupdate` on TimestampMixin only fires through the ORM path.
        """
        member = await self.get(member_id)
        if member is None:
            return None
        member.role = role
        await self._session.flush()
        return member

    async def delete(self, member_id: uuid.UUID) -> bool:
        """Remove a Member from the current Workspace. Returns whether a row was removed.

        A single scoped `DELETE`; the workspace predicate is part of the statement, so a
        member belonging to another tenant matches nothing rather than being fetched and
        then rejected.

        Uses `RETURNING` rather than `rowcount`: it stays one round trip, and `rowcount`
        lives on `CursorResult` while `session.execute()` is typed as returning the
        generic `Result` — reading it would need a cast that asserts something mypy
        cannot check.
        """
        stmt = (
            delete(Member)
            .where(
                Member.id == member_id,
                Member.workspace_id == self._ctx.workspace_id,
            )
            .returning(Member.id)
        )
        deleted_id: uuid.UUID | None = await self._session.scalar(stmt)
        return deleted_id is not None


def _is_duplicate_membership(err: IntegrityError) -> bool:
    """True when the error is the `(workspace_id, user_id)` unique violation.

    Matched on the constraint name rather than on message text, which is locale- and
    version-dependent.
    """
    return "uq_members_workspace_id_user_id" in str(getattr(err, "orig", err))


# The bootstrap resolver for invitation acceptance (ADR-0017 §6). An accepting user is not
# yet a member of the invitation's workspace, so the token lookup that DISCOVERS the
# workspace runs pre-RLS through the SECURITY DEFINER function — the same shape as
# `auth.resolve_api_token` and `auth.resolve_member_workspaces`.
_RESOLVE_INVITATION_SQL = text(
    "SELECT id, workspace_id, invited_email, role, invited_by, status, expires_at "
    "FROM auth.resolve_invitation(:token_hash)"
)


@dataclass(frozen=True, slots=True)
class ResolvedInvitation:
    """An invitation as discovered pre-RLS from its token, before any workspace is bound."""

    id: uuid.UUID
    workspace_id: uuid.UUID
    invited_email: str
    role: str
    invited_by: uuid.UUID | None
    status: str
    expires_at: datetime


class InvitationRepository:
    """Data access for Invitations, scoped to one Workspace by construction (ADR-0017).

    Scoped exactly like `MemberRepository`: `ctx` is required, every method filters on
    `workspace_id`, and RLS is the second net. Acceptance is different — the accepting user
    has no workspace yet — so token resolution is the one unscoped, pre-RLS operation and is
    a static method backed by the SECURITY DEFINER function. Transactions belong to the
    UnitOfWork; nothing here commits.
    """

    def __init__(self, session: AsyncSession, ctx: WorkspaceContext) -> None:
        self._session = session
        self._ctx = ctx

    @staticmethod
    async def resolve(session: AsyncSession, token_hash: str) -> ResolvedInvitation | None:
        """Discover an invitation by its token hash, pre-RLS. Never trusts the raw token."""
        row = (await session.execute(_RESOLVE_INVITATION_SQL, {"token_hash": token_hash})).first()
        if row is None:
            return None
        return ResolvedInvitation(
            id=row.id,
            workspace_id=row.workspace_id,
            invited_email=row.invited_email,
            role=row.role,
            invited_by=row.invited_by,
            status=row.status,
            expires_at=row.expires_at,
        )

    async def create(
        self,
        *,
        invited_email: str,
        role: str,
        token_hash: str,
        expires_at: datetime,
        invited_by: uuid.UUID | None,
    ) -> Invitation:
        """Persist a pending invitation into the current Workspace.

        `workspace_id` comes from the context, never a parameter. The partial unique index
        on `(workspace_id, lower(invited_email)) WHERE status='pending'` is the invariant
        that stops two live invitations for the same person; a violation surfaces here as a
        `ConflictError` so the service never interprets SQLAlchemy.
        """
        invitation = Invitation(
            workspace_id=self._ctx.workspace_id,
            invited_email=invited_email,
            role=role,
            token_hash=token_hash,
            expires_at=expires_at,
            invited_by=invited_by,
            status="pending",
        )
        self._session.add(invitation)
        try:
            await self._session.flush()
        except IntegrityError as err:
            if "uq_invitations_pending_email" in str(getattr(err, "orig", err)):
                raise ConflictError(
                    "A pending invitation already exists for that email in this workspace.",
                    details={"invited_email": invited_email},
                ) from err
            raise
        return invitation

    async def list_pending(self) -> list[Invitation]:
        """Every pending invitation for this Workspace, newest first."""
        stmt = (
            select(Invitation)
            .where(
                Invitation.workspace_id == self._ctx.workspace_id,
                Invitation.status == "pending",
            )
            .order_by(Invitation.created_at.desc(), Invitation.id.desc())
        )
        return list((await self._session.scalars(stmt)).all())

    async def consume(self, invitation_id: uuid.UUID) -> bool:
        """Atomically mark a pending invitation accepted. False if it was not pending.

        The `status = 'pending'` guard in the WHERE clause is the single-use arbiter: under
        two concurrent acceptances the row lock serializes the updates, so exactly one sees
        `pending` and consumes it; the other updates zero rows and is rejected. No
        application lock is involved (ADR-0017 §5).
        """
        stmt = (
            update(Invitation)
            .where(
                Invitation.id == invitation_id,
                Invitation.workspace_id == self._ctx.workspace_id,
                Invitation.status == "pending",
            )
            .values(status="accepted", accepted_at=func.now())
            .returning(Invitation.id)
        )
        return (await self._session.scalar(stmt)) is not None

    async def cancel(self, invitation_id: uuid.UUID) -> bool:
        """Cancel a pending invitation. False if absent, foreign, or not pending.

        A cancelled invitation can never be accepted (its status is no longer `pending`, so
        `consume` fails). Workspace-scoped, so a foreign invitation id simply is not found.
        """
        stmt = (
            update(Invitation)
            .where(
                Invitation.id == invitation_id,
                Invitation.workspace_id == self._ctx.workspace_id,
                Invitation.status == "pending",
            )
            .values(status="cancelled", cancelled_at=func.now())
            .returning(Invitation.id)
        )
        return (await self._session.scalar(stmt)) is not None
