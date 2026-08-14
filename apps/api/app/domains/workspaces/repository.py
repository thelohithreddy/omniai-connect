"""Data access for the workspaces domain. The only layer that touches the DB.

Every repository takes a `WorkspaceContext` in its constructor. That is the point: there
is no way to build one without a tenant, so "I forgot the WHERE clause" is not a mistake
this code can express (P-14). RLS is the second net, not the first.
"""

from __future__ import annotations

import uuid

from sqlalchemy import delete, select, tuple_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictError
from app.core.pagination import CursorPosition
from app.core.security import WorkspaceContext
from app.domains.workspaces.models import ApiToken, Member, Workspace


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
