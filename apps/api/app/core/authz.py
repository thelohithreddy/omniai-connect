"""Workspace authorization policy: which Role holds which Permission.

This module is **policy**, not enforcement. It answers exactly one question —
`(role, permission) -> allow | deny` — as a pure function over static data. It never
learns who the caller is, which Workspace they are in, or what they are requesting.
Resolving an authenticated request into a Role, and refusing the request when the answer
is deny, is the enforcement layer's job (M1.2-E) and is deliberately absent here.

Keeping the two apart is what makes the policy auditable: the entire security model is
visible in one table in source control, reviewable without running anything, with no
database, cache, network call, or request object involved.

**Canonical source.** The matrix below is a transcription of docs/SECURITY.md §4.1 — one
`Permission` per row of that table, with identical allow/deny values. SECURITY.md is
authoritative; if the two ever disagree, this file is wrong. Adding a capability means
editing the document and this table together, in the same change.

**Deny by default, in three places.** An unmapped Role holds nothing; an unknown
Permission is held by nobody; anything that is not a recognised member of either enum is
refused outright. There is no wildcard, no fallback grant, and no hierarchy that quietly
widens a role when another is edited.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Final


class Role(StrEnum):
    """Membership roles, mirroring the `members.role` CHECK domain (DATABASE_DESIGN.md §3).

    All four values are storable. That is not the same as all four being *defined* —
    see `ROLE_PERMISSIONS` for `VIEWER`.
    """

    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class Permission(StrEnum):
    """Atomic capabilities. One per row of SECURITY.md §4.1, no more and no fewer.

    Four of these govern resources that do not exist yet (Connections, Credentials, Tools,
    the audit log). They are included because SECURITY.md already states their policy —
    transcribing a decision the project has made is not speculation, whereas inventing a
    seventh capability would be. When those resources land, the policy is already written
    and was not improvised under delivery pressure.

    The wording deliberately preserves the canonical bundling: SECURITY.md treats
    "Manage billing, delete Workspace" as a single capability, so it is one Permission
    here. Splitting it would be inventing finer granularity than the project has decided.
    """

    #: "Manage billing, delete Workspace" — the workspace-lifecycle and money capability.
    WORKSPACE_MANAGE = "workspace:manage"
    #: "Manage Members and roles" — add, remove, and re-role members.
    MEMBERS_MANAGE = "members:manage"
    #: "Create/delete Connections, manage Credentials" — custody of customer secrets.
    CONNECTIONS_MANAGE = "connections:manage"
    #: "Create/revoke workspace API tokens" — machine identity administration.
    API_TOKENS_MANAGE = "api_tokens:manage"
    #: "Execute Tool Calls, view Tools and own logs" — ordinary product use.
    TOOLS_EXECUTE = "tools:execute"
    #: "View full audit log" — every member's activity, not just one's own.
    AUDIT_READ = "audit:read"


# ---------------------------------------------------------------------------------------
# The matrix. Transcribed row by row from docs/SECURITY.md §4.1.
#
#   Capability                                     | owner | admin | member |
#   Manage billing, delete Workspace               |   ✅  |   ❌  |   ❌   |
#   Manage Members and roles                       |   ✅  |   ✅  |   ❌   |
#   Create/delete Connections, manage Credentials  |   ✅  |   ✅  |   ❌   |
#   Create/revoke workspace API tokens             |   ✅  |   ✅  |   ❌   |
#   Execute Tool Calls, view Tools and own logs    |   ✅  |   ✅  |   ✅   |
#   View full audit log                            |   ✅  |   ✅  |   ❌   |
#
# Written out per role rather than derived by inheritance. `ADMIN` is *not* expressed as
# "OWNER minus workspace:manage": that shape means a capability added to OWNER silently
# lands on ADMIN too, and the reviewer of that future diff would see one line change while
# two roles gained power. Enumerating each set costs a few lines and makes every grant
# visible at the point it is granted.
# ---------------------------------------------------------------------------------------

ROLE_PERMISSIONS: Final[Mapping[Role, frozenset[Permission]]] = MappingProxyType(
    {
        Role.OWNER: frozenset(
            {
                Permission.WORKSPACE_MANAGE,
                Permission.MEMBERS_MANAGE,
                Permission.CONNECTIONS_MANAGE,
                Permission.API_TOKENS_MANAGE,
                Permission.TOOLS_EXECUTE,
                Permission.AUDIT_READ,
            }
        ),
        Role.ADMIN: frozenset(
            {
                Permission.MEMBERS_MANAGE,
                Permission.CONNECTIONS_MANAGE,
                Permission.API_TOKENS_MANAGE,
                Permission.TOOLS_EXECUTE,
                Permission.AUDIT_READ,
            }
        ),
        Role.MEMBER: frozenset({Permission.TOOLS_EXECUTE}),
        # VIEWER holds nothing, and that is a finding rather than a design.
        #
        # `viewer` is storable — DATABASE_DESIGN.md §3 puts it in the CHECK domain — but it
        # appears in no capability table anywhere in the repository. SECURITY.md §4.1 has
        # columns for owner/admin/member only, and PRD.md FR-CP-1 likewise lists three
        # roles. There is no canonical statement of what a viewer may do.
        #
        # Granting it "read everything" would be inventing policy, and read access to the
        # audit log or to Tool Calls is exactly the kind of grant that should be decided
        # deliberately rather than inferred from a role's name. An empty set is the only
        # option consistent with deny-by-default, so a `viewer` is currently a member who
        # can do nothing.
        #
        # Recorded as an open architectural decision: SECURITY.md §4.1 needs a `viewer`
        # column, or the role needs removing from the domain. Both are canonical-document
        # changes, not implementation choices.
        Role.VIEWER: frozenset(),
    }
)


def permissions_for(role: object) -> frozenset[Permission]:
    """Every Permission held by `role`; empty for anything unrecognised.

    Accepts `object` rather than `Role` on purpose. Static typing protects code that is
    type-checked, and this is the last line of defence for code that is not — a role
    string read from the database, decoded from a token, or supplied by a caller who
    should not have been trusted. An unmapped or malformed value yields no permissions
    instead of raising, so a policy check can never be turned into a denial-of-service by
    feeding it a bad role.
    """
    # Non-strings are refused before the enum lookup rather than relying on it to raise.
    # `Role` subclasses `str`, so genuine members pass straight through; `None`, integers,
    # and `True` do not. Being explicit also keeps the function honest under strict typing
    # instead of casting `object` to `str` and asserting something untrue.
    if not isinstance(role, str):
        return frozenset()
    try:
        resolved = Role(role)
    except ValueError:
        return frozenset()
    return ROLE_PERMISSIONS.get(resolved, frozenset())


def is_allowed(role: object, permission: object) -> bool:
    """Whether `role` holds `permission`. The whole policy decision.

    Deny is the answer for every question this module cannot answer with certainty: an
    unknown role, an unknown permission, a role with no mapping, `None`, or a value of the
    wrong type. There is no input for which this returns `True` by default.

    Note that an unknown *permission* is denied to every role including OWNER. SECURITY.md
    §4.1's "an unlisted capability requires owner" is authoring guidance — the default
    column values to choose when adding a capability to the table — not a runtime
    fallback. Treating it as a runtime rule would mean a typo in a permission name
    silently grants an owner access to something nobody defined, which is precisely the
    class of bug deny-by-default exists to prevent.
    """
    if not isinstance(permission, str):
        return False
    try:
        resolved_permission = Permission(permission)
    except ValueError:
        return False
    return resolved_permission in permissions_for(role)


__all__ = ["ROLE_PERMISSIONS", "Permission", "Role", "is_allowed", "permissions_for"]
