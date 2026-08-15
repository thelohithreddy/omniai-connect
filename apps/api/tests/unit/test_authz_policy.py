"""Workspace RBAC policy: the complete role × permission matrix, proved exhaustively.

Security policy is not a place for representative sampling. Every one of the 4 roles × 6
permissions = 24 combinations is asserted individually against a table transcribed here
independently of the implementation, so a single flipped grant fails a named test rather
than hiding inside a set comparison.

The expectations below are written from docs/SECURITY.md §4.1 directly. They are
deliberately *not* derived from `ROLE_PERMISSIONS` — a test that reads its expectations
out of the code under test proves only that the code equals itself.
"""

from __future__ import annotations

import ast
import inspect

import pytest

from app.core.authz import (
    ROLE_PERMISSIONS,
    Permission,
    Role,
    is_allowed,
    permissions_for,
)

# ---------------------------------------------------------------------------------------
# The matrix, transcribed by hand from docs/SECURITY.md §4.1.
#
#   Capability                                     | owner | admin | member | viewer
#   Manage billing, delete Workspace               |  yes  |  no   |  no    |  no
#   Manage Members and roles                       |  yes  |  yes  |  no    |  no
#   Create/configure/delete Connectors             |  yes  |  yes  |  no    |  no
#   Create/delete Connections, manage Credentials  |  yes  |  yes  |  no    |  no
#   Create/revoke workspace API tokens             |  yes  |  yes  |  no    |  no
#   Execute Tool Calls, view Tools and own logs    |  yes  |  yes  |  yes   |  no
#   View full audit log                            |  yes  |  yes  |  no    |  no
#
# `viewer` is `no` throughout because no canonical document grants it anything — see the
# comment on Role.VIEWER in app/core/authz.py.
# ---------------------------------------------------------------------------------------

EXPECTED: dict[tuple[Role, Permission], bool] = {
    (Role.OWNER, Permission.WORKSPACE_MANAGE): True,
    (Role.OWNER, Permission.MEMBERS_MANAGE): True,
    (Role.OWNER, Permission.CONNECTORS_MANAGE): True,
    (Role.OWNER, Permission.CONNECTIONS_MANAGE): True,
    (Role.OWNER, Permission.API_TOKENS_MANAGE): True,
    (Role.OWNER, Permission.TOOLS_EXECUTE): True,
    (Role.OWNER, Permission.AUDIT_READ): True,
    (Role.ADMIN, Permission.WORKSPACE_MANAGE): False,
    (Role.ADMIN, Permission.MEMBERS_MANAGE): True,
    (Role.ADMIN, Permission.CONNECTORS_MANAGE): True,
    (Role.ADMIN, Permission.CONNECTIONS_MANAGE): True,
    (Role.ADMIN, Permission.API_TOKENS_MANAGE): True,
    (Role.ADMIN, Permission.TOOLS_EXECUTE): True,
    (Role.ADMIN, Permission.AUDIT_READ): True,
    (Role.MEMBER, Permission.WORKSPACE_MANAGE): False,
    (Role.MEMBER, Permission.MEMBERS_MANAGE): False,
    (Role.MEMBER, Permission.CONNECTORS_MANAGE): False,
    (Role.MEMBER, Permission.CONNECTIONS_MANAGE): False,
    (Role.MEMBER, Permission.API_TOKENS_MANAGE): False,
    (Role.MEMBER, Permission.TOOLS_EXECUTE): True,
    (Role.MEMBER, Permission.AUDIT_READ): False,
    (Role.VIEWER, Permission.WORKSPACE_MANAGE): False,
    (Role.VIEWER, Permission.MEMBERS_MANAGE): False,
    (Role.VIEWER, Permission.CONNECTORS_MANAGE): False,
    (Role.VIEWER, Permission.CONNECTIONS_MANAGE): False,
    (Role.VIEWER, Permission.API_TOKENS_MANAGE): False,
    (Role.VIEWER, Permission.TOOLS_EXECUTE): False,
    (Role.VIEWER, Permission.AUDIT_READ): False,
}


# --------------------------------------------------------------------------- A/B/C. matrix


def test_the_expectation_table_is_complete() -> None:
    """Guards the guard: every combination must be stated, or coverage silently shrinks."""
    assert len(EXPECTED) == len(Role) * len(Permission) == 28
    assert set(EXPECTED) == {(r, p) for r in Role for p in Permission}


@pytest.mark.parametrize(
    ("role", "permission", "expected"),
    [(r, p, EXPECTED[(r, p)]) for r in Role for p in Permission],
    ids=[
        f"{r.value}-{p.value}-{'allow' if EXPECTED[(r, p)] else 'deny'}"
        for r in Role
        for p in Permission
    ],
)
def test_every_role_permission_combination(
    role: Role, permission: Permission, expected: bool
) -> None:
    assert is_allowed(role, permission) is expected


@pytest.mark.parametrize("role", list(Role))
def test_permissions_for_matches_the_matrix(role: Role) -> None:
    assert permissions_for(role) == {p for p in Permission if EXPECTED[(role, p)]}


# ----------------------------------------------------------------- privilege boundaries


def test_owner_is_the_only_role_that_can_manage_the_workspace() -> None:
    """Billing and workspace deletion are irreversible; the boundary is owner alone."""
    holders = {r for r in Role if is_allowed(r, Permission.WORKSPACE_MANAGE)}
    assert holders == {Role.OWNER}


def test_owner_admin_boundary_is_exactly_one_permission() -> None:
    """Admin is everything except workspace lifecycle and billing."""
    assert permissions_for(Role.OWNER) - permissions_for(Role.ADMIN) == {
        Permission.WORKSPACE_MANAGE
    }
    assert not permissions_for(Role.ADMIN) - permissions_for(Role.OWNER)


def test_admin_member_boundary_is_administration() -> None:
    """A member participates; it does not administer."""
    assert permissions_for(Role.ADMIN) - permissions_for(Role.MEMBER) == {
        Permission.MEMBERS_MANAGE,
        Permission.CONNECTORS_MANAGE,
        Permission.CONNECTIONS_MANAGE,
        Permission.API_TOKENS_MANAGE,
        Permission.AUDIT_READ,
    }


def test_member_viewer_boundary() -> None:
    assert permissions_for(Role.MEMBER) - permissions_for(Role.VIEWER) == {Permission.TOOLS_EXECUTE}


def test_no_role_below_owner_can_administer_credentials_or_tokens() -> None:
    """Credential custody and machine identity are the two highest-value grants."""
    for permission in (Permission.CONNECTIONS_MANAGE, Permission.API_TOKENS_MANAGE):
        assert not is_allowed(Role.MEMBER, permission)
        assert not is_allowed(Role.VIEWER, permission)


def test_only_administrators_read_the_full_audit_log() -> None:
    """A member sees its *own* logs via tools:execute; the full log is separate."""
    assert {r for r in Role if is_allowed(r, Permission.AUDIT_READ)} == {
        Role.OWNER,
        Role.ADMIN,
    }


# ------------------------------------------------------------- I. viewer, explicitly


def test_viewer_holds_no_permissions() -> None:
    """Not an oversight: no canonical document defines what a viewer may do.

    Deny-by-default is the only answer consistent with the architecture until
    SECURITY.md §4.1 grows a `viewer` column or the role is removed from the domain.
    """
    assert permissions_for(Role.VIEWER) == frozenset()
    for permission in Permission:
        assert is_allowed(Role.VIEWER, permission) is False


def test_viewer_is_still_a_storable_role() -> None:
    """The policy gap must not be 'fixed' by deleting the role from the domain.

    Removing it would be a schema change to an audited module (M1.2-A) made to paper over
    an undocumented policy question.
    """
    from app.domains.workspaces.models import MEMBER_ROLES

    assert "viewer" in MEMBER_ROLES
    assert {r.value for r in Role} == set(MEMBER_ROLES)


# ------------------------------------------------- D/E/F/G/H. unknown and malformed input


@pytest.mark.parametrize(
    "unknown_role",
    [
        "superuser",
        "root",
        "administrator",
        "OWNER",
        "Owner",
        "owner ",
        "",
        "*",
        "all",
        "admin;--",
        None,
        0,
        1,
        True,
        [],
        {},
        object(),
    ],
)
def test_unknown_or_malformed_role_is_denied_everything(unknown_role: object) -> None:
    assert permissions_for(unknown_role) == frozenset()
    for permission in Permission:
        assert is_allowed(unknown_role, permission) is False


@pytest.mark.parametrize(
    "unknown_permission",
    [
        "workspace:delete",
        "members:read",
        "*",
        "all",
        "admin",
        "",
        "WORKSPACE_MANAGE",
        "workspace:manage ",
        None,
        0,
        True,
        [],
        {},
        object(),
    ],
)
def test_unknown_or_malformed_permission_is_denied_to_every_role(
    unknown_permission: object,
) -> None:
    """Including OWNER.

    SECURITY.md's "an unlisted capability requires owner" is guidance for authoring the
    table, not a runtime fallback. Treated as runtime, a typo in a permission name would
    silently grant an owner access to something nobody ever defined.
    """
    for role in Role:
        assert is_allowed(role, unknown_permission) is False


def test_unknown_role_and_unknown_permission_together_deny() -> None:
    assert is_allowed("wizard", "everything:*") is False


def test_no_input_pair_produces_allow_outside_the_matrix() -> None:
    """Property: allow is reachable only for a stated (role, permission) pair."""
    candidates: list[object] = [
        *[r.value for r in Role],
        *[p.value for p in Permission],
        "*",
        "",
        "all",
        "admin",
        None,
        0,
        True,
    ]
    for role in candidates:
        for permission in candidates:
            if is_allowed(role, permission):
                assert (Role(role), Permission(permission)) in EXPECTED
                assert EXPECTED[(Role(role), Permission(permission))] is True


# ------------------------------------------------------------------ O. determinism


def test_policy_is_deterministic() -> None:
    for _ in range(50):
        for role in Role:
            assert permissions_for(role) == permissions_for(role)
            for permission in Permission:
                first = is_allowed(role, permission)
                assert is_allowed(role, permission) is first


def test_policy_mapping_is_immutable() -> None:
    """A mutable policy is a policy that can be widened at runtime."""
    with pytest.raises(TypeError):
        ROLE_PERMISSIONS[Role.VIEWER] = frozenset(Permission)  # type: ignore[index]
    with pytest.raises(AttributeError):
        permissions_for(Role.MEMBER).add(Permission.WORKSPACE_MANAGE)  # type: ignore[attr-defined]


def test_evaluating_the_policy_does_not_mutate_it() -> None:
    before = {r: set(permissions_for(r)) for r in Role}
    for role in Role:
        for permission in Permission:
            is_allowed(role, permission)
    assert {r: set(permissions_for(r)) for r in Role} == before


# ------------------------------------------- N. no external dependencies, no enforcement


def test_policy_module_has_no_external_dependencies() -> None:
    """Pure policy: no database, cache, network, or web framework.

    Checked on the import graph rather than by substring so an aliased import cannot slip
    past, and `ast.walk` also reaches imports deferred inside functions.
    """
    import app.core.authz as authz

    imported: set[str] = set()
    for node in ast.walk(ast.parse(inspect.getsource(authz))):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    banned = {
        "fastapi",
        "starlette",
        "sqlalchemy",
        "asyncpg",
        "redis",
        "httpx",
        "requests",
        "app.core.db",
        "app.core.security",
        "app.core.config",
    }
    offenders = {m for m in imported if m in banned or m.split(".")[0] in banned}
    assert not offenders, f"policy reaches external state: {sorted(offenders)}"


def test_policy_module_implements_no_enforcement() -> None:
    """Enforcement is M1.2-E. Policy must not grow a request-boundary shape."""
    import app.core.authz as authz

    source = inspect.getsource(authz)
    tree = ast.parse(source)
    defined = {
        n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
    }
    for forbidden in ("require_role", "require_permission", "authorize", "check_permission"):
        assert forbidden not in defined, f"enforcement helper defined in policy: {forbidden}"
    assert "Depends" not in source
    assert "PermissionDeniedError" not in source, (
        "policy returns decisions; raising belongs to the enforcement layer"
    )


def test_policy_functions_are_synchronous() -> None:
    """An async policy function implies IO, which this layer must never perform."""
    assert not inspect.iscoroutinefunction(is_allowed)
    assert not inspect.iscoroutinefunction(permissions_for)


# ----------------------------------------------- M. no role self-selection / escalation


def test_policy_never_derives_a_role_from_its_own_arguments() -> None:
    """A caller supplying `role="owner"` must not be how authorization is obtained.

    The policy cannot enforce that on its own — it is handed a role and must evaluate it.
    What it *can* guarantee is that it has no other input channel: two positional
    arguments, no keyword escape hatch, no defaults. Whether the role is trustworthy is
    the enforcement layer's contract (M1.2-E), which will read it from the authenticated
    membership rather than the request body.
    """
    sig = inspect.signature(is_allowed)
    assert list(sig.parameters) == ["role", "permission"]
    assert all(p.default is inspect.Parameter.empty for p in sig.parameters.values())


def test_a_caller_supplied_role_string_still_obeys_the_matrix() -> None:
    """Supplying "owner" as a raw string grants exactly owner's permissions — no more.

    String input is neither privileged nor rejected; it resolves through the same table.
    The trust question lives entirely in *where the string came from*.
    """
    assert permissions_for("owner") == permissions_for(Role.OWNER)
    assert is_allowed("member", "workspace:manage") is False
    assert is_allowed("viewer", "tools:execute") is False


# --------------------------------------------------------- future-proofing invariants


def test_every_permission_is_held_by_at_least_one_role() -> None:
    """A permission nobody holds is dead policy — likely a rename that lost its grants."""
    for permission in Permission:
        assert any(is_allowed(r, permission) for r in Role), f"{permission} is unreachable"


def test_no_role_holds_a_permission_outside_the_enum() -> None:
    for role in Role:
        assert permissions_for(role) <= set(Permission)


def test_every_role_in_the_domain_has_an_explicit_mapping() -> None:
    """A role missing from the table denies everything, which is safe but silent.

    Requiring an entry forces whoever adds a role to make its policy an explicit decision.
    """
    assert set(ROLE_PERMISSIONS) == set(Role)


def test_permission_count_matches_the_canonical_table() -> None:
    """SECURITY.md §4.1 has seven rows (connectors:manage added in M1.4-A, ADR-0019). An
    eighth here means policy was invented."""
    assert len(Permission) == 7
