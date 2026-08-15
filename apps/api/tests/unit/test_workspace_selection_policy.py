"""The workspace-selection policy as a pure function (M1.3-C, ADR-0016 §3).

`_select_membership` decides, with no IO, which workspace a human request binds given the
requested id and the subject's own membership map. Testing it directly is the
**RLS-independent** isolation proof the module requires: it shows the *application* refuses
a foreign selection before any database policy is consulted, so a green result here cannot
be an artifact of RLS quietly blocking the row. Every deny path must collapse to the same
`(None, None)` sentinel, which the caller maps to the single uniform 401.
"""

from __future__ import annotations

import uuid

from app.core.security import _select_membership

WS_A = uuid.UUID("00000000-0000-0000-0000-00000000000a")
WS_B = uuid.UUID("00000000-0000-0000-0000-00000000000b")
WS_FOREIGN = uuid.UUID("00000000-0000-0000-0000-0000000000ff")
MEM_A = uuid.UUID("00000000-0000-0000-0000-00000000aa0a")
MEM_B = uuid.UUID("00000000-0000-0000-0000-00000000aa0b")


def test_single_membership_no_selector_auto_binds() -> None:
    """Case B: exactly one membership, no header → bind it (M1.3-B behavior preserved)."""
    assert _select_membership(None, {WS_A: MEM_A}) == (MEM_A, WS_A)


def test_single_membership_matching_selector_binds() -> None:
    assert _select_membership(WS_A, {WS_A: MEM_A}) == (MEM_A, WS_A)


def test_single_membership_foreign_selector_fails_closed() -> None:
    """A single-membership human who selects a workspace they are not in → deny.

    This is the M1.3-B→M1.3-C change made unambiguous: the header is verified, not ignored.
    """
    assert _select_membership(WS_FOREIGN, {WS_A: MEM_A}) == (None, None)


def test_multi_membership_no_selector_fails_closed() -> None:
    """Case C without a header → deny. The server never picks one for the caller."""
    assert _select_membership(None, {WS_A: MEM_A, WS_B: MEM_B}) == (None, None)


def test_multi_membership_selects_exactly_the_named_workspace() -> None:
    """The header disambiguates, and it maps to that workspace's OWN member row."""
    memberships = {WS_A: MEM_A, WS_B: MEM_B}
    assert _select_membership(WS_A, memberships) == (MEM_A, WS_A)
    assert _select_membership(WS_B, memberships) == (MEM_B, WS_B)


def test_multi_membership_foreign_selector_fails_closed() -> None:
    assert _select_membership(WS_FOREIGN, {WS_A: MEM_A, WS_B: MEM_B}) == (None, None)


def test_zero_membership_always_fails_closed() -> None:
    """Case A: no memberships → deny, with or without a selector. Never auto-create."""
    assert _select_membership(None, {}) == (None, None)
    assert _select_membership(WS_A, {}) == (None, None)


def test_the_bound_member_id_always_matches_the_bound_workspace() -> None:
    """The member_id returned is never another workspace's member row.

    A user has one member row per workspace (unique(workspace_id, user_id)), so binding
    workspace X must bind member row X — never B's member id with A's workspace, which
    would be a cross-membership confusion.
    """
    memberships = {WS_A: MEM_A, WS_B: MEM_B}
    member_id, workspace_id = _select_membership(WS_B, memberships)
    assert (member_id, workspace_id) == (MEM_B, WS_B)
    assert member_id != MEM_A


def test_selection_is_deterministic_and_never_arbitrary() -> None:
    """No first/last/newest heuristic: an unmatched selector is always deny, never a
    fallback to some element of the map."""
    memberships = {WS_A: MEM_A, WS_B: MEM_B}
    for _ in range(5):
        assert _select_membership(WS_FOREIGN, memberships) == (None, None)
        assert _select_membership(None, memberships) == (None, None)
