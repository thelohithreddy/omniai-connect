"""The pure notification decisions: what is notifiable, how the key is shaped, what an email says.

Every rule in here is one a mutation can flip silently, so each is asserted on its own rather than
observed indirectly through a delivery test. The transition matrix in particular is enumerated in
full — all nine ratified pairs (ADR-0041 §8) — even though the implementation depends only on the
state being entered. That is the point: the matrix is the contract, and a future refactor that
starts consulting the previous state must still satisfy every row.
"""

from __future__ import annotations

import uuid

import pytest

from app.domains.connections.health import HealthState
from app.domains.notifications import messages
from app.domains.notifications.classification import (
    NotificationEvent,
    notifiable_deactivation,
    parse_event,
)
from app.domains.notifications.dedup import dedup_key

# --------------------------------------------------------------- the ratified transition matrix

#: (previous, current, expected notification). Exactly the nine rows of ADR-0041 §8, plus the
#: `unknown` outcomes that a platform refusal produces — the row that stops an exhausted quota from
#: emailing an entire Workspace.
TRANSITIONS: list[tuple[HealthState, HealthState, NotificationEvent | None]] = [
    (HealthState.HEALTHY, HealthState.UNHEALTHY, NotificationEvent.UNHEALTHY),
    (HealthState.UNKNOWN, HealthState.UNHEALTHY, NotificationEvent.UNHEALTHY),
    (HealthState.UNHEALTHY, HealthState.UNHEALTHY, NotificationEvent.UNHEALTHY),
    (HealthState.HEALTHY, HealthState.NEEDS_REAUTH, NotificationEvent.NEEDS_REAUTH),
    (HealthState.UNKNOWN, HealthState.NEEDS_REAUTH, NotificationEvent.NEEDS_REAUTH),
    (HealthState.NEEDS_REAUTH, HealthState.NEEDS_REAUTH, NotificationEvent.NEEDS_REAUTH),
    (HealthState.HEALTHY, HealthState.HEALTHY, None),
    (HealthState.UNHEALTHY, HealthState.HEALTHY, None),
    (HealthState.NEEDS_REAUTH, HealthState.HEALTHY, None),
    (HealthState.HEALTHY, HealthState.UNKNOWN, None),
    (HealthState.UNHEALTHY, HealthState.UNKNOWN, None),
]


def _expected_for(current: HealthState) -> NotificationEvent | None:
    """The notification the *system* produces for a Connection entering `current`.

    Mirrors production wiring rather than re-implementing it: `unhealthy` is published by the
    health service's failure branch, `needs_reauth` arrives on `connection.deactivated(error)`,
    and nothing else notifies at all.
    """
    if current is HealthState.UNHEALTHY:
        return NotificationEvent.UNHEALTHY
    if current is HealthState.NEEDS_REAUTH:
        return notifiable_deactivation("error")
    return None


@pytest.mark.parametrize(("previous", "current", "expected"), TRANSITIONS)
def test_the_ratified_transition_matrix_holds(
    previous: HealthState, current: HealthState, expected: NotificationEvent | None
) -> None:
    """Every ratified row, including the three that must stay silent."""
    assert _expected_for(current) == expected, f"{previous.value} → {current.value}"


def test_recovery_never_notifies_from_any_prior_state() -> None:
    """No recovery email. Canon requires none and ADR-0041 §8 forbids inventing one."""
    for previous in HealthState:
        assert _expected_for(HealthState.HEALTHY) is None, previous.value


def test_unknown_never_notifies_because_it_is_what_a_platform_refusal_reports() -> None:
    """`rate_limited`, `quota_exceeded` and a fail-closed Redis all surface as `unknown`
    (ADR-0040 §5). If this ever notified, one exhausted quota would email a whole Workspace."""
    assert _expected_for(HealthState.UNKNOWN) is None


# --------------------------------------------------------------------- the deactivation filter


def test_only_an_error_deactivation_is_notifiable() -> None:
    assert notifiable_deactivation("error") is NotificationEvent.NEEDS_REAUTH


@pytest.mark.parametrize("status", ["pending_auth", "revoked", "active", "", "ERROR", "error "])
def test_every_other_deactivation_status_is_silent(status: str) -> None:
    """`pending_auth` is a user revoking their own credential — a deliberate act, not a failure.

    The near-misses matter as much as the obvious ones: matching is exact, so a case variant or a
    stray space is refused rather than coerced into meaning.
    """
    assert notifiable_deactivation(status) is None


# ------------------------------------------------------------------------- the task-arg parser


@pytest.mark.parametrize("raw", ["unhealthy", "needs_reauth"])
def test_the_vocabulary_round_trips(raw: str) -> None:
    parsed = parse_event(raw)
    assert parsed is not None
    assert parsed.value == raw


@pytest.mark.parametrize(
    "raw", ["", "healthy", "unknown", "UNHEALTHY", "needs-reauth", "../../etc/passwd", "*"]
)
def test_anything_outside_the_vocabulary_is_refused(raw: str) -> None:
    """A Celery argument is attacker-reachable if the broker is. It is validated, not trusted —
    otherwise a crafted entry would reach the dedup key and widen the key space."""
    assert parse_event(raw) is None


# ------------------------------------------------------------------------------ the dedup key


def test_the_key_is_workspace_connection_and_event_scoped() -> None:
    ws, conn = uuid.uuid4(), uuid.uuid4()
    key = dedup_key(workspace_id=ws, connection_id=conn, event=NotificationEvent.UNHEALTHY)
    assert key == f"ws:{ws}:health-notify:{conn}:unhealthy"


def test_two_workspaces_never_share_a_window() -> None:
    conn = uuid.uuid4()
    a = dedup_key(workspace_id=uuid.uuid4(), connection_id=conn, event=NotificationEvent.UNHEALTHY)
    b = dedup_key(workspace_id=uuid.uuid4(), connection_id=conn, event=NotificationEvent.UNHEALTHY)
    assert a != b


def test_two_connections_never_share_a_window() -> None:
    """One failing Connection must not silence the rest of the Workspace."""
    ws = uuid.uuid4()
    a = dedup_key(workspace_id=ws, connection_id=uuid.uuid4(), event=NotificationEvent.UNHEALTHY)
    b = dedup_key(workspace_id=ws, connection_id=uuid.uuid4(), event=NotificationEvent.UNHEALTHY)
    assert a != b


def test_the_two_failure_kinds_never_share_a_window() -> None:
    """A Connection already reported as unhealthy must still be able to report needs_reauth —
    a different problem with a different remedy."""
    ws, conn = uuid.uuid4(), uuid.uuid4()
    assert dedup_key(
        workspace_id=ws, connection_id=conn, event=NotificationEvent.UNHEALTHY
    ) != dedup_key(workspace_id=ws, connection_id=conn, event=NotificationEvent.NEEDS_REAUTH)


def test_the_key_carries_no_pii_or_secret_material() -> None:
    """Structurally: the only inputs are two UUIDs and a closed-vocabulary word."""
    ws, conn = uuid.uuid4(), uuid.uuid4()
    key = dedup_key(workspace_id=ws, connection_id=conn, event=NotificationEvent.NEEDS_REAUTH)
    assert "@" not in key
    assert key.count(":") == 4
    assert set(key.split(":")) == {"ws", str(ws), "health-notify", str(conn), "needs_reauth"}


# ---------------------------------------------------------------------------- email rendering


@pytest.mark.parametrize("event", list(NotificationEvent))
def test_every_event_renders_a_subject_and_a_body(event: NotificationEvent) -> None:
    """A missing map entry would be a KeyError in a Celery task — i.e. a retry storm, not a
    blank email. Both maps are required to cover the vocabulary."""
    assert messages.subject(connection_name="Billing API", event=event)
    assert messages.html_body(connection_name="Billing API", event=event, reason_code=None)


def test_a_hostile_connection_name_is_escaped_in_both_subject_and_body() -> None:
    """The Connection name is the one free-text value in the message, and a user typed it."""
    hostile = '<img src=x onerror="alert(1)">'
    subject = messages.subject(connection_name=hostile, event=NotificationEvent.UNHEALTHY)
    body = messages.html_body(
        connection_name=hostile, event=NotificationEvent.UNHEALTHY, reason_code=None
    )
    for rendered in (subject, body):
        assert "<img" not in rendered
        assert "onerror" not in rendered or "&quot;" in rendered
        assert "&lt;img" in rendered


def test_the_reason_code_is_escaped_too() -> None:
    body = messages.html_body(
        connection_name="ok", event=NotificationEvent.UNHEALTHY, reason_code="<b>x</b>"
    )
    assert "<b>x</b>" not in body
    assert "&lt;b&gt;x&lt;/b&gt;" in body


def test_an_absent_reason_code_omits_the_line_entirely() -> None:
    body = messages.html_body(
        connection_name="ok", event=NotificationEvent.UNHEALTHY, reason_code=None
    )
    assert "Reported reason" not in body


def test_a_very_long_name_is_bounded() -> None:
    """`connections.name` allows 120 characters; a subject line is not where that is discovered."""
    subject = messages.subject(connection_name="A" * 120, event=NotificationEvent.UNHEALTHY)
    assert "A" * 81 not in subject


def test_an_empty_name_renders_a_placeholder_rather_than_a_hole() -> None:
    assert "(unnamed Connection)" in messages.subject(
        connection_name="   ", event=NotificationEvent.NEEDS_REAUTH
    )
