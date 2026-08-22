"""Connection Health domain rules: safe probe selection and the derived projection (M2.7-A). No DB.

The probe selector is a security control, not a convenience. It decides which Tool gets executed
against a customer's live third-party API, with their real credential, without a human reading the
request first. Every test below is written so that removing the specific guard it covers makes it
fail — a selector that "usually picks something harmless" is not a control.

The projection is tested for the property that makes it trustworthy: it reports what the last
*health check* found, and it refuses to report anything at all when nothing has been checked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from app.domains.connections.health import (
    HealthState,
    is_probe_eligible,
    needs_reauth,
    project_health,
    select_probe_tool,
)

NOW = "2026-08-22T10:00:00Z"


@dataclass
class FakeTool:
    """A Tool as the selector sees it. Defaults describe the *safe* Tool; each test spoils one
    attribute, so a test failing points at exactly one guard."""

    name: str = "list_things"
    enabled: bool = True
    deleted_at: Any = None
    annotations: Any = field(default_factory=lambda: {"readonly": True, "destructive": False})
    input_schema: Any = field(default_factory=lambda: {"type": "object", "properties": {}})


# ------------------------------------------------------------------ the safe baseline


def test_a_readonly_zero_argument_enabled_live_tool_is_eligible() -> None:
    assert is_probe_eligible(FakeTool()) is True


# ------------------------------------------------------------------ hostile inventory


@pytest.mark.parametrize(
    ("label", "tool"),
    [
        ("disabled", FakeTool(enabled=False)),
        ("soft-deleted", FakeTool(deleted_at=NOW)),
        ("readonly false", FakeTool(annotations={"readonly": False})),
        ("annotations empty (the DB default)", FakeTool(annotations={})),
        ("annotations missing readonly key", FakeTool(annotations={"destructive": False})),
        ("annotations null", FakeTool(annotations=None)),
        ("annotations not a dict", FakeTool(annotations="readonly")),
        ("readonly truthy but not True", FakeTool(annotations={"readonly": "true"})),
        ("readonly 1 (int, not bool)", FakeTool(annotations={"readonly": 1})),
        ("destructive POST", FakeTool(annotations={"readonly": False, "destructive": True})),
        (
            "readonly but requires an argument",
            FakeTool(input_schema={"type": "object", "required": ["id"]}),
        ),
        (
            "readonly but requires several",
            FakeTool(input_schema={"type": "object", "required": ["a", "b"]}),
        ),
        ("input_schema missing", FakeTool(input_schema=None)),
        ("input_schema not a dict", FakeTool(input_schema="object")),
        ("required is not a list", FakeTool(input_schema={"required": "id"})),
    ],
)
def test_unsafe_tools_are_never_eligible(label: str, tool: FakeTool) -> None:
    """Fail-closed on every axis. `readonly` must be exactly the boolean `True`: a string "true"
    or an int 1 is a malformed annotation, and treating it as consent is how a truthiness bug
    becomes an unattended write against a customer's API."""
    assert is_probe_eligible(tool) is False, label


def test_an_empty_required_list_is_argument_free() -> None:
    """`required: []` is a normalizer artifact, not a requirement."""
    assert is_probe_eligible(FakeTool(input_schema={"type": "object", "required": []})) is True


# ------------------------------------------------------------------ selection


def test_no_eligible_tool_returns_none_rather_than_a_fallback() -> None:
    """The outcome the endpoint reports as `health_check_unavailable`. A Connector whose read
    operations all take parameters genuinely has no zero-argument probe; the only alternative to
    refusing is fabricating a request, which is never acceptable."""
    inventory = [
        FakeTool(name="delete_thing", annotations={"readonly": False, "destructive": True}),
        FakeTool(name="get_thing", input_schema={"required": ["id"]}),
        FakeTool(name="disabled_list", enabled=False),
        FakeTool(name="removed_list", deleted_at=NOW),
        FakeTool(name="unannotated_list", annotations={}),
    ]
    assert select_probe_tool(inventory) is None


def test_selection_is_deterministic_by_canonical_name() -> None:
    """The same Connector must probe the same third-party endpoint every time, or health results
    are not comparable across checks and a re-ingestion could silently retarget the probe."""
    inventory = [FakeTool(name="zzz_list"), FakeTool(name="aaa_list"), FakeTool(name="mmm_list")]
    assert select_probe_tool(inventory).name == "aaa_list"
    # Order of the input must not matter.
    assert select_probe_tool(list(reversed(inventory))).name == "aaa_list"


def test_selection_ignores_unsafe_tools_even_when_they_sort_first() -> None:
    """Sort order must never outrank eligibility — the destructive Tool sorts first alphabetically
    and must still lose."""
    inventory = [
        FakeTool(name="aaa_delete", annotations={"readonly": False, "destructive": True}),
        FakeTool(name="bbb_list"),
    ]
    assert select_probe_tool(inventory).name == "bbb_list"


def test_an_empty_inventory_selects_nothing() -> None:
    assert select_probe_tool([]) is None


# ------------------------------------------------------------------ projection


def test_unknown_when_no_check_has_completed() -> None:
    assert (
        project_health(
            connection_status="active",
            credential_type="api_key",
            last_health_check_at=None,
            last_check_status=None,
        )
        is HealthState.UNKNOWN
    )


def test_unknown_when_the_timestamp_has_no_matching_audit_row() -> None:
    """A stamped timestamp with no recoverable audit status must not be optimistically green."""
    assert (
        project_health(
            connection_status="active",
            credential_type="api_key",
            last_health_check_at=NOW,
            last_check_status=None,
        )
        is HealthState.UNKNOWN
    )


def test_healthy_only_for_a_succeeded_audit_status() -> None:
    assert (
        project_health(
            connection_status="active",
            credential_type="api_key",
            last_health_check_at=NOW,
            last_check_status="succeeded",
        )
        is HealthState.HEALTHY
    )


@pytest.mark.parametrize("status", ["failed", "denied", "timeout"])
def test_every_non_succeeded_audit_status_is_unhealthy(status: str) -> None:
    """The audit taxonomy is `succeeded|failed|denied|timeout`; only the first is health."""
    assert (
        project_health(
            connection_status="active",
            credential_type="api_key",
            last_health_check_at=NOW,
            last_check_status=status,
        )
        is HealthState.UNHEALTHY
    )


def test_needs_reauth_requires_both_error_status_and_an_oauth_credential() -> None:
    """The M2.5 D5 derivation, exactly. An `error` on an api_key Connection is not recoverable by
    re-authorizing, so calling it `needs_reauth` would send the user to a dead end."""
    assert needs_reauth(connection_status="error", credential_type="oauth2") is True
    assert needs_reauth(connection_status="error", credential_type="api_key") is False
    assert needs_reauth(connection_status="active", credential_type="oauth2") is False
    assert needs_reauth(connection_status="error", credential_type=None) is False


def test_needs_reauth_outranks_a_stale_successful_check() -> None:
    """A Connection whose OAuth refresh budget is spent cannot succeed, so reporting `healthy`
    from an earlier probe would actively mislead the operator into ignoring it."""
    assert (
        project_health(
            connection_status="error",
            credential_type="oauth2",
            last_health_check_at=NOW,
            last_check_status="succeeded",
        )
        is HealthState.NEEDS_REAUTH
    )


def test_an_errored_api_key_connection_reports_unhealthy_not_needs_reauth() -> None:
    assert (
        project_health(
            connection_status="error",
            credential_type="api_key",
            last_health_check_at=NOW,
            last_check_status="failed",
        )
        is HealthState.UNHEALTHY
    )


def test_health_states_are_exactly_the_ratified_four() -> None:
    """A fifth state would be a contract change; the released `connections.status` CHECK stays
    `pending_auth|active|error|revoked` and health stays derived."""
    assert {state.value for state in HealthState} == {
        "unknown",
        "healthy",
        "unhealthy",
        "needs_reauth",
    }


def test_projection_never_returns_a_connection_status_value() -> None:
    """Health and lifecycle status are different vocabularies; leaking one into the other is how a
    UI starts treating `revoked` as a health problem."""
    for status in ("pending_auth", "active", "error", "revoked"):
        result = project_health(
            connection_status=status,
            credential_type="api_key",
            last_health_check_at=NOW,
            last_check_status="succeeded",
        )
        assert result.value not in {"pending_auth", "active", "error", "revoked"}
