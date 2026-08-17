"""Version-to-version diff engine (M1.4-B1.4). Pure, deterministic, breaking-flag classification.

Covers the matrix of CONNECTOR_SPECIFICATION §185: added / removed / changed on source identity;
the breaking triggers (required argument added, argument removed, type narrows) and the additive
cases that are NOT breaking (new tool, new optional argument, description / annotation / enum
edits); identity keyed on canonical name (re-described op = changed, not remove+add); order
independence; and defensive handling of malformed tools / empty sets.
"""

from __future__ import annotations

from typing import Any

from app.domains.connectors.diff import compute_diff


def tool(name: str, **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "name": name,
        "description": name,
        "input_schema": {"type": "object", "properties": {}},
        "endpoint": {"method": "GET", "url": f"/{name}", "binding": {}, "body_style": "none"},
        "auth": {"required": False},
        "annotations": {"readonly": True, "destructive": False, "idempotent": True},
        "tags": [],
        "extensions": {"openapi": {"operationId": name, "method": "GET", "path": f"/{name}"}},
    }
    base.update(overrides)
    return base


def _schema(props: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return schema


# ------------------------------------------------------------------ added / removed


def test_identical_versions_have_an_empty_non_breaking_diff() -> None:
    tools = [tool("a"), tool("b")]
    diff = compute_diff(tools, tools)
    assert diff == {"added": [], "removed": [], "changed": [], "breaking": False}


def test_first_version_is_all_added_and_not_breaking() -> None:
    diff = compute_diff([], [tool("a"), tool("b")])
    assert diff["added"] == ["a", "b"]
    assert diff["breaking"] is False


def test_a_removed_tool_is_breaking() -> None:
    diff = compute_diff([tool("a"), tool("b")], [tool("a")])
    assert diff["removed"] == ["b"]
    assert diff["breaking"] is True


def test_an_added_tool_is_additive() -> None:
    diff = compute_diff([tool("a")], [tool("a"), tool("b")])
    assert diff["added"] == ["b"]
    assert diff["removed"] == []
    assert diff["breaking"] is False


def test_emptying_the_tool_set_removes_everything_and_is_breaking() -> None:
    diff = compute_diff([tool("a"), tool("b")], [])
    assert diff["removed"] == ["a", "b"]
    assert diff["breaking"] is True


# ------------------------------------------------------------------ changed (non-breaking)


def test_description_change_is_a_non_breaking_changed_entry() -> None:
    diff = compute_diff([tool("a")], [tool("a", description="new")])
    assert diff["changed"] == [{"name": "a", "fields": ["description"], "breaking": False}]
    assert diff["breaking"] is False


def test_a_new_optional_argument_is_a_non_breaking_change() -> None:
    old = [tool("a", input_schema=_schema({"x": {"type": "string"}}))]
    new = [tool("a", input_schema=_schema({"x": {"type": "string"}, "y": {"type": "string"}}))]
    diff = compute_diff(old, new)
    assert diff["changed"] == [{"name": "a", "fields": ["input_schema"], "breaking": False}]


def test_making_a_required_argument_optional_is_not_breaking() -> None:
    old = [tool("a", input_schema=_schema({"x": {"type": "string"}}, required=["x"]))]
    new = [tool("a", input_schema=_schema({"x": {"type": "string"}}))]
    diff = compute_diff(old, new)
    assert diff["changed"][0]["breaking"] is False


def test_an_enum_change_is_changed_but_not_breaking() -> None:
    old = [tool("a", input_schema=_schema({"x": {"type": "string", "enum": ["p"]}}))]
    new = [tool("a", input_schema=_schema({"x": {"type": "string", "enum": ["p", "q"]}}))]
    diff = compute_diff(old, new)
    assert diff["changed"][0] == {"name": "a", "fields": ["input_schema"], "breaking": False}


def test_auth_and_annotation_changes_are_non_breaking() -> None:
    old = [tool("a")]
    new = [tool("a", auth={"required": True}, annotations={"readonly": False})]
    diff = compute_diff(old, new)
    assert diff["changed"][0]["fields"] == ["annotations", "auth"]
    assert diff["changed"][0]["breaking"] is False


# ------------------------------------------------------------------ changed (breaking)


def test_adding_a_required_argument_is_breaking() -> None:
    old = [tool("a", input_schema=_schema({"x": {"type": "string"}}))]
    new = [
        tool(
            "a",
            input_schema=_schema(
                {"x": {"type": "string"}, "y": {"type": "string"}}, required=["y"]
            ),
        )
    ]
    diff = compute_diff(old, new)
    assert diff["changed"][0]["breaking"] is True
    assert diff["breaking"] is True


def test_making_an_existing_argument_required_is_breaking() -> None:
    old = [tool("a", input_schema=_schema({"x": {"type": "string"}}))]
    new = [tool("a", input_schema=_schema({"x": {"type": "string"}}, required=["x"]))]
    assert compute_diff(old, new)["changed"][0]["breaking"] is True


def test_removing_an_argument_is_breaking() -> None:
    old = [tool("a", input_schema=_schema({"x": {"type": "string"}, "y": {"type": "string"}}))]
    new = [tool("a", input_schema=_schema({"x": {"type": "string"}}))]
    assert compute_diff(old, new)["changed"][0]["breaking"] is True


def test_narrowing_an_argument_type_is_breaking() -> None:
    old = [tool("a", input_schema=_schema({"x": {"type": "string"}}))]
    new = [tool("a", input_schema=_schema({"x": {"type": "integer"}}))]
    assert compute_diff(old, new)["changed"][0]["breaking"] is True


def test_multiple_simultaneous_changes_are_reported_together() -> None:
    old = [tool("a", input_schema=_schema({"x": {"type": "string"}}))]
    new = [
        tool(
            "a",
            description="d2",
            input_schema=_schema({"x": {"type": "integer"}}),  # type narrowed → breaking
        )
    ]
    entry = compute_diff(old, new)["changed"][0]
    assert entry["fields"] == ["description", "input_schema"]
    assert entry["breaking"] is True


# ------------------------------------------------------------------ identity / determinism


def test_a_redescribed_operation_keeps_identity_not_remove_add() -> None:
    # Same canonical name (same operationId) → a `changed` entry, never remove+add.
    diff = compute_diff([tool("a", description="old")], [tool("a", description="new")])
    assert diff["added"] == [] and diff["removed"] == []
    assert [c["name"] for c in diff["changed"]] == ["a"]


def test_reordering_tools_produces_no_semantic_diff() -> None:
    a, b, c = tool("a"), tool("b"), tool("c")
    assert compute_diff([a, b, c], [c, a, b]) == {
        "added": [],
        "removed": [],
        "changed": [],
        "breaking": False,
    }


def test_endpoint_change_under_a_stable_name_is_non_breaking_changed() -> None:
    old = [tool("a", endpoint={"method": "GET", "url": "/a", "binding": {}, "body_style": "none"})]
    new = [tool("a", endpoint={"method": "GET", "url": "/a2", "binding": {}, "body_style": "none"})]
    diff = compute_diff(old, new)
    assert diff["changed"][0] == {"name": "a", "fields": ["endpoint"], "breaking": False}


# ------------------------------------------------------------------ defensive


def test_malformed_tools_do_not_crash_the_diff() -> None:
    # A tool missing a name is ignored; a non-dict input_schema is tolerated.
    old = [{"description": "no name"}, tool("a", input_schema="not a dict")]
    new = [tool("a", input_schema={"type": "object"})]
    diff = compute_diff(old, new)  # must not raise
    assert diff["changed"][0]["name"] == "a"
    assert diff["added"] == [] and diff["removed"] == []
