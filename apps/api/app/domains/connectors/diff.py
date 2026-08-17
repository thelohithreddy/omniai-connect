"""Version-to-version connector diff (M1.4-B1.4, ADR-0028).

A pure, deterministic function over two ordered canonical Tool Schema sets — the connector's
current version and a freshly normalized one. It produces the `diff_summary` persisted on the new
`connector_versions` row and the `breaking` flag that drives the promotion gate
(CONNECTOR_SPECIFICATION §185).

Identity (§5/§138): tools are matched on the **canonical tool name**, which deterministically
encodes source identity (operationId, else method+path) with stable disambiguation suffixes — so a
re-described operation keeps its identity (a `changed` entry), while a renamed operationId is a
remove + add. The output is deterministic (sorted, content-only): no timestamps, ids, URLs,
workspace ids, or secrets — the same two Tool sets always yield the same summary.

`breaking` (§185): an `input_schema` change is breaking when a required argument is added, an
argument is removed, or an existing argument's declared type narrows (here: changes) — plus any
**removed** tool is breaking for the gate (a removed Tool starts failing `tool_not_found`, §169).
Additive changes (new tool, new optional argument, description/annotation edits) are not breaking.
"""

from __future__ import annotations

from typing import Any

# Content fields compared for a `changed` entry. Deliberately excludes `schema_version` (constant),
# `connector_version` (version-specific, injected at persist), and `extensions` (source identity,
# already the match key) — a change to any of these is not a semantic Tool change.
_COMPARED_FIELDS = ("description", "input_schema", "endpoint", "auth", "annotations", "tags")


def _by_name(tools: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        tool["name"]: tool
        for tool in tools
        if isinstance(tool, dict) and isinstance(tool.get("name"), str)
    }


def _changed_fields(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """The sorted content fields that differ between two same-identity tools (value comparison)."""
    return sorted(field for field in _COMPARED_FIELDS if old.get(field) != new.get(field))


def _properties(input_schema: Any) -> dict[str, Any]:
    if isinstance(input_schema, dict) and isinstance(input_schema.get("properties"), dict):
        props: dict[str, Any] = input_schema["properties"]
        return props
    return {}


def _required(input_schema: Any) -> set[str]:
    if isinstance(input_schema, dict) and isinstance(input_schema.get("required"), list):
        return {name for name in input_schema["required"] if isinstance(name, str)}
    return set()


def _input_schema_breaking(old_schema: Any, new_schema: Any) -> bool:
    """True if the input_schema change breaks existing callers (§185): a required argument added,
    an argument removed, or an existing argument's declared type changed (narrowed)."""
    old_props, new_props = _properties(old_schema), _properties(new_schema)
    old_required, new_required = _required(old_schema), _required(new_schema)

    if new_required - old_required:  # a newly-required argument breaks callers that omit it
        return True
    if set(old_props) - set(new_props):  # a removed argument breaks callers that send it
        return True
    for name in old_props.keys() & new_props.keys():  # a narrowed type breaks callers
        old_type = old_props[name].get("type") if isinstance(old_props[name], dict) else None
        new_type = new_props[name].get("type") if isinstance(new_props[name], dict) else None
        if old_type != new_type:
            return True
    return False


def compute_diff(
    old_tools: list[dict[str, Any]], new_tools: list[dict[str, Any]]
) -> dict[str, Any]:
    """Diff two canonical Tool Schema sets into `{added, removed, changed, breaking}`.

    `added`/`removed` are sorted tool names; `changed` is a sorted list of
    `{name, fields, breaking}`; `breaking` is the gate flag (any removed tool, or any changed tool
    whose input_schema change is breaking). Deterministic and content-only.
    """
    old_by_name = _by_name(old_tools)
    new_by_name = _by_name(new_tools)

    added = sorted(set(new_by_name) - set(old_by_name))
    removed = sorted(set(old_by_name) - set(new_by_name))

    changed: list[dict[str, Any]] = []
    for name in sorted(set(old_by_name) & set(new_by_name)):
        old_tool, new_tool = old_by_name[name], new_by_name[name]
        fields = _changed_fields(old_tool, new_tool)
        if not fields:
            continue
        breaking = "input_schema" in fields and _input_schema_breaking(
            old_tool.get("input_schema"), new_tool.get("input_schema")
        )
        changed.append({"name": name, "fields": fields, "breaking": breaking})

    breaking = bool(removed) or any(entry["breaking"] for entry in changed)
    return {"added": added, "removed": removed, "changed": changed, "breaking": breaking}


__all__ = ["compute_diff"]
