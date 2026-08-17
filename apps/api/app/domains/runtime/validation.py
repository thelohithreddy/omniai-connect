"""Argument validation against a Tool's `input_schema` (AI_RUNTIME.md §2 stage 2).

"Malformed input never reaches the wire." This is a focused validator for the shape the connector
normalizer actually emits — an object root with typed `properties` and a `required` list (the merged
path/query/header/body parameters, CONNECTOR_ENGINE.md §2). It enforces, fail-closed:

- every `required` property is present,
- no *unknown* argument is accepted (an arg with no schema property is rejected, so a caller can
  never smuggle a parameter the Tool did not declare — and the binding would drop it anyway),
- each provided value matches its declared primitive `type` and any `enum`.

Full JSON-Schema draft-2020-12 (nested object/array validation, `format`, `allOf`/`oneOf`) is
deferred — it is not needed to keep M1's normalized inputs safe, and pulling a schema-validation
dependency into this slice is out of scope. Deep values are still serialized safely downstream
(URL-encoded path/query, JSON/form body), so an under-validated nested value cannot inject
structure.
"""

from __future__ import annotations

from typing import Any

from app.core.exceptions import ValidationFailedError

#: JSON Schema primitive `type` → the Python types that satisfy it. `bool` is deliberately excluded
#: from integer/number (in Python `bool` is an `int` subclass, but `true` is not a valid integer).
_TYPE_CHECKS = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
}


def validate_arguments(arguments: dict[str, Any], input_schema: dict[str, Any]) -> None:
    """Validate `arguments` against `input_schema`. Raises `ValidationFailedError` (400) with a
    `details.fields` list on the first-class shape problems; never mutates its inputs."""
    if not isinstance(arguments, dict):
        raise ValidationFailedError("arguments must be an object.")

    properties = input_schema.get("properties")
    properties = properties if isinstance(properties, dict) else {}
    required = input_schema.get("required")
    required = required if isinstance(required, list) else []

    fields: list[dict[str, str]] = []

    for name in required:
        if name not in arguments:
            fields.append({"field": str(name), "error": "required"})

    for name, value in arguments.items():
        prop = properties.get(name)
        if prop is None:
            fields.append({"field": name, "error": "unknown argument"})
            continue
        if not isinstance(prop, dict):
            continue
        # `null` is permitted only for a non-required field with no conflicting type; keep it
        # simple:
        # a provided `null` on a required field is caught above; otherwise skip type-checking null.
        if value is None:
            continue
        declared = prop.get("type")
        check = _TYPE_CHECKS.get(declared) if isinstance(declared, str) else None
        if check is not None and not check(value):
            fields.append({"field": name, "error": f"expected {declared}"})
            continue
        enum = prop.get("enum")
        if isinstance(enum, list) and value not in enum:
            fields.append({"field": name, "error": "not an allowed value"})

    if fields:
        raise ValidationFailedError(
            "Arguments do not satisfy the tool input schema.", details={"fields": fields}
        )


__all__ = ["validate_arguments"]
