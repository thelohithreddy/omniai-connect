"""Argument validation against a Tool input_schema (M1 Execution Runtime, AI_RUNTIME §2 stage 2)."""

from __future__ import annotations

from typing import Any

import pytest

from app.core.exceptions import ValidationFailedError
from app.domains.runtime.validation import validate_arguments

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "a": {"type": "string"},
        "n": {"type": "integer"},
        "f": {"type": "number"},
        "b": {"type": "boolean"},
        "e": {"type": "string", "enum": ["x", "y"]},
    },
    "required": ["a"],
}


def test_valid_arguments_pass() -> None:
    validate_arguments({"a": "hi", "n": 3, "f": 1.5, "b": True, "e": "x"}, SCHEMA)


def test_missing_required_is_rejected() -> None:
    with pytest.raises(ValidationFailedError):
        validate_arguments({"n": 3}, SCHEMA)


def test_unknown_argument_is_rejected() -> None:
    # An arg with no schema property cannot be smuggled onto the wire.
    with pytest.raises(ValidationFailedError):
        validate_arguments({"a": "x", "surprise": 1}, SCHEMA)


def test_wrong_type_is_rejected() -> None:
    with pytest.raises(ValidationFailedError):
        validate_arguments({"a": 123}, SCHEMA)


def test_integer_rejects_bool_and_float() -> None:
    with pytest.raises(ValidationFailedError):
        validate_arguments({"a": "x", "n": True}, SCHEMA)
    with pytest.raises(ValidationFailedError):
        validate_arguments({"a": "x", "n": 1.5}, SCHEMA)


def test_number_accepts_int_and_float() -> None:
    validate_arguments({"a": "x", "f": 2}, SCHEMA)
    validate_arguments({"a": "x", "f": 2.5}, SCHEMA)


def test_enum_violation_is_rejected() -> None:
    with pytest.raises(ValidationFailedError):
        validate_arguments({"a": "x", "e": "z"}, SCHEMA)


def test_null_on_optional_field_skips_type_check() -> None:
    validate_arguments({"a": "x", "n": None}, SCHEMA)


def test_non_dict_arguments_is_rejected() -> None:
    with pytest.raises(ValidationFailedError):
        validate_arguments(["a"], SCHEMA)  # type: ignore[arg-type]


def test_error_details_name_the_bad_fields() -> None:
    with pytest.raises(ValidationFailedError) as exc:
        validate_arguments({"n": "not-an-int", "unknown": 1}, SCHEMA)
    fields = {f["field"] for f in exc.value.details["fields"]}  # type: ignore[index]
    assert {"a", "n", "unknown"} <= fields
