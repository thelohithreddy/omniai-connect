"""Tools admin wire contract (M1-Tools-v1): the mutable surface and the read projection."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.domains.tools.schemas import ToolRead, ToolUpdate


def test_tool_update_accepts_only_enabled() -> None:
    assert ToolUpdate(enabled=False).enabled is False


def test_tool_update_requires_enabled() -> None:
    with pytest.raises(ValidationError):
        ToolUpdate()  # type: ignore[call-arg]


def test_tool_update_rejects_immutable_fields() -> None:
    # extra="forbid": a client cannot rewrite name/description/schema/connector identity.
    for extra in ("name", "description", "input_schema", "connector_id", "connector_version_id"):
        with pytest.raises(ValidationError):
            ToolUpdate.model_validate({"enabled": True, extra: "x"})


def test_tool_read_exposes_only_safe_metadata() -> None:
    # No endpoint, no auth_config, no secret material in the public projection.
    fields = set(ToolRead.model_fields)
    assert fields == {
        "id",
        "connector_id",
        "connector_version_id",
        "name",
        "description",
        "input_schema",
        "output_hints",
        "annotations",
        "enabled",
        "created_at",
        "updated_at",
    }
    assert "endpoint" not in fields
    assert "auth_config" not in fields
    assert "workspace_id" not in fields
    assert "deleted_at" not in fields


def test_tool_read_round_trips_from_attributes() -> None:
    class _Row:
        id = uuid.uuid4()
        connector_id = uuid.uuid4()
        connector_version_id = uuid.uuid4()
        name = "demo_op"
        description = "d"
        input_schema = {"type": "object"}
        output_hints = None
        annotations = {"tags": []}
        enabled = True
        created_at = datetime.now(UTC)
        updated_at = datetime.now(UTC)

    read = ToolRead.model_validate(_Row())
    assert read.name == "demo_op"
    assert read.enabled is True
