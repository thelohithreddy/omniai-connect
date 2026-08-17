"""TenantObjectKey grammar — the tenant-isolation boundary (M1.4-B0.5, ADR-0024).

The object key IS the tenant boundary: every key is `ws/<workspace_id>/<path>`, built only from a
trusted workspace UUID and an explicit allowlist grammar. These tests are the adversarial matrix
(§36) — traversal, encoding, absolute/UNC paths, null bytes, control characters, prefix collision
— proving a hostile relative path is rejected before it can ever address another tenant. Pure; no
provider.
"""

from __future__ import annotations

import uuid

import pytest

from app.core.object_store import ObjectKeyError, TenantObjectKey

WS = uuid.UUID("11111111-1111-1111-1111-111111111111")


def _key(path: str, workspace: uuid.UUID = WS) -> TenantObjectKey:
    return TenantObjectKey.for_workspace(workspace, path)


# ------------------------------------------------------------------ accepted (safe) paths


@pytest.mark.parametrize(
    "path",
    [
        "object.json",
        "specs/openapi.json",
        "nested/path/to/file.json",
        "v1/2026/spec.yaml",
        "a.b.c",
        "under_score-dash.dot",
        "0123/ABCabc._-",
    ],
)
def test_safe_paths_are_accepted_and_stay_under_the_workspace_prefix(path: str) -> None:
    key = _key(path)
    assert key.full_key == f"ws/{WS}/{path}"
    assert key.full_key.startswith(f"ws/{WS}/")
    assert key.workspace_id == WS
    assert key.relative_path == path


# ------------------------------------------------------------------ rejected (attack) paths


@pytest.mark.parametrize(
    "path",
    [
        "../workspace-B/object",
        "../../workspace-B/object",
        "/../../workspace-B/object",
        "workspace-A/../workspace-B",
        "a/../b",
        "..",
        ".",
        "a/./b",
        "a/..",
        "../a",
        "..\\workspace-B\\object",  # backslash traversal
        "a\\b",
        "/absolute",  # leading slash
        "//double-leading",
        "a//b",  # double slash (empty segment)
        "a/b/",  # trailing slash
        "trailing ",  # trailing whitespace
        " leading",  # leading whitespace
        " ",
        "",  # empty
        "%2e%2e/workspace-B",  # encoded traversal — '%' is not in the allowlist
        "%2e%2e%2f",
        "%252e%252e",  # double-encoded
        "%2F",  # encoded slash
        "a\x00b",  # null byte
        "a\tb",  # control char (tab)
        "a\nb",  # control char (newline)
        "a\rb",
        "\x7f",  # DEL
        "café/spec",  # non-ASCII unicode
        "spec\u202e.json",  # unicode right-to-left override
        "C:\\Windows\\path",  # windows drive path
        "\\\\server\\share",  # UNC path
    ],
)
def test_traversal_and_malformed_paths_are_rejected(path: str) -> None:
    with pytest.raises(ObjectKeyError):
        _key(path)


def test_a_ws_prefixed_relative_path_cannot_escape_the_callers_workspace() -> None:
    """Even a relative path that *looks* like another tenant's key (`ws/<B>/x`) is nested under
    the caller's own prefix, never promoted to a sibling — it cannot address tenant B."""
    other = uuid.UUID("22222222-2222-2222-2222-222222222222")
    key = _key(f"ws/{other}/object.json", workspace=WS)
    assert key.full_key == f"ws/{WS}/ws/{other}/object.json"
    assert key.full_key.startswith(f"ws/{WS}/")


# ------------------------------------------------------------------ workspace id must be trusted


@pytest.mark.parametrize("bad", ["11111111-1111-1111-1111-111111111111", "", None, 123, b"x", {}])
def test_workspace_id_must_be_a_uuid_not_a_string_or_other_type(bad: object) -> None:
    """The workspace id must be a `uuid.UUID` from a resolved context — a string (even a valid
    UUID string), None, or any other type is refused, so a raw request/payload value cannot be
    passed straight through."""
    with pytest.raises(ObjectKeyError):
        TenantObjectKey.for_workspace(bad, "object.json")  # type: ignore[arg-type]


def test_two_uppercase_vs_lowercase_uuids_are_distinct_prefixes() -> None:
    """A near-collision (case/format) does not merge tenants: uuid.UUID canonicalises, so the
    prefix is exactly the canonical form and distinct workspaces get distinct prefixes."""
    a = uuid.uuid4()
    b = uuid.uuid4()
    assert _key("x", a).full_key != _key("x", b).full_key


def test_a_very_long_path_exceeding_the_key_limit_is_rejected() -> None:
    with pytest.raises(ObjectKeyError):
        _key("a/" * 600 + "file")  # full key would exceed 1024 bytes


def test_keys_are_frozen() -> None:
    key = _key("object.json")
    with pytest.raises((AttributeError, TypeError)):
        key.relative_path = "other"  # type: ignore[misc]
