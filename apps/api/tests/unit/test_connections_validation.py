"""Connection `config_overrides` validation (M1-Connections-v1). Pure, no DB.

`config_overrides` is data, never authority. The only field with a security contract is a `base_url`
override, which must pass the SAME SSRF lint a Connector's base URL does (reused, not rebuilt):
https-only, no embedded credentials, no private/loopback/link-local/metadata host, no odd scheme.
Every other key — including a smuggled `workspace_id`/`status`/`role` — is stored opaquely and is
never consulted for tenant/role/status, so it cannot become authority.
"""

from __future__ import annotations

import pytest

from app.core.exceptions import ValidationFailedError
from app.domains.connections.service import _validate_config_overrides


def test_empty_config_is_valid() -> None:
    assert _validate_config_overrides({}) == {}


def test_a_valid_https_base_url_override_is_accepted() -> None:
    cfg = {"base_url": "https://api.example.com/v1"}
    assert _validate_config_overrides(cfg) == cfg


@pytest.mark.parametrize(
    "base_url",
    [
        "http://api.example.com",  # not https
        "ftp://api.example.com",  # unsupported scheme
        "not a url",  # malformed → no https scheme
        "https://localhost",  # local hostname
        "https://api.internal.local",  # .local
        "https://127.0.0.1",  # loopback
        "https://10.0.0.1",  # private IPv4
        "https://192.168.1.1",  # private IPv4
        "https://169.254.169.254",  # link-local / cloud metadata
        "https://[fd00::1]",  # private IPv6 (ULA)
        "https://[::1]",  # loopback IPv6
        "https://user:pass@api.example.com",  # embedded credentials
    ],
)
def test_an_unsafe_base_url_override_is_refused(base_url: str) -> None:
    with pytest.raises(ValidationFailedError):
        _validate_config_overrides({"base_url": base_url})


def test_a_non_string_base_url_is_refused() -> None:
    with pytest.raises(ValidationFailedError):
        _validate_config_overrides({"base_url": 123})


def test_a_non_object_config_is_refused() -> None:
    with pytest.raises(ValidationFailedError):
        _validate_config_overrides(["not", "a", "dict"])  # type: ignore[arg-type]


def test_non_base_url_keys_are_stored_opaquely() -> None:
    cfg = {"timeout_ms": 5000, "note": "primary"}
    assert _validate_config_overrides(cfg) == cfg


def test_smuggled_authority_keys_are_inert_data_not_authority() -> None:
    # These are stored verbatim and NEVER read as tenant/role/status — the validator neither
    # rejects nor honors them; they are pure data with no effect on isolation or authorization.
    smuggled = {
        "workspace_id": "00000000-0000-0000-0000-000000000000",
        "status": "active",
        "role": "owner",
    }
    assert _validate_config_overrides(smuggled) == smuggled
