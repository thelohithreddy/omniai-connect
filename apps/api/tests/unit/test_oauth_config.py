"""Connector OAuth provider configuration — definition-time validation (M2.5, ADR-0038).

Proves the two security properties enforced at Connector save: provider endpoints pass the ONE
canonical SSRF lint (no second validator), and secret material can never enter `auth_config`,
which is public metadata. Also pins the founder-ratified D3 grant scope.
"""

from __future__ import annotations

import pytest

from app.core.exceptions import ValidationFailedError
from app.domains.connectors.oauth_config import (
    GRANT_AUTHORIZATION_CODE,
    SUPPORTED_GRANTS,
    is_oauth2,
    parse_oauth_config,
    validate_oauth_auth_config,
)

VALID = {
    "type": "oauth2",
    "grant": "authorization_code",
    "authorization_url": "https://provider.example.com/authorize",
    "token_url": "https://provider.example.com/token",
    "scopes": ["read", "write"],
    "client_id": "client-abc",
    "quirks": {"scope_separator": " "},
}


def test_valid_config_parses() -> None:
    config = validate_oauth_auth_config(VALID)
    assert config.authorization_url == "https://provider.example.com/authorize"
    assert config.token_url == "https://provider.example.com/token"  # noqa: S105 (a URL)
    assert config.scopes == ("read", "write")
    assert config.client_id == "client-abc"
    assert config.quirks == {"scope_separator": " "}


def test_d3_grant_scope_is_authorization_code_only() -> None:
    """Founder-ratified D3: client_credentials is M2/P1 — refused explicitly, never half-honored."""
    assert SUPPORTED_GRANTS == (GRANT_AUTHORIZATION_CODE,)
    with pytest.raises(ValidationFailedError) as excinfo:
        validate_oauth_auth_config({**VALID, "grant": "client_credentials"})
    assert "grant" in str(excinfo.value)


def test_secret_material_is_refused_from_public_config() -> None:
    """`auth_config` is returned as Connector metadata; a secret there would be published."""
    for key in ("client_secret", "access_token", "refresh_token", "password", "private_key"):
        with pytest.raises(ValidationFailedError) as excinfo:
            validate_oauth_auth_config({**VALID, key: "super-secret"})
        assert "secret" in str(excinfo.value).lower(), key
        # The offending VALUE must never be echoed back in the error.
        assert "super-secret" not in str(excinfo.value)


@pytest.mark.parametrize(
    "url",
    [
        "http://provider.example.com/token",  # scheme
        "https://localhost/token",
        "https://127.0.0.1/token",
        "https://169.254.169.254/token",  # cloud metadata
        "https://10.0.0.5/token",  # RFC1918
        "https://192.168.1.1/token",
        "https://[::1]/token",  # IPv6 loopback
        "https://user:pass@provider.example.com/token",  # embedded credentials
        "ftp://provider.example.com/token",
        "https:///token",  # no host
        "https://internal.local/token",
    ],
)
def test_provider_endpoints_are_ssrf_linted(url: str) -> None:
    """Both endpoints go through the same lint that guards `base_url` — no second validator."""
    with pytest.raises(ValidationFailedError):
        validate_oauth_auth_config({**VALID, "token_url": url})
    with pytest.raises(ValidationFailedError):
        validate_oauth_auth_config({**VALID, "authorization_url": url})


def test_error_message_names_the_offending_field() -> None:
    with pytest.raises(ValidationFailedError) as excinfo:
        validate_oauth_auth_config({**VALID, "token_url": "https://127.0.0.1/token"})
    assert "auth_config.token_url" in str(excinfo.value)


def test_required_endpoints_are_mandatory() -> None:
    for key in ("authorization_url", "token_url"):
        missing = {k: v for k, v in VALID.items() if k != key}
        with pytest.raises(ValidationFailedError) as excinfo:
            validate_oauth_auth_config(missing)
        assert key in str(excinfo.value)


def test_scope_grammar_is_enforced() -> None:
    for bad in (["read write"], [""], [None], "read", [123], ["x" * 300]):
        with pytest.raises(ValidationFailedError):
            validate_oauth_auth_config({**VALID, "scopes": bad})
    # Absent scopes are allowed (a provider may define defaults).
    assert (
        validate_oauth_auth_config({k: v for k, v in VALID.items() if k != "scopes"}).scopes == ()
    )


def test_too_many_scopes_rejected() -> None:
    with pytest.raises(ValidationFailedError):
        validate_oauth_auth_config({**VALID, "scopes": [f"s{i}" for i in range(65)]})


def test_quirks_must_be_an_object() -> None:
    with pytest.raises(ValidationFailedError):
        validate_oauth_auth_config({**VALID, "quirks": ["not", "an", "object"]})


def test_is_oauth2_and_parse_guard() -> None:
    assert is_oauth2(VALID) is True
    assert is_oauth2({"type": "api_key"}) is False
    assert is_oauth2(None) is False
    with pytest.raises(ValidationFailedError):
        parse_oauth_config({"type": "api_key"})


def test_base_url_messages_are_unchanged_for_m1_callers() -> None:
    """The lint gained a `field` label; the default must keep M1's exact wording."""
    from app.domains.connectors.service import validate_base_url

    with pytest.raises(ValidationFailedError) as excinfo:
        validate_base_url("http://example.com")
    assert str(excinfo.value) == "base_url must use https."
