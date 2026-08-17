"""Credential → HTTP injection mapping (M1 Execution Runtime, CONNECTOR_SPECIFICATION §8)."""

from __future__ import annotations

import base64

import pytest

from app.core.exceptions import UpstreamAPIError
from app.domains.runtime.injection import build_auth_injection
from app.domains.runtime.secrets import CredentialSecret


def test_bearer_sets_authorization_header() -> None:
    out = build_auth_injection(CredentialSecret("bearer", value="tok123"), {})
    assert out.headers == {"Authorization": "Bearer tok123"}
    assert out.query_params == {}
    assert out.redact_query_keys == frozenset()


def test_basic_base64_encodes_username_password() -> None:
    cred = CredentialSecret("basic", username="u", password="p")  # noqa: S106
    out = build_auth_injection(cred, {})
    expected = base64.b64encode(b"u:p").decode("ascii")
    assert out.headers == {"Authorization": f"Basic {expected}"}


def test_api_key_header_default_location() -> None:
    cfg = {"type": "api_key", "key_name": "X-API-Key", "location": "header"}
    out = build_auth_injection(CredentialSecret("api_key", value="secret"), cfg)
    assert out.headers == {"X-API-Key": "secret"}
    assert out.redact_query_keys == frozenset()


def test_api_key_query_location_is_flagged_for_redaction() -> None:
    cfg = {"type": "api_key", "key_name": "api_key", "location": "query"}
    out = build_auth_injection(CredentialSecret("api_key", value="secret"), cfg)
    assert out.query_params == {"api_key": "secret"}
    assert out.headers == {}
    assert out.redact_query_keys == frozenset({"api_key"})


def test_api_key_missing_key_name_fails_closed() -> None:
    # An ingested connector with an unprojected auth_config cannot inject an api_key.
    with pytest.raises(UpstreamAPIError):
        build_auth_injection(CredentialSecret("api_key", value="secret"), {})


def test_api_key_unsupported_location_fails_closed() -> None:
    cfg = {"type": "api_key", "key_name": "k", "location": "body"}
    with pytest.raises(UpstreamAPIError):
        build_auth_injection(CredentialSecret("api_key", value="secret"), cfg)


def test_missing_material_fails_closed() -> None:
    with pytest.raises(UpstreamAPIError):
        build_auth_injection(CredentialSecret("bearer", value=None), {})
    with pytest.raises(UpstreamAPIError):
        build_auth_injection(CredentialSecret("basic", username="u", password=None), {})


def test_unsupported_credential_type_fails_closed() -> None:
    # A forged/edited row of an M2 type must never leave as an unauthenticated request.
    with pytest.raises(UpstreamAPIError):
        build_auth_injection(CredentialSecret("oauth2", value="tok"), {})
