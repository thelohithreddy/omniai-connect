"""Outbound-request construction from the canonical Tool endpoint (M1 Execution Runtime)."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from app.core.exceptions import UpstreamAPIError, ValidationFailedError
from app.domains.runtime.build import build_request
from app.domains.runtime.injection import InjectedAuth

BASE = "https://api.example.com"


def _endpoint(**over: Any) -> dict[str, Any]:
    ep: dict[str, Any] = {"method": "get", "url": "/v1/things", "binding": {}, "body_style": "none"}
    ep.update(over)
    return ep


def test_method_and_url_are_composed() -> None:
    built = build_request(_endpoint(), base_url=BASE, arguments={}, injected=InjectedAuth())
    assert built.method == "GET"
    assert built.url == "https://api.example.com/v1/things"
    assert built.allowed_host == "api.example.com"


def test_path_param_is_url_encoded_and_cannot_add_segments() -> None:
    ep = _endpoint(url="/v1/things/{id}", binding={"id": {"location": "path"}})
    built = build_request(ep, base_url=BASE, arguments={"id": "a/b c"}, injected=InjectedAuth())
    assert built.url == "https://api.example.com/v1/things/a%2Fb%20c"


def test_missing_path_argument_is_a_validation_error() -> None:
    ep = _endpoint(url="/v1/things/{id}", binding={"id": {"location": "path"}})
    with pytest.raises(ValidationFailedError):
        build_request(ep, base_url=BASE, arguments={}, injected=InjectedAuth())


def test_query_args_are_encoded() -> None:
    ep = _endpoint(binding={"q": {"location": "query"}})
    built = build_request(ep, base_url=BASE, arguments={"q": "a b&c"}, injected=InjectedAuth())
    assert parse_qs(urlsplit(built.url).query) == {"q": ["a b&c"]}


def test_header_arg_with_crlf_is_rejected() -> None:
    ep = _endpoint(binding={"h": {"location": "header"}})
    with pytest.raises(ValidationFailedError):
        build_request(
            ep, base_url=BASE, arguments={"h": "x\r\nInjected: 1"}, injected=InjectedAuth()
        )


def test_json_body_is_serialized_with_content_type() -> None:
    ep = _endpoint(method="post", body_style="json", binding={"name": {"location": "body"}})
    built = build_request(ep, base_url=BASE, arguments={"name": "abc"}, injected=InjectedAuth())
    assert built.content == b'{"name":"abc"}'
    assert built.headers["Content-Type"] == "application/json"


def test_form_body_is_urlencoded() -> None:
    ep = _endpoint(method="post", body_style="form", binding={"name": {"location": "body"}})
    built = build_request(ep, base_url=BASE, arguments={"name": "a b"}, injected=InjectedAuth())
    assert built.content == b"name=a+b"
    assert built.headers["Content-Type"] == "application/x-www-form-urlencoded"


def test_injected_auth_header_wins_over_tool_header() -> None:
    ep = _endpoint(binding={"Authorization": {"location": "header"}})
    injected = InjectedAuth(headers={"Authorization": "Bearer real"})
    built = build_request(
        ep, base_url=BASE, arguments={"Authorization": "attacker"}, injected=injected
    )
    assert built.headers["Authorization"] == "Bearer real"


def test_injected_query_api_key_is_added_and_flagged() -> None:
    injected = InjectedAuth(
        query_params={"api_key": "secret"}, redact_query_keys=frozenset({"api_key"})
    )
    built = build_request(_endpoint(), base_url=BASE, arguments={}, injected=injected)
    assert parse_qs(urlsplit(built.url).query) == {"api_key": ["secret"]}
    assert built.redact_query_keys == frozenset({"api_key"})


def test_base_url_with_path_prefix_is_preserved() -> None:
    built = build_request(
        _endpoint(url="/things"),
        base_url="https://api.example.com/v2",
        arguments={},
        injected=InjectedAuth(),
    )
    assert built.url == "https://api.example.com/v2/things"


def test_malformed_endpoint_is_connector_error() -> None:
    with pytest.raises(UpstreamAPIError):
        build_request(
            {"method": "", "url": ""}, base_url=BASE, arguments={}, injected=InjectedAuth()
        )
