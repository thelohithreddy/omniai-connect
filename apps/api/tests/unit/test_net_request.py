"""Guarded general egress — `net.request` (M1 Execution Runtime, SECURITY §6, AI_RUNTIME §7).

Same seam discipline as the `fetch` suite: an injected resolver is the DNS boundary and
`httpx.MockTransport` is the byte boundary, so every branch — method/headers/body, the host
allowlist, redirect re-validation, and the truncation cap — is deterministic with no real egress.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from app.core.net import SSRFError, request


def _resolver(*ips: str) -> Callable[[str, int], list[tuple[int, str]]]:
    return lambda _host, _port: [(2, ip) for ip in ips]


_PUBLIC = _resolver("8.8.8.8")
_ALLOW = frozenset({"api.test"})


def _mock(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


async def test_method_headers_and_body_reach_the_transport() -> None:
    seen: dict[str, object] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["method"] = req.method
        seen["auth"] = req.headers.get("authorization")
        seen["body"] = req.content
        return httpx.Response(200, json={"ok": True})

    resp = await request(
        "POST",
        "https://api.test/things",
        headers={"Authorization": "Bearer tok"},
        content=b'{"a":1}',
        allowed_hosts=_ALLOW,
        resolver=_PUBLIC,
        transport=_mock(handler),
    )
    assert resp.status_code == 200
    assert seen == {"method": "POST", "auth": "Bearer tok", "body": b'{"a":1}'}


async def test_private_ip_target_is_blocked() -> None:
    with pytest.raises(SSRFError):
        await request(
            "GET",
            "https://api.test/x",
            allowed_hosts=_ALLOW,
            resolver=_resolver("127.0.0.1"),
            transport=_mock(lambda r: httpx.Response(200)),
        )


async def test_off_allowlist_host_is_blocked() -> None:
    with pytest.raises(SSRFError):
        await request(
            "GET",
            "https://evil.test/x",
            allowed_hosts=_ALLOW,
            resolver=_PUBLIC,
            transport=_mock(lambda r: httpx.Response(200)),
        )


async def test_http_scheme_is_rejected() -> None:
    with pytest.raises(SSRFError):
        await request("GET", "http://api.test/x", allowed_hosts=_ALLOW, resolver=_PUBLIC)


async def test_embedded_credentials_are_rejected() -> None:
    with pytest.raises(SSRFError):
        await request("GET", "https://u:p@api.test/x", allowed_hosts=_ALLOW, resolver=_PUBLIC)


async def test_redirect_off_allowlist_is_refused() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.test/next"})

    with pytest.raises(SSRFError):
        await request(
            "GET",
            "https://api.test/x",
            allowed_hosts=_ALLOW,
            resolver=_PUBLIC,
            transport=_mock(handler),
        )


async def test_same_host_redirect_is_followed() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/x":
            return httpx.Response(302, headers={"location": "https://api.test/final"})
        return httpx.Response(200, text="done")

    resp = await request(
        "GET",
        "https://api.test/x",
        allowed_hosts=_ALLOW,
        resolver=_PUBLIC,
        transport=_mock(handler),
    )
    assert resp.body == b"done"


async def test_oversized_body_is_truncated_not_errored() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 100)

    resp = await request(
        "GET",
        "https://api.test/x",
        allowed_hosts=_ALLOW,
        resolver=_PUBLIC,
        transport=_mock(handler),
        max_bytes=10,
    )
    assert resp.truncated is True
    assert len(resp.body) == 10


async def test_https_to_http_downgrade_on_redirect_is_rejected() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://api.test/next"})

    with pytest.raises(SSRFError):
        await request(
            "GET",
            "https://api.test/x",
            allowed_hosts=_ALLOW,
            resolver=_PUBLIC,
            transport=_mock(handler),
        )
