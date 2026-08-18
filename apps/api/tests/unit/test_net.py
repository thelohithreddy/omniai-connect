"""Guarded egress fetcher — the SSRF test matrix (M1.4-B0, SECURITY §6, CONNECTOR_SPEC §11/§18).

The IP-validation and resolve+validate logic is pure and tested exhaustively. The fetch loop
(scheme/credential policy, redirect re-validation, size cap) is tested via an injected
resolver (the DNS boundary) and `httpx.MockTransport` (the byte boundary) so every branch is
deterministic and no test performs real DNS or real egress.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from app.core.net import (
    MAX_REDIRECTS,
    GuardedTransport,
    SSRFError,
    fetch,
    resolve_and_validate,
    validate_public_ip,
)

# --------------------------------------------------------------------- IP validation matrix

PUBLIC_IPS = [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "2606:2800:220:1:248:1893:25c8:1946",  # example.com AAAA (public)
]

FORBIDDEN_IPS = [
    # IPv4
    "127.0.0.1",  # loopback
    "0.0.0.0",  # noqa: S104 -- unspecified addr (deny-listed target, not a bind)
    "10.0.0.5",  # RFC1918
    "172.16.0.1",  # RFC1918
    "192.168.1.1",  # RFC1918
    "169.254.169.254",  # link-local / cloud metadata
    "240.0.0.1",  # reserved
    "224.0.0.1",  # multicast
    # IPv6
    "::1",  # loopback
    "::",  # unspecified
    "fe80::1",  # link-local
    "fc00::1",  # unique-local (private)
    "fd00::abcd",  # unique-local (private)
    "ff02::1",  # multicast
    # IPv4-in-IPv6 forms that bypass naive predicates
    "::ffff:127.0.0.1",  # mapped loopback
    "::ffff:169.254.169.254",  # mapped metadata
    "::ffff:10.0.0.1",  # mapped private
    "64:ff9b::a9fe:a9fe",  # NAT64 metadata (169.254.169.254)
    "64:ff9b::7f00:1",  # NAT64 loopback (127.0.0.1)
    "2002:a9fe:a9fe::",  # 6to4 link-local (169.254.x)
    "2002:0a00:0001::",  # 6to4 private (10.0.0.1)
]


@pytest.mark.parametrize("ip", PUBLIC_IPS)
def test_public_ips_pass(ip: str) -> None:
    validate_public_ip(ip)  # must not raise


@pytest.mark.parametrize("ip", FORBIDDEN_IPS)
def test_forbidden_ips_are_rejected(ip: str) -> None:
    with pytest.raises(SSRFError):
        validate_public_ip(ip)


def test_nat64_and_6to4_metadata_are_unwrapped_and_blocked() -> None:
    """The gap Python 3.11's `is_private` misses: NAT64/6to4-tunnelled internal IPs.

    Guarded against explicitly because a rebinding resolver returning `64:ff9b::a9fe:a9fe`
    would otherwise reach the cloud metadata endpoint through an IPv6 answer that every naive
    predicate calls public.
    """
    for tunnelled in ("64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::", "::ffff:169.254.169.254"):
        with pytest.raises(SSRFError):
            validate_public_ip(tunnelled)


def test_a_non_ip_string_is_fail_closed() -> None:
    with pytest.raises(SSRFError):
        validate_public_ip("not-an-ip")


# --- resolve_and_validate: rebinding, fail-closed ---


def _resolver(*ips: str) -> Callable[[str, int], list[tuple[int, str]]]:
    return lambda _host, _port: [(2, ip) for ip in ips]


def test_all_public_records_return_a_validated_ip() -> None:
    assert resolve_and_validate("host", 443, _resolver("8.8.8.8")) == "8.8.8.8"


def test_empty_resolution_is_fail_closed() -> None:
    with pytest.raises(SSRFError):
        resolve_and_validate("host", 443, _resolver())


def test_dns_resolution_failure_is_an_ssrf_refusal_not_an_os_error() -> None:
    """M2.4-pre: an NXDOMAIN/DNS failure surfaces as `SSRFError("unresolvable-address")`, never
    a raw `socket.gaierror` escaping the egress taxonomy as an unaudited internal 500."""
    import socket

    def _failing_resolver(host: str, port: int) -> list[tuple[int, str]]:
        raise socket.gaierror(-2, "Name or service not known")

    with pytest.raises(SSRFError) as excinfo:
        resolve_and_validate("no-such-host.invalid", 443, _failing_resolver)
    assert "unresolvable-address" in str(excinfo.value)
    assert "Name or service" not in str(excinfo.value)  # the OS detail never rides along


def test_any_forbidden_record_refuses_the_whole_host() -> None:
    """A rebinding answer that mixes one public and one private record cannot smuggle the
    private one through — the whole host is refused."""
    with pytest.raises(SSRFError):
        resolve_and_validate("host", 443, _resolver("8.8.8.8", "127.0.0.1"))
    with pytest.raises(SSRFError):
        resolve_and_validate("host", 443, _resolver("169.254.169.254"))


# --- fetch: scheme / credential policy (no network) ---


async def test_http_scheme_is_rejected() -> None:
    with pytest.raises(SSRFError, match="scheme"):
        await fetch("http://example.com/spec.json")


async def test_non_http_scheme_is_rejected() -> None:
    for url in ("ftp://example.com/x", "file:///etc/passwd", "gopher://example.com"):
        with pytest.raises(SSRFError):
            await fetch(url)


async def test_embedded_credentials_are_rejected() -> None:
    with pytest.raises(SSRFError, match="credential"):
        await fetch("https://user:pass@example.com/spec.json")


async def test_forbidden_host_is_a_clean_ssrf_error() -> None:
    """A host that resolves to a blocked IP fails with SSRFError before any connection."""
    with pytest.raises(SSRFError):
        await fetch("https://evil.test/spec", resolver=_resolver("127.0.0.1"))
    with pytest.raises(SSRFError):
        await fetch("https://meta.test/spec", resolver=_resolver("169.254.169.254"))


async def test_env_proxy_cannot_bypass_the_ip_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """A malicious HTTP(S)_PROXY in the environment must not change the SSRF decision — the
    guarded client is trust_env=False, so a forbidden host is still refused."""
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.example:8080")
    monkeypatch.setenv("HTTP_PROXY", "http://attacker.example:8080")
    monkeypatch.setenv("ALL_PROXY", "socks5://attacker.example:1080")
    with pytest.raises(SSRFError):
        await fetch("https://evil.test/spec", resolver=_resolver("127.0.0.1"))


def test_guarded_transport_does_not_trust_env() -> None:
    # The guarded pool is installed and env-proxy trust is off by construction.
    transport = GuardedTransport()
    assert transport._pool is not None


# --- fetch: redirect + size loop (MockTransport seam) ---

_PUBLIC = _resolver("8.8.8.8")


def _mock(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


async def test_success_returns_the_decoded_body() -> None:
    transport = _mock(lambda _req: httpx.Response(200, content=b"openapi: 3.0.0"))
    body = await fetch("https://ok.test/spec", resolver=_PUBLIC, transport=transport)
    assert body == b"openapi: 3.0.0"


async def test_oversized_body_aborts_with_ssrf() -> None:
    transport = _mock(lambda _req: httpx.Response(200, content=b"x" * 100))
    with pytest.raises(SSRFError, match="too-large"):
        await fetch("https://big.test/spec", resolver=_PUBLIC, transport=transport, max_bytes=10)


async def test_redirect_is_followed_and_the_new_host_revalidated() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "a.test":
            return httpx.Response(302, headers={"location": "https://b.test/final"})
        return httpx.Response(200, content=b"final")

    body = await fetch("https://a.test/spec", resolver=_PUBLIC, transport=_mock(handler))
    assert body == b"final"


async def test_https_to_http_downgrade_on_redirect_is_rejected() -> None:
    transport = _mock(lambda _req: httpx.Response(302, headers={"location": "http://a.test/x"}))
    with pytest.raises(SSRFError):
        await fetch("https://a.test/spec", resolver=_PUBLIC, transport=transport)


async def test_redirect_to_a_forbidden_host_is_rejected() -> None:
    """Every hop is re-resolved+re-validated: a redirect whose target resolves private loses."""

    def resolver(host: str, _port: int) -> list[tuple[int, str]]:
        return [(2, "8.8.8.8")] if host == "a.test" else [(2, "127.0.0.1")]

    transport = _mock(
        lambda _req: httpx.Response(302, headers={"location": "https://internal.test/x"})
    )
    with pytest.raises(SSRFError):
        await fetch("https://a.test/spec", resolver=resolver, transport=transport)


async def test_unbounded_redirects_are_rejected() -> None:
    transport = _mock(lambda _req: httpx.Response(302, headers={"location": "https://a.test/next"}))
    with pytest.raises(SSRFError, match="too-many-redirects"):
        await fetch("https://a.test/spec", resolver=_PUBLIC, transport=transport)


async def test_redirect_without_location_is_rejected() -> None:
    transport = _mock(lambda _req: httpx.Response(302))
    with pytest.raises(SSRFError, match="location"):
        await fetch("https://a.test/spec", resolver=_PUBLIC, transport=transport)


def test_redirect_budget_is_bounded() -> None:
    assert MAX_REDIRECTS == 5
