"""Guarded outbound HTTP egress — SSRF-safe fetching for the ingestion worker (M1.4-B0).

The Execution Runtime is the canonical "only egress" for *tenant* traffic (Bible §6.3,
SECURITY.md §6). Connector-spec ingestion is a *second, worker-only* egress class
(CONNECTOR_SPECIFICATION.md §18): it fetches an operator-supplied — and therefore
attacker-influenced — URL before any Connection or Credential exists. This module is the one
guarded fetcher that class uses. It exists and is proven *before* any importer consumes it.

Threat model and the properties this enforces (all fail-closed):

- **Scheme.** `https` only. `http` (the dev-flagged exception) is out of M1.4-B scope.
- **No embedded credentials.** A `user:pass@host` URL is refused, never sent.
- **DNS resolution is validated, and the validated IP is the one connected to.** A naive
  `resolve → validate → client.get(host)` re-resolves at connect time, leaving a TOCTOU a
  rebinding resolver exploits. Here a custom httpcore network backend resolves the host,
  validates *every* returned A/AAAA record, and connects to a *validated* IP — the same
  resolution that was checked is the one dialed. TLS still verifies the original hostname.
- **The blocklist covers IPv4 and IPv6, including the representations Python's stdlib misses
  on 3.11.** Loopback, link-local (incl. 169.254.169.254 cloud metadata), private, multicast,
  unspecified, and reserved are rejected — and IPv4-mapped (`::ffff:…`), NAT64 (`64:ff9b::/96`)
  and 6to4 (`2002::/16`) IPv6 forms are unwrapped to their embedded IPv4 and re-checked,
  because `ipaddress.is_private` does not unwrap NAT64/6to4.
- **Redirects are bounded and re-validated per hop** (no `https→http` downgrade; each hop's
  host is resolved+validated by the backend again).
- **`trust_env=False`.** An `HTTP(S)_PROXY` in the environment would perform its own DNS and
  connection, bypassing every check above; the guarded client never honors a proxy.
- **Response size is capped on *decompressed* bytes with a streaming early-abort**, and
  connect/read/total timeouts bound how long a hostile server can hold a worker.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Protocol
from urllib.parse import urlsplit

import anyio
import httpcore
import httpx

# ---- Policy constants (SECURITY.md §6, CONNECTOR_SPECIFICATION.md §11/§18) ----------------

#: Max fetched bytes after decompression. §11 caps raw specs at 10 MB.
MAX_RESPONSE_BYTES = 10 * 1024 * 1024
#: Redirect hops. §18 mandates re-validation per hop; an unbounded chain is itself an abuse.
MAX_REDIRECTS = 5
#: Timeouts (seconds): DNS+connect, per-read, and a total deadline (Architecture §7 = 30s).
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 15.0
TOTAL_TIMEOUT = 30.0


class SSRFError(Exception):
    """An egress request was refused by policy. Deliberately does not carry the raw URL,
    userinfo, or resolved address into the message a caller might log."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class Resolver(Protocol):
    """Host → list of (family, ip_str). Injectable so the validation and rebinding behaviour
    is testable without real DNS."""

    def __call__(self, host: str, port: int) -> list[tuple[int, str]]: ...


def _default_resolver(host: str, port: int) -> list[tuple[int, str]]:
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    # De-duplicate while preserving order; each entry is (family, sockaddr[0]).
    seen: dict[tuple[int, str], None] = {}
    for family, _type, _proto, _canon, sockaddr in infos:
        seen.setdefault((int(family), str(sockaddr[0])), None)
    return list(seen)


def _embedded_ipv4(addr: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 tunnelled inside an IPv6 address, if any — mapped, NAT64, or 6to4.

    `ipaddress` unwraps `::ffff:a.b.c.d` (via `.ipv4_mapped`) but NOT NAT64 (`64:ff9b::/96`)
    or 6to4 (`2002:AABB:CCDD::`), so a resolver returning `64:ff9b::a9fe:a9fe` (the metadata
    IP behind NAT64) slips past `is_private`. Extract those forms explicitly.
    """
    if addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    packed = addr.packed
    # NAT64 well-known prefix 64:ff9b::/96 → last 4 bytes are the IPv4.
    if packed[:12] == b"\x00\x64\xff\x9b" + b"\x00" * 8:
        return ipaddress.IPv4Address(packed[12:16])
    # 6to4 2002::/16 → bytes 2..6 are the IPv4.
    if packed[0:2] == b"\x20\x02":
        return ipaddress.IPv4Address(packed[2:6])
    return None


def _forbidden_reason(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """A category name if `addr` (or its embedded IPv4) is a non-routable/internal target,
    else None. Deny-by-default: anything not clearly a normal public unicast address loses."""
    if isinstance(addr, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(addr)
        if embedded is not None:
            # Validate the tunnelled IPv4 under the same rules (NAT64/6to4/mapped bypass).
            reason = _forbidden_reason(embedded)
            if reason is not None:
                return f"embedded-ipv4-{reason}"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:  # 169.254.0.0/16 and fe80::/10 — includes cloud metadata
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private:  # RFC1918, ULA fc00::/7, and other private ranges
        return "private"
    if addr.is_reserved:
        return "reserved"
    return None


def validate_public_ip(ip_str: str) -> None:
    """Raise `SSRFError` unless `ip_str` is a routable public unicast address."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError as exc:
        raise SSRFError("unresolvable-address") from exc
    reason = _forbidden_reason(addr)
    if reason is not None:
        raise SSRFError(f"blocked-{reason}")


def resolve_and_validate(host: str, port: int, resolver: Resolver = _default_resolver) -> str:
    """Resolve `host`, validate EVERY returned address, and return one validated IP to dial.

    Fail-closed twice over: an empty resolution is refused, and if *any* returned record is a
    forbidden target the whole host is refused (a rebinding resolver that mixes one public and
    one private answer cannot smuggle the private one through). The returned string is a
    literal IP that the caller connects to directly — closing the resolve→connect TOCTOU.
    """
    records = resolver(host, port)
    if not records:
        raise SSRFError("no-address")
    validated: list[str] = []
    for _family, ip_str in records:
        validate_public_ip(ip_str)  # raises on the first forbidden record
        validated.append(ip_str)
    return validated[0]


class _GuardedBackend(httpcore.AsyncNetworkBackend):
    """A network backend that resolves+validates+pins before connecting.

    `connect_tcp` receives the *hostname*; we resolve and validate it and hand the underlying
    backend a *validated IP*, so the connection lands on exactly the address that was checked.
    `start_tls` is untouched, so httpcore still verifies the certificate against the original
    hostname — IP-pinning does not weaken TLS.
    """

    def __init__(self, resolver: Resolver = _default_resolver) -> None:
        self._inner = httpcore.AnyIOBackend()
        self._resolver = resolver

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: object = None,
    ) -> httpcore.AsyncNetworkStream:
        validated_ip = await anyio.to_thread.run_sync(
            resolve_and_validate, host, port, self._resolver
        )
        return await self._inner.connect_tcp(
            validated_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,  # type: ignore[arg-type]
        )

    async def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: object = None
    ) -> httpcore.AsyncNetworkStream:
        # No unix-socket egress is ever legitimate for spec fetching.
        raise SSRFError("unix-socket-forbidden")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class GuardedTransport(httpx.AsyncHTTPTransport):
    """An httpx transport whose connection pool uses `_GuardedBackend` and never trusts env
    proxies. Redirects are handled by the caller (`fetch`), not the transport."""

    def __init__(self, resolver: Resolver = _default_resolver) -> None:
        super().__init__(trust_env=False, retries=0)
        self._pool = httpcore.AsyncConnectionPool(
            network_backend=_GuardedBackend(resolver),
            retries=0,
        )


def _validate_url(url: str, *, previous_scheme: str | None) -> tuple[str, int]:
    """Enforce scheme/userinfo policy on a URL (initial or redirect target). Returns
    (host, port). Raises `SSRFError` on any violation."""
    parts = urlsplit(url)
    if parts.scheme != "https":
        # Covers http (incl. an https→http downgrade on redirect) and anything exotic.
        raise SSRFError("scheme-not-https")
    if previous_scheme == "https" and parts.scheme != "https":
        raise SSRFError("https-downgrade")
    if parts.username or parts.password or "@" in (parts.netloc or ""):
        raise SSRFError("embedded-credentials")
    host = parts.hostname
    if not host:
        raise SSRFError("no-host")
    return host, parts.port or 443


async def fetch(
    url: str,
    *,
    max_bytes: int = MAX_RESPONSE_BYTES,
    resolver: Resolver = _default_resolver,
    transport: httpx.AsyncBaseTransport | None = None,
) -> bytes:
    """Fetch `url` under the full egress policy and return the decompressed body bytes.

    Manual, bounded redirect handling so every hop is re-validated (scheme, credentials) and
    re-resolved+re-validated by the guarded backend. The body is streamed and aborted the
    moment it exceeds `max_bytes` *after* content-decoding, so a decompression bomb costs one
    capped read, not memory. Every failure path raises `SSRFError` or an `httpx` timeout —
    never a partial/oversized body.
    """
    timeout = httpx.Timeout(TOTAL_TIMEOUT, connect=CONNECT_TIMEOUT, read=READ_TIMEOUT)
    current = url
    previous_scheme: str | None = None
    # `transport` is a test seam: production always uses the guarded, IP-pinning transport;
    # a test may pass httpx.MockTransport to exercise the redirect/size loop deterministically
    # (the SSRF resolve+validate below still runs, so tests cannot bypass it).
    async with httpx.AsyncClient(
        transport=transport or GuardedTransport(resolver),
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        for _hop in range(MAX_REDIRECTS + 1):
            host, port = _validate_url(current, previous_scheme=previous_scheme)
            previous_scheme = "https"
            # Early, clean-erroring resolve+validate for a precise SSRFError. The guarded
            # backend re-resolves and validates again at connect time and pins the IP it
            # checks, so this pre-check is a fast fail, never the authoritative control — a
            # rebinding answer that flips after this line is still refused at connect.
            resolve_and_validate(host, port, resolver)
            async with client.stream("GET", current) as response:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        raise SSRFError("redirect-without-location")
                    current = str(response.url.join(location))
                    continue
                response.raise_for_status()
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > max_bytes:
                        raise SSRFError("response-too-large")
                return bytes(body)
    raise SSRFError("too-many-redirects")


__all__ = [
    "MAX_REDIRECTS",
    "MAX_RESPONSE_BYTES",
    "GuardedTransport",
    "SSRFError",
    "fetch",
    "resolve_and_validate",
    "validate_public_ip",
]
