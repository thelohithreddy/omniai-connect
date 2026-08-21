"""Guarded outbound HTTP egress — the one SSRF-safe network policy for the whole platform.

Two egress classes share this module's guard machinery, so there is exactly one place where the
scheme/credential/DNS-rebinding/private-IP/redirect/size/timeout controls live (Bible §6.3,
SECURITY.md §6):

- **`fetch`** — connector-spec ingestion (M1.4-B0, CONNECTOR_SPECIFICATION.md §18): a GET of an
  operator-supplied — therefore attacker-influenced — URL, before any Connection or Credential
  exists. GET only, returns bytes, hard-fails on oversize.
- **`request`** — the Execution Runtime's tenant egress (M1, AI_RUNTIME.md §2 stage 5): an arbitrary
  method with injected credential headers + body against a Connection's allowlisted host, returning
  status + headers + a size-capped (truncated, not failed) body for LLM-facing normalization.

Both run the identical guard: `_validate_url` (https-only, no `user:pass@`), `resolve_and_validate`
(every A/AAAA record checked), and the IP-pinning `GuardedTransport`. `request` also enforces
a per-call host allowlist on every hop (the runtime's per-Connection egress boundary, §7). Neither
honors an environment proxy. This module exists and is proven *before* any caller consumes it.

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
from collections.abc import Mapping
from dataclasses import dataclass
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
    try:
        records = resolver(host, port)
    except socket.gaierror as exc:
        # M2.4-pre: a host that does not resolve (NXDOMAIN, DNS failure) is an egress-policy
        # refusal like every other unresolvable target — never a raw OS error escaping the
        # taxonomy as an unaudited 500. Same fail-closed shape as a malformed literal address.
        raise SSRFError("unresolvable-address") from exc
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


def _host_allowed(host: str, allowed_hosts: frozenset[str] | None) -> None:
    """Raise `SSRFError` unless `host` is in the per-call allowlist. `None` means no allowlist
    (ingestion's model); an *empty* set allows nothing (fail-closed). Comparison is case-folded."""
    if allowed_hosts is None:
        return
    if host.lower() not in allowed_hosts:
        raise SSRFError("host-not-allowlisted")


@dataclass(frozen=True, slots=True)
class GuardedResponse:
    """The outcome of a guarded outbound request. `body` is decompressed and capped at `max_bytes`;
    `truncated` is True when the upstream body was longer and got cut (never an error — the runtime
    normalizes/truncates, unlike ingestion which hard-fails). Carries no request-side secrets."""

    status_code: int
    headers: httpx.Headers
    body: bytes
    truncated: bool


async def request(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    content: bytes | None = None,
    allowed_hosts: frozenset[str] | None = None,
    max_bytes: int = MAX_RESPONSE_BYTES,
    resolver: Resolver = _default_resolver,
    transport: httpx.AsyncBaseTransport | None = None,
) -> GuardedResponse:
    """Issue one guarded outbound request under the full egress policy (AI_RUNTIME.md §2 stage 5).

    Identical guard to `fetch` — https-only, no embedded credentials, resolve-and-validate every
    record, IP-pinned connect, per-hop redirect re-validation, `trust_env=False`, bounded redirects,
    connect/read/total timeouts — plus a per-call **host allowlist** enforced on the initial target
    *and every redirect hop* (the runtime's per-Connection egress boundary, §7): a redirect that
    leaves the allowlist is refused, which also means an injected credential header can never follow
    a redirect to a foreign host. The response body is streamed and capped at `max_bytes` *after*
    content-decoding; exceeding the cap truncates (with `truncated=True`), it does not raise.

    Every egress-policy violation raises `SSRFError`; a slow/hung upstream raises an `httpx`
    timeout.
    Neither the exception nor the returned value ever carries the injected request headers or body.
    """
    timeout = httpx.Timeout(TOTAL_TIMEOUT, connect=CONNECT_TIMEOUT, read=READ_TIMEOUT)
    current = url
    previous_scheme: str | None = None
    request_headers = dict(headers or {})
    async with httpx.AsyncClient(
        transport=transport or GuardedTransport(resolver),
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        for _hop in range(MAX_REDIRECTS + 1):
            host, port = _validate_url(current, previous_scheme=previous_scheme)
            previous_scheme = "https"
            _host_allowed(host, allowed_hosts)
            # Fast, clean-erroring pre-check; the guarded backend re-resolves + validates + pins at
            # connect, so a rebinding answer that flips after this line is still refused.
            resolve_and_validate(host, port, resolver)
            async with client.stream(
                method, current, headers=request_headers, content=content
            ) as response:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        raise SSRFError("redirect-without-location")
                    current = str(response.url.join(location))
                    continue
                body = bytearray()
                truncated = False
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > max_bytes:
                        del body[max_bytes:]  # keep exactly the budget; drop the overflow
                        truncated = True
                        break
                return GuardedResponse(
                    status_code=response.status_code,
                    headers=response.headers,
                    body=bytes(body),
                    truncated=truncated,
                )
    raise SSRFError("too-many-redirects")


__all__ = [
    "MAX_REDIRECTS",
    "MAX_RESPONSE_BYTES",
    "GuardedResponse",
    "GuardedTransport",
    "SSRFError",
    "fetch",
    "request",
    "resolve_and_validate",
    "validate_public_ip",
]
