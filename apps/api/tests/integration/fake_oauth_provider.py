"""A deterministic RFC 6749 / RFC 7636-conformant fake OAuth provider (M2.5, D4).

Mounted at the **outermost socket** (`app.core.net.request`) — the only boundary the M2.4 testing
standard permits mocking. Everything above it (state consumption, PKCE verification on our side,
vault sealing, connection lifecycle, RLS) is the real production path.

A real provider cannot be made to rotate refresh tokens, omit fields, return 5xx, or go offline on
demand; this one can, which is why D4 makes it the automated-test vehicle and leaves the live
provider a product configuration. It validates the parts of the protocol that protect us:

- `grant_type` must be one we actually send;
- `code` must be one it issued, unexpired and unused (single-use, like a real provider);
- `code_verifier` must S256-hash to the challenge captured at authorize time (RFC 7636 §4.6) —
  so a wrong or missing verifier fails here exactly as it would in production;
- `redirect_uri` must equal the one from the authorization request (RFC 6749 §4.1.3).
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

from app.core import net


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@dataclass
class IssuedCode:
    challenge: str
    redirect_uri: str
    used: bool = False


@dataclass
class FakeOAuthProvider:
    """Records what we sent it and returns what a conformant provider would."""

    codes: dict[str, IssuedCode] = field(default_factory=dict)
    valid_refresh_tokens: set[str] = field(default_factory=set)
    #: Recorded (grant_type, form) pairs — lets a test assert what actually went on the wire.
    exchanges: list[tuple[str, dict[str, str]]] = field(default_factory=list)
    #: When True, every refresh returns a NEW refresh token (rotation), invalidating the old one.
    rotate_refresh_tokens: bool = False
    #: Override the next response entirely: (status_code, raw_body).
    next_response: tuple[int, bytes] | None = None
    #: Raise this instead of responding (timeouts, SSRF refusals, transport errors).
    raise_error: Exception | None = None
    access_token_value: str = "fake-access-token"  # noqa: S105 (test fixture)
    expires_in: int = 3600

    # ---------------------------------------------------------------- authorization endpoint side
    def issue_code(self, authorize_url: str) -> str:
        """Simulate the user consenting: capture the challenge and mint a single-use code."""
        params = parse_qs(urlsplit(authorize_url).query)
        assert params["response_type"] == ["code"]
        assert params["code_challenge_method"] == ["S256"], "server must not offer plain PKCE"
        code = secrets.token_urlsafe(16)
        self.codes[code] = IssuedCode(
            challenge=params["code_challenge"][0], redirect_uri=params["redirect_uri"][0]
        )
        return code

    @staticmethod
    def state_from(authorize_url: str) -> str:
        return parse_qs(urlsplit(authorize_url).query)["state"][0]

    # --------------------------------------------------------------------- token endpoint side
    def _token_body(self, *, refresh_token: str | None) -> bytes:
        payload: dict[str, Any] = {
            "access_token": self.access_token_value,
            "token_type": "Bearer",
            "expires_in": self.expires_in,
            "scope": "read write",
        }
        if refresh_token is not None:
            payload["refresh_token"] = refresh_token
            self.valid_refresh_tokens.add(refresh_token)
        return json.dumps(payload).encode()

    def _error(self, code: str, status: int = 400) -> net.GuardedResponse:
        # RFC 6749 §5.2 — deliberately verbose, to prove we never surface a provider body.
        body = json.dumps(
            {"error": code, "error_description": f"SENSITIVE-PROVIDER-DETAIL:{code}"}
        ).encode()
        return net.GuardedResponse(
            status_code=status,
            headers=httpx.Headers({"content-type": "application/json"}),
            body=body,
            truncated=False,
        )

    async def __call__(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        allowed_hosts: frozenset[str] | None = None,
        max_bytes: int = 0,
        **_: object,
    ) -> net.GuardedResponse:
        if self.raise_error is not None:
            raise self.raise_error
        if self.next_response is not None:
            status, body = self.next_response
            self.next_response = None
            return net.GuardedResponse(
                status_code=status,
                headers=httpx.Headers({"content-type": "application/json"}),
                body=body,
                truncated=False,
            )

        form = {k: v[0] for k, v in parse_qs((content or b"").decode()).items()}
        grant = form.get("grant_type", "")
        self.exchanges.append((grant, form))

        if grant == "authorization_code":
            issued = self.codes.get(form.get("code", ""))
            if issued is None or issued.used:
                return self._error("invalid_grant")
            verifier = form.get("code_verifier")
            if not verifier:
                return self._error("invalid_request")  # PKCE is mandatory here
            if _b64url(hashlib.sha256(verifier.encode()).digest()) != issued.challenge:
                return self._error("invalid_grant")  # RFC 7636 §4.6 verification failed
            if form.get("redirect_uri") != issued.redirect_uri:
                return self._error("invalid_grant")  # RFC 6749 §4.1.3
            issued.used = True
            return net.GuardedResponse(
                status_code=200,
                headers=httpx.Headers({"content-type": "application/json"}),
                body=self._token_body(refresh_token=secrets.token_urlsafe(16)),
                truncated=False,
            )

        if grant == "refresh_token":
            presented = form.get("refresh_token", "")
            if presented not in self.valid_refresh_tokens:
                return self._error("invalid_grant")
            if self.rotate_refresh_tokens:
                self.valid_refresh_tokens.discard(presented)  # old one dies on rotation
                return net.GuardedResponse(
                    status_code=200,
                    headers=httpx.Headers({"content-type": "application/json"}),
                    body=self._token_body(refresh_token=secrets.token_urlsafe(16)),
                    truncated=False,
                )
            return net.GuardedResponse(
                status_code=200,
                headers=httpx.Headers({"content-type": "application/json"}),
                body=self._token_body(refresh_token=None),
                truncated=False,
            )

        return self._error("unsupported_grant_type")


__all__ = ["FakeOAuthProvider", "IssuedCode"]
