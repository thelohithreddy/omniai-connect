"""Token-endpoint exchange (M2.5, ADR-0038) — a new destination, never a new egress boundary.

Every provider call goes through `core.net.request`, the same guarded egress the Execution
Runtime uses: https-only, no embedded credentials, resolve-and-validate every DNS record,
IP-pinned connect, per-hop redirect re-validation with a **host allowlist pinned to the token
endpoint**, `trust_env=False`, bounded timeouts, and a size-capped body. There is no second HTTP
client and no second SSRF implementation — a redirect off the token host is refused, which also
means the exchange's form body can never follow a redirect to a foreign host.

Provider differences are **data** (`auth_config.quirks`), never code branches
(CONNECTOR_SPECIFICATION §215): `expires_in_field` and `scope_separator` are read from quirks
with RFC defaults. A provider needing something genuinely new is a config entry plus a fixture.

Nothing here logs or returns a token, a code, or a verifier: failures raise a stable domain error
whose message names the failure class only, never the provider's response body or URL.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urlencode, urlsplit

import httpx

from app.core import net
from app.core.exceptions import EgressBlockedError, UpstreamAPIError
from app.core.logging import get_logger
from app.domains.connectors.oauth_config import OAuthConfig

log = get_logger(__name__)

#: Token responses are small; anything larger is a misbehaving or hostile endpoint.
MAX_TOKEN_RESPONSE_BYTES: Final = 64 * 1024
#: RFC 6749 §5.1 default expiry when a provider omits `expires_in`, kept deliberately short so a
#: silent omission cannot pin a token as "fresh" for a long time.
DEFAULT_EXPIRES_IN_SECONDS: Final = 3600
_FORM_CONTENT_TYPE: Final = "application/x-www-form-urlencoded"


@dataclass(frozen=True, repr=False, slots=True)
class TokenSet:
    """A validated token response. `repr` is redacted — tokens never render into logs."""

    access_token: str
    refresh_token: str | None
    token_type: str
    scope: str | None
    expires_in: int

    def __repr__(self) -> str:  # never leak tokens through repr / f-strings / tracebacks
        return "<TokenSet redacted>"


def _token_host(config: OAuthConfig) -> str:
    host = urlsplit(config.token_url).hostname
    if not host:  # unreachable: validated at Connector save, re-asserted here
        raise UpstreamAPIError("The provider token endpoint is not usable.")
    return host.lower()


def _quirk(config: OAuthConfig, key: str, default: Any) -> Any:
    value = config.quirks.get(key)
    return default if value is None else value


def _parse_token_response(body: bytes, config: OAuthConfig) -> TokenSet:
    """Validate an RFC 6749 §5.1 token response. Every rejection is a stable, body-free error."""
    try:
        payload = json.loads(body)
    except ValueError:
        raise UpstreamAPIError("The provider returned a malformed token response.") from None
    if not isinstance(payload, dict):
        raise UpstreamAPIError("The provider returned a malformed token response.")

    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise UpstreamAPIError("The provider response did not include an access token.")

    token_type = payload.get("token_type")
    # RFC 6749 §7.1: type is case-insensitive; only Bearer is injectable by this runtime.
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        raise UpstreamAPIError("The provider returned an unsupported token type.")

    refresh_token = payload.get("refresh_token")
    if refresh_token is not None and (not isinstance(refresh_token, str) or not refresh_token):
        raise UpstreamAPIError("The provider returned a malformed refresh token.")

    expires_field = str(_quirk(config, "expires_in_field", "expires_in"))
    raw_expiry = payload.get(expires_field, DEFAULT_EXPIRES_IN_SECONDS)
    try:
        expires_in = int(raw_expiry)
    except (TypeError, ValueError):
        raise UpstreamAPIError("The provider returned an invalid token expiry.") from None
    if expires_in <= 0:
        raise UpstreamAPIError("The provider returned an invalid token expiry.")

    scope = payload.get("scope")
    if scope is not None and not isinstance(scope, str):
        raise UpstreamAPIError("The provider returned a malformed scope.")

    return TokenSet(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="Bearer",  # noqa: S106 (an RFC 6749 token TYPE, not a secret)
        scope=scope,
        expires_in=expires_in,
    )


async def _post_token_endpoint(config: OAuthConfig, form: dict[str, str]) -> TokenSet:
    """POST the form to the token endpoint through the canonical guarded egress."""
    body = urlencode(form).encode("ascii")
    try:
        response = await net.request(
            "POST",
            config.token_url,
            headers={"Content-Type": _FORM_CONTENT_TYPE, "Accept": "application/json"},
            content=body,
            allowed_hosts=frozenset({_token_host(config)}),
            max_bytes=MAX_TOKEN_RESPONSE_BYTES,
        )
    except net.SSRFError:
        # Egress policy refused the provider endpoint (private/link-local/metadata target, an
        # off-allowlist redirect, an https downgrade, or an unresolvable host). Mapped to the
        # canonical `ssrf_blocked` domain error — the same translation `runtime/egress.py`
        # performs — so it travels as a typed DomainError instead of escaping as a 500. The
        # message never carries the target or the resolved address.
        raise EgressBlockedError("The outbound request was blocked by egress policy.") from None
    except httpx.TimeoutException:
        raise UpstreamAPIError("The provider did not respond in time.") from None
    except httpx.HTTPError:
        raise UpstreamAPIError("The provider could not be reached.") from None

    if not 200 <= response.status_code < 300:
        # RFC 6749 §5.2 error bodies routinely echo request parameters; never surface the body.
        log.warning("oauth.token_endpoint_error", status=response.status_code)
        raise UpstreamAPIError("The provider rejected the token request.")
    if response.truncated:
        raise UpstreamAPIError("The provider returned an oversized token response.")
    return _parse_token_response(response.body, config)


async def exchange_authorization_code(
    config: OAuthConfig, *, code: str, code_verifier: str, redirect_uri: str
) -> TokenSet:
    """Exchange an authorization code for a token set (RFC 6749 §4.1.3 + RFC 7636 §4.5).

    `redirect_uri` is replayed from the **stored state row**, not from the callback request, as
    §4.1.3 requires it to match the authorization request exactly.
    """
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    if config.client_id:
        # RFC 6749 §3.2.1: a public client identifies itself with client_id in the token request.
        form["client_id"] = config.client_id
    return await _post_token_endpoint(config, form)


async def refresh_access_token(config: OAuthConfig, *, refresh_token: str) -> TokenSet:
    """Redeem a refresh token for a new token set (RFC 6749 §6).

    A provider that rotates refresh tokens returns a new one; the caller must persist whatever
    comes back. When the response omits `refresh_token`, RFC 6749 §6 says the existing one stays
    valid — the caller preserves it rather than dropping it.
    """
    form = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    if config.client_id:
        form["client_id"] = config.client_id
    return await _post_token_endpoint(config, form)


def build_authorize_url(
    config: OAuthConfig, *, state: str, code_challenge: str, redirect_uri: str
) -> str:
    """Construct the provider authorization URL (RFC 6749 §4.1.1 + RFC 7636 §4.3)."""
    from app.domains.oauth.state import CODE_CHALLENGE_METHOD

    separator = str(_quirk(config, "scope_separator", " "))
    params = {
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": CODE_CHALLENGE_METHOD,
    }
    if config.client_id:
        params["client_id"] = config.client_id
    if config.scopes:
        params["scope"] = separator.join(config.scopes)
    joiner = "&" if urlsplit(config.authorization_url).query else "?"
    return f"{config.authorization_url}{joiner}{urlencode(params)}"


__all__ = [
    "DEFAULT_EXPIRES_IN_SECONDS",
    "MAX_TOKEN_RESPONSE_BYTES",
    "TokenSet",
    "build_authorize_url",
    "exchange_authorization_code",
    "refresh_access_token",
]
