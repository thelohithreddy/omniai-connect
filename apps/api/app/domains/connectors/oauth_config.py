"""OAuth 2.0 provider configuration on a Connector (M2.5, ADR-0038).

`connectors.auth_config` declares *requirements*, never secret values (CONNECTOR_SPECIFICATION
§5 binding rule at line 219). For `oauth2` the canonical public fields are exactly
`authorization_url`, `token_url`, `scopes`, plus `quirks` — provider differences are **declared
data, never provider `if`-ladders in code** (§215).

Two security properties are enforced here, at definition time:

1. **Provider endpoints are SSRF-linted through the one canonical lint** — `validate_base_url`,
   the same function that guards a Connector's `base_url` (§11, SECURITY §6). There is no second
   validator. The runtime independently re-validates at egress time (`core/net`), so a lint
   bypass is never by itself a compromise — this is the definition-time half of the same
   two-layer defense M1 established.
2. **Secret material can never enter public configuration.** `auth_config` is returned by
   `GET /v1/connectors` as metadata; a `client_secret` placed there would be published to every
   member who can read a Connector. It is refused outright rather than silently stripped.

**Grant scope (founder-ratified D3):** M2.5 implements `authorization_code` only.
`client_credentials` remains M2/P1 and is refused with an explicit message — never silently
accepted and half-honored.

**Client type:** §215's auth-code contract names only `authorization_url`/`token_url`/`scopes`
— no client secret — so M2.5 speaks the RFC 6749 §2.1 *public client* profile, where PKCE S256
(RFC 7636) is the proof-of-possession that replaces a client secret. `client_id` is public by
definition (RFC 6749 §2.2) and may be declared here; it is required in the token request for a
public client (§3.2.1). Confidential-client support would need a canonical home for the secret
that canon does not currently define for this grant — see ADR-0038 "Deferred".
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from app.core.exceptions import ValidationFailedError

OAUTH2_TYPE: Final = "oauth2"
GRANT_AUTHORIZATION_CODE: Final = "authorization_code"
#: D3: only the authorization-code grant ships in M2.5.
SUPPORTED_GRANTS: Final[tuple[str, ...]] = (GRANT_AUTHORIZATION_CODE,)

#: Keys that would publish secret material through a metadata surface. Refused, never stripped.
FORBIDDEN_CONFIG_KEYS: Final[frozenset[str]] = frozenset(
    {"client_secret", "access_token", "refresh_token", "password", "private_key", "secret"}
)

# Bounds keep a hostile Connector definition from producing an unbounded authorize URL.
MAX_SCOPES: Final = 64
MAX_SCOPE_LENGTH: Final = 256


@dataclass(frozen=True, slots=True)
class OAuthConfig:
    """The validated, non-secret OAuth provider configuration of a Connector."""

    authorization_url: str
    token_url: str
    scopes: tuple[str, ...]
    client_id: str | None
    quirks: Mapping[str, Any]


def is_oauth2(auth_config: Mapping[str, Any] | None) -> bool:
    """Whether this Connector declares the oauth2 auth model."""
    return isinstance(auth_config, Mapping) and auth_config.get("type") == OAUTH2_TYPE


def _require_str(auth_config: Mapping[str, Any], key: str) -> str:
    value = auth_config.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailedError(f"auth_config.{key} is required for oauth2.")
    return value.strip()


def _validate_scopes(raw: Any) -> tuple[str, ...]:
    """Scopes are space-delimited tokens (RFC 6749 §3.3): each must be a non-empty string with no
    internal whitespace, or the authorize URL's `scope` parameter would be ambiguous."""
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ValidationFailedError("auth_config.scopes must be a list of strings.")
    if len(raw) > MAX_SCOPES:
        raise ValidationFailedError("auth_config.scopes declares too many scopes.")
    scopes: list[str] = []
    for scope in raw:
        if not isinstance(scope, str) or not scope.strip():
            raise ValidationFailedError("auth_config.scopes entries must be non-empty strings.")
        cleaned = scope.strip()
        if len(cleaned) > MAX_SCOPE_LENGTH:
            raise ValidationFailedError("auth_config.scopes entry is too long.")
        if any(character.isspace() for character in cleaned):
            raise ValidationFailedError("auth_config.scopes entries must not contain whitespace.")
        scopes.append(cleaned)
    return tuple(scopes)


def validate_oauth_auth_config(auth_config: Mapping[str, Any]) -> OAuthConfig:
    """Validate a Connector's `oauth2` auth_config at definition time; return the parsed form.

    Raises `ValidationFailedError` (400) for every rejection — an unsafe or ambiguous provider
    configuration is refused when it is saved, not discovered at the token endpoint.
    """
    # Imported here (not at module import) because `connectors.service` imports this module; a
    # top-level import would close the cycle. The lint lives there and is reused, never copied.
    from app.domains.connectors.service import validate_base_url

    leaked = sorted(key for key in auth_config if key.lower() in FORBIDDEN_CONFIG_KEYS)
    if leaked:
        raise ValidationFailedError(
            "auth_config must not contain secret material; secrets belong to the Credential.",
            details={"forbidden_keys": leaked},
        )

    grant = auth_config.get("grant", GRANT_AUTHORIZATION_CODE)
    if not isinstance(grant, str) or grant not in SUPPORTED_GRANTS:
        raise ValidationFailedError(
            "auth_config.grant is not supported.",
            details={"supported": list(SUPPORTED_GRANTS)},
        )

    # The one canonical SSRF lint, applied to both provider endpoints (never a second copy).
    authorization_url = validate_base_url(
        _require_str(auth_config, "authorization_url"), field="auth_config.authorization_url"
    )
    token_url = validate_base_url(
        _require_str(auth_config, "token_url"), field="auth_config.token_url"
    )

    client_id = auth_config.get("client_id")
    if client_id is not None and (not isinstance(client_id, str) or not client_id.strip()):
        raise ValidationFailedError("auth_config.client_id must be a non-empty string.")

    quirks = auth_config.get("quirks", {})
    if not isinstance(quirks, Mapping):
        raise ValidationFailedError("auth_config.quirks must be an object.")

    return OAuthConfig(
        authorization_url=authorization_url,
        token_url=token_url,
        scopes=_validate_scopes(auth_config.get("scopes")),
        client_id=client_id.strip() if isinstance(client_id, str) else None,
        quirks=quirks,
    )


def parse_oauth_config(auth_config: Mapping[str, Any] | None) -> OAuthConfig:
    """The validated config of a Connector that must be oauth2. Raises if it is not, or if the
    stored configuration no longer validates (a Connector saved before a rule tightened)."""
    if not is_oauth2(auth_config):
        raise ValidationFailedError("Connector does not use the oauth2 auth model.")
    assert auth_config is not None  # narrowed by is_oauth2
    return validate_oauth_auth_config(auth_config)


__all__ = [
    "FORBIDDEN_CONFIG_KEYS",
    "GRANT_AUTHORIZATION_CODE",
    "MAX_SCOPES",
    "MAX_SCOPE_LENGTH",
    "OAUTH2_TYPE",
    "SUPPORTED_GRANTS",
    "OAuthConfig",
    "is_oauth2",
    "parse_oauth_config",
    "validate_oauth_auth_config",
]
