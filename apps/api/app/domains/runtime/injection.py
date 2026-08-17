"""Credential → HTTP injection (AI_RUNTIME.md §2 stage 4, CONNECTOR_SPECIFICATION.md §8).

A pure function: given the decrypted `CredentialSecret` and the Connector's `auth_config`
(requirements only, never secrets), produce exactly what to add to the outbound request. It does no
I/O and holds no state. The canonical M1 mapping:

- `bearer` → header `Authorization: Bearer <value>`.
- `basic`  → header `Authorization: Basic <base64(username:password)>` (encoded here, never stored).
- `api_key` → the value placed at the Connector-declared `key_name` + `location`: `header` (default)
  or `query`. A query-placed key is flagged for redaction in every log / audit summary / error
  (SECURITY.md §2.3, CONNECTOR_SPECIFICATION.md:211).

Where the api_key goes is authority owned by the Connector, not the caller and not the Credential —
so a malformed/absent `auth_config` fails closed (`UpstreamAPIError` → `connector_error`), never a
guess. `location: body` and the M2 credential types (jwt/oauth2/custom_headers) are out of M1 scope
and rejected explicitly.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from app.core.exceptions import UpstreamAPIError
from app.domains.runtime.secrets import CredentialSecret


@dataclass(frozen=True, slots=True)
class InjectedAuth:
    """What to merge into the outbound request. `redact_query_keys` names query parameters whose
    values are secret and must be scrubbed from logs/audit (api_key in query)."""

    headers: dict[str, str] = field(default_factory=dict)
    query_params: dict[str, str] = field(default_factory=dict)
    redact_query_keys: frozenset[str] = frozenset()


def build_auth_injection(secret: CredentialSecret, auth_config: Mapping[str, Any]) -> InjectedAuth:
    """Translate a decrypted secret into request headers/query per the Connector's auth model.

    Raises `UpstreamAPIError` (connector_error) when the material or the Connector configuration
    cannot yield a deterministic injection — the runtime never invents a header name or location.
    """
    credential_type = secret.credential_type

    if credential_type == "bearer":
        if not secret.value:
            raise UpstreamAPIError("Credential is not usable for this Connection.")
        return InjectedAuth(headers={"Authorization": f"Bearer {secret.value}"})

    if credential_type == "basic":
        if secret.username is None or secret.password is None:
            raise UpstreamAPIError("Credential is not usable for this Connection.")
        token = base64.b64encode(f"{secret.username}:{secret.password}".encode()).decode("ascii")
        return InjectedAuth(headers={"Authorization": f"Basic {token}"})

    if credential_type == "api_key":
        if not secret.value:
            raise UpstreamAPIError("Credential is not usable for this Connection.")
        key_name = auth_config.get("key_name")
        location = str(auth_config.get("location") or "header").lower()
        if not isinstance(key_name, str) or not key_name.strip():
            # Ingested connectors do not yet project securitySchemes → auth_config (deferred); an
            # api_key connector with no declared key name cannot be injected. Fail closed.
            raise UpstreamAPIError("Connector auth is not configured for api_key.")
        if location == "header":
            return InjectedAuth(headers={key_name: secret.value})
        if location == "query":
            return InjectedAuth(
                query_params={key_name: secret.value},
                redact_query_keys=frozenset({key_name}),
            )
        raise UpstreamAPIError("Connector api_key location is not supported.")

    # jwt / oauth2 / custom_headers are M2; the credential vault never mints them in M1, but a
    # forged/edited row must not slip through as an unauthenticated request.
    raise UpstreamAPIError("Credential type is not supported by the runtime.")


__all__ = ["InjectedAuth", "build_auth_injection"]
