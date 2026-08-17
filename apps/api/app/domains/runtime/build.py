"""Outbound-request construction from the canonical Tool endpoint (AI_RUNTIME.md §2 stage 5 input).

A pure function: given a Tool's `endpoint` (method, URL template, per-argument `binding`,
`body_style`
from `connector_versions.normalized_schema`), the resolved base URL, the validated `arguments`, and
the `InjectedAuth`, produce the exact wire request. It builds *only* from server-side schema — the
caller supplies argument **values**, never header names, the target host, the scheme, or the
credential. Security properties enforced here:

- path/query values are URL-encoded (`quote`, `urlencode`) so an argument can never inject an extra
  path segment or query parameter;
- header values are rejected if they contain CR/LF (no header splitting);
- injected credential headers are applied **last**, so a Tool's own header parameter can never
  override the `Authorization`/api-key the runtime set (CONNECTOR_SPECIFICATION.md §8, directive
  §8).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from app.core.exceptions import UpstreamAPIError, ValidationFailedError
from app.domains.runtime.injection import InjectedAuth


@dataclass(frozen=True, slots=True)
class BuiltRequest:
    """A fully-resolved outbound request. `allowed_host` is the single egress-allowlist entry (the
    Connection's host); `redact_query_keys` names secret query params to redact from a URL."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    content: bytes | None = None
    allowed_host: str = ""
    redact_query_keys: frozenset[str] = frozenset()


def _binding_location(binding: dict[str, Any], name: str) -> str:
    entry = binding.get(name)
    if isinstance(entry, dict):
        loc = entry.get("location")
        if isinstance(loc, str):
            return loc
    return "query"  # unbound normalized args default to query (never a header/path)


def _reject_crlf(value: str, field_name: str) -> str:
    if "\r" in value or "\n" in value:
        raise ValidationFailedError(
            "Argument contains an illegal control character.",
            details={"fields": [{"field": field_name, "error": "illegal character"}]},
        )
    return value


def build_request(
    endpoint: dict[str, Any],
    *,
    base_url: str,
    arguments: dict[str, Any],
    injected: InjectedAuth,
) -> BuiltRequest:
    """Compose the outbound request. Raises `UpstreamAPIError` on a malformed endpoint (connector
    bug) and `ValidationFailedError` on an unroutable/illegal argument."""
    method = str(endpoint.get("method") or "").upper()
    path_template = endpoint.get("url")
    if not method or not isinstance(path_template, str) or not path_template:
        raise UpstreamAPIError("Tool endpoint is not executable.")
    raw_binding = endpoint.get("binding")
    binding: dict[str, Any] = raw_binding if isinstance(raw_binding, dict) else {}
    body_style = str(endpoint.get("body_style") or "none").lower()

    path = path_template
    query: list[tuple[str, str]] = []
    headers: dict[str, str] = {}
    body_fields: dict[str, Any] = {}

    for name, value in arguments.items():
        location = _binding_location(binding, name)
        if location == "path":
            # Encode the whole value, slashes included, so a path arg cannot add segments.
            path = path.replace("{" + name + "}", quote(str(value), safe=""))
        elif location == "header":
            headers[name] = _reject_crlf(str(value), name)
        elif location == "body":
            body_fields[name] = value
        else:  # query
            if isinstance(value, (list, tuple)):
                query.extend((name, str(v)) for v in value)
            else:
                query.append((name, str(value)))

    if "{" in path and "}" in path:  # an unsubstituted path placeholder remains
        raise ValidationFailedError("A required path argument is missing.")

    content: bytes | None = None
    if body_style == "json" and body_fields:
        content = json.dumps(body_fields, separators=(",", ":")).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    elif body_style == "form" and body_fields:
        content = urlencode(body_fields, doseq=True).encode("utf-8")
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    headers.setdefault("Accept", "application/json")

    # Injected credential material wins over any Tool-declared header of the same name (directive
    # §8).
    for key, value in injected.query_params.items():
        query.append((key, value))
    headers.update(injected.headers)

    base = base_url.rstrip("/")
    url = f"{base}/{path.lstrip('/')}"
    if query:
        url = f"{url}?{urlencode(query)}"

    host = (urlsplit(base_url).hostname or "").lower()
    return BuiltRequest(
        method=method,
        url=url,
        headers=headers,
        content=content,
        allowed_host=host,
        redact_query_keys=injected.redact_query_keys,
    )


__all__ = ["BuiltRequest", "build_request"]
