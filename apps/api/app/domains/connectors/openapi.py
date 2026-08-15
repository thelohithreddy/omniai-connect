"""OpenAPI 3.0 → canonical Tool Schema (M1.4-B1.1, ADR-0025).

Deterministic, framework-free, and hostile-input-safe: the specification is untrusted. This
module parses JSON or YAML, validates it is a supported OpenAPI 3.0 document, resolves **local**
`$ref`s under bounded depth/count/cycle guards, and normalizes every `(path, method)` operation
into the canonical Tool Schema of CONNECTOR_SPECIFICATION §2. It never fetches anything (URL and
external-`$ref` egress belong to the guarded fetcher, B0.1 — external refs are a later slice), and
it never executes specification content (no `eval`/`exec`, no YAML object construction).

The output is deterministic — same bytes, same normalized set, same `spec_hash` — because ordering
follows spec position and the hash is over canonical JSON (UTF-8, sorted keys, no insignificant
whitespace) of the ordered Tool set (CONNECTOR_SPECIFICATION §3).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import yaml

# --- bounds (schema-bomb guards, CONNECTOR_SPECIFICATION §11/§18) ---
MAX_RAW_BYTES = 10 * 1024 * 1024  # 10 MB raw (the fetcher also caps this)
MAX_DEPTH = 64  # structural nesting: OpenAPI docs are shallow; deep nesting is an attack
MAX_REF_DEPTH = 32  # $ref resolution depth (§11: "resolution depth ≤ 32")
MAX_REFS = 10_000  # total $ref resolutions (§11: "total refs ≤ 10 000")
MAX_TOOLS = 5_000  # a spec with more operations than this is refused, not normalized slowly
_TOOL_NAME_MAX = 64

# HTTP methods that become Tools (endpoint.method enum, CONNECTOR_SPECIFICATION §2).
_HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head")
# Idempotent + read/write classification for the required `annotations` (§6/§8).
_READONLY = {"get", "head"}
_IDEMPOTENT = {"get", "head", "put", "delete"}
_DESTRUCTIVE = {"delete"}

# A canonical tool/operation slug: lowercase snake, must start with a letter (Tool Schema §2
# `name` pattern is applied to the full `{connector}_{op}` name).
_SLUG_CLEAN = re.compile(r"[^a-z0-9]+")
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")


class IngestionError(Exception):
    """A spec could not be ingested. `reason_code` is a stable, non-secret taxonomy value
    (surfaced to the connector's failure state); the message never carries raw spec content,
    a URL, or a credential."""

    def __init__(self, reason_code: str, message: str = "") -> None:
        super().__init__(message or reason_code)
        self.reason_code = reason_code


# --------------------------------------------------------------------------- safe parsing


class _SafeLoader(yaml.SafeLoader):
    """`SafeLoader` (no Python object construction) that additionally refuses YAML anchors/
    aliases — the alias-expansion ('billion laughs') vector. OpenAPI reuse is JSON `$ref`, not
    YAML anchors, so refusing aliases costs nothing and removes the bomb."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        # An alias node (`*anchor`) is what an expansion bomb multiplies; refuse it before the
        # loader can resolve and duplicate the referenced subtree.
        if self.check_event(yaml.events.AliasEvent):
            raise IngestionError("malformed_spec", "YAML anchors/aliases are not permitted")
        return super().compose_node(parent, index)


def _reject_non_finite(value: str) -> float:
    # json.loads calls this for NaN/Infinity/-Infinity; refuse them (not valid JSON, and a
    # non-finite number cannot be canonically serialized for hashing).
    raise IngestionError("malformed_spec", "non-finite numbers are not permitted")


def load_spec(raw: bytes) -> dict[str, Any]:
    """Parse raw bytes into a document. JSON first (strict), then YAML via the hardened safe
    loader. Fails closed on oversize, non-UTF-8, non-finite numbers, YAML aliases, a non-object
    root, or excessive nesting."""
    if len(raw) > MAX_RAW_BYTES:
        raise IngestionError("spec_too_large", "specification exceeds the size limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IngestionError("malformed_spec", "specification is not valid UTF-8") from exc

    document: Any
    try:
        document = json.loads(text, parse_constant=_reject_non_finite)
    except json.JSONDecodeError:
        try:
            document = yaml.load(text, Loader=_SafeLoader)  # noqa: S506 (hardened SafeLoader)
        except IngestionError:
            raise
        except yaml.YAMLError as exc:
            raise IngestionError("malformed_spec", "not valid JSON or YAML") from exc

    if not isinstance(document, dict):
        raise IngestionError("malformed_spec", "specification root must be an object")
    _guard_depth(document)
    return document


def _guard_depth(node: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise IngestionError("malformed_spec", "specification nesting is too deep")
    if isinstance(node, dict):
        for value in node.values():
            _guard_depth(value, depth + 1)
    elif isinstance(node, list):
        for item in node:
            _guard_depth(item, depth + 1)


# --------------------------------------------------------------------------- validation


def detect_version(document: dict[str, Any]) -> str:
    """Confirm this is a supported OpenAPI 3.0 document, from parsed structure (never the
    filename). Swagger 2.0 and OpenAPI 3.1 are recognised but declared unsupported in this slice
    (converted / handled by later slices), never silently mis-parsed."""
    if "swagger" in document:
        raise IngestionError("unsupported_format", "Swagger 2.0 is not supported in this slice")
    version = document.get("openapi")
    if not isinstance(version, str):
        raise IngestionError("unsupported_format", "not an OpenAPI document")
    if not version.startswith("3.0"):
        raise IngestionError("unsupported_format", "only OpenAPI 3.0 is supported in this slice")
    return version


# --------------------------------------------------------------------------- $ref resolution


class _RefResolver:
    """Bounded resolver for **local** JSON-pointer `$ref`s (`#/...`). Remote refs (anything not
    starting with `#/`) are refused — external-ref fetching is a later slice and must not bypass
    the SSRF boundary. Depth, total count, and cycles are all bounded (§11)."""

    def __init__(self, document: dict[str, Any]) -> None:
        self._document = document
        self._count = 0

    def resolve(self, node: Any, _stack: tuple[str, ...] = (), depth: int = 0) -> Any:
        if depth > MAX_REF_DEPTH:
            raise IngestionError("invalid_reference", "reference resolution is too deep")
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str):
                return self._follow(ref, _stack, depth)
            return {k: self.resolve(v, _stack, depth + 1) for k, v in node.items()}
        if isinstance(node, list):
            return [self.resolve(v, _stack, depth + 1) for v in node]
        return node

    def _follow(self, ref: str, stack: tuple[str, ...], depth: int) -> Any:
        if not ref.startswith("#/"):
            raise IngestionError("invalid_reference", "external references are not supported")
        if ref in stack:
            # A cycle: break it with a permissive empty schema rather than looping forever.
            return {}
        self._count += 1
        if self._count > MAX_REFS:
            raise IngestionError("invalid_reference", "too many references")
        target = self._document
        for token in ref[2:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")  # JSON-pointer unescape
            if not isinstance(target, dict) or token not in target:
                raise IngestionError("invalid_reference", "reference does not resolve")
            target = target[token]
        return self.resolve(target, (*stack, ref), depth + 1)


# --------------------------------------------------------------------------- normalization


def _operation_slug(method: str, path: str, operation: dict[str, Any]) -> str:
    """operationId (sanitized) → generated `{method}_{path_tokens}` (CONNECTOR_ENGINE §5)."""
    raw = operation.get("operationId")
    if isinstance(raw, str) and raw.strip():
        slug = _SLUG_CLEAN.sub("_", raw.strip().lower()).strip("_")
        if slug:
            return slug
    tokens = _SLUG_CLEAN.sub("_", path.lower()).strip("_")
    return f"{method}_{tokens}".strip("_")


def _tool_name(connector_slug: str, op_slug: str, used: set[str]) -> str:
    """`{connector_slug}_{operation_slug}`, ≤64, matching `^[a-z][a-z0-9_]*$`; duplicates get
    deterministic `_2`, `_3` suffixes (stable, ordered by spec position)."""
    base = _SLUG_CLEAN.sub("_", f"{connector_slug}_{op_slug}".lower()).strip("_")
    if not base or not base[0].isalpha():
        base = f"t_{base}".strip("_")
    base = base[:_TOOL_NAME_MAX]
    name, n = base, 1
    while name in used or not _NAME_RE.match(name):
        n += 1
        suffix = f"_{n}"
        name = base[: _TOOL_NAME_MAX - len(suffix)] + suffix
    used.add(name)
    return name


def _merge_parameters(
    resolver: _RefResolver,
    params: list[Any],
    properties: dict[str, Any],
    required: list[str],
    binding: dict[str, Any],
) -> None:
    for raw in params:
        param = resolver.resolve(raw)
        if not isinstance(param, dict):
            continue
        name, location = param.get("name"), param.get("in")
        if not isinstance(name, str) or location not in ("path", "query", "header"):
            continue
        schema = param.get("schema")
        properties[name] = schema if isinstance(schema, dict) else {}
        if isinstance(param.get("description"), str):
            properties[name] = {**properties[name], "description": param["description"]}
        if param.get("required") or location == "path":  # path params are always required
            required.append(name)
        binding[name] = {"location": location}


def _merge_request_body(
    resolver: _RefResolver,
    request_body: Any,
    properties: dict[str, Any],
    required: list[str],
    binding: dict[str, Any],
) -> str:
    """Merge a JSON request body's properties as top-level arguments (bound to `body`). Returns
    the body_style. Non-JSON bodies are downgraded to `form` (CONNECTOR_SPECIFICATION §6)."""
    body = resolver.resolve(request_body)
    if not isinstance(body, dict):
        return "none"
    content = body.get("content")
    if not isinstance(content, dict):
        return "none"
    if "application/json" not in content:
        return "form"
    raw_schema = content["application/json"].get("schema")
    schema = resolver.resolve(raw_schema) if isinstance(raw_schema, dict) else {}
    raw_required = schema.get("required")
    body_required: list[Any] = raw_required if isinstance(raw_required, list) else []
    raw_properties = schema.get("properties")
    body_properties = raw_properties if isinstance(raw_properties, dict) else {}
    for prop, prop_schema in body_properties.items():
        if not isinstance(prop, str):
            continue
        properties[prop] = prop_schema if isinstance(prop_schema, dict) else {}
        binding[prop] = {"location": "body"}
        if prop in body_required:
            required.append(prop)
    return "json"


def _annotations(method: str) -> dict[str, bool]:
    return {
        "readonly": method in _READONLY,
        "destructive": method in _DESTRUCTIVE,
        "idempotent": method in _IDEMPOTENT,
    }


def _auth(operation: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
    # Operation-level security overrides document-level (§6). A non-empty requirement → required.
    security = operation.get("security")
    if security is None:
        security = document.get("security")
    return {"required": bool(security)}


def normalize(document: dict[str, Any], connector_slug: str) -> list[dict[str, Any]]:
    """Produce the ordered canonical Tool Schema set — one Tool per `(path, method)`, in spec
    position. Deterministic and bounded.

    The output is **version-independent**: it carries no `connector_version` or persisted `id`,
    so `spec_hash` over it is stable across re-syncs and dedupes no-op churn (§3). The pipeline
    injects `connector_version` into each Tool only when it persists `normalized_schema`.
    """
    resolver = _RefResolver(document)
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise IngestionError("no_operations", "specification declares no paths")

    tools: list[dict[str, Any]] = []
    used_names: set[str] = set()
    for path, path_item in paths.items():
        if not isinstance(path, str) or not isinstance(path_item, dict):
            continue
        shared_params = path_item.get("parameters") or []
        for method in _HTTP_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            if len(tools) >= MAX_TOOLS:
                raise IngestionError("spec_too_large", "specification declares too many operations")

            properties: dict[str, Any] = {}
            required: list[str] = []
            binding: dict[str, Any] = {}
            op_params = list(shared_params) + list(operation.get("parameters") or [])
            _merge_parameters(resolver, op_params, properties, required, binding)
            body_style = "none"
            if "requestBody" in operation:
                body_style = _merge_request_body(
                    resolver, operation["requestBody"], properties, required, binding
                )

            op_slug = _operation_slug(method, path, operation)
            name = _tool_name(connector_slug, op_slug, used_names)
            description = operation.get("description") or operation.get("summary") or name
            input_schema: dict[str, Any] = {"type": "object", "properties": properties}
            if required:
                input_schema["required"] = sorted(set(required))

            tool: dict[str, Any] = {
                "name": name,
                "schema_version": "1.0.0",
                "description": str(description)[:4096],
                "input_schema": input_schema,
                "auth": _auth(operation, document),
                "endpoint": {
                    "method": method.upper(),
                    "url": path,
                    "binding": binding,
                    "body_style": body_style,
                },
                "annotations": _annotations(method),
                "tags": [t for t in (operation.get("tags") or []) if isinstance(t, str)],
                "extensions": {
                    "openapi": {
                        "operationId": operation.get("operationId"),
                        "method": method.upper(),
                        "path": path,
                    }
                },
            }
            tools.append(tool)

    if not tools:
        raise IngestionError("no_operations", "specification declares no operations")
    return tools


def base_url_from_servers(document: dict[str, Any]) -> str | None:
    """The first `servers[].url` with its `variables` defaults substituted, or None. Never
    fetched — this is metadata for the Connection's base_url (SSRF-linted by the service)."""
    servers = document.get("servers")
    if not isinstance(servers, list) or not servers or not isinstance(servers[0], dict):
        return None
    url = servers[0].get("url")
    if not isinstance(url, str):
        return None
    variables = servers[0].get("variables")
    if isinstance(variables, dict):
        for var, spec in variables.items():
            if isinstance(spec, dict) and isinstance(spec.get("default"), str):
                url = url.replace(f"{{{var}}}", spec["default"])
    return url


def canonical_bytes(tools: list[dict[str, Any]]) -> bytes:
    """Canonical JSON of the ordered Tool set: UTF-8, sorted keys, no insignificant whitespace,
    non-finite refused (CONNECTOR_SPECIFICATION §3)."""
    return json.dumps(
        tools, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def spec_hash(tools: list[dict[str, Any]]) -> str:
    """`spec_hash` = SHA-256 over the canonical JSON of the ordered normalized Tool set."""
    return hashlib.sha256(canonical_bytes(tools)).hexdigest()


__all__ = [
    "IngestionError",
    "base_url_from_servers",
    "canonical_bytes",
    "detect_version",
    "load_spec",
    "normalize",
    "spec_hash",
]
