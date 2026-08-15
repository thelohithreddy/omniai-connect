"""OpenAPI 3.0 → canonical Tool Schema (M1.4-B1.1/B1.2, ADR-0025/0026).

Deterministic, framework-free, and hostile-input-safe: the specification is untrusted. This
module parses JSON or YAML, validates it is a supported OpenAPI 3.0 document, resolves local **and
remote** `$ref`s under bounded depth/count/size/cycle guards, and normalizes every `(path, method)`
operation into the canonical Tool Schema of CONNECTOR_SPECIFICATION §2. It never executes
specification content (no `eval`/`exec`, no YAML object construction) and has **no network
capability of its own** — a remote `$ref` is fetched only through the injected guarded fetch
callback (B0.1, §15/§18), so there is exactly one SSRF boundary.

The output is deterministic — same bytes (and same resolved remote content), same normalized set,
same `spec_hash` — because ordering follows spec position, refs are inlined before the Tool set is
built (so the hash depends on resolved content, not ref origin), and the hash is over canonical
JSON (UTF-8, sorted keys, no insignificant whitespace) of the ordered Tool set (§3).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urljoin

import yaml

# --- bounds (schema-bomb guards, CONNECTOR_SPECIFICATION §11/§18) ---
MAX_RAW_BYTES = 10 * 1024 * 1024  # 10 MB raw per document (the guarded fetcher also caps this)
MAX_DEPTH = 64  # structural nesting: OpenAPI docs are shallow; deep nesting is an attack
MAX_REF_DEPTH = 32  # $ref resolution depth (§11: "resolution depth ≤ 32")
MAX_REFS = 10_000  # total $ref resolutions (§11: "total refs ≤ 10 000")
MAX_REMOTE_BYTES = (
    50 * 1024 * 1024
)  # aggregate remote download budget (§11: "≤ 50 MB after $ref expansion")
MAX_TOOLS = 5_000  # a spec with more operations than this is refused, not normalized slowly
_TOOL_NAME_MAX = 64

# A remote $ref is resolved by handing its URL to the guarded fetcher (B0.1, injected). openapi.py
# itself has no network capability — see the `Fetcher` seam and _RefResolver (M1.4-B1.2, §15/§18).
Fetcher = Callable[[str], Awaitable[bytes]]

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


def _safe_parse(raw: bytes) -> Any:
    """Bytes → a bounded, safe Python structure: size-capped, UTF-8, JSON-first then the hardened
    YAML loader (no aliases, no object construction), non-finite refused, nesting-depth guarded.
    Shared by the root spec (`load_spec`) and every fetched remote `$ref` document."""
    if len(raw) > MAX_RAW_BYTES:
        raise IngestionError("spec_too_large", "document exceeds the size limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IngestionError("malformed_spec", "document is not valid UTF-8") from exc
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
    _guard_depth(document)
    return document


def load_spec(raw: bytes) -> dict[str, Any]:
    """Parse the root specification's raw bytes into a document object, or fail closed (oversize,
    non-UTF-8, non-finite numbers, YAML aliases, a non-object root, or excessive nesting)."""
    document = _safe_parse(raw)
    if not isinstance(document, dict):
        raise IngestionError("malformed_spec", "specification root must be an object")
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
    """The OpenAPI-3.0 gate: confirm this is a supported OpenAPI 3.0.x document, from parsed
    structure (never the filename). A Swagger 2.0 document is converted upstream by `to_openapi3`
    (M1.4-B1.3) *before* this runs, so a `swagger` key reaching here is refused as defence in
    depth; OpenAPI 3.1 is recognised but declared unsupported in this slice. Nothing is silently
    mis-parsed."""
    if "swagger" in document:
        raise IngestionError("unsupported_format", "Swagger 2.0 must be converted first")
    version = document.get("openapi")
    if not isinstance(version, str):
        raise IngestionError("unsupported_format", "not an OpenAPI document")
    if not version.startswith("3.0"):
        raise IngestionError("unsupported_format", "only OpenAPI 3.0 is supported in this slice")
    return version


def to_openapi3(document: dict[str, Any]) -> dict[str, Any]:
    """Return an OpenAPI 3.0.x document ready for the reference importer (M1.4-B1.3).

    Deterministically classifies the parsed root and performs the single upfront upgrade step
    (CONNECTOR_ENGINE §3): an OpenAPI 3.0.x document passes through; a Swagger 2.0 document
    (`swagger: "2.0"`, exact) is converted by the pure, network-free converter; a document that
    declares BOTH `swagger` and `openapi` is refused as ambiguous (an attacker must not be able to
    steer parser selection). The converted document is then re-validated by the SAME OpenAPI-3 gate
    (`detect_version`), so a bad conversion can never slip past the importer, and 3.1 / unknown /
    malformed inputs fail closed with the existing safe taxonomy."""
    if "swagger" in document:
        if "openapi" in document:
            raise IngestionError(
                "unsupported_format", "ambiguous specification: both swagger and openapi present"
            )
        # Local import keeps openapi.py free of a module-level swagger dependency (swagger.py
        # imports IngestionError from here); the converter has no network capability of its own.
        from app.domains.connectors import swagger

        document = swagger.convert(document)
    detect_version(document)
    return document


# --------------------------------------------------------------------------- $ref resolution


def _navigate(document: Any, fragment: str) -> Any:
    """Walk a JSON-pointer fragment (`/a/b/c`, or empty for the whole document) within one doc."""
    target = document
    for token in fragment.lstrip("/").split("/") if fragment.strip("/") else ():
        token = token.replace("~1", "/").replace("~0", "~")  # JSON-pointer unescape
        if not isinstance(target, dict) or token not in target:
            raise IngestionError("invalid_reference", "reference does not resolve")
        target = target[token]
    return target


class _RefResolver:
    """Bounded, cycle-safe resolver for local **and** remote `$ref`s (M1.4-B1.2).

    Local refs (`#/...`) resolve within the document that owns the node. Remote refs
    (`https://host/doc#/frag`, or relative to a remote doc's URL) are fetched **only** through the
    injected guarded fetch callback (B0.1, §15/§18) — this module has no network capability of its
    own — parsed with the same hardened loader, and resolved within the fetched document. When
    `fetch` is None (the local-only mode B1.1 shipped), a remote ref is refused.

    Every dimension is bounded (§11): resolution depth ≤ `MAX_REF_DEPTH`, total resolutions ≤
    `MAX_REFS`, aggregate remote bytes ≤ `MAX_REMOTE_BYTES`, per-document ≤ `MAX_RAW_BYTES` (also
    the fetcher's cap); cycles across any documents are detected by a `(url, fragment)` stack and
    broken with a permissive empty schema. Each distinct remote URL is fetched at most once per
    ingestion (in-memory dedup), so a fan-out of repeated refs is one fetch, not N.
    """

    def __init__(self, document: dict[str, Any], fetch: Fetcher | None = None) -> None:
        self._root = document
        self._fetch = fetch
        self._count = 0
        self._remote_bytes = 0
        self._remote_docs: dict[str, Any] = {}

    async def resolve(
        self,
        node: Any,
        doc: Any,
        url: str = "",
        stack: tuple[tuple[str, str], ...] = (),
        depth: int = 0,
    ) -> Any:
        if depth > MAX_REF_DEPTH:
            raise IngestionError("invalid_reference", "reference resolution is too deep")
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str):
                return await self._follow(ref, doc, url, stack, depth)
            return {k: await self.resolve(v, doc, url, stack, depth + 1) for k, v in node.items()}
        if isinstance(node, list):
            return [await self.resolve(v, doc, url, stack, depth + 1) for v in node]
        return node

    async def _follow(
        self, ref: str, doc: Any, url: str, stack: tuple[tuple[str, str], ...], depth: int
    ) -> Any:
        base, _, fragment = ref.partition("#")
        if base == "":
            target_doc, target_url = doc, url
        else:
            if self._fetch is None:
                raise IngestionError("invalid_reference", "external references are not supported")
            target_url = urljoin(url, base) if url else base
            target_doc = await self._fetch_remote(target_url)
        key = (target_url, fragment)
        if key in stack:
            return {}  # a cycle across any documents — break it, never loop
        self._count += 1
        if self._count > MAX_REFS:
            raise IngestionError("invalid_reference", "too many references")
        target = _navigate(target_doc, fragment)
        return await self.resolve(target, target_doc, target_url, (*stack, key), depth + 1)

    async def _fetch_remote(self, url: str) -> Any:
        if self._fetch is None:  # unreachable via _follow (guarded there); narrows the type
            raise IngestionError("invalid_reference", "external references are not supported")
        if url in self._remote_docs:
            return self._remote_docs[url]  # dedup: one fetch per distinct URL per ingestion
        # Only http(s) reaches the guarded fetcher; file:/// and other schemes are refused here so
        # they can never bypass the SSRF boundary. The fetcher (B0.1) enforces https/no-creds/no-
        # proxy/IP-validation/redirect-revalidation/10 MB/30 s. Any failure is fatal and safe.
        if not url.lower().startswith(("http://", "https://")):
            raise IngestionError("invalid_reference", "unsupported reference scheme")
        try:
            raw = await self._fetch(url)
        except IngestionError:
            raise
        except Exception as exc:  # SSRFError / timeout / connection — never leak the URL or detail
            raise IngestionError(
                "invalid_reference", "could not resolve a remote reference"
            ) from exc
        self._remote_bytes += len(raw)
        if self._remote_bytes > MAX_REMOTE_BYTES:
            raise IngestionError("invalid_reference", "remote references exceed the size budget")
        document = _safe_parse(raw)
        self._remote_docs[url] = document
        return document

    async def resolve_root(self, node: Any) -> Any:
        """Resolve a node that belongs to the root document."""
        return await self.resolve(node, self._root, "")


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


async def _merge_parameters(
    resolver: _RefResolver,
    params: list[Any],
    properties: dict[str, Any],
    required: list[str],
    binding: dict[str, Any],
) -> None:
    for raw in params:
        param = await resolver.resolve_root(raw)
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


async def _merge_request_body(
    resolver: _RefResolver,
    request_body: Any,
    properties: dict[str, Any],
    required: list[str],
    binding: dict[str, Any],
) -> str:
    """Merge a JSON request body's properties as top-level arguments (bound to `body`). Returns
    the body_style. Non-JSON bodies are downgraded to `form` (CONNECTOR_SPECIFICATION §6)."""
    body = await resolver.resolve_root(request_body)
    if not isinstance(body, dict):
        return "none"
    content = body.get("content")
    if not isinstance(content, dict):
        return "none"
    if "application/json" not in content:
        return "form"
    raw_schema = content["application/json"].get("schema")
    schema = await resolver.resolve_root(raw_schema) if isinstance(raw_schema, dict) else {}
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


async def normalize(
    document: dict[str, Any], connector_slug: str, *, fetch: Fetcher | None = None
) -> list[dict[str, Any]]:
    """Produce the ordered canonical Tool Schema set — one Tool per `(path, method)`, in spec
    position. Deterministic and bounded.

    Remote `$ref`s are resolved through the injected guarded `fetch` (B0.1); with `fetch=None`
    (the default) a remote ref is refused — the local-only behaviour B1.1 shipped. Because refs
    (local and remote) are inlined *before* the Tool set is built, the output — and thus
    `spec_hash` — depends only on the resolved content, not on where a ref was fetched from.

    The output is **version-independent**: it carries no `connector_version` or persisted `id`,
    so `spec_hash` over it is stable across re-syncs and dedupes no-op churn (§3). The pipeline
    injects `connector_version` into each Tool only when it persists `normalized_schema`.
    """
    resolver = _RefResolver(document, fetch)
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
            await _merge_parameters(resolver, op_params, properties, required, binding)
            body_style = "none"
            if "requestBody" in operation:
                body_style = await _merge_request_body(
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
    "to_openapi3",
]
