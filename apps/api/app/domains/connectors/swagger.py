"""Swagger 2.0 → OpenAPI 3.0 conversion (M1.4-B1.3, ADR-0027).

A pure, deterministic, framework-free, **network-free** structural transform: a parsed Swagger
2.0 document in, an equivalent OpenAPI 3.0.3 document out. It is the *single upfront upgrade step*
of CONNECTOR_ENGINE §3 / CONNECTOR_SPECIFICATION §6 — so the ONE OpenAPI-3 importer (`openapi.py`)
runs unchanged afterwards. There is no separate normalization logic, no second parser, no second
`$ref` resolver, and no second SSRF boundary.

The converter touches **no I/O of any kind**: no network, no database, no object store, no
request / auth / tenant state. Swagger `host` / `schemes` / `basePath` become OpenAPI `servers`
*metadata* only — never an ingestion fetch target (the ingestion pipeline fetches only its own
`source_url`, and remote `$ref`s resolve through B0.1). It receives specification data and returns
specification data, which keeps it independently testable and keeps the pipeline's single egress
boundary intact.

Mapping (CONNECTOR_SPECIFICATION §6, CONNECTOR_ENGINE §3):

    definitions          → components.schemas
    parameters           → components.parameters (non-body) / components.requestBodies (body)
    responses            → components.responses
    securityDefinitions  → components.securitySchemes
    body parameter       → requestBody (content per `consumes`, default application/json)
    formData parameters  → form requestBody (multipart if a file field is present)
    schemes/host/basePath → servers (metadata; never fetched)
    consumes / produces  → per-operation request/response media types
    local `#/definitions|parameters|responses/*` refs → `#/components/*` (remote refs untouched)

Only the *root* document is converted; a remote `$ref` document is resolved as-is by B1.2's one
resolver, which navigates its JSON-pointer fragment literally (a Swagger `#/definitions/…`
fragment resolves in a Swagger remote doc), so there is nothing Swagger-specific to fetch here.
The original Swagger bytes remain the canonical `raw_spec_ref`; this converted document is a
transient intermediate consumed only by the importer.
"""

from __future__ import annotations

import copy
from typing import Any, cast

from app.domains.connectors.openapi import IngestionError

# The canonical OpenAPI 3 target: the importer accepts any 3.0.x (`detect_version`), and the exact
# patch is never part of the Tool Schema or `spec_hash` (the normalizer drops the version). 3.0.3
# is the last 3.0 patch and the standard conversion target.
OPENAPI_TARGET = "3.0.3"

# Defence in depth: the root document is already depth-bounded by `openapi.load_spec` (≤ MAX_DEPTH),
# so any recursion here is naturally bounded; this explicit cap fails closed if that ever changes.
MAX_CONVERT_DEPTH = 200

# Swagger 2 puts a non-body parameter's schema inline (type/format/items/…); OpenAPI 3 moves it
# under `schema`. These are the schema-bearing keys of a Swagger "items"/parameter object.
_PARAM_SCHEMA_KEYS = (
    "type",
    "format",
    "items",
    "default",
    "maximum",
    "exclusiveMaximum",
    "minimum",
    "exclusiveMinimum",
    "maxLength",
    "minLength",
    "pattern",
    "maxItems",
    "minItems",
    "uniqueItems",
    "enum",
    "multipleOf",
)

# Swagger `collectionFormat` → OpenAPI 3 (style, explode) for query array parameters. Inert for the
# current normalizer (which ignores style/explode) but converted for fidelity.
_COLLECTION_FORMAT = {
    "csv": ("form", False),
    "multi": ("form", True),
    "ssv": ("spaceDelimited", False),
    "pipes": ("pipeDelimited", False),
}

_HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch")


def is_swagger2(document: dict[str, Any]) -> bool:
    """True iff the document declares the exact Swagger 2.0 identity (`swagger: "2.0"`).

    Strict by design (ratified): the version must be the string ``"2.0"``. Swagger is never
    inferred from incidental fields (`host`, `basePath`, `definitions`) — only this explicit
    identity selects the converter, so an attacker cannot steer parser selection.
    """
    return document.get("swagger") == "2.0"


def convert(document: dict[str, Any]) -> dict[str, Any]:
    """Convert a Swagger 2.0 document to an equivalent OpenAPI 3.0.3 document. Pure, no network.

    Fails closed with the existing safe taxonomy: a non-2.0 `swagger` value → `unsupported_format`;
    a structurally broken document → `malformed_spec`. The output carries no raw input beyond the
    converted structure and never reaches out to any host.
    """
    if document.get("swagger") != "2.0":
        raise IngestionError("unsupported_format", "unsupported Swagger version")

    global_consumes = _string_list(document.get("consumes"))
    global_produces = _string_list(document.get("produces"))

    top_params = document.get("parameters")
    top_params = top_params if isinstance(top_params, dict) else {}
    # Names of reusable *body* parameters — their `#/parameters/<name>` refs must become
    # `#/components/requestBodies/<name>` (a requestBody is not an ordinary OpenAPI-3 parameter).
    body_param_names = {
        name
        for name, param in top_params.items()
        if isinstance(name, str) and isinstance(param, dict) and param.get("in") == "body"
    }

    out: dict[str, Any] = {"openapi": OPENAPI_TARGET}
    if isinstance(document.get("info"), dict):
        out["info"] = copy.deepcopy(document["info"])
    if isinstance(document.get("tags"), list):
        out["tags"] = copy.deepcopy(document["tags"])
    if isinstance(document.get("externalDocs"), dict):
        out["externalDocs"] = copy.deepcopy(document["externalDocs"])

    servers = _servers(document)
    if servers:
        out["servers"] = servers

    out["paths"] = _convert_paths(
        document.get("paths"), global_consumes, global_produces, body_param_names
    )

    components = _components(top_params, document, global_consumes, global_produces)
    if components:
        out["components"] = components

    if isinstance(document.get("security"), list):
        out["security"] = copy.deepcopy(document["security"])

    # Vendor extensions on the root are valid in both specs — carry them through verbatim.
    for key, value in document.items():
        if key.startswith("x-"):
            out[key] = copy.deepcopy(value)

    # A single, final local-ref rewrite over the whole assembled document. Only refs that start
    # with `#` (local) are rewritten; remote refs (`other.json#/…`) are left untouched so B1.2's
    # resolver fetches and navigates them as-is. The root is always a dict.
    return cast(dict[str, Any], _rewrite_local_refs(out, body_param_names))


# --------------------------------------------------------------------------- servers


def _servers(document: dict[str, Any]) -> list[dict[str, Any]]:
    """schemes + host + basePath → OpenAPI `servers` (metadata only; never fetched).

    https is preferred and ordered first so the connector's default `base_url` is the secure one.
    A spec-declared URL is SSRF-governed by the egress guard when a Tool actually executes (§11);
    conversion performs no fetch, so `host` can never become an ingestion SSRF vector.
    """
    host = document.get("host")
    base_path = document.get("basePath")
    base_path = base_path if isinstance(base_path, str) else ""
    if not isinstance(host, str) or not host:
        # No host: at most a relative base path becomes a relative server.
        return [{"url": base_path}] if base_path else []

    schemes = [s for s in _string_list(document.get("schemes")) if s in ("https", "http")]
    ordered = [s for s in ("https", "http") if s in schemes] or ["https"]
    return [{"url": f"{scheme}://{host}{base_path}"} for scheme in ordered]


# --------------------------------------------------------------------------- paths / operations


def _convert_paths(
    paths: Any,
    global_consumes: list[str],
    global_produces: list[str],
    body_param_names: set[str],
) -> dict[str, Any]:
    if not isinstance(paths, dict):
        raise IngestionError("no_operations", "specification declares no paths")
    out: dict[str, Any] = {}
    for path, item in paths.items():
        if not isinstance(path, str) or not isinstance(item, dict):
            continue
        out[path] = _convert_path_item(item, global_consumes, global_produces, body_param_names)
    return out


def _convert_path_item(
    item: dict[str, Any],
    global_consumes: list[str],
    global_produces: list[str],
    body_param_names: set[str],
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    # Path-level shared parameters split into non-body (kept at path level) and body/formData
    # (inherited by any operation that does not define its own).
    shared = item.get("parameters")
    shared_nonbody, shared_body_fd = _split_parameters(
        shared if isinstance(shared, list) else [], body_param_names
    )
    if shared_nonbody:
        out["parameters"] = [_convert_parameter(p) for p in shared_nonbody]

    for method in _HTTP_METHODS:
        operation = item.get(method)
        if isinstance(operation, dict):
            out[method] = _convert_operation(
                operation, global_consumes, global_produces, body_param_names, shared_body_fd
            )

    for key, value in item.items():
        if key.startswith("x-"):
            out[key] = copy.deepcopy(value)
    return out


def _convert_operation(
    operation: dict[str, Any],
    global_consumes: list[str],
    global_produces: list[str],
    body_param_names: set[str],
    inherited_body_fd: list[Any],
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in ("operationId", "summary", "description", "deprecated"):
        if key in operation:
            out[key] = copy.deepcopy(operation[key])
    if isinstance(operation.get("tags"), list):
        out["tags"] = copy.deepcopy(operation["tags"])
    if isinstance(operation.get("externalDocs"), dict):
        out["externalDocs"] = copy.deepcopy(operation["externalDocs"])
    if isinstance(operation.get("security"), list):
        out["security"] = copy.deepcopy(operation["security"])

    params = operation.get("parameters")
    nonbody, body_fd = _split_parameters(
        params if isinstance(params, list) else [], body_param_names
    )
    if nonbody:
        out["parameters"] = [_convert_parameter(p) for p in nonbody]

    consumes = _string_list(operation.get("consumes")) or global_consumes
    request_body = _build_request_body(body_fd or inherited_body_fd, consumes)
    if request_body is not None:
        out["requestBody"] = request_body

    produces = _string_list(operation.get("produces")) or global_produces
    responses = _convert_responses(operation.get("responses"), produces)
    if responses is not None:
        out["responses"] = responses

    for key, value in operation.items():
        if key.startswith("x-"):
            out[key] = copy.deepcopy(value)
    return out


def _split_parameters(params: list[Any], body_param_names: set[str]) -> tuple[list[Any], list[Any]]:
    """Partition a Swagger parameter list into (path/query/header, body/formData). A `$ref` to a
    reusable body parameter is routed to the body/formData bucket so it relocates to `requestBody`;
    every other `$ref` stays a parameter."""
    nonbody: list[Any] = []
    body_fd: list[Any] = []
    for param in params:
        if not isinstance(param, dict):
            continue
        ref = param.get("$ref")
        if isinstance(ref, str):
            name = ref[len("#/parameters/") :] if ref.startswith("#/parameters/") else ""
            (body_fd if name in body_param_names else nonbody).append(param)
            continue
        (body_fd if param.get("in") in ("body", "formData") else nonbody).append(param)
    return nonbody, body_fd


def _convert_parameter(param: dict[str, Any]) -> dict[str, Any]:
    """Convert one Swagger path/query/header parameter to its OpenAPI 3 form (schema-under-`schema`,
    collectionFormat → style/explode). A `$ref` parameter passes through (rewritten globally)."""
    ref = param.get("$ref")
    if isinstance(ref, str):
        return {"$ref": ref}

    location = param.get("in")
    out: dict[str, Any] = {}
    if isinstance(param.get("name"), str):
        out["name"] = param["name"]
    if isinstance(location, str):
        out["in"] = location
    if isinstance(param.get("description"), str):
        out["description"] = param["description"]
    # Path parameters are required by definition in OpenAPI 3; else preserve explicit `required`.
    if location == "path" or param.get("required") is True:
        out["required"] = True
    if param.get("allowEmptyValue") is True:
        out["allowEmptyValue"] = True

    if isinstance(param.get("schema"), dict):  # unusual for a Swagger non-body param, but be robust
        out["schema"] = _convert_schema(param["schema"])
    else:
        out["schema"] = _param_schema(param)

    if location == "query" and param.get("type") == "array":
        style = _COLLECTION_FORMAT.get(str(param.get("collectionFormat", "csv")))
        if style is not None:
            out["style"], out["explode"] = style

    for key, value in param.items():
        if key.startswith("x-"):
            out[key] = copy.deepcopy(value)
    return out


def _param_schema(param: dict[str, Any]) -> dict[str, Any]:
    """Lift a Swagger non-body parameter's inline schema keys into an OpenAPI 3 schema object."""
    schema: dict[str, Any] = {}
    for key in _PARAM_SCHEMA_KEYS:
        if key not in param:
            continue
        # `items` is a nested schema (convert discriminator etc.); other keys are scalar/list.
        schema[key] = _convert_schema(param[key]) if key == "items" else copy.deepcopy(param[key])
    return schema


def _build_request_body(body_fd: list[Any], consumes: list[str]) -> dict[str, Any] | None:
    """Build an OpenAPI 3 requestBody from Swagger body / formData parameters, or None if there is
    neither. A body parameter wins over formData (they are mutually exclusive in Swagger 2)."""
    body = None
    body_ref = None
    form_data: list[dict[str, Any]] = []
    for param in body_fd:
        if not isinstance(param, dict):
            continue
        if isinstance(param.get("$ref"), str):
            body_ref = param["$ref"]
        elif param.get("in") == "body":
            body = param
        elif param.get("in") == "formData":
            form_data.append(param)

    if body_ref is not None:
        return {"$ref": body_ref}  # relocated reusable body param (rewritten globally)

    if body is not None:
        media_types = consumes or ["application/json"]
        schema = _convert_schema(body["schema"]) if isinstance(body.get("schema"), dict) else {}
        request_body: dict[str, Any] = {
            "content": {media: {"schema": schema} for media in media_types}
        }
        if body.get("required") is True:
            request_body["required"] = True
        if isinstance(body.get("description"), str):
            request_body["description"] = body["description"]
        return request_body

    if form_data:
        properties: dict[str, Any] = {}
        required: list[str] = []
        has_file = False
        for param in form_data:
            name = param.get("name")
            if not isinstance(name, str):
                continue
            if param.get("type") == "file":
                properties[name] = {"type": "string", "format": "binary"}
                has_file = True
            else:
                properties[name] = _param_schema(param)
            if param.get("required") is True:
                required.append(name)
        schema = {"type": "object", "properties": properties}
        if required:
            schema["required"] = required
        media = _form_media_type(consumes, has_file)
        request_body = {"content": {media: {"schema": schema}}}
        if required:
            request_body["required"] = True
        return request_body

    return None


def _form_media_type(consumes: list[str], has_file: bool) -> str:
    for media in consumes:
        if media in ("multipart/form-data", "application/x-www-form-urlencoded"):
            return media
    return "multipart/form-data" if has_file else "application/x-www-form-urlencoded"


def _convert_responses(responses: Any, produces: list[str]) -> dict[str, Any] | None:
    if not isinstance(responses, dict):
        return None
    out: dict[str, Any] = {}
    for code, response in responses.items():
        if not isinstance(code, str):
            continue
        out[code] = _convert_response(response, produces)
    return out


def _convert_response(response: Any, produces: list[str]) -> dict[str, Any]:
    if not isinstance(response, dict):
        return {"description": ""}
    ref = response.get("$ref")
    if isinstance(ref, str):
        return {"$ref": ref}  # rewritten globally → components.responses
    out: dict[str, Any] = {
        "description": response["description"]
        if isinstance(response.get("description"), str)
        else ""
    }
    if isinstance(response.get("headers"), dict):
        out["headers"] = copy.deepcopy(response["headers"])
    if isinstance(response.get("schema"), dict):
        media_types = produces or ["application/json"]
        schema = _convert_schema(response["schema"])
        out["content"] = {media: {"schema": schema} for media in media_types}
    for key, value in response.items():
        if key.startswith("x-"):
            out[key] = copy.deepcopy(value)
    return out


# --------------------------------------------------------------------------- components


def _components(
    top_params: dict[str, Any],
    document: dict[str, Any],
    global_consumes: list[str],
    global_produces: list[str],
) -> dict[str, Any]:
    components: dict[str, Any] = {}

    definitions = document.get("definitions")
    if isinstance(definitions, dict):
        schemas = {
            name: _convert_schema(schema)
            for name, schema in definitions.items()
            if isinstance(name, str)
        }
        if schemas:
            components["schemas"] = schemas

    parameters: dict[str, Any] = {}
    request_bodies: dict[str, Any] = {}
    for name, param in top_params.items():
        if not isinstance(name, str) or not isinstance(param, dict):
            continue
        if param.get("in") == "body":
            request_bodies[name] = _build_request_body(
                [param], global_consumes or ["application/json"]
            )
        else:
            parameters[name] = _convert_parameter(param)
    if parameters:
        components["parameters"] = parameters
    if request_bodies:
        components["requestBodies"] = request_bodies

    responses = document.get("responses")
    if isinstance(responses, dict):
        converted = {
            name: _convert_response(response, global_produces)
            for name, response in responses.items()
            if isinstance(name, str)
        }
        if converted:
            components["responses"] = converted

    security_schemes = _security_schemes(document.get("securityDefinitions"))
    if security_schemes:
        components["securitySchemes"] = security_schemes

    return components


def _security_schemes(definitions: Any) -> dict[str, Any]:
    if not isinstance(definitions, dict):
        return {}
    out: dict[str, Any] = {}
    for name, definition in definitions.items():
        if not isinstance(name, str) or not isinstance(definition, dict):
            continue
        out[name] = _security_scheme(definition)
    return out


def _security_scheme(definition: dict[str, Any]) -> dict[str, Any]:
    scheme_type = definition.get("type")
    description = definition.get("description")
    scheme: dict[str, Any]
    if scheme_type == "basic":
        scheme = {"type": "http", "scheme": "basic"}
    elif scheme_type == "apiKey":
        scheme = {"type": "apiKey"}
        if isinstance(definition.get("name"), str):
            scheme["name"] = definition["name"]
        if definition.get("in") in ("header", "query"):
            scheme["in"] = definition["in"]
    elif scheme_type == "oauth2":
        scheme = {"type": "oauth2", "flows": _oauth2_flow(definition)}
    else:
        scheme = copy.deepcopy(definition)  # unknown scheme: carry through verbatim (inert)
    if isinstance(description, str):
        scheme["description"] = description
    for key, value in definition.items():
        if key.startswith("x-"):
            scheme[key] = copy.deepcopy(value)
    return scheme


def _oauth2_flow(definition: dict[str, Any]) -> dict[str, Any]:
    flow_name = {
        "implicit": "implicit",
        "password": "password",
        "application": "clientCredentials",
        "accessCode": "authorizationCode",
    }.get(str(definition.get("flow")))
    if flow_name is None:
        return {}
    flow: dict[str, Any] = {}
    if flow_name in ("implicit", "authorizationCode") and isinstance(
        definition.get("authorizationUrl"), str
    ):
        flow["authorizationUrl"] = definition["authorizationUrl"]
    if flow_name in ("password", "clientCredentials", "authorizationCode") and isinstance(
        definition.get("tokenUrl"), str
    ):
        flow["tokenUrl"] = definition["tokenUrl"]
    flow["scopes"] = (
        copy.deepcopy(definition["scopes"]) if isinstance(definition.get("scopes"), dict) else {}
    )
    return {flow_name: flow}


# --------------------------------------------------------------------------- schema + refs


def _convert_schema(node: Any, depth: int = 0) -> Any:
    """Deep-copy a Swagger schema into its OpenAPI 3.0 form. OpenAPI 3.0 schemas are the same JSON
    Schema subset as Swagger 2, so the only structural change is `discriminator` (a property-name
    string in Swagger → an object in OpenAPI 3). Local `$ref`s are rewritten in the final global
    pass, not here."""
    if depth > MAX_CONVERT_DEPTH:
        raise IngestionError("malformed_spec", "schema nesting is too deep")
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for key, value in node.items():
            if key == "discriminator" and isinstance(value, str):
                out[key] = {"propertyName": value}
            else:
                out[key] = _convert_schema(value, depth + 1)
        return out
    if isinstance(node, list):
        return [_convert_schema(item, depth + 1) for item in node]
    return node


def _rewrite_local_refs(node: Any, body_param_names: set[str], depth: int = 0) -> Any:
    """Rewrite every LOCAL `$ref` pointer from Swagger's flat namespaces to OpenAPI 3 `components`.
    Remote refs (anything with a non-empty base before `#`) are left untouched so B1.2's resolver
    fetches and navigates them as-is."""
    if depth > MAX_CONVERT_DEPTH:
        raise IngestionError("malformed_spec", "specification nesting is too deep")
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str) and value.startswith("#"):
                out[key] = _rewrite_pointer(value, body_param_names)
            else:
                out[key] = _rewrite_local_refs(value, body_param_names, depth + 1)
        return out
    if isinstance(node, list):
        return [_rewrite_local_refs(item, body_param_names, depth + 1) for item in node]
    return node


def _rewrite_pointer(ref: str, body_param_names: set[str]) -> str:
    if ref.startswith("#/definitions/"):
        return "#/components/schemas/" + ref[len("#/definitions/") :]
    if ref.startswith("#/responses/"):
        return "#/components/responses/" + ref[len("#/responses/") :]
    if ref.startswith("#/parameters/"):
        name = ref[len("#/parameters/") :]
        if name in body_param_names:
            return "#/components/requestBodies/" + name
        return "#/components/parameters/" + name
    return ref


def _string_list(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


__all__ = ["OPENAPI_TARGET", "convert", "is_swagger2"]
