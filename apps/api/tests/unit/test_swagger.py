"""Swagger 2.0 → OpenAPI 3.0 conversion (M1.4-B1.3). Deterministic, pure, network-free.

Two layers of assertion: (1) DIRECT on `swagger.convert(doc)` — the OpenAPI-3 structure it emits,
including the parts the current normalizer ignores (responses, securitySchemes, servers), because
the converter must be faithful independently of what consumes it; (2) THROUGH `to_openapi3` +
`normalize` — the canonical Tool Schema an ingested Swagger spec produces, and the guarantee that a
Swagger document and its native OpenAPI-3 equivalent normalize to the SAME `spec_hash` (there is no
separate normalization logic, CONNECTOR_ENGINE §3). Detection is strict; `host`/`schemes` never
trigger a fetch (the module imports nothing network-capable).
"""

from __future__ import annotations

import json

import pytest

from app.domains.connectors import openapi as oa
from app.domains.connectors import swagger
from app.domains.connectors.openapi import IngestionError

# A representative Swagger 2.0 document exercising every top-level construct.
PETSTORE: dict = {
    "swagger": "2.0",
    "info": {"title": "Petstore", "version": "1"},
    "host": "api.pets.com",
    "basePath": "/v1",
    "schemes": ["https"],
    "consumes": ["application/json"],
    "produces": ["application/json"],
    "tags": [{"name": "pets"}],
    "securityDefinitions": {
        "api_key": {"type": "apiKey", "name": "X-Key", "in": "header"},
        "basic_auth": {"type": "basic"},
        "oauth": {
            "type": "oauth2",
            "flow": "accessCode",
            "authorizationUrl": "https://auth.pets.com/authorize",
            "tokenUrl": "https://auth.pets.com/token",
            "scopes": {"read": "read pets"},
        },
    },
    "security": [{"api_key": []}],
    "definitions": {
        "Pet": {
            "type": "object",
            "required": ["name"],
            "properties": {"name": {"type": "string"}, "tag": {"type": "string"}},
        }
    },
    "parameters": {
        "PageSize": {"name": "page_size", "in": "query", "type": "integer", "maximum": 100}
    },
    "responses": {"NotFound": {"description": "missing"}},
    "paths": {
        "/pets": {
            "get": {
                "operationId": "listPets",
                "summary": "List pets",
                "tags": ["pets"],
                "parameters": [
                    {"name": "limit", "in": "query", "type": "integer"},
                    {"$ref": "#/parameters/PageSize"},
                ],
                "responses": {
                    "200": {
                        "description": "ok",
                        "schema": {"type": "array", "items": {"$ref": "#/definitions/Pet"}},
                    },
                    "404": {"$ref": "#/responses/NotFound"},
                },
            },
            "post": {
                "operationId": "createPet",
                "parameters": [
                    {
                        "name": "body",
                        "in": "body",
                        "required": True,
                        "schema": {"$ref": "#/definitions/Pet"},
                    }
                ],
                "responses": {"201": {"description": "created"}},
            },
        },
        "/pets/{id}": {
            "delete": {
                "operationId": "deletePet",
                "parameters": [{"name": "id", "in": "path", "required": True, "type": "string"}],
                "responses": {"204": {"description": "gone"}},
            }
        },
    },
}


def _bytes(doc: object) -> bytes:
    return json.dumps(doc).encode()


# ================================================================== detection


def test_is_swagger2_requires_the_exact_version_string() -> None:
    assert swagger.is_swagger2({"swagger": "2.0"}) is True
    assert swagger.is_swagger2({"swagger": 2.0}) is False  # numeric, not the string identity
    assert swagger.is_swagger2({"swagger": "1.0"}) is False
    # Never inferred from incidental fields.
    assert swagger.is_swagger2({"host": "x", "basePath": "/v1", "definitions": {}}) is False


def test_to_openapi3_converts_swagger_and_passes_openapi_through() -> None:
    converted = oa.to_openapi3({"swagger": "2.0", "paths": {"/x": {"get": {}}}})
    assert converted["openapi"].startswith("3.0")
    native = {"openapi": "3.0.0", "paths": {}}
    assert oa.to_openapi3(native) is native  # OpenAPI 3 passes straight through


def test_a_document_with_both_swagger_and_openapi_is_ambiguous() -> None:
    with pytest.raises(IngestionError) as e:
        oa.to_openapi3({"swagger": "2.0", "openapi": "3.0.0", "paths": {}})
    assert e.value.reason_code == "unsupported_format"


@pytest.mark.parametrize("version", [2.0, "1.0", "3.0", "2", "2.0.0"])
def test_an_unsupported_swagger_version_is_refused(version: object) -> None:
    with pytest.raises(IngestionError) as e:
        swagger.convert({"swagger": version, "paths": {}})
    assert e.value.reason_code == "unsupported_format"


# ================================================================== top-level mapping


def test_version_info_tags_externaldocs() -> None:
    out = swagger.convert(PETSTORE)
    assert out["openapi"] == "3.0.3"
    assert out["info"] == {"title": "Petstore", "version": "1"}
    assert out["tags"] == [{"name": "pets"}]


def test_schemes_host_basepath_become_servers_https_first() -> None:
    out = swagger.convert({**PETSTORE, "schemes": ["http", "https"]})
    assert out["servers"] == [
        {"url": "https://api.pets.com/v1"},
        {"url": "http://api.pets.com/v1"},
    ]


def test_no_schemes_defaults_to_https_server() -> None:
    doc = {"swagger": "2.0", "host": "api.pets.com", "basePath": "/v1", "paths": {}}
    assert swagger.convert(doc)["servers"] == [{"url": "https://api.pets.com/v1"}]


def test_basepath_only_yields_a_relative_server_and_no_host_no_servers() -> None:
    assert swagger.convert({"swagger": "2.0", "basePath": "/v2", "paths": {}})["servers"] == [
        {"url": "/v2"}
    ]
    assert "servers" not in swagger.convert({"swagger": "2.0", "paths": {}})


def test_definitions_become_component_schemas() -> None:
    schemas = swagger.convert(PETSTORE)["components"]["schemas"]
    assert schemas["Pet"]["required"] == ["name"]
    assert schemas["Pet"]["properties"]["name"] == {"type": "string"}


def test_top_level_parameters_become_component_parameters() -> None:
    params = swagger.convert(PETSTORE)["components"]["parameters"]
    assert params["PageSize"] == {
        "name": "page_size",
        "in": "query",
        "schema": {"type": "integer", "maximum": 100},
    }


def test_top_level_responses_become_component_responses() -> None:
    responses = swagger.convert(PETSTORE)["components"]["responses"]
    assert responses["NotFound"] == {"description": "missing"}


def test_security_definitions_become_security_schemes() -> None:
    schemes = swagger.convert(PETSTORE)["components"]["securitySchemes"]
    assert schemes["api_key"] == {"type": "apiKey", "name": "X-Key", "in": "header"}
    assert schemes["basic_auth"] == {"type": "http", "scheme": "basic"}
    assert schemes["oauth"] == {
        "type": "oauth2",
        "flows": {
            "authorizationCode": {
                "authorizationUrl": "https://auth.pets.com/authorize",
                "tokenUrl": "https://auth.pets.com/token",
                "scopes": {"read": "read pets"},
            }
        },
    }


def test_top_level_security_is_carried_through() -> None:
    assert swagger.convert(PETSTORE)["security"] == [{"api_key": []}]


def test_vendor_extensions_survive() -> None:
    out = swagger.convert({"swagger": "2.0", "x-logo": {"url": "u"}, "paths": {}})
    assert out["x-logo"] == {"url": "u"}


# ================================================================== parameters + body


def test_query_and_path_parameters_convert_to_schema_form() -> None:
    get = swagger.convert(PETSTORE)["paths"]["/pets"]["get"]
    limit = next(p for p in get["parameters"] if p.get("name") == "limit")
    assert limit == {"name": "limit", "in": "query", "schema": {"type": "integer"}}
    delete = swagger.convert(PETSTORE)["paths"]["/pets/{id}"]["delete"]
    assert delete["parameters"][0] == {
        "name": "id",
        "in": "path",
        "required": True,
        "schema": {"type": "string"},
    }


def test_a_parameter_ref_is_preserved_and_rewritten() -> None:
    get = swagger.convert(PETSTORE)["paths"]["/pets"]["get"]
    assert {"$ref": "#/components/parameters/PageSize"} in get["parameters"]


def test_a_path_parameter_is_required_even_without_an_explicit_flag() -> None:
    doc = {
        "swagger": "2.0",
        "paths": {
            "/x/{id}": {"get": {"operationId": "g", "parameters": [{"name": "id", "in": "path"}]}}
        },
    }
    param = swagger.convert(doc)["paths"]["/x/{id}"]["get"]["parameters"][0]
    assert param["required"] is True


def test_a_reusable_body_parameter_becomes_a_request_body_ref() -> None:
    doc = {
        "swagger": "2.0",
        "parameters": {
            "PetBody": {"name": "b", "in": "body", "schema": {"$ref": "#/definitions/Pet"}}
        },
        "definitions": {"Pet": {"type": "object"}},
        "paths": {
            "/pets": {
                "post": {"operationId": "cp", "parameters": [{"$ref": "#/parameters/PetBody"}]}
            }
        },
    }
    out = swagger.convert(doc)
    # The reusable body lives under components.requestBodies, and the operation refs it there.
    assert "PetBody" in out["components"]["requestBodies"]
    assert out["paths"]["/pets"]["post"]["requestBody"] == {
        "$ref": "#/components/requestBodies/PetBody"
    }
    assert "parameters" not in out["paths"]["/pets"]["post"]


def test_body_parameter_becomes_request_body() -> None:
    post = swagger.convert(PETSTORE)["paths"]["/pets"]["post"]
    assert post["requestBody"] == {
        "required": True,
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}},
    }
    assert "parameters" not in post  # the body param left the parameter list


def test_body_parameter_uses_declared_consumes_media_types() -> None:
    doc = {
        "swagger": "2.0",
        "consumes": ["application/xml"],
        "paths": {
            "/x": {
                "post": {
                    "operationId": "x",
                    "parameters": [{"name": "b", "in": "body", "schema": {"type": "object"}}],
                }
            }
        },
    }
    post = swagger.convert(doc)["paths"]["/x"]["post"]
    assert set(post["requestBody"]["content"]) == {"application/xml"}


def test_form_data_becomes_a_form_request_body() -> None:
    doc = {
        "swagger": "2.0",
        "paths": {
            "/upload": {
                "post": {
                    "operationId": "up",
                    "parameters": [
                        {"name": "note", "in": "formData", "type": "string", "required": True},
                        {"name": "file", "in": "formData", "type": "file"},
                    ],
                }
            }
        },
    }
    rb = swagger.convert(doc)["paths"]["/upload"]["post"]["requestBody"]
    assert set(rb["content"]) == {"multipart/form-data"}  # a file field forces multipart
    schema = rb["content"]["multipart/form-data"]["schema"]
    assert schema["properties"]["note"] == {"type": "string"}
    assert schema["properties"]["file"] == {"type": "string", "format": "binary"}
    assert schema["required"] == ["note"]


def test_form_data_without_a_file_is_urlencoded() -> None:
    doc = {
        "swagger": "2.0",
        "paths": {
            "/f": {
                "post": {
                    "operationId": "f",
                    "parameters": [{"name": "a", "in": "formData", "type": "string"}],
                }
            }
        },
    }
    rb = swagger.convert(doc)["paths"]["/f"]["post"]["requestBody"]
    assert set(rb["content"]) == {"application/x-www-form-urlencoded"}


def test_collection_format_maps_to_style_and_explode() -> None:
    doc = {
        "swagger": "2.0",
        "paths": {
            "/x": {
                "get": {
                    "operationId": "x",
                    "parameters": [
                        {
                            "name": "ids",
                            "in": "query",
                            "type": "array",
                            "items": {"type": "string"},
                            "collectionFormat": "multi",
                        }
                    ],
                }
            }
        },
    }
    param = swagger.convert(doc)["paths"]["/x"]["get"]["parameters"][0]
    assert param["style"] == "form" and param["explode"] is True


def test_path_level_parameters_are_preserved() -> None:
    doc = {
        "swagger": "2.0",
        "paths": {
            "/x": {
                "parameters": [{"name": "tenant", "in": "header", "type": "string"}],
                "get": {"operationId": "x"},
            }
        },
    }
    item = swagger.convert(doc)["paths"]["/x"]
    assert item["parameters"][0] == {
        "name": "tenant",
        "in": "header",
        "schema": {"type": "string"},
    }


def test_responses_with_schema_become_content() -> None:
    get = swagger.convert(PETSTORE)["paths"]["/pets"]["get"]
    assert get["responses"]["200"]["content"]["application/json"]["schema"] == {
        "type": "array",
        "items": {"$ref": "#/components/schemas/Pet"},
    }
    assert get["responses"]["404"] == {"$ref": "#/components/responses/NotFound"}


# ================================================================== schema conversion


def test_discriminator_string_becomes_an_object() -> None:
    doc = {
        "swagger": "2.0",
        "definitions": {"Base": {"type": "object", "discriminator": "petType"}},
        "paths": {},
    }
    assert swagger.convert(doc)["components"]["schemas"]["Base"]["discriminator"] == {
        "propertyName": "petType"
    }


def test_nested_schema_constructs_and_constraints_survive() -> None:
    doc = {
        "swagger": "2.0",
        "definitions": {
            "C": {
                "allOf": [{"$ref": "#/definitions/Base"}],
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {"type": "integer", "minimum": 0, "maximum": 10},
                        "uniqueItems": True,
                    }
                },
                "additionalProperties": False,
            },
            "Base": {"type": "object"},
        },
        "paths": {},
    }
    c = swagger.convert(doc)["components"]["schemas"]["C"]
    assert c["allOf"] == [{"$ref": "#/components/schemas/Base"}]
    assert c["properties"]["items"]["items"] == {"type": "integer", "minimum": 0, "maximum": 10}
    assert c["properties"]["items"]["uniqueItems"] is True
    assert c["additionalProperties"] is False


# ================================================================== references


def test_local_refs_are_rewritten_remote_refs_are_untouched() -> None:
    doc = {
        "swagger": "2.0",
        "paths": {
            "/x": {
                "post": {
                    "operationId": "x",
                    "parameters": [
                        {
                            "name": "b",
                            "in": "body",
                            "schema": {
                                "properties": {
                                    "local": {"$ref": "#/definitions/Pet"},
                                    "remote": {"$ref": "https://ext.example/s.json#/definitions/Q"},
                                }
                            },
                        }
                    ],
                }
            }
        },
        "definitions": {"Pet": {"type": "object"}},
    }
    schema = swagger.convert(doc)["paths"]["/x"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    assert schema["properties"]["local"] == {"$ref": "#/components/schemas/Pet"}
    # A remote ref keeps its Swagger-style fragment — B1.2's resolver navigates it as-is.
    assert schema["properties"]["remote"] == {"$ref": "https://ext.example/s.json#/definitions/Q"}


def test_deeply_nested_schema_is_rejected() -> None:
    deep: dict = {"type": "object"}
    for _ in range(swagger.MAX_CONVERT_DEPTH + 5):
        deep = {"type": "object", "properties": {"n": deep}}
    with pytest.raises(IngestionError) as e:
        swagger.convert({"swagger": "2.0", "definitions": {"D": deep}, "paths": {}})
    assert e.value.reason_code == "malformed_spec"


# ================================================================== no network


def test_the_swagger_module_has_no_network_capability() -> None:
    import inspect

    source = inspect.getsource(swagger)
    for imp in (
        "import httpx",
        "import socket",
        "urllib.request",
        "urllib",
        "import requests",
        "aiohttp",
        "http.client",
        "app.core.net",
        "get_object_store",
    ):
        assert imp not in source, f"the swagger converter must not reference {imp}"


# ================================================================== through the importer


async def _tools(doc: object, slug: str = "demo") -> list[dict]:
    parsed = oa.load_spec(_bytes(doc))
    return await oa.normalize(oa.to_openapi3(parsed), slug)


async def test_swagger_normalizes_to_the_canonical_tool_schema() -> None:
    tools = {t["name"]: t for t in await _tools(PETSTORE)}
    assert set(tools) == {"demo_listpets", "demo_createpet", "demo_deletepet"}
    # body parameter → json body argument
    post = tools["demo_createpet"]
    assert post["endpoint"]["body_style"] == "json"
    assert post["input_schema"]["required"] == ["name"]
    assert post["endpoint"]["binding"]["name"] == {"location": "body"}
    # query + reusable-parameter ref both land as query args
    get = tools["demo_listpets"]
    assert get["endpoint"]["binding"]["limit"] == {"location": "query"}
    assert get["endpoint"]["binding"]["page_size"] == {"location": "query"}
    # path param required
    assert tools["demo_deletepet"]["input_schema"]["required"] == ["id"]
    assert tools["demo_deletepet"]["annotations"]["destructive"] is True


async def test_form_data_normalizes_to_a_form_body_style() -> None:
    doc = {
        "swagger": "2.0",
        "paths": {
            "/u": {
                "post": {
                    "operationId": "u",
                    "parameters": [{"name": "f", "in": "formData", "type": "file"}],
                }
            }
        },
    }
    tool = (await _tools(doc))[0]
    assert tool["endpoint"]["body_style"] == "form"


async def test_base_url_comes_from_the_converted_servers() -> None:
    parsed = oa.load_spec(_bytes(PETSTORE))
    assert oa.base_url_from_servers(oa.to_openapi3(parsed)) == "https://api.pets.com/v1"


# ================================================================== determinism + equivalence


async def test_conversion_is_deterministic() -> None:
    assert swagger.convert(PETSTORE) == swagger.convert(PETSTORE)
    assert oa.spec_hash(await _tools(PETSTORE)) == oa.spec_hash(await _tools(PETSTORE))


async def test_swagger_and_native_openapi3_equivalents_hash_identically() -> None:
    # The SAME API described two ways must produce the SAME normalized Tool set → SAME spec_hash
    # (there is no separate normalization logic — CONNECTOR_ENGINE §3).
    swagger_doc = {
        "swagger": "2.0",
        "info": {"title": "T", "version": "1"},
        "host": "api.x.com",
        "basePath": "/v1",
        "schemes": ["https"],
        "paths": {
            "/things": {
                "get": {
                    "operationId": "listThings",
                    "summary": "List things",
                    "tags": ["t"],
                    "parameters": [{"name": "limit", "in": "query", "type": "integer"}],
                },
                "post": {
                    "operationId": "createThing",
                    "parameters": [
                        {
                            "name": "body",
                            "in": "body",
                            "required": True,
                            "schema": {
                                "type": "object",
                                "required": ["name"],
                                "properties": {"name": {"type": "string"}},
                            },
                        }
                    ],
                },
            }
        },
    }
    native_doc = {
        "openapi": "3.0.3",
        "info": {"title": "T", "version": "1"},
        "servers": [{"url": "https://api.x.com/v1"}],
        "paths": {
            "/things": {
                "get": {
                    "operationId": "listThings",
                    "summary": "List things",
                    "tags": ["t"],
                    "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer"}}],
                },
                "post": {
                    "operationId": "createThing",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["name"],
                                    "properties": {"name": {"type": "string"}},
                                }
                            }
                        },
                    },
                },
            }
        },
    }
    assert oa.spec_hash(await _tools(swagger_doc)) == oa.spec_hash(await _tools(native_doc))


async def test_a_changed_swagger_operation_changes_the_hash() -> None:
    changed = json.loads(json.dumps(PETSTORE))
    changed["paths"]["/pets"]["get"]["parameters"].append(
        {"name": "sort", "in": "query", "type": "string"}
    )
    assert oa.spec_hash(await _tools(PETSTORE)) != oa.spec_hash(await _tools(changed))
