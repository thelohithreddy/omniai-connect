"""OpenAPI 3.0 parser + normalizer (M1.4-B1.1) — hostile input, determinism, mapping. No DB.

The spec is untrusted: these tests are the adversarial matrix (safe YAML, alias/depth/size bombs,
remote/cyclic/missing $ref, non-finite numbers) plus the normalization contract (one Tool per
(path, method), name derivation, input_schema merge, endpoint binding, safety annotations) and the
determinism/hash guarantee that dedupes no-op re-syncs.
"""

from __future__ import annotations

import json

import pytest

from app.domains.connectors import openapi as oa
from app.domains.connectors.openapi import IngestionError

MINIMAL = {
    "openapi": "3.0.3",
    "info": {"title": "T", "version": "1"},
    "servers": [{"url": "https://api.example.com/v1"}],
    "paths": {
        "/customers": {
            "get": {
                "operationId": "listCustomers",
                "summary": "List customers",
                "tags": ["cust"],
                "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer"}}],
            },
            "post": {
                "operationId": "createCustomer",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["email"],
                                "properties": {"email": {"type": "string"}},
                            }
                        }
                    }
                },
            },
        },
        "/customers/{id}": {
            "delete": {
                "operationId": "deleteCustomer",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
            }
        },
    },
}


def _spec(doc: object) -> bytes:
    return json.dumps(doc).encode()


async def _tools(doc: object = MINIMAL, slug: str = "demo") -> list[dict]:
    parsed = oa.load_spec(_spec(doc))
    oa.detect_version(parsed)
    return await oa.normalize(parsed, slug)


# ------------------------------------------------------------------ parsing: JSON + YAML


async def test_json_and_yaml_parse_equivalently() -> None:
    yaml_spec = b"openapi: '3.0.0'\npaths:\n  /x:\n    get:\n      operationId: getX\n"
    doc = oa.load_spec(yaml_spec)
    assert doc["openapi"] == "3.0.0"
    assert oa.detect_version(doc) == "3.0.0"


async def test_root_must_be_an_object() -> None:
    with pytest.raises(IngestionError) as e:
        oa.load_spec(b"[1, 2, 3]")
    assert e.value.reason_code == "malformed_spec"


async def test_invalid_utf8_is_rejected() -> None:
    with pytest.raises(IngestionError) as e:
        oa.load_spec(b"\xff\xfe\x00bad")
    assert e.value.reason_code == "malformed_spec"


async def test_oversize_is_rejected() -> None:
    with pytest.raises(IngestionError) as e:
        oa.load_spec(b"x" * (oa.MAX_RAW_BYTES + 1))
    assert e.value.reason_code == "spec_too_large"


async def test_non_finite_numbers_are_rejected() -> None:
    with pytest.raises(IngestionError):
        oa.load_spec(b'{"openapi":"3.0.0","x":NaN}')
    with pytest.raises(IngestionError):
        oa.load_spec(b'{"openapi":"3.0.0","x":Infinity}')


# ------------------------------------------------------------------ YAML safety


async def test_yaml_aliases_are_refused_alias_bomb() -> None:
    # The classic 'billion laughs' expansion — refused before it can multiply.
    bomb = b"a: &a ['x','x']\nb: &b [*a,*a,*a]\nc: [*b,*b,*b]\n"
    with pytest.raises(IngestionError) as e:
        oa.load_spec(bomb)
    assert e.value.reason_code == "malformed_spec"


async def test_yaml_python_object_tags_are_refused() -> None:
    # SafeLoader refuses `!!python/...` construction — no code execution from a spec.
    with pytest.raises(IngestionError):
        oa.load_spec(b"x: !!python/object/apply:os.system ['echo hi']\n")


async def test_excessive_nesting_is_rejected() -> None:
    deep: object = {}
    for _ in range(oa.MAX_DEPTH + 5):
        deep = {"a": deep}
    with pytest.raises(IngestionError) as e:
        oa.load_spec(_spec({"openapi": "3.0.0", "paths": {}, "deep": deep}))
    assert e.value.reason_code == "malformed_spec"


# ------------------------------------------------------------------ version detection


@pytest.mark.parametrize("version", ["3.0.0", "3.0.1", "3.0.3"])
async def test_supported_openapi_30_versions(version: str) -> None:
    assert oa.detect_version({"openapi": version, "paths": {}}) == version


@pytest.mark.parametrize(
    "doc",
    [
        {"swagger": "2.0", "paths": {}},  # swagger 2 — deferred
        {"openapi": "3.1.0", "paths": {}},  # 3.1 — deferred
        {"info": {}},  # not an OpenAPI doc
        {"openapi": 3.0, "paths": {}},  # numeric, not a version string
    ],
)
async def test_unsupported_or_non_openapi_is_rejected(doc: dict) -> None:
    with pytest.raises(IngestionError) as e:
        oa.detect_version(doc)
    assert e.value.reason_code == "unsupported_format"


# ------------------------------------------------------------------ normalization mapping


async def test_one_tool_per_path_method_in_spec_order() -> None:
    tools = await _tools()
    assert [t["name"] for t in tools] == [
        "demo_listcustomers",
        "demo_createcustomer",
        "demo_deletecustomer",
    ]
    assert [t["endpoint"]["method"] for t in tools] == ["GET", "POST", "DELETE"]


async def test_input_schema_merges_params_and_body_with_binding() -> None:
    tools = {t["name"]: t for t in await _tools()}
    post = tools["demo_createcustomer"]
    assert post["input_schema"]["properties"]["email"] == {"type": "string"}
    assert post["input_schema"]["required"] == ["email"]
    assert post["endpoint"]["binding"]["email"] == {"location": "body"}
    assert post["endpoint"]["body_style"] == "json"
    get = tools["demo_listcustomers"]
    assert get["endpoint"]["binding"]["limit"] == {"location": "query"}


async def test_path_parameters_are_always_required() -> None:
    delete = {t["name"]: t for t in await _tools()}["demo_deletecustomer"]
    assert delete["input_schema"]["required"] == ["id"]
    assert delete["endpoint"]["binding"]["id"] == {"location": "path"}


async def test_a_path_param_is_required_even_without_explicit_required() -> None:
    # OpenAPI path params are required by definition; a spec that omits `required: true` must
    # still yield a required argument.
    doc = {
        "openapi": "3.0.0",
        "paths": {
            "/x/{id}": {
                "get": {
                    "operationId": "g",
                    "parameters": [{"name": "id", "in": "path", "schema": {}}],
                }
            }
        },
    }
    tool = (await oa.normalize(doc, "c"))[0]
    assert tool["input_schema"]["required"] == ["id"]


async def test_annotations_reflect_http_semantics() -> None:
    tools = {t["name"]: t for t in await _tools()}
    assert tools["demo_listcustomers"]["annotations"] == {
        "readonly": True,
        "destructive": False,
        "idempotent": True,
    }
    assert tools["demo_deletecustomer"]["annotations"] == {
        "readonly": False,
        "destructive": True,
        "idempotent": True,
    }
    assert tools["demo_createcustomer"]["annotations"] == {
        "readonly": False,
        "destructive": False,
        "idempotent": False,
    }


async def test_required_fields_of_the_tool_schema_are_present() -> None:
    for tool in await _tools():
        for field in ("name", "description", "input_schema", "endpoint", "annotations"):
            assert field in tool
        assert tool["name"] and tool["name"][0].isalpha()
        assert len(tool["name"]) <= 64


async def test_missing_operation_id_generates_a_slug_from_method_and_path() -> None:
    doc = {"openapi": "3.0.0", "paths": {"/foo/bar": {"get": {}}}}
    assert (await oa.normalize(doc, "c"))[0]["name"] == "c_get_foo_bar"


async def test_duplicate_operation_ids_get_deterministic_suffixes() -> None:
    doc = {
        "openapi": "3.0.0",
        "paths": {
            "/a": {"get": {"operationId": "same"}},
            "/b": {"get": {"operationId": "same"}},
        },
    }
    names = [t["name"] for t in await oa.normalize(doc, "c")]
    assert names == ["c_same", "c_same_2"]


async def test_auth_required_follows_security() -> None:
    doc = {
        "openapi": "3.0.0",
        "security": [{"apiKey": []}],
        "paths": {
            "/secured": {"get": {"operationId": "s"}},
            "/open": {"get": {"operationId": "o", "security": []}},  # operation overrides doc
        },
    }
    tools = {t["name"]: t for t in await oa.normalize(doc, "c")}
    assert tools["c_s"]["auth"]["required"] is True
    assert tools["c_o"]["auth"]["required"] is False


async def test_servers_resolve_base_url_with_variable_defaults() -> None:
    doc = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://{host}/v1", "variables": {"host": {"default": "api.x.com"}}}],
        "paths": {},
    }
    assert oa.base_url_from_servers(doc) == "https://api.x.com/v1"


async def test_a_spec_with_no_operations_is_rejected() -> None:
    with pytest.raises(IngestionError) as e:
        await oa.normalize({"openapi": "3.0.0", "paths": {}}, "c")
    assert e.value.reason_code == "no_operations"


# ------------------------------------------------------------------ $ref resolution


async def test_local_ref_is_resolved() -> None:
    doc = {
        "openapi": "3.0.0",
        "components": {
            "parameters": {"Limit": {"name": "limit", "in": "query", "schema": {"type": "integer"}}}
        },
        "paths": {
            "/x": {
                "get": {
                    "operationId": "x",
                    "parameters": [{"$ref": "#/components/parameters/Limit"}],
                }
            }
        },
    }
    tool = (await oa.normalize(doc, "c"))[0]
    assert tool["endpoint"]["binding"]["limit"] == {"location": "query"}


async def test_remote_ref_is_refused() -> None:
    doc = {
        "openapi": "3.0.0",
        "paths": {
            "/x": {"get": {"operationId": "x", "parameters": [{"$ref": "https://evil.example/p"}]}}
        },
    }
    with pytest.raises(IngestionError) as e:
        await oa.normalize(doc, "c")
    assert e.value.reason_code == "invalid_reference"


async def test_missing_local_ref_is_refused() -> None:
    doc = {
        "openapi": "3.0.0",
        "paths": {"/x": {"get": {"operationId": "x", "parameters": [{"$ref": "#/nope/missing"}]}}},
    }
    with pytest.raises(IngestionError) as e:
        await oa.normalize(doc, "c")
    assert e.value.reason_code == "invalid_reference"


async def test_the_total_ref_count_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oa, "MAX_REFS", 2)
    doc = {
        "openapi": "3.0.0",
        "components": {"schemas": {"A": {"type": "string"}}},
        "paths": {
            "/x": {
                "post": {
                    "operationId": "x",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        k: {"$ref": "#/components/schemas/A"} for k in "abcd"
                                    },
                                }
                            }
                        }
                    },
                }
            }
        },
    }
    with pytest.raises(IngestionError) as e:
        await oa.normalize(doc, "c")
    assert e.value.reason_code == "invalid_reference"


async def test_ref_resolution_depth_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oa, "MAX_REF_DEPTH", 2)
    doc = {
        "openapi": "3.0.0",
        "paths": {
            "/x": {
                "post": {
                    "operationId": "x",
                    "requestBody": {
                        "content": {"application/json": {"schema": {"a": {"b": {"c": {"d": {}}}}}}}
                    },
                }
            }
        },
    }
    with pytest.raises(IngestionError) as e:
        await oa.normalize(doc, "c")
    assert e.value.reason_code == "invalid_reference"


def test_the_openapi_module_has_no_network_capability() -> None:
    # Remote $refs are fetched only through the INJECTED guarded callback (B0.1) — the module
    # imports no network-capable library of its own, so it can never open a socket directly.
    # (`urllib.parse.urljoin` is pure string manipulation, not network I/O.)
    import inspect

    module_source = inspect.getsource(oa)
    for imp in (
        "import httpx",
        "import socket",
        "urllib.request",
        "import requests",
        "aiohttp",
        "http.client",
        "app.core.net",
    ):
        assert imp not in module_source, f"the openapi module must not import {imp}"


async def test_cyclic_ref_is_broken_not_infinite() -> None:
    doc = {
        "openapi": "3.0.0",
        "components": {
            "schemas": {"Node": {"properties": {"next": {"$ref": "#/components/schemas/Node"}}}}
        },
        "paths": {
            "/x": {
                "post": {
                    "operationId": "x",
                    "requestBody": {
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Node"}}
                        }
                    },
                }
            }
        },
    }
    tool = (await oa.normalize(doc, "c"))[0]  # must terminate
    assert "next" in tool["input_schema"]["properties"]


# ------------------------------------------------------------------ determinism + hash


async def test_normalization_is_deterministic() -> None:
    assert oa.spec_hash(await _tools()) == oa.spec_hash(await _tools())


async def test_reordered_keys_produce_the_same_hash() -> None:
    reordered = {
        "paths": MINIMAL["paths"],
        "info": MINIMAL["info"],
        "servers": MINIMAL["servers"],
        "openapi": "3.0.3",
    }
    assert oa.spec_hash(await _tools()) == oa.spec_hash(await _tools(reordered))


async def test_a_changed_operation_changes_the_hash() -> None:
    changed = json.loads(json.dumps(MINIMAL))
    changed["paths"]["/customers"]["get"]["parameters"].append(
        {"name": "email", "in": "query", "schema": {"type": "string"}}
    )
    assert oa.spec_hash(await _tools()) != oa.spec_hash(await _tools(changed))


async def test_canonical_bytes_are_sorted_and_compact() -> None:
    raw = oa.canonical_bytes([{"b": 1, "a": 2}])
    assert raw == b'[{"a":2,"b":1}]'
