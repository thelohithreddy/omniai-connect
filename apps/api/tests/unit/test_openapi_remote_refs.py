"""Remote `$ref` resolution (M1.4-B1.2) — the reference graph is attacker-controlled.

The resolver never fetches directly; it hands each remote URL to an injected guarded-fetch callback
(here a canned map / a failing stub). These tests prove: remote refs are resolved and inlined;
local refs inside a remote doc resolve against that doc; nested/relative refs work; cycles,
self-refs, and fan-out are bounded and deduped; count/depth/aggregate-size budgets hold; a fetch
failure (SSRF/timeout) is FATAL (never silently skipped); non-http schemes are refused; and with no
fetch callback remote refs are refused (the B1.1 local-only mode). The real SSRF enforcement lives
in B0.1 (tests/unit/test_net.py) and is verified end-to-end in the integration suite.
"""

from __future__ import annotations

import json

import pytest

from app.domains.connectors import openapi as oa
from app.domains.connectors.openapi import Fetcher, IngestionError

BASE = "https://schemas.example.com"


def _bytes(doc: object) -> bytes:
    return json.dumps(doc).encode()


def _fetcher(docs: dict[str, bytes], calls: list[str] | None = None) -> Fetcher:
    async def fetch(url: str) -> bytes:
        if calls is not None:
            calls.append(url)
        if url not in docs:
            # Simulate the guarded fetcher refusing/failing (SSRF, 404, timeout) — any exception.
            raise RuntimeError("blocked or unreachable")
        return docs[url]

    return fetch


def _root(ref: object) -> dict:
    return {
        "openapi": "3.0.0",
        "paths": {
            "/x": {
                "get": {
                    "operationId": "x",
                    "parameters": [{"name": "q", "in": "query", "schema": ref}],
                }
            }
        },
    }


async def _one_tool(root: dict, fetch: Fetcher | None) -> dict:
    tools = await oa.normalize(root, "c", fetch=fetch)
    return tools[0]


# ------------------------------------------------------------------ resolution


async def test_remote_json_ref_is_resolved_and_inlined() -> None:
    remote = {"components": {"schemas": {"Q": {"type": "string", "maxLength": 5}}}}
    root = _root({"$ref": f"{BASE}/c.json#/components/schemas/Q"})
    tool = await _one_tool(root, _fetcher({f"{BASE}/c.json": _bytes(remote)}))
    assert tool["input_schema"]["properties"]["q"] == {"type": "string", "maxLength": 5}


async def test_remote_yaml_ref_is_resolved() -> None:
    remote_yaml = b"components:\n  schemas:\n    Q:\n      type: integer\n"
    root = _root({"$ref": f"{BASE}/c.yaml#/components/schemas/Q"})
    tool = await _one_tool(root, _fetcher({f"{BASE}/c.yaml": remote_yaml}))
    assert tool["input_schema"]["properties"]["q"] == {"type": "integer"}


async def test_local_ref_inside_a_remote_doc_resolves_against_that_doc() -> None:
    # The remote schema Q refs Base *within its own document* — must resolve against the remote doc.
    remote = {
        "components": {
            "schemas": {
                "Base": {"type": "string"},
                "Q": {"allOf": [{"$ref": "#/components/schemas/Base"}]},
            }
        }
    }
    root = _root({"$ref": f"{BASE}/c.json#/components/schemas/Q"})
    tool = await _one_tool(root, _fetcher({f"{BASE}/c.json": _bytes(remote)}))
    assert tool["input_schema"]["properties"]["q"]["allOf"] == [{"type": "string"}]


async def test_a_remote_doc_can_reference_another_remote_doc() -> None:
    a = {"components": {"schemas": {"A": {"$ref": f"{BASE}/b.json#/components/schemas/B"}}}}
    b = {"components": {"schemas": {"B": {"type": "boolean"}}}}
    root = _root({"$ref": f"{BASE}/a.json#/components/schemas/A"})
    tool = await _one_tool(
        root, _fetcher({f"{BASE}/a.json": _bytes(a), f"{BASE}/b.json": _bytes(b)})
    )
    assert tool["input_schema"]["properties"]["q"] == {"type": "boolean"}


async def test_relative_ref_resolves_against_the_remote_doc_url() -> None:
    a = {"components": {"schemas": {"A": {"$ref": "b.json#/components/schemas/B"}}}}  # relative
    b = {"components": {"schemas": {"B": {"type": "null"}}}}
    root = _root({"$ref": f"{BASE}/dir/a.json#/components/schemas/A"})
    tool = await _one_tool(
        root, _fetcher({f"{BASE}/dir/a.json": _bytes(a), f"{BASE}/dir/b.json": _bytes(b)})
    )
    assert tool["input_schema"]["properties"]["q"] == {"type": "null"}


# ------------------------------------------------------------------ dedup / cycles / bounds


async def test_a_repeated_remote_ref_is_fetched_once() -> None:
    remote = {"components": {"schemas": {"Q": {"type": "string"}}}}
    root = {
        "openapi": "3.0.0",
        "paths": {
            "/x": {
                "get": {
                    "operationId": "x",
                    "parameters": [
                        {
                            "name": "a",
                            "in": "query",
                            "schema": {"$ref": f"{BASE}/c.json#/components/schemas/Q"},
                        },
                        {
                            "name": "b",
                            "in": "query",
                            "schema": {"$ref": f"{BASE}/c.json#/components/schemas/Q"},
                        },
                    ],
                }
            }
        },
    }
    calls: list[str] = []
    await oa.normalize(root, "c", fetch=_fetcher({f"{BASE}/c.json": _bytes(remote)}, calls))
    assert calls == [f"{BASE}/c.json"]  # deduped: fetched once despite two refs


async def test_a_remote_cycle_is_broken_not_infinite() -> None:
    a = {"components": {"schemas": {"A": {"$ref": f"{BASE}/b.json#/components/schemas/B"}}}}
    b = {"components": {"schemas": {"B": {"$ref": f"{BASE}/a.json#/components/schemas/A"}}}}
    root = _root({"$ref": f"{BASE}/a.json#/components/schemas/A"})
    tool = await _one_tool(
        root, _fetcher({f"{BASE}/a.json": _bytes(a), f"{BASE}/b.json": _bytes(b)})
    )  # must terminate
    assert "q" in tool["input_schema"]["properties"]


async def test_remote_ref_count_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oa, "MAX_REFS", 2)
    docs = {
        f"{BASE}/{k}.json": _bytes({"components": {"schemas": {"S": {"type": "string"}}}})
        for k in "abcd"
    }
    root = {
        "openapi": "3.0.0",
        "paths": {
            "/x": {
                "get": {
                    "operationId": "x",
                    "parameters": [
                        {
                            "name": k,
                            "in": "query",
                            "schema": {"$ref": f"{BASE}/{k}.json#/components/schemas/S"},
                        }
                        for k in "abcd"
                    ],
                }
            }
        },
    }
    with pytest.raises(IngestionError) as e:
        await oa.normalize(root, "c", fetch=_fetcher(docs))
    assert e.value.reason_code == "invalid_reference"


async def test_remote_aggregate_size_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oa, "MAX_REMOTE_BYTES", 10)  # tiny budget
    remote = {"components": {"schemas": {"Q": {"type": "string", "description": "x" * 100}}}}
    root = _root({"$ref": f"{BASE}/c.json#/components/schemas/Q"})
    with pytest.raises(IngestionError) as e:
        await _one_tool(root, _fetcher({f"{BASE}/c.json": _bytes(remote)}))
    assert e.value.reason_code == "invalid_reference"


# ------------------------------------------------------------------ failure = fatal


async def test_remote_fetch_failure_is_fatal() -> None:
    # The fetcher refuses (SSRF/404/timeout): a remote ref is never silently skipped.
    root = _root({"$ref": f"{BASE}/missing.json#/x"})
    with pytest.raises(IngestionError) as e:
        await _one_tool(root, _fetcher({}))  # empty map → the fetch raises
    assert e.value.reason_code == "invalid_reference"


async def test_a_malformed_remote_document_is_rejected() -> None:
    root = _root({"$ref": f"{BASE}/bad.json#/x"})
    with pytest.raises(IngestionError):
        await _one_tool(root, _fetcher({f"{BASE}/bad.json": b"{ not valid"}))


async def test_a_remote_fragment_that_does_not_resolve_is_rejected() -> None:
    remote = {"components": {"schemas": {"Q": {"type": "string"}}}}
    root = _root({"$ref": f"{BASE}/c.json#/components/schemas/Missing"})
    with pytest.raises(IngestionError) as e:
        await _one_tool(root, _fetcher({f"{BASE}/c.json": _bytes(remote)}))
    assert e.value.reason_code == "invalid_reference"


@pytest.mark.parametrize("scheme", ["file:///etc/passwd#/x", "ftp://host/x#/y", "gopher://x#/y"])
async def test_non_http_ref_schemes_are_refused_before_any_fetch(scheme: str) -> None:
    # A non-http scheme is refused BEFORE the fetcher is invoked — it can never reach egress even
    # if a (hypothetical) fetcher would serve it. The canned fetcher here *would* return valid
    # content, so only the scheme guard prevents resolution.
    root = _root({"$ref": scheme})
    calls: list[str] = []
    valid = _bytes({"x": {"type": "string"}})
    with pytest.raises(IngestionError) as e:
        await _one_tool(root, _fetcher({scheme: valid}, calls))
    assert e.value.reason_code == "invalid_reference"
    assert calls == []  # the fetcher was never called for a non-http scheme


async def test_without_a_fetch_callback_remote_refs_are_refused() -> None:
    # The B1.1 local-only mode: no fetch → a remote ref is refused (never silently ignored).
    root = _root({"$ref": f"{BASE}/c.json#/x"})
    with pytest.raises(IngestionError) as e:
        await _one_tool(root, None)
    assert e.value.reason_code == "invalid_reference"


# ------------------------------------------------------------------ determinism (location-free)


async def test_same_resolved_content_yields_the_same_hash_regardless_of_ref_origin() -> None:
    schema = {"type": "string", "maxLength": 3}
    # (a) inline; (b) via a remote ref that resolves to the identical schema.
    inline_root = _root(schema)
    remote_root = _root({"$ref": f"{BASE}/c.json#/components/schemas/Q"})
    remote_docs = {f"{BASE}/c.json": _bytes({"components": {"schemas": {"Q": schema}}})}

    inline_tools = await oa.normalize(inline_root, "c", fetch=None)
    remote_tools = await oa.normalize(remote_root, "c", fetch=_fetcher(remote_docs))
    assert oa.spec_hash(inline_tools) == oa.spec_hash(remote_tools)


async def test_a_changed_remote_dependency_changes_the_hash() -> None:
    root = _root({"$ref": f"{BASE}/c.json#/components/schemas/Q"})
    v1 = await oa.normalize(
        root,
        "c",
        fetch=_fetcher(
            {f"{BASE}/c.json": _bytes({"components": {"schemas": {"Q": {"type": "string"}}}})}
        ),
    )
    v2 = await oa.normalize(
        root,
        "c",
        fetch=_fetcher(
            {f"{BASE}/c.json": _bytes({"components": {"schemas": {"Q": {"type": "integer"}}}})}
        ),
    )
    assert oa.spec_hash(v1) != oa.spec_hash(v2)
