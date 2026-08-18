"""MCP interface adapter (M2.2, ADR-0035) — a thin protocol layer over the canonical domains.

MCP is one Interface, not the product (Bible §2; MCP_RUNTIME §1). This package owns protocol
translation and transport only: JSON-RPC over Streamable HTTP, the pinned protocol-revision
allowlist, the canonical-Tool → MCP-tool mapping, and the workspace tools-discovery cache with
its event-driven eviction. It performs no execution, no credential work, no outbound HTTP, and
no authorization policy of its own — authentication and workspace binding reuse the existing
machine-token machinery (`core/security.py`), and PostgreSQL + RLS remain authoritative.
"""
