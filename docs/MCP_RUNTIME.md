# MCP Runtime

> Consistent with docs/MASTER_PROJECT_BIBLE.md. **MCP is one Interface, not the
> product** (Bible §2): this document specifies a thin adapter over the Execution
> Runtime (docs/AI_RUNTIME.md), built on FastMCP.
>
> Version 1.0 · 2026-08-02

## 1. Position in the architecture

The MCP server is one adapter in `apps/api/app/interfaces/mcp/`, alongside REST
tool-invocation, OpenAPI manifests, and framework SDK exporters. It translates MCP
protocol messages to `ToolCallRequest`/`ToolCallResult` and nothing more. *(M2.2,
ADR-0035: the adapter is currently a minimal in-house JSON-RPC/Streamable-HTTP layer
rather than FastMCP — founder-ratified for the discovery surface; FastMCP is
re-evaluated when tools/call lands, M2.3.)* Per Bible
tenet 4: **if an MCP handler contains an `if`, ask whether it belongs in the
runtime.** Policy, rate limits, quotas, credential handling, audit — all happen in
the Execution Runtime; the adapter owns only protocol translation and transport.

## 2. Endpoint model: server-per-workspace

Each Workspace gets its own logical MCP server at a stable URL:

```
https://mcp.omniaiconnect.com/v1/{workspace_slug}
Authorization: Bearer <workspace-scoped api token>
```

- **Authentication** uses the workspace-scoped api tokens issued by the API
  (ADR-0002 — machine identity, never human sessions). The token both authenticates
  and selects the Workspace; a token/slug mismatch is rejected before any listing.
- One FastMCP application serves all workspaces (the API is stateless,
  SYSTEM_ARCHITECTURE.md §6); "server-per-workspace" is a routing and scoping model,
  not a process-per-tenant model. Every session is bound to exactly one
  `WorkspaceContext` at connect time, and no MCP message can escape it (Bible
  tenet 1).
- Token scopes can narrow a server further (e.g. a token exposing only read-only
  Tools) — enforcement is the runtime's policy stage, but listing honors scopes too,
  so clients never see Tools they cannot call.

## 3. Tool listing

`tools/list` returns the Tools of the Workspace's **active Connections** — enabled
Tools only, filtered by token scope — exported from the canonical Tool Schema
(ADR-0003): canonical `name`, `description`, `input_schema` as the MCP inputSchema,
and safety `annotations` mapped to MCP tool annotations (readOnlyHint,
destructiveHint, idempotentHint).

Listings are **cached** (Redis, `ws:{workspace_id}:mcp:tools`) and
**event-invalidated**: `connector.ingested`, `connection.activated`,
`connection.deactivated` (a Connection left the active set without being revoked —
credential revoke today, OAuth-refresh failure `error` later; founder-ratified
2026-08-18, ADR-0034), `connection.revoked`, `tool.enabled`, and `tool.disabled` on the
internal bus evict the cache (BACKEND_SPEC.md §4; emission contracts in ADR-0034 —
implemented M2.1). The adapter then emits MCP `listChanged` notifications on
transports that support them, so long-lived clients refresh without reconnecting.

## 4. Call translation

| MCP | Runtime |
|---|---|
| `tools/call` name + arguments | `ToolCallRequest` (workspace + caller from session, `request_id` generated) |
| `ToolCallResult.content` | MCP content blocks (text/JSON; binary as resource links per AI_RUNTIME.md truncation rules) |
| `status: failed/timeout` | MCP tool result with `isError: true` and the stable error code + safe message |
| `status: denied`, `confirmation_required` | Error result carrying the confirmation token contract (AI_RUNTIME.md §7); clients with elicitation support can prompt the human and re-call |
| `status: pending` (async mode) | Result held and streamed on completion where the transport allows; otherwise a pending reference the client polls via a follow-up call |

The adapter performs **no** argument validation, no retries, no credential work —
those are runtime stages. A `tools/call` handler is ~20 lines by design.

*Implemented M2.3 (ADR-0036): `interfaces/mcp/execution.py` maps params → the existing
`RuntimeService.execute` → MCP tool result. The Runtime re-authorizes at execution time, so a
stale `tools/list` cache never authorizes a disabled/revoked Tool. Audited failures (upstream,
timeout, `ssrf_blocked`, credential, bad arguments) map to `isError: true` results; an
unresolvable Tool or ambiguous Connection is a JSON-RPC error. Exactly one execution attempt (no
retries). Audit rows are tagged `caller.interface="mcp"`. `confirmation_required` and async/
`pending` streaming remain deferred (no such Runtime status exists yet).*

## 5. Transports

- **Streamable HTTP** is the primary transport — it is what remote clients (ChatGPT,
  Claude, Cursor) speak, it works through Cloudflare, and it fits the stateless API.
- **stdio** is supported for local development only, via a small launcher
  (`omniai-mcp --workspace <slug> --token <token>`) that proxies to the same adapter
  code path. It exists so engineers can test against MCP Inspector and local clients
  without deploying; it is not a supported production surface.
- SSE-only legacy transport is not offered; clients that require it predate the
  protocol versions we pin (§7).

## 6. Scope for v1: tools only

MCP **resources** and **prompts** are explicitly out of scope for v1. Rationale:

- The product's unit of value is the **Tool Call** (north-star metric, Bible §11);
  resources/prompts have no counterpart in the canonical Tool Schema, so supporting
  them would push connector semantics into one adapter — exactly the N×M creep
  ADR-0003 exists to prevent.
- Client support for resources/prompts remains uneven; tools are the interoperable
  core across every target client.
- Revisiting is cheap: if a real use case appears (e.g. exposing Connector docs as
  resources), it lands as an additive adapter feature behind a new ADR, without
  touching the runtime.

## 7. Spec-churn risk

The MCP specification still evolves quickly (auth in particular). Mitigations:

- **Pin protocol versions** explicitly: the server advertises and accepts a tested
  allowlist of protocol revisions, upgraded deliberately — never implicitly by a
  FastMCP dependency bump (uv lockfile, ADR-0006, keeps this deterministic).
  *Current pin (founder-ratified 2026-08-18, ADR-0035): allowlist
  `{2025-06-18, 2025-11-25}`, advertising `2025-11-25`; `2026-07-28` (stateless core,
  beta SDKs) is deliberately excluded until reconciled with this document's session
  model — adopting it is a normal upgrade PR with contract tests.*
- **The adapter isolates churn**: because MCP touches nothing but
  `interfaces/mcp/`, a breaking spec change is an adapter-sized diff. The runtime
  contract (`ToolCallRequest`/`ToolCallResult`) does not move when MCP does.
- Track spec releases in RISKS.md; a protocol-version upgrade is a normal PR with
  contract tests (BACKEND_SPEC.md §8) against recorded client exchanges.

## 8. Connecting AI surfaces

Every remote-MCP-capable client uses the same two ingredients — the workspace MCP URL
and a workspace-scoped api token, both shown on the dashboard's Interfaces page with
copy-paste snippets:

- **Claude (web/desktop):** add a custom connector with the remote MCP URL + bearer
  token.
- **ChatGPT:** register the server in connector/developer-mode settings with URL +
  token.
- **Cursor / VS Code-family:** an `mcp.json` entry with the URL and an
  `Authorization` header (dashboard renders the exact JSON).
- **Agent frameworks (OpenAI Agents SDK, LangGraph, LlamaIndex):** may consume the
  MCP endpoint as generic MCP clients, though the native exporters (AI_RUNTIME.md §5)
  are the better path — same runtime either way.

Revoking the api token on the dashboard severs every client using it immediately;
tokens are per-purpose by convention (one per client surface) so revocation is
surgical.
