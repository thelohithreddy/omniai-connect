# Product Requirements Document — OmniAI Connect

> Consistent with docs/MASTER_PROJECT_BIBLE.md

Version 1.0 · 2026-08-02 · Owners: Uday (CEO), Claude (CTO)

---

## 1. Problem statement

Every team building with AI hits the same wall: the model can reason, but it cannot *act*
on the software the team actually uses. Today, giving an AI access to an API means one of:

- **Hand-writing tool wrappers** per API, per framework — brittle, unmaintained, and
  duplicated across ChatGPT, Claude, Cursor, LangGraph, and n8n.
- **Running one-off MCP servers** — each with its own credential handling (often a token
  in an env var), no audit trail, no tenancy, and coverage limited to whatever someone
  has published.
- **Using an integration catalog** — great until the API you need is your own internal
  service, a partner API, or anything outside the vendor's list.

The result: credentials sprayed across configs, no visibility into what an agent actually
did, and an N×M integration matrix (N APIs × M AI surfaces) that every team rebuilds badly.

**OmniAI Connect collapses N×M to N+M.** Connect any API once — OpenAPI/Swagger, GraphQL,
or a manual REST definition, authenticated via API key, OAuth 2.0, JWT, Bearer, or Basic —
and it becomes a set of Tools usable from every Interface: MCP, a REST tool-invocation
API, OpenAPI plugin manifests, and framework SDKs. Credentials live in an encrypted vault;
every Tool Call is audit-logged; everything is scoped to a Workspace. MCP is one
Interface, not the product.

## 2. Target personas

### P1 — Agent-building developer (primary)
Builds agents with LangGraph, CrewAI, the OpenAI Agents SDK, or directly against
Claude/ChatGPT. Comfortable with OpenAPI specs and OAuth, allergic to writing the same
Stripe wrapper for the third time. Wants: paste a spec URL, get typed tools in every
runtime they use, and see exactly what the agent called when something breaks.

### P2 — Automation / ops engineer
Lives in n8n, Zapier, Make, and internal scripts. Increasingly asked to "add AI" to
workflows. Less interested in SDKs, very interested in: connecting company systems
(including internal APIs behind a spec), safe credential storage the security team will
sign off on, and logs they can point to when a run misbehaves.

### P3 — Technical team lead
Engineering or platform lead at a 10–200 person company. Doesn't call the APIs personally;
approves the tool that does. Cares about: one Workspace for the team with roles (Members),
a Credential vault instead of tokens in Slack, an audit log of every Tool Call, and a
vendor that won't lock the team into a single AI ecosystem.

## 3. Jobs-to-be-done

| # | When… | I want to… | So that… |
|---|---|---|---|
| J1 | I'm building an agent that needs a third-party or internal API | connect that API once from its spec | I never hand-write tool wrappers again |
| J2 | My team uses several AI surfaces (Claude, Cursor, LangGraph, n8n) | expose the same Tools to all of them | behavior is consistent and maintained in one place |
| J3 | An API needs OAuth on behalf of a user | complete the flow in a dashboard, not in code | tokens are stored, refreshed, and rotated for me |
| J4 | An agent did something unexpected | inspect the exact Tool Calls, inputs, outputs, and latency | I can debug and prove what happened |
| J5 | I'm responsible for security | keep Credentials encrypted, scoped, and revocable per Connection | no secret ever lands in a prompt, log, or repo |
| J6 | Usage grows | see and cap Tool Call volume per Workspace | costs and blast radius stay bounded |

## 4. Core user journeys (v1)

### UJ-1 · Connect an API via OpenAPI URL
1. Member opens the dashboard → **New Connector** → pastes an OpenAPI/Swagger URL (or uploads the file).
2. Ingestion runs async (Celery): fetch → validate → normalize to the canonical Tool Schema → persist the Connector and its Tools. Progress and validation errors surface in the UI.
3. Member reviews the generated Tools (names, descriptions, parameters), toggles off any they don't want exposed.
4. Member creates a Connection by entering the API key (or other credential); the Credential is encrypted into the vault and the Connection becomes `active`.

### UJ-2 · Connect an API via OAuth 2.0
1. Member selects a Connector whose auth type is OAuth 2.0 (prebuilt or ingested with OAuth config).
2. Dashboard initiates the authorization flow; Member consents at the provider.
3. The callback lands in the `credentials` domain: tokens are encrypted and stored, refresh is scheduled, and the Connection becomes `active`. Token refresh failures flag the Connection as `needs_reauth` and notify the Workspace.

### UJ-3 · Use Tools from Claude via MCP
1. Member generates a workspace-scoped API token in the dashboard.
2. Member adds the OmniAI Connect MCP endpoint to Claude (or any MCP client) with that token.
3. The MCP Interface lists Tools for the Workspace's active Connections; every invocation flows through the Execution Runtime (authz → rate/quota → credential decrypt → outbound call → audit log).

### UJ-4 · Use Tools from an agent framework
1. Developer installs the SDK (or uses the LangChain/OpenAI Agents SDK export) and configures it with the workspace-scoped API token.
2. `client.tools()` returns the Workspace's Tools in the framework's native format (generated from the canonical Tool Schema).
3. Framework tool invocations call the REST tool-invocation API; the same runtime path executes and audit-logs them. Adapters stay thin — no framework-specific business logic.

### UJ-5 · Inspect Tool Call logs
1. Member opens **Logs** in the dashboard, filtered to their Workspace.
2. Each Tool Call row shows: Tool, Connection, Interface, caller identity (Member or API token), status, latency, timestamp.
3. Drill-in shows request parameters and response (with secrets redacted — Credentials never appear), plus the `request_id` for support. Filters: Connection, Tool, Interface, status, time range. Export: CSV.

## 5. Functional requirements

Grouped by product pillar (Bible §3). Priority: **P0** = required for v1 launch, **P1** = fast-follow.

### 5.1 Connector Engine
- **FR-CE-1 (P0)** Ingest OpenAPI 3.x and Swagger 2 from URL or file upload; normalize to the canonical Tool Schema (ADR-0003); persist Connector + Tools.
- **FR-CE-2 (P0)** Manual Connector definition: describe REST endpoints (method, path, params, auth) in a form or JSON; same normalization path.
- **FR-CE-3 (P0)** Auth types on Connectors: API key (header/query), Bearer, Basic, JWT, OAuth 2.0 (auth-code + refresh; client-credentials P1).
- **FR-CE-4 (P0)** Per-Tool enable/disable and description editing on a Connector (descriptions are what the AI sees — they must be editable).
- **FR-CE-5 (P1)** GraphQL ingestion via introspection → Tools per query/mutation (M4).
- **FR-CE-6 (P1)** Re-ingestion/spec refresh with diff preview (added/changed/removed Tools).

### 5.2 Execution Runtime
- **FR-RT-1 (P0)** Single execution path for every Tool Call regardless of Interface: authz → rate/quota check (Redis) → Credential decrypt in-memory only → outbound httpx call → response normalization → audit log row → usage event.
- **FR-RT-2 (P0)** Credential vault: AES-256-GCM envelope encryption at rest; Credentials never logged, never serialized into responses, decrypted only inside the runtime.
- **FR-RT-3 (P0)** Per-Workspace and per-Connection rate limits and quotas; fail closed if Redis is unavailable on billing-relevant checks.
- **FR-RT-4 (P0)** Timeouts (default 30s), bounded retries with jitter for idempotent operations, circuit breaker per Connection.
- **FR-RT-5 (P0)** Audit log: immutable Tool Call records with `workspace_id`, `request_id`, caller identity, Interface, redacted request/response.
- **FR-RT-6 (P1)** OAuth token refresh as a background task (Celery) with `needs_reauth` state on failure.
- **FR-RT-7 (P1)** Async execution contract for long-running Tool Calls (job + polling/webhook), per API_GUIDELINES.md.

### 5.3 Interface Adapters
- **FR-IF-1 (P0)** MCP server (FastMCP): list/call Tools for a Workspace via workspace-scoped API token; streaming-capable transport.
- **FR-IF-2 (P0)** REST tool-invocation API (v1): list Tools, invoke a Tool, fetch a Tool Call result.
- **FR-IF-3 (P0)** Workspace-scoped API tokens: create, name, scope (read/invoke, subset of Connections), revoke. Machine identity is distinct from Member identity (ADR-0002).
- **FR-IF-4 (P1)** Exporters from the canonical Tool Schema: OpenAI function-calling JSON, LangChain tool objects, OpenAPI plugin manifest (M4).
- **FR-IF-5 (P0, invariant)** Adapters contain zero business logic; all policy lives in the runtime.

### 5.4 Control Plane
- **FR-CP-1 (P0)** Auth via Better Auth (email + OAuth social); Workspace creation; Member invitations with roles (`owner`, `admin`, `member`).
- **FR-CP-2 (P0)** Connector and Connection management UI: create, configure auth, test ("run one Tool Call"), pause, delete.
- **FR-CP-3 (P0)** Tool Call log viewer per UJ-5 (filters, drill-in, CSV export).
- **FR-CP-4 (P0)** API token management UI.
- **FR-CP-5 (P1)** Billing: Stripe subscriptions (Free/Pro/Team), usage metering per Tool Call, plan limits enforced by the runtime (M3).
- **FR-CP-6 (P1)** Usage dashboard: Tool Calls over time, top Tools, error rates per Connection.

## 6. Non-functional requirements

| Area | Requirement |
|---|---|
| Latency | Runtime overhead (everything except the third-party API's own time) p50 < 150 ms, p95 < 400 ms for synchronous Tool Calls. Tool listing served from Redis cache: p95 < 100 ms. |
| Uptime | 99.9% monthly for the execution path (API + MCP Interface) at launch; dashboard 99.5%. Status page via Better Stack. |
| Security | Tenant isolation on every query (`workspace_id` + Postgres RLS); Credentials per FR-RT-2; TLS everywhere; secrets scanning (Gitleaks) in CI; secret-redaction filter on all log sinks. SOC 2 readiness tracked in SECURITY.md — controls (audit log, access reviews, encryption) built from M1 so certification is a paperwork exercise, not a rewrite. |
| Observability | Structured logs with `request_id` + `workspace_id`; errors to Sentry; product events to PostHog; every Tool Call traceable end-to-end. |
| Scalability | Stateless API; hot path touches Redis + one audit insert; ingestion/refresh async via Celery (SYSTEM_ARCHITECTURE.md §6). |
| Data | Audit log retention: 30 days Free, 90 days Pro/Team, custom Enterprise. Deleting a Connection revokes and destroys its Credentials. |

## 7. Out of scope for v1

Explicitly **not** building (revisit via ROADMAP.md, never ad hoc):

- Agent orchestration / workflow builder — we execute Tool Calls; we do not chain them. Frameworks and automation platforms do that on top of us.
- A hosted LLM or model routing — we are model-agnostic infrastructure.
- Marketplace of prebuilt Connectors (M5) beyond a small curated starter set.
- Self-hosted / on-prem deployment (Enterprise conversation, post-M5).
- SSO/SAML and SCIM (M5).
- Non-HTTP protocols: SOAP, gRPC ingestion, websocket-native APIs, databases-as-connectors.
- Fine-grained per-Tool human approval flows (design noted in AI_RUNTIME.md; not v1).
- Mobile apps; localization; a public Connector-sharing community.

## 8. Success metrics

**North star: weekly executed Tool Calls per workspace** (Bible §11) — it only moves when
a real AI surface is wired to a real Connection and used repeatedly.

Supporting metrics (PostHog, reviewed weekly in SPRINTS.md):

| Metric | Definition | Early target (private beta, M3) |
|---|---|---|
| Activation rate | Signups reaching first successful Tool Call | ≥ 40% |
| Time-to-first-Tool-Call | Signup → first successful Tool Call | median < 15 min |
| Connector ingestion success | Spec submissions yielding usable Tools without support | ≥ 85% |
| Week-4 retention | Workspaces with ≥ 1 Tool Call in week 4 after activation | ≥ 30% |
| Interfaces per active Workspace | Distinct Interfaces used in a week | ≥ 1.3 (validates "any AI") |
| Runtime error rate | Tool Calls failing due to platform (not upstream) faults | < 0.5% |

Guardrail metrics: p95 runtime overhead (§6), support tickets per active Workspace, and
credential-related incidents (target: zero, always).
