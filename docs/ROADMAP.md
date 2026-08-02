# Roadmap — Milestones M0–M5

> Consistent with docs/MASTER_PROJECT_BIBLE.md

Version 1.0 · 2026-08-02 · Owners: Uday (CEO), Claude (CTO)

Milestones are scope-based, not date-based. Quarter labels are **estimates** for a
two-person team and will be re-forecast at every milestone review; only M0 has a real
date because it is done. Sequencing rationale: prove the core loop (connect → execute →
audit) before adding Interfaces; add Interfaces before polish; monetize before scaling
surface area; scale/enterprise last. Detailed sprint-level planning lives in SPRINTS.md.

---

## M0 — Foundation ✅ Done 2026-08-02

**Goal:** A repo, a plan, and a build pipeline — nothing to demo, everything to build on.

**Scope**
- Monorepo scaffold per Bible §8 (apps/web, apps/api, packages, infra/docker).
- Core documentation set: Bible, SYSTEM_ARCHITECTURE, DECISIONS (ADR-0001…0007), PRD, ROADMAP, SPRINTS, COMPETITOR_ANALYSIS, RISKS.
- CI (GitHub Actions): lint, type-check, test, Gitleaks. Docker images build locally.
- Tooling decisions locked: uv (ADR-0006), trunk-based flow (ADR-0005).

**Exit criteria** — all met 2026-08-02
- `main` is green; a fresh clone reaches a running local stack via documented steps.
- Every doc in the Bible §9 index that M0 promises exists and is consistent with the Bible.

## M1 — Core platform *(estimate: Q3 2026)*

**Goal:** The core loop works end-to-end for one auth type and one Interface-precursor:
connect an OpenAPI spec, attach an API key, execute a Tool Call via REST, see it in the
audit log.

**Scope**
- Auth integration: Better Auth in apps/web; FastAPI token verification → Member + Workspace context (ADR-0002).
- Workspaces and Members: creation, invitations, roles; `workspace_id` on every table with Postgres RLS enabled (ADR-0004).
- Connector Engine v1: OpenAPI 3.x / Swagger 2 ingestion (URL + upload) via Celery → canonical Tool Schema (ADR-0003); manual REST definition; per-Tool enable/disable.
- Credentials v1: API-key / Bearer / Basic storage with envelope encryption (vault hardening completes in M2).
- Execution Runtime v1: the single execution path (authz → limits → decrypt → httpx → normalize → audit); timeouts, retries, circuit breaker.
- REST tool-invocation API v1 + workspace-scoped API tokens.
- Audit log: persisted Tool Call records + minimal dashboard viewer.

**Exit criteria**
- A new user connects a public OpenAPI API with an API key and executes a successful Tool Call from `curl` in under 15 minutes, and the Tool Call appears in the log with full detail.
- RLS verified by an automated cross-tenant access test suite in CI.
- Runtime overhead p95 < 400 ms on the demo path.

## M2 — MCP Interface, credential vault, OAuth *(estimate: Q4 2026)*

**Goal:** "Use it from any AI" becomes literally true for Claude and every MCP client,
with credentials handled well enough to trust with real accounts.

**Scope**
- MCP server (FastMCP) as a thin adapter over the runtime: list Tools, call Tools, workspace-scoped tokens, streaming transport.
- Credential vault hardening: key rotation, per-Workspace data keys, redaction filters on all log sinks, vault access audit.
- OAuth 2.0 flows: auth-code + PKCE dance in the dashboard, encrypted token storage, Celery-driven refresh, `needs_reauth` lifecycle.
- Connection health: test-call button, status states, failure notifications (Resend).
- Rate limits and quotas per Workspace/Connection enforced in the runtime.

**Exit criteria**
- Claude Desktop (or any MCP client) lists and successfully calls Tools from two different Connections — one API-key, one OAuth — in one Workspace.
- OAuth tokens refresh automatically across expiry without user action.
- Security checklist in SECURITY.md for the vault is fully checked; zero plaintext secrets findable in logs under a deliberate red-team pass.

## M3 — Dashboard polish, billing, private beta *(estimate: Q4 2026 → Q1 2027)*

**Goal:** Strangers can self-serve, pay, and be supported — a real product with 20–50
design-partner Workspaces.

**Scope**
- Dashboard polish: onboarding flow tuned for time-to-first-Tool-Call < 15 min; log viewer filters/drill-in/CSV; usage dashboard (Tool Calls over time, top Tools, error rates).
- Billing: Stripe subscriptions (Free/Pro/Team), per-Tool-Call metering, plan limits enforced by the runtime.
- Small curated set of prebuilt Connectors (popular SaaS APIs) to shorten evaluation.
- Private beta: invite system, feedback loop, PostHog funnels on the PRD §8 metrics; status page live.

**Exit criteria**
- ≥ 20 external Workspaces active; activation ≥ 40%; at least 3 paying.
- Billing events reconcile with audit-logged Tool Calls to the cent.
- North-star metric (weekly executed Tool Calls per workspace) reported automatically every Monday.

## M4 — More Interfaces, GraphQL, public launch *(estimate: Q1–Q2 2027)*

**Goal:** Interface-agnostic in practice, not just architecture: the same Connection is
usable from MCP, REST, and the major agent frameworks — then open the doors.

**Scope**
- Exporters from the canonical Tool Schema: OpenAI Agents SDK tools, LangChain tool export, OpenAI function-calling JSON, OpenAPI plugin manifest.
- REST invocation API v1 hardening: async long-running Tool Call contract (job + polling/webhook), pagination, versioning per API_GUIDELINES.md.
- GraphQL ingestion via introspection → Tools per operation.
- Spec re-ingestion with diff preview (added/changed/removed Tools).
- Public launch: pricing page, docs site, launch content; self-serve signup opened.

**Exit criteria**
- One demo Workspace drives the same Connection from Claude (MCP), a LangGraph agent, and plain REST with zero adapter-specific configuration.
- GraphQL ingestion success on the top public GraphQL APIs we target ≥ 85%.
- Public signup live; ≥ 1.3 Interfaces per active Workspace within a month of launch.

## M5 — Scale and enterprise *(estimate: Q2–Q3 2027, re-forecast at M4 review)*

**Goal:** The platform survives success: bigger tenants, compliance conversations, and a
supply-side moat via prebuilt Connectors.

**Scope**
- Tenancy/RLS hardening: continuous cross-tenant tests, audit log partitioning (ClickHouse path per SYSTEM_ARCHITECTURE.md §6 if volume demands), egress proxy pool.
- Enterprise auth: SSO/SAML, SCIM provisioning, audit export.
- Rate-limit and quota tiers wired to plans; overage handling; per-token scoping (subset of Connections).
- Marketplace of prebuilt Connectors: curated, versioned, one-click Connections; contribution pipeline defined (community submissions gated by review).
- SOC 2 Type I engagement started (controls having been built since M1, per SECURITY.md).

**Exit criteria**
- First enterprise deal unblocked by SSO + audit export (not by promises).
- ≥ 50 marketplace Connectors installable in one click.
- Load test: 10× current peak Tool Call volume with p95 overhead still < 400 ms.

---

## Deliberately after M5 (parking lot)

Self-hosted deployment · human-in-the-loop Tool Call approvals · non-HTTP protocols
(gRPC/SOAP) · workflow/orchestration features (likely never — see PRD §7) · dedicated
DB per tenant (behind the repository layer when a customer pays for it).
