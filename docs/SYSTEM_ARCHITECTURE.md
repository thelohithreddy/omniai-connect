# System Architecture

> Consistent with docs/MASTER_PROJECT_BIBLE.md §5–§7. Changes here require an ADR in
> docs/DECISIONS.md.

## 1. Architecture style

**Modular monolith, microservice-ready.** One FastAPI deployable + Celery workers.
Domains are isolated Python packages with explicit public interfaces and an internal
event bus. Extraction path: any domain can become a service by (a) moving its package,
(b) swapping the in-process event bus for a broker (Redis Streams already in the stack),
(c) exposing its service interface over HTTP/gRPC. We deliberately do NOT start with
microservices: a two-person team pays microservice tax (distributed tracing, network
failure modes, N deploy pipelines) with zero of the benefits at our scale.

## 2. Component diagram

```
                ┌────────────────────────────────────────────────┐
   Browser ────▶│  apps/web — Next.js (Vercel)                   │
                │  Better Auth (identity) · Dashboard · Billing  │
                └───────────────┬────────────────────────────────┘
                                │ REST (signed session token)
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  apps/api — FastAPI modular monolith (Railway)                   │
│                                                                  │
│  Interface adapters:  REST v1 │ MCP server │ manifests │ SDKs    │
│  ────────────────────────────────────────────────────────────    │
│  Domains: connectors │ connections │ credentials │ tools │       │
│           runtime │ workspaces │ billing │ audit                 │
│  ────────────────────────────────────────────────────────────    │
│  Shared kernel: event bus · DB session · settings · logging      │
└──────┬───────────────┬───────────────┬───────────────────────────┘
       │               │               │
       ▼               ▼               ▼
  PostgreSQL       Redis           Celery workers ──▶ Third-party APIs
  (Neon)           (Upstash)       (spec ingestion,    (ONLY via the
  source of        cache, queues,   token refresh,      Execution Runtime)
  truth            rate limits      async tool calls)
```

Cross-cutting: Sentry (errors), PostHog (product analytics), Better Stack (uptime/logs),
Cloudflare (DNS/CDN/WAF), R2 (spec files, export artifacts), Stripe, Resend.

## 3. Key data flows

### 3.1 Connect an API
1. User submits an OpenAPI URL / GraphQL endpoint / manual definition in the dashboard.
2. `connectors` domain enqueues ingestion (Celery): fetch spec → validate → normalize to
   canonical Tool Schema → persist Connector + Tools.
3. User authorizes: OAuth dance or credential entry → `credentials` domain encrypts and
   stores → Connection becomes `active`.

### 3.2 AI calls a tool (MCP example)
1. AI client connects to the MCP endpoint with a workspace-scoped API token.
2. MCP adapter lists Tools for that workspace's active Connections (from cache).
3. Tool call → adapter translates to a runtime `ToolCallRequest` → Execution Runtime:
   authz check → rate/quota check (Redis) → credential decrypt (in-memory only) →
   signed outbound request via httpx → response normalization → audit log row →
   usage event (billing) → response back through the adapter.

Same runtime path serves REST tool-invocation and SDK adapters — MCP is one thin door.

## 4. Multi-tenancy

- Single database, shared schema, `workspace_id NOT NULL` on every tenant table,
  enforced by a SQLAlchemy base mixin + repository-layer scoping (repositories require a
  workspace context to construct queries).
- PostgreSQL Row-Level Security is enabled on tenant tables as defense-in-depth from M1.
- Redis keys namespaced `ws:{workspace_id}:…`.
- Upgrade path for enterprise: dedicated schema or dedicated DB per tenant — repository
  layer isolates this decision.

## 5. Deployment topology

| Component | Platform | Notes |
|---|---|---|
| web | Vercel | Preview deploy per PR |
| api + workers | Railway | Docker images from infra/docker |
| Postgres | Neon | Branching for preview envs |
| Redis | Upstash | |
| DNS/CDN/WAF | Cloudflare | |
| Objects | Cloudflare R2 | |

Environments: `development` (local Docker), `staging`, `production`. Promotion is
git-driven: merge to `main` → staging auto-deploy → manual promote to production.

## 6. Scalability posture

- API is stateless → horizontal scale behind Railway/Cloudflare.
- Hot path (tool call) touches Redis + one audit insert; spec ingestion and analytics are
  async via Celery.
- Read-heavy tool listings cached in Redis with event-driven invalidation.
- Known future bottlenecks and answers: audit log volume → partitioned tables then
  ClickHouse; outbound egress IPs → dedicated proxy pool; long-running tool calls →
  async job + webhook/polling contract (defined in API_GUIDELINES.md from day one).

## 7. Failure and resilience rules

- Every outbound call: timeout (default 30s), bounded retries with jitter (idempotent
  operations only), circuit breaker per Connection.
- Celery tasks are idempotent and carry `workspace_id` + `request_id`.
- Graceful degradation: if Redis is down, tool calls fail closed on quota checks
  (security over availability for billing-relevant paths).
