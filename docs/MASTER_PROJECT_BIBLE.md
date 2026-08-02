# OmniAI Connect — Master Project Bible

> **This is the single source of truth.** Every implementation decision, every PR, every
> new document must be consistent with this file. If reality diverges from this document,
> either fix reality or update this document in the same PR — never let them drift.
>
> Version 1.0 · Created 2026-08-02 · Owners: Uday (CEO), Claude (CTO)

---

## 1. Mission

**Connect Any API. Use It From Any AI.**

## 2. Vision

OmniAI Connect is the universal integration layer between AI and software. A user connects
an API **once** — via API key, OAuth 2.0, JWT, Bearer token, Basic auth, an OpenAPI/Swagger
spec, a GraphQL schema, or a plain REST description — and that API instantly becomes a set
of tools usable from **every** AI surface: ChatGPT, Claude, Cursor, Copilot, Gemini,
Perplexity, agent frameworks (OpenAI Agents SDK, LangChain/LangGraph, CrewAI, AutoGen,
Semantic Kernel, LlamaIndex), and automation platforms (n8n, Zapier, Make, Pipedream).

MCP is **one interface**, not the product. The product is the connector graph and the
runtime that executes tool calls safely on the user's behalf. Interfaces (MCP, OpenAPI
tool manifests, framework SDKs, HTTP APIs) are thin adapters over that runtime.

## 3. Product pillars

1. **Connector Engine** — ingest any API description (OpenAPI, GraphQL introspection,
   manual definition), normalize it into a canonical internal Tool Schema, and manage the
   credential lifecycle for it. See docs/CONNECTOR_ENGINE.md.
2. **Execution Runtime** — the only component that ever calls a third-party API. Enforces
   auth injection, rate limits, quotas, retries, audit logging, and tenant isolation.
   See docs/AI_RUNTIME.md.
3. **Interface Adapters** — MCP server (docs/MCP_RUNTIME.md), REST tool-invocation API,
   OpenAPI plugin manifests, and framework SDKs. Adapters translate; they never contain
   business logic.
4. **Control Plane** — the Next.js dashboard: connect APIs, manage credentials, inspect
   tool-call logs, manage team/workspace, billing. See docs/FRONTEND_SPEC.md.

## 4. Canonical domain model (names are law)

Use these exact terms in code, docs, DB tables, and UI. Synonyms breed bugs.

| Term | Meaning |
|---|---|
| **Workspace** | The tenant. All data is scoped by `workspace_id`. |
| **Member** | A user's membership in a workspace, with a role. |
| **Connector** | A definition of an external API (its tools, auth requirements, base config). |
| **Connection** | A workspace's authenticated instance of a Connector (credentials attached). |
| **Tool** | A single callable operation exposed by a Connector (one endpoint/operation). |
| **Tool Call** | One execution of a Tool through the runtime, always audit-logged. |
| **Credential** | An encrypted secret bound to a Connection. Never leaves the vault decrypted except inside the runtime. |
| **Interface** | A surface through which an AI consumes tools (MCP, REST, SDK, manifest). |

## 5. Architecture in one paragraph

A **modular monolith** (FastAPI) with strict domain boundaries, deployed as one service
plus Celery workers, in front of PostgreSQL (Neon) and Redis (Upstash). The Next.js app
(Vercel) is the control plane. Better Auth (running in the Next.js layer) owns identity;
the API trusts its sessions via signed tokens. Everything is multi-tenant from day one
(`workspace_id` on every table). Domains communicate through an internal event bus so any
domain can later be extracted into a microservice without rewriting callers — we are
**microservice-ready, not microservice-first**. Full details: docs/SYSTEM_ARCHITECTURE.md.

## 6. Non-negotiable engineering tenets

1. **Tenant isolation is sacred.** Every query filters by `workspace_id`. Every new table
   carries it. Cross-tenant data exposure is a company-ending bug.
2. **Credentials are radioactive.** Encrypted at rest (AES-256-GCM via envelope
   encryption), never logged, never serialized into responses, decrypted only inside the
   Execution Runtime. See docs/SECURITY.md.
3. **The runtime is the only egress.** No code outside the Execution Runtime may call a
   customer's third-party API.
4. **Adapters are thin.** If an MCP handler contains an `if`, ask whether it belongs in
   the runtime.
5. **Schema-first.** API contracts (Pydantic + OpenAPI) and DB migrations (Alembic) are
   written before implementation.
6. **Everything is observable.** Structured logs with `request_id` + `workspace_id`,
   errors to Sentry, product events to PostHog.
7. **No secrets in code, config files, or CI logs.** `.env.example` lists every variable;
   Gitleaks runs in CI.
8. **Docs move with code.** A PR that changes behavior updates CHANGELOG.md; a PR that
   changes architecture updates DECISIONS.md and the relevant spec.

## 7. Tech stack (locked unless DECISIONS.md says otherwise)

| Layer | Choice |
|---|---|
| Frontend | Next.js (App Router), TypeScript, Tailwind, shadcn/ui, React Hook Form + Zod, Zustand, TanStack Table, Motion |
| Backend | FastAPI, Python 3.11+, SQLAlchemy 2 (async), Alembic, Pydantic v2, httpx, Celery |
| Data | PostgreSQL (Neon) · Redis (Upstash) |
| Auth | Better Auth (identity in the Next.js layer; API verifies tokens) |
| AI runtime | FastMCP, OpenAI Agents SDK, LangGraph, LlamaIndex |
| Infra | Docker, GitHub Actions, Railway (API/workers), Vercel (web), Cloudflare (DNS/CDN), Cloudflare R2 (objects) |
| Monitoring | Sentry, PostHog, Better Stack |
| Billing / Email | Stripe · Resend |

## 8. Repository map

```
omniai-connect/
├── apps/
│   ├── web/          # Next.js control plane (Vercel)
│   └── api/          # FastAPI modular monolith + Celery workers (Railway)
├── packages/
│   ├── types/        # Shared TS contracts (generated from OpenAPI later)
│   └── config/       # Shared lint/TS configs
├── docs/             # All project documentation (index below)
├── infra/docker/     # Dockerfiles
├── scripts/          # Developer utilities
└── .github/          # CI, templates, CODEOWNERS
```

## 9. Documentation index

| Doc | Purpose |
|---|---|
| MASTER_PROJECT_BIBLE.md | This file. Source of truth. |
| PRD.md | Product requirements, personas, user journeys |
| SYSTEM_ARCHITECTURE.md | Components, data flows, deployment topology |
| DATABASE_DESIGN.md | Schema conventions, core ERD, migration rules |
| BACKEND_SPEC.md | FastAPI structure, layering, DI, events |
| FRONTEND_SPEC.md | Next.js structure, state, forms, UI standards |
| AI_RUNTIME.md | Execution runtime: tool calls, agents, safety |
| CONNECTOR_ENGINE.md | API ingestion, canonical Tool Schema, auth types |
| MCP_RUNTIME.md | MCP server design (one adapter among several) |
| SECURITY.md | Threat model, credential vault, tenancy, compliance path |
| API_GUIDELINES.md | REST conventions, versioning, error envelope |
| CODING_STANDARDS.md | Style, naming, testing, review rules |
| ROADMAP.md | Milestones M0–M5 |
| SPRINTS.md | Sprint log (living) |
| COMPETITOR_ANALYSIS.md | Landscape and positioning |
| DECISIONS.md | Architecture Decision Records (ADRs) |
| RISKS.md | Risk register with mitigations |
| CHANGELOG.md | Human-readable change history |
| MEETING_NOTES.md | Founder/eng meeting log |

## 10. Ways of working

- **Branching**: trunk-based-ish. `main` is always deployable. Feature branches
  `feat/<slug>`, `fix/<slug>`, `docs/<slug>`, `chore/<slug>` merge to `main` via PR with
  green CI. Release tags `vX.Y.Z`. No long-lived `develop` branch once CI + preview
  deploys are reliable (see DECISIONS.md ADR-0005).
- **Commits**: Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`,
  `test:`, `ci:`).
- **Definition of done**: code + tests + docs + migration (if schema) + CHANGELOG entry.
- **What we do NOT do**: build features not on the roadmap, hand-roll crypto, bypass the
  repository layer, ship without CI, store plaintext secrets, copy-paste between domains.

## 11. Business guardrails (v1)

- SaaS, subscription via Stripe: Free (evaluation) → Pro (individual/small team) → Team →
  Enterprise (SSO, audit export, self-host conversation). Usage metered per Tool Call.
- Launch targets: developer-first (agent builders, automation engineers), then
  ops/RevOps teams via templates.
- North-star metric: **weekly executed Tool Calls per workspace**.

## 12. Glossary discipline

New concept → add it to §4 or don't ship it. Renaming a concept → ADR + repo-wide rename
in one PR.
