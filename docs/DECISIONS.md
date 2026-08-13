# Architecture Decision Records

> Append-only. One ADR per significant decision. Status: Proposed → Accepted → Superseded.
> Format: Context / Decision / Consequences. Reference ADRs by number in PRs.

---

## ADR-0001 — Modular monolith, not microservices
**Status:** Accepted · 2026-08-02

**Context:** Vision calls for "microservice ready". Team size is 2. Microservices add
distributed-systems tax (network failures, tracing, deploy orchestration) that a seed-stage
team cannot afford.

**Decision:** One FastAPI deployable with strictly bounded domain packages and an internal
event bus. Extraction contract documented in SYSTEM_ARCHITECTURE.md §1.

**Consequences:** Fast iteration now; discipline required at domain boundaries (enforced
in code review + import-linting later). Revisit when a domain has independent scaling
needs or a dedicated team.

---

## ADR-0002 — Better Auth lives in the Next.js layer; FastAPI verifies tokens
**Status:** Accepted · 2026-08-02

**Context:** Chosen auth (Better Auth) is a TypeScript library; the API is Python. Running
identity in FastAPI would mean hand-rolling auth — forbidden by SECURITY.md.

**Decision:** Better Auth owns signup/login/sessions/OAuth-social in apps/web. FastAPI
validates the signed session/JWT on every request via shared JWKS/secret and maps it to a
Member + Workspace context. Machine access (AI clients) uses separate workspace-scoped API
tokens issued by the API itself — human identity and machine identity are different
credential types.

**Consequences:** Two auth surfaces to document, but no custom crypto and each tool does
what it's best at. If this boundary hurts later, the fallback ADR is moving identity to a
dedicated provider — never hand-rolling.

---

## ADR-0003 — Canonical Tool Schema as the internal contract
**Status:** Accepted · 2026-08-02

**Context:** We ingest OpenAPI, Swagger 2, GraphQL, and manual definitions; we export MCP,
OpenAI function-calling JSON, LangChain tools, etc. N formats in × M formats out must not
become N×M converters.

**Decision:** Everything normalizes to one internal Tool Schema (CONNECTOR_ENGINE.md §3):
N importers + M exporters, hub-and-spoke.

**Consequences:** The Tool Schema is versioned and changes require an ADR. Some
format-specific fidelity is lost at the edges; importers record `extensions` for
round-trip data.

---

## ADR-0004 — Single Postgres, shared schema, workspace_id + RLS for tenancy
**Status:** Accepted · 2026-08-02

**Context:** Options: shared schema, schema-per-tenant, DB-per-tenant.

**Decision:** Shared schema with mandatory `workspace_id`, repository-enforced scoping,
and Postgres RLS as defense-in-depth. Neon branching gives cheap preview environments.

**Consequences:** Simplest ops and migrations. Enterprise "dedicated instance" asks are
handled later behind the repository layer.

---

## ADR-0005 — Trunk-based development; no long-lived develop branch
**Status:** Accepted · 2026-08-02

**Context:** GitFlow's `develop` branch adds merge ceremony without value for a small team
with preview deploys.

**Decision:** `main` always deployable; short-lived `feat/*`, `fix/*`, `docs/*`, `chore/*`
branches; squash-merge via PR with green CI; release tags `vX.Y.Z`. CI currently also
tolerates a `develop` branch for transition; delete it once staging auto-deploy is live.

**Consequences:** Requires solid CI and feature flags for incomplete work.

---

## ADR-0006 — uv for Python dependency management
**Status:** Accepted · 2026-08-02

**Context:** pip/poetry/uv. Speed and lockfile determinism matter for CI cost.

**Decision:** uv with `pyproject.toml` + `uv.lock` (lockfile generated on first
`uv sync`).

**Consequences:** Contributors need uv installed (`make setup` handles it).

---

## ADR-0007 — Celery + Redis for async work (revisit at scale)
**Status:** Accepted · 2026-08-02

**Context:** Stack mandates Celery. Alternatives (arq, Dramatiq, temporal) are arguably
lighter for async-first FastAPI, but Celery is battle-tested and known.

**Decision:** Celery with Redis broker for ingestion, token refresh, async tool calls,
usage aggregation. All tasks idempotent.

**Consequences:** Celery's asyncio story is imperfect; long-running/stateful agent
workflows may justify a workflow engine later — that would be a new ADR.

---

## ADR-0008 — Database role separation and a single SECURITY DEFINER exemption for tenancy
**Status:** Accepted · 2026-08-13

**Context:** ADR-0004 chose shared-schema tenancy with `workspace_id` + RLS, but did not
say *which database role the application connects as*, and did not anticipate the
bootstrap paradox in credential lookup. Both turned out to be load-bearing.

Postgres has **two** unconditional RLS bypasses, and `FORCE ROW LEVEL SECURITY` stops
neither: `rolsuper` and `rolbypassrls`. Table ownership is a third bypass that `FORCE`
*does* stop. An application connecting as a superuser, as `BYPASSRLS`, or as the table
owner without `FORCE` reads every tenant's rows while the policies sit there looking
correct — and an isolation test suite run on such a connection passes green.

Separately: resolving a workspace-scoped API token is what *discovers* the workspace, so
the lookup cannot run under a policy that already requires it. The tempting workaround —
`USING (... OR current_setting('app.workspace_id', true) IS NULL)` — disables isolation
for every unbound query in the system.

**Decision:**

1. **Three roles.** The migration role owns the schema and runs Alembic. The application
   connects as `omniai_app`: not a superuser, not an owner, no `BYPASSRLS`. A third role,
   `omniai_auth`, is `NOLOGIN` and exists only to own the token-resolution function.
   `omniai_app` is provisioned outside Alembic because it needs a password, and a password
   in a migration is a secret in git (P-18).
2. **`FORCE ROW LEVEL SECURITY` on every tenant table**, in addition to `ENABLE`.
3. **The migration refuses to run** if `omniai_app` is missing, is a superuser, or holds
   `BYPASSRLS`. The integration suite asserts the same two flags before asserting anything
   about isolation.
4. **Exactly one RLS exemption**, and it is granted through ordinary policy targeting
   rather than `BYPASSRLS`: a policy `TO omniai_auth` plus a `SECURITY DEFINER` function
   owned by that role, with `SET search_path` pinned and `EXECUTE` revoked from `PUBLIC`.
   Deliberately avoids `BYPASSRLS`, which requires superuser to grant and is frequently
   unavailable on managed Postgres (Neon).
5. **Every future exemption requires an ADR** and is reviewed as a security change.

**Consequences:** Deploying to a new environment now has a prerequisite step — creating
`omniai_app` — which belongs in the platform runbook, not in a migration. `SET search_path`
on the function is mandatory: without it a caller controlling `search_path` could shadow
the target table and have the function read it under another role's privileges. The
mechanism generalises to any future lookup that must run before a tenant is known
(SECURITY.md §3, DATABASE_DESIGN.md §6).
