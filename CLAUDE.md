# CLAUDE.md — AI Engineering Instructions

> Read this before every session. This file is the permanent instruction manual for AI
> engineers (Claude Code and any other coding agent) working in this repository.
> Authority order: docs/MASTER_PROJECT_BIBLE.md → docs/DECISIONS.md (ADRs) →
> docs/ENGINEERING_PRINCIPLES.md → domain specs → this file's checklists.
> If this file conflicts with the Bible, the Bible wins — fix the conflict in the same PR.

## Project overview

**OmniAI Connect** — Connect Any API. Use It From Any AI.

A universal AI integration platform: users connect any API once (API key, OAuth, JWT,
Bearer, Basic, OpenAPI/Swagger, GraphQL, REST) and it becomes tools usable from every AI
surface (ChatGPT, Claude, Cursor, Copilot, agent frameworks, automation platforms).
**MCP is one interface, not the product.** The product is the Connector Engine + Execution
Runtime. Full vision: docs/MASTER_PROJECT_BIBLE.md §1–§3. Product detail: docs/PRD.md.

## Architecture summary

Modular monolith (FastAPI) + Celery workers on Railway; Next.js control plane on Vercel;
Postgres (Neon) + Redis (Upstash); Better Auth owns human identity in the Next.js layer
(ADR-0002); workspace-scoped API tokens for machines. Multi-tenant: `workspace_id` on
every tenant table (ADR-0004). All third-party API calls go through the Execution Runtime
— it is the **only** egress. Details: docs/SYSTEM_ARCHITECTURE.md.

Canonical domain terms (use these exact words — Bible §4): **Workspace, Member,
Connector, Connection, Tool, Tool Call, Credential, Interface.**

## Folder structure

```
apps/web        Next.js control plane        → docs/FRONTEND_SPEC.md
apps/api        FastAPI monolith + workers   → docs/BACKEND_SPEC.md
  app/domains/  one package per domain: router → service → repository (never skip layers)
packages/types  shared TS contracts
docs/           all documentation (index: Bible §9)
infra/docker    Dockerfiles · .github/ CI · scripts/ dev utilities
```

## Conventions (summary — full rules in docs/CODING_STANDARDS.md)

- Python: ruff + mypy strict, async-first, no blocking IO in request path, settings only
  via `app/core/config.py`, domain layout router/service/repository/models/schemas/events.
- TypeScript: strict mode, no `any`, kebab-case files, PascalCase components, server
  components by default.
- Naming: snake_case DB + Python, camelCase TS, kebab-case REST resources and branches.
- API: /v1, error envelope `{error: {code, message, details?, request_id}}` — docs/API_GUIDELINES.md.
- DB: UUIDv7 PKs, `workspace_id NOT NULL`, one Alembic migration per PR — docs/DATABASE_DESIGN.md.

## Development workflow

1. Branch from `main`: `feat/<slug>`, `fix/<slug>`, `docs/<slug>`, `chore/<slug>` (ADR-0005).
2. Conventional Commits. Small PRs (<400 lines ideally). Squash merge, green CI required.
3. `make help` lists all dev commands; `make dev` runs the full stack.
4. Update PROJECT_STATUS.md after every major milestone; SPRINTS.md weekly.

## Checklists

**Pull request checklist**
- [ ] Scope matches one roadmap item / issue; no drive-by features
- [ ] Tests for behavior changes; Alembic migration for schema changes
- [ ] docs/CHANGELOG.md entry; ADR in docs/DECISIONS.md if architectural
- [ ] `.env.example` updated for any new env var
- [ ] No secrets, keys, tokens, or real credentials anywhere in the diff

**Review checklist**
- [ ] Layering respected (router → service → repository; adapters thin)
- [ ] Every query scoped by `workspace_id`
- [ ] Errors map to the standard envelope; no swallowed exceptions
- [ ] Naming uses canonical domain terms
- [ ] New concepts added to Bible §4 glossary or rejected

**Security checklist (docs/SECURITY.md is law)**
- [ ] Credentials never logged, serialized, or returned; decrypt only inside the runtime
- [ ] Outbound calls: SSRF guards, timeouts, size caps
- [ ] AuthZ checked at the service layer, not just the router
- [ ] No new dependency without lockfile update and a reason

**Performance checklist**
- [ ] Hot path (tool call) adds no new synchronous external call
- [ ] N+1 queries checked; indexes lead with `workspace_id`
- [ ] Heavy work (ingestion, aggregation) goes to Celery, not the request path
- [ ] Caching has explicit invalidation (event-driven, not TTL-and-pray)

## Documentation rules

Docs move with code (Bible §6.8). A PR that changes behavior updates CHANGELOG.md; one
that changes architecture updates DECISIONS.md + the relevant spec. Never let docs and
reality drift.

## Testing requirements

Pyramid per docs/BACKEND_SPEC.md: unit tests for services (~80% coverage target),
integration tests against test Postgres for repositories, contract tests per interface
adapter. A failing test is never skipped to make CI green.

## What Claude must NEVER do

- Call a third-party API from anywhere except the Execution Runtime
- Write a query unscoped by `workspace_id` on a tenant table
- Log, print, serialize, or echo a Credential — even in tests or debug output
- Hand-roll auth or crypto (ADR-0002; SECURITY.md)
- Commit secrets, `.env` files, or generated junk; force-push `main`
- Invent new domain terminology or rename canonical terms without an ADR
- Build features not on the current milestone without explicit founder approval
- Mark work done with failing tests, missing migrations, or stale docs
- Delete or rewrite ADRs (they are append-only; supersede instead)

## What Claude must ALWAYS do

- Read PROJECT_STATUS.md at session start to know current phase and priorities
- Follow the layering and the canonical Tool Schema hub (ADR-0003)
- Question a poor instruction and propose the better alternative before implementing
- Keep adapters thin and push logic into domains/runtime
- Ask (or record an Open Question in PROJECT_STATUS.md) when a decision is genuinely
  the founder's to make; otherwise decide, record it, and move
- Leave the repo better than found: green CI, clean `git status`, updated docs
