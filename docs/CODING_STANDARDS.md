# Coding Standards

> Consistent with docs/MASTER_PROJECT_BIBLE.md. Enforced by CI (.github/workflows/ci.yml)
> where automatable, by code review everywhere else.

Version 1.0 · 2026-08-02

---

## 1. General principles

1. **Clarity over cleverness.** Code is read far more often than written. A boring,
   obvious solution beats an elegant one that needs a comment to decode.
2. **Small PRs.** Small changes get real reviews; large ones get rubber stamps (§6.4).
3. **Boy-scout rule.** Leave touched code slightly better — rename the confusing
   variable, add the missing type — but keep drive-by refactors out of feature PRs
   (separate `refactor:` PR instead).
4. **Names are law.** Use the canonical domain terms from Bible §4 (Workspace, Member,
   Connector, Connection, Tool, Tool Call, Credential, Interface) in code, tests, and
   docs. No synonyms — "integration", "plugin", and "secret" mean nothing here.
5. **Schema-first** (Bible §6.5): Pydantic schemas and Alembic migrations before
   implementation.

## 2. Python (apps/api)

Tooling is configured in `apps/api/pyproject.toml` and runs in CI: `ruff check`,
`ruff format --check`, `mypy` (strict, pydantic plugin), `pytest`. Line length 100,
target py311. Do not add per-file ignores without a comment explaining why.

### 2.1 Naming

- Modules and packages: `snake_case`, singular for modules (`service.py`), plural only
  when the domain term is plural.
- Classes: `PascalCase` (`ToolCallService`); Pydantic schemas suffixed by purpose
  (`ConnectionCreate`, `ConnectionRead`).
- Functions/variables: `snake_case`; constants `UPPER_SNAKE_CASE`.
- Private helpers prefixed `_`; nothing outside a domain package imports an
  underscore-prefixed name.

### 2.2 Module layout per domain

Each domain (connectors, connections, credentials, tools, runtime, workspaces, billing,
audit — per SYSTEM_ARCHITECTURE.md §2) is a package with a fixed internal shape:

```
app/domains/<domain>/
├── router.py       # FastAPI routes — thin: parse, call service, shape response
├── service.py      # Business logic; the only layer with domain rules
├── repository.py   # All DB access; requires workspace context (Architecture §4)
├── models.py       # SQLAlchemy models
├── schemas.py      # Pydantic request/response schemas
└── events.py       # Events published/consumed on the internal bus
```

Cross-domain calls go through the other domain's service interface or the event bus —
never its repository or models (ADR-0001 boundary discipline). Never bypass the
repository layer (Bible §10).

### 2.3 Async rules

- The request path is fully async: async SQLAlchemy sessions, `httpx.AsyncClient`, async
  Redis. **No blocking IO in the request path** — no `requests`, no sync DB drivers, no
  `time.sleep`.
- CPU-heavy or genuinely blocking work goes to Celery (ADR-0007) or, rarely,
  `run_in_executor` with a comment justifying it.
- Celery tasks are idempotent and carry `workspace_id` + `request_id`
  (Architecture §7).

### 2.4 Exceptions

- Raise domain exceptions (`ConnectionNotFoundError`, `QuotaExceededError`) from
  services; a single exception-handler layer maps them to the API error envelope
  (API_GUIDELINES.md §6). Routers never build error responses by hand.
- Never `except Exception: pass`. Catch the narrowest type; re-raise with context
  (`raise ... from err`).
- Expected upstream failures (timeouts, 4xx from third-party APIs) are results the
  runtime normalizes, not exceptions that bubble to 500s.

### 2.5 Docstrings

Public service methods get a docstring: one summary line, plus args/raises when
non-obvious. Routers and repositories usually don't need them — their signatures and
schemas are the documentation. No docstring restating the function name.

## 3. TypeScript (apps/web, packages)

- `strict: true` everywhere; `eslint-config-next` plus shared rules from
  `packages/config`. CI runs `pnpm lint` and `pnpm typecheck`.
- **No `any`.** Use `unknown` and narrow, or define the type. `as` casts require a
  comment.
- **Named exports only** (exception: Next.js requires default exports for
  pages/layouts/route handlers). Named exports keep renames honest and imports greppable.
- API types come from `@omniai/types` (hand-written now, generated from OpenAPI later —
  see packages/types/src/index.ts header). Never redeclare an API shape locally.

### 3.1 Components

- Files: **kebab-case** (`connection-form.tsx`); components: **PascalCase**
  (`ConnectionForm`). Hooks `use-*.ts` exporting `useX`.
- Server Components by default; `"use client"` only where interactivity demands it,
  as low in the tree as possible.
- Forms: React Hook Form + Zod (stack, Bible §7). The Zod schema is the single source of
  client-side validation. Client global state in Zustand; server state stays in
  fetch/cache, not copied into stores.

## 4. Monorepo folder naming

- Directories: kebab-case throughout (`tool-calls/`, not `toolCalls/`).
- Apps in `apps/`, shared packages in `packages/` (namespaced `@omniai/*`), Dockerfiles
  in `infra/docker/`, utilities in `scripts/`, all docs in `docs/` — per Bible §8.
  New top-level directories require an ADR.

## 5. Testing

- **pytest**, `asyncio_mode = "auto"` (pyproject), tests in `apps/api/tests/` mirroring
  the domain layout (`tests/domains/connections/test_service.py`).
- Naming: `test_<unit>_<behavior>[_<condition>]`, e.g.
  `test_create_connection_rejects_foreign_workspace`.
- Coverage expectation: **~80% on service layers** — services carry the business logic
  and the tenant-isolation guarantees, so that's where the tests pay rent. Routers get
  thin contract tests; repositories get tests where queries are non-trivial.
- Every bug fix ships with a regression test. Tenant-isolation behavior gets explicit
  negative tests (workspace A cannot read workspace B).
- Frontend posture for now: typecheck + lint + build in CI are the safety net; component
  tests arrive with the first complex interactive flows (M2+). Don't write snapshot
  tests — they rot.

## 6. Git and reviews

### 6.1 Conventional Commits

Format: `type(scope)?: imperative summary` (Bible §10). Types: `feat`, `fix`, `docs`,
`chore`, `refactor`, `test`, `ci`.

```
feat(connections): add OAuth token refresh task
fix(runtime): re-validate redirect targets against egress allowlist
docs: add API_GUIDELINES pagination section
chore(deps): bump httpx to 0.28.1
```

Breaking changes: `!` after the type/scope plus a `BREAKING CHANGE:` footer.

### 6.2 Branches (ADR-0005)

`main` is always deployable. Short-lived branches: `feat/<slug>`, `fix/<slug>`,
`docs/<slug>`, `chore/<slug>` (e.g. `feat/connection-oauth-refresh`). No long-lived
`develop`. Release tags `vX.Y.Z`.

### 6.3 Merging

**Squash merge only**, via PR, with green CI. The squash commit message follows
Conventional Commits — it becomes the changelog raw material.

### 6.4 PR size and review

- Target **<400 lines of diff** (generated code and lockfiles excluded). Bigger change?
  Split it: schema PR, then implementation PR, then wiring PR.
- Review SLA: **first response within one business day**; small PRs same-day.
- Reviewer checklist:
  1. Every new query/table scoped by `workspace_id`? (Bible §6.1)
  2. Any chance a Credential reaches a log, response, or task payload? (SECURITY.md §2)
  3. Domain boundaries respected — no cross-domain repository/model imports?
  4. Tests cover the behavior change, including the failure path?
  5. Docs updated: CHANGELOG entry, ADR if architectural, spec if contract changed?
  6. Canonical names from Bible §4 used?

## 7. Documentation rules

- **Every behavior change adds a CHANGELOG.md entry** under `[Unreleased]` in the same
  PR (Bible §6.8 — definition of done includes docs).
- **Every architectural decision gets an ADR** in DECISIONS.md (append-only, referenced
  by number in the PR description).
- Spec docs (SYSTEM_ARCHITECTURE.md, BACKEND_SPEC.md, etc.) are updated in the PR that
  changes what they describe — reality and docs never drift (Bible header).
- New domain concept → Bible §4 first, or it doesn't ship (Bible §12).
