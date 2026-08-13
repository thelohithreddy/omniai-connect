# Sprint Log

> Consistent with docs/MASTER_PROJECT_BIBLE.md

Living document. Newest sprint at the top of the log (after the process section).
Owners: Uday (CEO), Claude (CTO).

---

## Cadence and process

- **Length:** 1 week, Monday → Friday (weekend work happens but is never planned).
- **Monday (plan):** pick a single sprint goal that advances the current ROADMAP.md
  milestone; list scope items; anything not listed is out of scope by default.
- **Friday (review):** mark each item Shipped / Partial / Dropped; write 1–3 learnings;
  explicitly list carry-over. Update the north-star and PRD §8 metrics once instrumented
  (from M3 onward).
- **Rules:** one goal per sprint; carry-over is normal, silent carry-over is not; scope
  added mid-sprint must displace something and be noted; every "Shipped" meets the
  Definition of Done (Bible §10: code + tests + docs + migration + CHANGELOG).

## Entry format

```markdown
## Sprint N (YYYY-MM-DD → YYYY-MM-DD) · Milestone Mx
**Goal:** one sentence.
**Planned:** bullets.
**Shipped:** bullets (with PR links once the repo is public-facing).
**Partial / Dropped:** bullets with one-line reasons.
**Learnings:** 1–3 bullets.
**Carry-over:** bullets, or "none".
```

---

## Sprint 1 (2026-08-03 → 2026-08-07) · Milestone M1 — *in progress*

**Goal:** M1.1 — tenancy foundation and machine identity: a workspace-scoped API token
authenticates a caller, binds tenant context, and returns its Workspace, with isolation
proven by an automated cross-tenant suite.

**Scope change from the plan.** The drafted sprint opened with Better Auth. Reordered to
machine identity first: the runtime authenticates with workspace-scoped tokens rather than
human sessions (MCP_RUNTIME.md §2), so tokens unblock the product's real hot path, and
deferring keeps the contested half of ADR-0002 — the cross-language shared-secret split —
open until dashboard work forces it. Better Auth and `members` move to M1.2.

**Shipped:**
- `workspaces` + `api_tokens` (UUIDv7 PKs, `workspace_id NOT NULL`, workspace-leading
  indexes); RLS `ENABLE` + `FORCE` with transaction-local `app.workspace_id`.
- Least-privileged `omniai_app` role (non-superuser, non-owner, no `BYPASSRLS`); migration
  preflight refuses to run otherwise.
- `auth.resolve_api_token` — one `SECURITY DEFINER` function, pinned `search_path`, owned
  by a `NOLOGIN` role — resolving the bootstrap paradox of looking up a token before the
  workspace it names is known.
- Application spine: UnitOfWork, structlog with `request_id`/`workspace_id` contextvars and
  secret redaction, domain exception hierarchy, uniform error envelope, request middleware.
- `GET /v1/workspaces/me`; Alembic scaffolding; 26 tests; CI integration lane on real
  Postgres with migration up/down/up verification.

**Also fixed (found during implementation, not planned):**
- DATABASE_DESIGN.md §6 specified a *session-scoped* RLS GUC — a cross-tenant leak.
- `web.Dockerfile`'s prod stage could never build (`output: "standalone"` was unset).
- No `.dockerignore`: every build shipped ~453 MB of context.

**Carry-over to M1.2:** Better Auth, `members` + role matrix, api-token issue/revoke
endpoints, `/health/ready`.

**Learnings:**
- Postgres RLS has two bypasses, not one — superuser *and* table owner. A suite that only
  asserts positive cases, run as either, passes while the system leaks. The guard test and
  role separation are what make the isolation suite mean anything.
- Mutation-testing the security tests (reintroducing the bug and watching them fail) was
  worth more than adding more of them.
- Doc-first design caught the right architecture and still shipped a specified leak. Specs
  need executable assertions, not just review.

---

## Sprint 0 (2026-07-27 → 2026-08-02) · Milestone M0 — *retrospective*

**Goal:** Project foundation — a repo, a plan, and a pipeline we trust.

**Planned:** monorepo scaffold, core documentation set, CI, local Docker stack,
foundational tooling decisions.

**Shipped:**
- Monorepo per Bible §8: `apps/web` (Next.js), `apps/api` (FastAPI + Celery),
  `packages/types`, `packages/config`, `infra/docker`, `scripts`, `.github`.
- Documentation set: MASTER_PROJECT_BIBLE, SYSTEM_ARCHITECTURE, DECISIONS
  (ADR-0001…0007), PRD, ROADMAP, SPRINTS, COMPETITOR_ANALYSIS, RISKS.
- CI on GitHub Actions: lint, type-check, tests, Gitleaks secret scanning; green on `main`.
- Docker: local development stack builds and runs (web, api, Postgres, Redis).
  *(Corrected 2026-08-04: this line originally claimed a `worker` service. No Celery worker
  exists in docker-compose.yml and none was written. Recorded rather than quietly edited —
  a sprint log that overstates what shipped is worse than no sprint log.)*
- Tooling locked: uv for Python deps (ADR-0006); trunk-based branching (ADR-0005).

**Partial / Dropped:** none — M0 exit criteria met (see ROADMAP.md).

**Learnings:**
- Writing the canonical domain model (Bible §4) before any schema work killed several
  naming debates in advance; keep enforcing it in review.
- The N importers + M exporters decision (ADR-0003) simplified every downstream doc —
  decide data contracts before features.

**Carry-over:** none.
