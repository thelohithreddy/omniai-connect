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

## Sprint 1 (2026-08-03 → 2026-08-07) · Milestone M1 — *planned*

**Goal:** *(to set Monday 2026-08-03)* First vertical slice of M1: Better Auth in
apps/web, FastAPI token verification producing a Member + Workspace context, and the
Workspace/Member tables with `workspace_id` scoping in place.

**Candidate scope (from ROADMAP.md M1):**
- Better Auth setup in apps/web (email + one social provider).
- FastAPI middleware: verify signed session token → Member + Workspace context (ADR-0002).
- Alembic migrations: `workspaces`, `members` with the tenancy mixin; RLS enabled.
- Skeleton of the `connectors` domain package + event bus wiring.

**Shipped / Partial / Learnings / Carry-over:** — *(filled Friday 2026-08-07)*

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
- Docker: local development stack builds and runs (web, api, worker, Postgres, Redis).
- Tooling locked: uv for Python deps (ADR-0006); trunk-based branching (ADR-0005).

**Partial / Dropped:** none — M0 exit criteria met (see ROADMAP.md).

**Learnings:**
- Writing the canonical domain model (Bible §4) before any schema work killed several
  naming debates in advance; keep enforcing it in review.
- The N importers + M exporters decision (ADR-0003) simplified every downstream doc —
  decide data contracts before features.

**Carry-over:** none.
