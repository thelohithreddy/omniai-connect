# PROJECT_STATUS.md

> Living tracker. Updated after every major milestone (and at sprint boundaries).
> AI engineers: read this at session start (per CLAUDE.md). Detail lives in the linked
> docs — this file is the dashboard, not the archive.
>
> **Last updated:** 2026-08-02 · **Updated by:** CTO Agent

## Current phase

**M0 — Foundation: COMPLETE.** Awaiting founder approval to start **M1 — Core platform
loop** (see docs/ROADMAP.md). No business features exist yet, by design.

## Current sprint

Sprint 0 (2026-07-27 → 2026-08-02) closed — see docs/SPRINTS.md. Sprint 1 is drafted,
scoped to M1's first vertical slice, pending kickoff approval.

## Completed work

- Monorepo (pnpm + Turborepo; apps/web Next.js shell, apps/api FastAPI shell with
  passing smoke test), Docker Compose stack, multi-stage Dockerfiles
- CI: lint, typecheck, tests, secret scan (Gitleaks), Docker build (.github/workflows/ci.yml)
- Documentation set: 21 docs in docs/ + CLAUDE.md, AGENTS.md, PROJECT_STATUS.md at root
- Engineering standards locked: coding, API, security, database, branching (ADR-0005)
- Git repo initialized; foundation committed

## Pending work (next up)

All M1 scope — docs/ROADMAP.md is authoritative: workspaces + tenancy plumbing, Better
Auth integration (ADR-0002), OpenAPI ingestion with api_key auth, Execution Runtime v1,
audit log, minimal dashboard slice.

## Architecture decisions

ADR-0001 modular monolith · ADR-0002 auth boundary (Better Auth in web, API verifies) ·
ADR-0003 canonical Tool Schema hub · ADR-0004 shared-schema tenancy + RLS ·
ADR-0005 trunk-based branching · ADR-0006 uv · ADR-0007 Celery+Redis.
Full records: docs/DECISIONS.md.

## Open questions

1. Product name/domain availability check for "OmniAI Connect" (trademark + .com) — before public launch.
2. MCP protocol version pinning policy: which spec revisions do we commit to at M2? (docs/MCP_RUNTIME.md flags churn risk.)
3. Free-tier limits: which quota (Tool Calls/week) balances evaluation value vs egress cost? (RISKS.md R-cost.)
4. Neon vs Railway Postgres for staging parity — validate Neon branching workflow in Sprint 1.

## Technical debt (known, accepted, tracked)

| Item | Why accepted | Pay down by |
|---|---|---|
| No lockfiles committed yet (pnpm-lock.yaml, uv.lock) | Generated on first `make setup`; CI uses --no-frozen-lockfile | Sprint 1, then freeze CI installs |
| @omniai/types hand-written | OpenAPI not stable yet | Generate from spec at M2 |
| packages/config is a placeholder | Only one consumer per config today | When second consumer appears |
| CI also triggers on `develop` | Transition allowance (ADR-0005) | Remove once staging auto-deploy is live |
| Frontend has no test lane | No UI logic to test yet | First interactive dashboard feature |

## Upcoming milestones

M1 core loop → M2 MCP + vault + OAuth → M3 billing + private beta → M4 interfaces +
GraphQL + public launch → M5 scale/enterprise. Exit criteria per milestone: docs/ROADMAP.md.

## High-priority tasks

1. Founder review + approval of foundation (this gate)
2. Create GitHub repository and push (blocked — see below); enable branch protection on `main`
3. Sprint 1 kickoff: tenancy plumbing + Better Auth spike (riskiest integration, do first)
4. Generate and commit lockfiles; switch CI to frozen installs

## Blocked tasks

| Task | Blocked on |
|---|---|
| GitHub repo creation + push | GitHub auth on founder's machine (`gh repo create omniai-connect --private --source=. --push`) |
| Sprint 1 start | Founder approval of M1 scope |
| Sentry/PostHog/Better Stack project setup | Account provisioning (founder) |

## Known risks

Top of register: credential breach, cross-tenant leak, MCP spec churn, platform vendors
commoditizing integrations, bus factor. Full register with mitigations: docs/RISKS.md.
Review cadence: weekly at sprint review.

## Current tech stack

Locked per Bible §7: Next.js/TS/Tailwind/shadcn · FastAPI/Python 3.11/SQLAlchemy 2/
Alembic/Celery · Postgres (Neon)/Redis (Upstash) · Better Auth · FastMCP + agent SDKs ·
Docker/GitHub Actions/Railway/Vercel/Cloudflare/R2 · Sentry/PostHog/Better Stack ·
Stripe · Resend. Changes require an ADR.

## Current folder structure

See CLAUDE.md "Folder structure" (kept in one place deliberately). Docs index: Bible §9.

## Current project health

| Signal | Status |
|---|---|
| CI | 🟢 defined; runs on first push to GitHub |
| Tests | 🟢 API smoke test passing locally |
| Docs ↔ reality drift | 🟢 none (docs-first stage) |
| Security posture | 🟢 standards defined; no secrets in repo; enforcement starts with M1 code |
| Delivery risk | 🟡 single engineer-founder pair; bus factor tracked in RISKS.md |
