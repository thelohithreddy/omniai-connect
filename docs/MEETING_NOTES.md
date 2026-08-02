# Meeting Notes

> Consistent with docs/MASTER_PROJECT_BIBLE.md.

## Format

Reverse-chronological: newest entry first. Every founder/engineering meeting that
produces a decision or an action item gets an entry with:

- **Date / Attendees** — who was in the room.
- **Decisions** — what was decided, referencing ADR numbers where architectural
  (the ADR in docs/DECISIONS.md is the authority; the note here is the pointer).
- **Actions** — owner + concrete next step. Actions are carried forward or closed in
  the next entry.

Discussion without a decision or action doesn't need an entry.

---

## 2026-08-02 — Founding session

**Attendees:** Uday (CEO), Claude (CTO)

### Decisions

- **Mission agreed:** "Connect Any API. Use It From Any AI." MCP is one Interface, not
  the product; the product is the connector graph plus the Execution Runtime
  (Bible §1–§2).
- **Stack locked** (Bible §7): Next.js/TypeScript on Vercel, FastAPI/Python 3.11 on
  Railway, Postgres (Neon), Redis (Upstash), Better Auth, Stripe, Cloudflare.
- **Foundation scope agreed:** milestone M0 delivers monorepo, documentation set,
  Docker, CI/CD, and standards only — **no business features** before the foundation
  is reviewed.
- Key architectural decisions recorded as ADRs:
  - ADR-0001 — modular monolith, not microservices.
  - ADR-0002 — Better Auth in the Next.js layer; FastAPI verifies tokens.
  - ADR-0003 — canonical Tool Schema as the internal contract.
  - ADR-0004 — single Postgres, shared schema, `workspace_id` + RLS tenancy.
  - ADR-0005 — trunk-based development, squash merges, no long-lived `develop`.
  - ADR-0006 — uv for Python dependency management.
  - ADR-0007 — Celery + Redis for async work.

### Actions

- [ ] **Uday** — review the foundation (docs set, repo structure, CI) end to end.
- [ ] **Uday + Claude** — approve M1 kickoff once the foundation review passes.
