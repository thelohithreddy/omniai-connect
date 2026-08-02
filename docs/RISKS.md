# Risk Register

> Consistent with docs/MASTER_PROJECT_BIBLE.md

Version 1.0 · 2026-08-02 · Owners: Uday (CEO), Claude (CTO)

Scales: Likelihood and Impact are Low / Medium / High. Status: Open · Mitigating ·
Accepted · Closed. "Mitigating" means the mitigation is actively being built or run,
not merely written down. Owner is the accountable person, not the only worker.

---

## 1. Register

| ID | Risk | Category | Likelihood | Impact | Mitigation | Owner | Status |
|---|---|---|---|---|---|---|---|
| R-01 | **Credential breach** — vault compromise or a leak path (logs, responses, memory dumps) exposes customer Credentials | Security | Low | High | Envelope encryption (AES-256-GCM), runtime-only decryption, redaction filters on every log sink, Gitleaks in CI, key rotation (M2), vault access audit, red-team pass as an M2 exit criterion; incident runbook in SECURITY.md | Claude (CTO) | Mitigating |
| R-02 | **Cross-tenant data leak** — a query missing `workspace_id` exposes one Workspace's Connections, Tools, or logs to another | Security | Medium | High | Tenancy mixin + repository-enforced scoping, Postgres RLS as defense-in-depth from M1 (ADR-0004), automated cross-tenant test suite in CI (M1 exit criterion), code-review checklist item on every new table/query | Claude (CTO) | Mitigating |
| R-03 | **MCP spec churn** — protocol/auth/transport changes break our MCP Interface or fragment client behavior | Technology | High | Medium | MCP is one thin adapter over the runtime (Bible §2, ADR-0003) — churn is contained to the adapter; track spec releases; version-pin FastMCP; conformance tests against major MCP clients | Claude (CTO) | Mitigating |
| R-04 | **Platform dependence** — AI vendors (OpenAI, Anthropic, Google) ship native connector directories with managed auth, absorbing the casual use case | Market | High | High | Differentiate where natives won't go: private/internal APIs, cross-vendor portability, vault + audit for teams (COMPETITOR_ANALYSIS.md §5); ship M1–M3 fast to build a base before "good enough" is free; keep exporters cheap so we ride new surfaces instead of fighting them | Uday (CEO) | Open |
| R-05 | **OAuth app-review friction** — Google/Microsoft/Meta et al. impose slow reviews, verification, or policy limits on our OAuth apps, blocking popular Connections | Product / Legal | High | Medium | Start reviews early for the top providers (M2); support customer-owned OAuth apps ("bring your own client ID") as the escape hatch and the enterprise default; document per-provider status; API-key auth paths keep the demo loop alive regardless | Uday (CEO) | Open |
| R-06 | **Bus factor** — a single founder-engineer (CTO) carries the architecture; illness or departure stalls the company | Team | Medium | High | Docs-move-with-code discipline (Bible §6.8) keeps the system rebuildable from docs; ADRs capture *why*; CI + one-command local stack lower onboarding cost; plan first engineering hire around M3 revenue; credentials/infra access shared via a password manager with the CEO | Uday (CEO) | Open |
| R-07 | **Celery/asyncio operational complexity** — Celery's imperfect asyncio story causes deadlocks, lost tasks, or ops burden as tool-call volume grows | Technology | Medium | Medium | Acknowledged in ADR-0007: all tasks idempotent with `workspace_id` + `request_id`; keep the hot synchronous path out of Celery; Better Stack alerting on queue depth/age; pre-agreed exit (arq/Dramatiq/Temporal) requires only a new ADR, not a rewrite, because domains talk via the event bus | Claude (CTO) | Mitigating |
| R-08 | **Cost blowout from unbounded egress** — runaway agents or abusive clients drive third-party API calls, compute, and egress beyond what plans recoup | Financial | Medium | Medium | Per-Workspace and per-Connection rate limits + quotas enforced in the runtime (fail closed if Redis is down — SYSTEM_ARCHITECTURE.md §7); hard caps on Free tier; usage metering per Tool Call reconciled with billing (M3); anomaly alerts on per-Workspace volume spikes | Claude (CTO) | Mitigating |
| R-09 | **Commoditization by a distribution giant** — Zapier MCP's ~8,000-app catalog or an OpenAI-scale entrant makes "connect AI to apps" a free checkbox | Market | High | High | Same posture as R-04 plus: win the segment catalogs can't serve (arbitrary specs, internal APIs); make vault + audit + Workspace the reason security-conscious teams choose us; consider partnering/embedding rather than fighting head-on; monitor via COMPETITOR_ANALYSIS.md reviews every milestone | Uday (CEO) | Open |
| R-10 | **Compliance blocks enterprise deals** — prospects require SOC 2 (and DPAs, pen tests) before signing; certification takes months | Compliance | High | Medium | Build controls from M1 so audit is paperwork, not rework (PRD §6): audit log, encryption, access reviews, structured logging; SECURITY.md tracks the compliance path; start SOC 2 Type I engagement at M5; sell to developers/teams (no SOC 2 gate) until then | Uday (CEO) | Open |

## 2. Scoring definitions

To keep scores honest across reviews:

- **Likelihood** — Low: we'd be surprised this year. Medium: plausible within two
  quarters. High: expected unless actively countered.
- **Impact** — Low: absorbed within a sprint. Medium: costs a milestone's momentum or
  material money. High: threatens customer trust, revenue, or company viability.
- A risk scored High/High at two consecutive milestone reviews must get a dedicated
  mitigation task on the next sprint plan (SPRINTS.md), not just a register edit.

## 3. Watchlist (not yet register-worthy)

Candidate risks we monitor but have not promoted to the register. Promotion requires a
concrete trigger, at which point the item gets an ID and a full row.

- **Upstream API instability** — third-party APIs breaking Connections at scale.
  Trigger: >5% of active Connections erroring on unchanged Connectors in a week.
- **Prompt-injection abuse of Tools** — hostile content steering an AI into damaging
  Tool Calls. Trigger: first credible report or beta incident; design notes already in
  AI_RUNTIME.md (per-Tool disable is the v1 blunt instrument).
- **Neon/Upstash/Railway platform risk** — an infra provider outage or pricing shift.
  Trigger: second SLA-relevant incident in a quarter; repository layer and Docker keep
  the exit path credible.
- **Data-residency requirements (EU)** — prospects requiring EU-hosted processing.
  Trigger: first deal blocked on residency.

## 4. Reading the register

- The two **High/High-adjacent security risks (R-01, R-02)** are existential by
  definition — Bible §6 calls cross-tenant exposure "a company-ending bug." They stay
  permanently on the review agenda even when Mitigating; they can never reach Accepted.
- The **market pair (R-04, R-09)** is not mitigable by engineering alone; the mitigation
  is strategy and speed. Expect these to remain Open for the life of the company and
  manage them through positioning reviews.
- **R-03, R-05, R-07** are the "cost of our bets" risks — each traces to an explicit
  decision (MCP-as-adapter, managed OAuth, ADR-0007) and each has a pre-planned exit.

## 5. Risk review cadence

- **Weekly (Friday sprint review):** scan for new risks surfaced during the sprint; add
  rows immediately — an unwritten risk is an unmanaged one.
- **Per milestone (ROADMAP.md boundaries):** full pass — re-score likelihood/impact,
  verify each "Mitigating" row has evidence (a test, an alert, a control — not a
  sentence), close or accept what's resolved, and re-check R-04/R-09 against a refreshed
  COMPETITOR_ANALYSIS.md.
- **On incident:** any security or availability incident triggers an immediate register
  update plus a post-mortem linked from the affected row.
- **Change discipline:** rows are edited in place with the change noted in the PR; risks
  are never silently deleted — they move to Closed/Accepted with a one-line rationale.
