# Observability

> Consistent with docs/MASTER_PROJECT_BIBLE.md. This document is the monitoring and
> observability **strategy**; the mechanics it builds on live in BACKEND_SPEC.md §7
> (structlog setup), SECURITY.md §2.3 (redaction), and DATABASE_DESIGN.md (`tool_calls`).

Version 1.0 · 2026-08-02

---

## 1. Philosophy

**Observe the tool-call path first.** The Tool Call is the product (Bible §11). Every
observability investment is ranked by one question: does it help us see, debug, or
defend the path AI client → Interface adapter → Execution Runtime → third-party API?
Dashboard CSS bugs can wait; a silent runtime failure cannot.

**Cardinality discipline.** Labels and log fields use bounded sets: `workspace_id`,
`domain`, `status`, `error_code`, `interface` — never raw URLs, tool arguments, or
user-supplied strings. Unbounded cardinality turns every metrics bill into a surprise
and every dashboard into noise. Per-Tool granularity lives in the `tool_calls` table
(§10), where SQL can slice it, not in metric labels.

**Buy, don't build, at our size.** Two people run this. We lean on Sentry (errors),
PostHog (product analytics), Better Stack (uptime + log drains), and Railway/Vercel
platform metrics rather than running our own Prometheus/Grafana/OTel stack before the
scale justifies it (§3 and §4 define the adoption triggers).

## 2. Logging

Mechanics are specified in BACKEND_SPEC.md §7; this section fixes the strategy.

- **structlog, JSON in staging/production**, pretty console in development. JSON logs
  drain to Better Stack for search and retention.
- **Canonical fields on every event:** `timestamp`, `level`, `request_id`,
  `workspace_id` (once resolved), `domain` (the owning domain package), `event`
  (snake_case, stable, greppable — e.g. `tool_call.completed`, `ingestion.failed`).
  Celery tasks carry the same fields via their payload (BACKEND_SPEC.md §5).
- **One canonical line per unit of work.** Each request and each task emits a single
  summary event with status and duration; incidental debug lines are `debug` level and
  dropped in production. Log volume is a cost and a search-noise problem.
- **Credential redaction is law**, enforced by the structlog processor and Sentry
  `before_send` scrubber defined in SECURITY.md §2.3. Never logged: credential
  plaintext or ciphertext, API token secrets, `Authorization` headers, full tool-call
  arguments/responses (BACKEND_SPEC.md §7).
- **Retention:** 30 days in Better Stack for application logs (matches the Free-tier
  audit retention floor in PRD.md §6); `error`-level events live longer in Sentry per
  its own retention. Ops logs are disposable by design — the durable trail is §10.

## 3. Metrics

Pre-Prometheus, metrics live where the vendors put them; we adopt a real time-series
stack only when a question can't be answered by the sources below plus SQL over
`tool_calls`.

Golden signals for the API and the Execution Runtime:

| Signal | Definition | Lives today | Later |
|---|---|---|---|
| Latency | Tool Call runtime overhead p50/p95 (PRD.md §6 budgets) | `duration_ms` in `tool_calls` (SQL), Better Stack response-time checks | Prometheus histogram |
| Errors | Tool Call platform error rate (`status`, `error_code`) | `tool_calls` SQL + Sentry issue volume | Prometheus counter |
| Throughput | Tool Calls/min per Workspace and total | `tool_calls` SQL, PostHog events | Prometheus counter |
| Saturation | Railway CPU/memory, Neon/Upstash connection usage | Platform dashboards | Prometheus + exporters |
| Queue depth | Celery queue length and oldest-task age per queue | Redis `LLEN` polled by a beat task, alerted via Better Stack (RISKS.md R-07) | Prometheus |
| Importer success | Spec submissions yielding usable Tools (PRD.md §8 target ≥ 85%) | PostHog funnel on ingestion events | unchanged |

Adoption trigger for Prometheus/Grafana (or a hosted equivalent): sustained production
traffic where 1-minute-resolution SQL polling becomes the bottleneck, or the first
paying customer SLA that requires real-time percentile tracking — whichever comes first,
recorded as an ADR.

## 4. Tracing

We do not pretend to have distributed tracing on day one. What we have — and enforce —
is **`request_id` propagation across every hop**: middleware generates or accepts
`X-Request-Id` (API_GUIDELINES.md §1), binds it to structlog contextvars, passes it in
every Celery payload (BACKEND_SPEC.md §5), forwards it on outbound httpx calls, stamps
it on the `tool_calls` row, and returns it in every response and error envelope. One
grep in Better Stack reconstructs a request across web → api → celery → outbound.

**OpenTelemetry adoption criteria** (any one, via ADR): first domain extracted into a
separate service (ADR-0001's seam makes tracing genuinely distributed), p95 debugging
that log-correlation can no longer answer within an hour, or an enterprise requirement
for trace export. Until then, OTel would be microservice tax paid early (ADR-0001).

## 5. Alerts

An alert is a request for human action. If no action exists, it's a dashboard line.

| Severity | Meaning | Delivery |
|---|---|---|
| **Page** | Execution path down or Credentials/tenancy at risk — act now | Better Stack phone/push to on-point founder |
| **Notify** | Degradation that can wait until working hours | Better Stack → Slack/email |
| **Info** | Trend worth a weekly look | Dashboard only, reviewed in sprint review (SPRINTS.md) |

Paging set (initial): production `/health` failing (§6), Tool Call platform error rate
> 5% over 10 min, quota checks failing closed on Redis loss (SYSTEM_ARCHITECTURE.md
§7), any credential-redaction bypass signature in Sentry, Celery `runtime` queue oldest
task > 5 min. Notify set: staging down, ingestion failure spike, webhook outbox `dead`
growth, per-Workspace volume anomaly (RISKS.md R-08), Sentry new-issue bursts.

Hygiene rules: every alert has an owner and a linked runbook line; an alert that fires
without action twice is retuned or deleted in the same week; thresholds live in config,
not tribal memory; test alerts fire monthly so silence means healthy, not broken.

## 6. Health checks

- **Now:** `GET /health` liveness on the API — process up, event loop responsive. No
  dependency checks, so a Neon blip doesn't restart-loop healthy processes.
- **Now:** `GET /health/ready` readiness — verifies DB connectivity (cheap `SELECT 1`)
  and Redis ping, each bounded and run concurrently. Railway uses readiness for deploy
  gating; liveness for restarts. Returns `200 {"status":"ready"}` or
  `503 {"status":"not_ready"}`; the body names no dependency, because the endpoint is
  unauthenticated and monitored from the public internet — which dependency failed is
  recorded in the structured log instead (ADR-0013).
- **Still outstanding:** workers exposing health via Celery inspect ping wired to the same
  monitor. The API halves of §6 are delivered; the worker half is not.
- **Better Stack uptime monitors per environment:** production `/health`,
  production `/health/ready` (M1), the MCP Interface endpoint, the Vercel dashboard,
  and staging equivalents (notify-only). Production monitors feed the public status
  page promised in PRD.md §6.

## 7. Dashboards

Two dashboards, two audiences. Ops answers "is the platform healthy?"; product answers
"is the product working?". Neither duplicates the other.

**Ops dashboard (Better Stack)** starts with:
1. Uptime per monitor (API, MCP Interface, dashboard) — current + 30-day
2. Tool Call throughput (calls/min, total)
3. Tool Call platform error rate vs the 0.5% target (PRD.md §8)
4. Runtime overhead p50/p95 vs PRD budgets
5. Celery queue depth + oldest-task age per queue
6. Sentry error volume by domain
7. Redis/Postgres saturation (from platform metrics)

**Product dashboard (PostHog)** starts with:
1. Weekly executed Tool Calls per Workspace (north star, Bible §11)
2. Activation funnel: signup → first Connection → first successful Tool Call
3. Time-to-first-Tool-Call (median)
4. Connector ingestion success rate
5. Interfaces per active Workspace
6. Week-4 retention cohort
7. Top Connectors/Tools by executed Tool Calls

## 8. Performance monitoring

The budgets are set in PRD.md §6 and are not renegotiated here: runtime overhead
p50 < 150 ms / p95 < 400 ms for synchronous Tool Calls; cached tool listing p95 < 100 ms.

- **p95 tracking:** computed daily from `tool_calls.duration_ms` (minus recorded
  upstream time) and charted on the ops dashboard; a budget breach for 3 consecutive
  days becomes a sprint item, not a backlog wish.
- **Regression guard:** any PR touching the hot path answers the performance checklist
  (no new synchronous external call — CLAUDE.md); suspicious changes get a before/after
  measurement in the PR description.
- **Load-test cadence:** first load test at M2 exit (MCP Interface live), then before
  every launch-gating milestone (M3 beta, M4 public launch), scripted and repeatable in
  `scripts/`. Target: sustain 10× current peak Tool Call throughput inside the p95
  budget, with quota enforcement (including fail-closed behavior) verified under load.

## 9. Incident response

Severity matrix — the operational companion to SECURITY.md §8, which owns the
security-incident process (detect/triage/contain/notify/learn):

| Sev | Definition | Response | Examples |
|---|---|---|---|
| **SEV-1** | Execution path down, or any Credential/tenant-isolation exposure (auto-SEV-1 per SECURITY.md §8) | Page; drop everything; customer notification path per SECURITY.md | Runtime 5xx storm, vault anomaly |
| **SEV-2** | Execution path degraded or a major feature down; workaround exists | Same-day fix during waking hours | Ingestion broken, one Interface down |
| **SEV-3** | Cosmetic or contained; SLO unaffected | Next sprint | Dashboard chart broken, flaky staging |

**On-call reality for two people:** no rotation — an on-point founder (CTO for
platform, CEO for comms), shared access continuity via password manager (RISKS.md
R-06), and an honest promise: pages are answered best-effort outside working hours
until the first engineering hire (M3+). We publish the SLO (§11), not response-time
commitments we can't staff.

**Postmortems:** every SEV-1/SEV-2 gets a blameless write-up in MEETING_NOTES.md within
one week — timeline, impact, root cause, actions with owners — plus a RISKS.md update
and, for security incidents, the SECURITY.md §8 steps. SEV-3s get a sprint-review line.

## 10. Audit logs

The **`tool_calls` table is the product-facing audit trail** — every Tool Call, always
logged (Bible §4). DATABASE_DESIGN.md owns the schema; nothing here redefines it.

- **Immutability:** rows are append-only and never updated (no `updated_at` by design);
  retention is enforced by dropping monthly partitions, never by row deletes
  (DATABASE_DESIGN.md §1, §3). Application DB roles get no UPDATE/DELETE grant on it.
- **Retention is a plan feature:** 30 days Free, 90 days Pro/Team, custom Enterprise
  (PRD.md §6) — implemented as partition-drop policy per plan tier.
- **Distinct from ops logs (§2):** ops logs are ours, ephemeral, and exist to debug the
  platform; the audit trail is the customer's, durable, queryable in the dashboard
  (PRD.md UJ-4/FR-CP-3), export-ready for compliance (SECURITY.md §9), and stores only
  sanitized summaries — never credentials or raw payloads (SECURITY.md §2.3). The two
  meet only through `request_id`, which links an audit row to its ops-log trace.

## 11. SLOs, SLIs, and error budgets

Formal SLOs start at **M3 (private beta)** — before real users, an SLO is theater.
Until M3 we track the same numbers as targets, not commitments.

Initial SLOs proposed for M3 (ratify at the M3 review; derived from PRD.md §6):

| SLO | SLI | Target |
|---|---|---|
| Tool Call execution availability | Successful platform handling / all Tool Calls (upstream faults excluded via `error_code`) | 99.9% monthly |
| Runtime overhead latency | p95 of `duration_ms` minus upstream time, synchronous Tool Calls | < 400 ms |
| Ingestion success | Spec submissions yielding usable Tools without support | ≥ 85% |

**Error budget policy:** 99.9% monthly ≈ 43 minutes of budget. When a month's budget is
burned — or is trending to burn by mid-month — reliability work preempts feature work on
the next sprint plan (SPRINTS.md), no negotiation; the milestone slips before the SLO
does. Budget status is a standing line in the Friday sprint review, next to the risk
scan (RISKS.md §5).
