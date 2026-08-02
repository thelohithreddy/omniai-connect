# Engineering Principles

> Consistent with docs/MASTER_PROJECT_BIBLE.md. This is the engineering constitution:
> the quotable principles behind every spec — mechanics live in the referenced docs,
> never here ("link, don't copy").

Version 1.0 · 2026-08-02

---

## Preamble

These principles exist to be **cited** — in PRs, reviews, and design debates — by
number: "violates P-7". Each states a principle and its rationale in one breath and
points to the document that holds the mechanics.

**Amendment:** changing, adding, or retiring a principle requires an ADR in
docs/DECISIONS.md, merged in the same PR as the edit. Principles are never renumbered;
retired ones are struck through with the ADR reference. **Conflict resolution:**
Bible > ADRs > this document > domain specs — the higher document wins and the lower
one is fixed in the same PR (Bible header: never let them drift).

## 1. Architecture Principles

- **P-1. Modular monolith, microservice-ready — never microservice-first.** A two-person
  team pays distributed-systems tax with none of the benefits; the extraction seam is
  designed in, not bolted on. → SYSTEM_ARCHITECTURE.md §1, ADR-0001.
- **P-2. The Execution Runtime is the only egress.** One choke point for auth injection,
  SSRF defense, quotas, and audit beats N leaky ones. → Bible §6.3, SECURITY.md §6.
- **P-3. Adapters are thin; logic lives in domains.** If an MCP handler contains an
  `if`, it probably belongs in the runtime — MCP is one door, not the house.
  → Bible §6.4, BACKEND_SPEC.md §2.
- **P-4. Hub-and-spoke over N×M.** Every format normalizes to the canonical Tool Schema;
  N importers + M exporters stay linear as both sides grow. → ADR-0003, CONNECTOR_ENGINE.md.
- **P-5. Domains talk through service interfaces and events, never each other's
  internals.** The boundary you respect today is the microservice you extract for free
  tomorrow. → BACKEND_SPEC.md §2, §4.
- **P-6. Schema-first.** Contracts (Pydantic + OpenAPI) and migrations (Alembic) precede
  implementation, because a contract written after the code merely describes bugs.
  → Bible §6.5.

## 2. Coding Principles

- **P-7. Clarity over cleverness.** Code is read far more often than written; boring and
  obvious beats elegant and opaque. → CODING_STANDARDS.md §1.
- **P-8. Names are law.** Workspace, Member, Connector, Connection, Tool, Tool Call,
  Credential, Interface — synonyms breed bugs. New concept → Bible §4 or it doesn't
  ship. → Bible §4, §12.
- **P-9. Never skip a layer.** Router → service → repository, always — every shortcut is
  a place where tenancy, authz, or transactions silently escape. → BACKEND_SPEC.md §2.
- **P-10. Async-first, no blocking IO in the request path.** One blocking call stalls
  every request sharing the event loop; heavy work goes to Celery.
  → CODING_STANDARDS.md §2.3, ADR-0007.
- **P-11. Configuration flows through one typed door.** Only `core/config.py` reads the
  environment, so every setting is discoverable, typed, and testable.
  → BACKEND_SPEC.md §9.
- **P-12. Boy-scout rule, not drive-by refactors.** Leave touched code slightly better;
  ship unrelated cleanups as separate `refactor:` PRs so reviews stay honest.
  → CODING_STANDARDS.md §1.

## 3. Security Principles

- **P-13. Credentials are radioactive.** Encrypted at rest, decrypted only inside the
  runtime, in memory, per Tool Call — losing one is a company-ending event.
  → Bible §6.2, SECURITY.md §2.
- **P-14. Tenant isolation is sacred.** Every tenant query is workspace-scoped by
  construction, with Postgres RLS as defense-in-depth — an unscoped query must be
  unrepresentable. → Bible §6.1, SECURITY.md §3, ADR-0004.
- **P-15. Never hand-roll auth or crypto.** Better Auth owns identity, standard
  primitives own encryption; our creativity is not welcome here. → ADR-0002,
  SECURITY.md §2.1.
- **P-16. Omission is the design; redaction is the backstop.** Response schemas simply
  contain no secret fields, and scrubbers catch what bugs leak. → SECURITY.md §2.3.
- **P-17. Deny by default.** Unlisted capability → owner-only; cross-tenant probes get
  `not_found`, never an existence oracle. → SECURITY.md §4.1, §3.
- **P-18. No secrets in code, config, or CI — ever.** `.env.example` is the contract and
  Gitleaks is the enforcer; a leaked value is rotated even if it never merged.
  → Bible §6.7, SECURITY.md §5.

## 4. Performance Principles

- **P-19. The hot path is the Tool Call path — protect it.** It touches Redis and one
  audit insert; adding a synchronous external call to it needs extraordinary
  justification. → SYSTEM_ARCHITECTURE.md §6.
- **P-20. Budgets are requirements, not aspirations.** p50 < 150 ms / p95 < 400 ms
  runtime overhead is a commitment we track daily. → PRD.md §6, OBSERVABILITY.md §8.
- **P-21. Heavy work is async work.** Ingestion, aggregation, refresh — anything slow
  goes to Celery so the request path stays flat. → ADR-0007, BACKEND_SPEC.md §5.
- **P-22. Cache with explicit invalidation, never TTL-and-pray.** Event-driven
  invalidation keeps caches honest; stale tool listings are user-visible lies.
  → SYSTEM_ARCHITECTURE.md §6.

## 5. Documentation Standards

- **P-23. Docs move with code.** A behavior change without its CHANGELOG/spec update is
  an incomplete PR, because a doc that drifts is worse than no doc. → Bible §6.8,
  CODING_STANDARDS.md §7.
- **P-24. One fact, one home.** Every rule lives in exactly one document and is linked
  from everywhere else — duplication is where contradictions are born. → Bible §9 index.
- **P-25. Decisions are recorded, append-only, with their why.** ADRs capture context so
  future engineers inherit reasoning, not just ruins. → DECISIONS.md header.
- **P-26. Docstrings explain the non-obvious or don't exist.** A docstring restating the
  function name is noise wearing a suit. → CODING_STANDARDS.md §2.5.

## 6. Testing Standards

- **P-27. Tests pay rent where the logic lives.** ~80% coverage on services — the layer
  holding business rules and tenancy guarantees — beats vanity coverage everywhere.
  → CODING_STANDARDS.md §5, BACKEND_SPEC.md §8.
- **P-28. Every bug fix ships with its regression test.** A bug without a test is a bug
  scheduled for re-release. → CODING_STANDARDS.md §5.
- **P-29. Tenant isolation gets explicit negative tests.** Workspace A must provably
  fail to read Workspace B — for every new repository. → BACKEND_SPEC.md §8.
- **P-30. A failing test is never skipped to make CI green.** Skipping converts a known
  bug into an unknown one. → CLAUDE.md testing requirements.
- **P-31. Contract tests keep adapters honest.** Adapters prove they translate — not
  reinterpret — runtime behavior. → BACKEND_SPEC.md §8.

## 7. Git Workflow

- **P-32. `main` is always deployable.** Trunk-based, short-lived branches, squash
  merges — merge ceremony is a tax on iteration speed. → ADR-0005, CODING_STANDARDS.md §6.
- **P-33. Small PRs get real reviews.** Target <400 diff lines; bigger changes split into
  schema → implementation → wiring. → CODING_STANDARDS.md §6.4.
- **P-34. Conventional Commits, no exceptions.** Commit messages are changelog raw
  material, not diary entries. → Bible §10, CODING_STANDARDS.md §6.1.
- **P-35. Green CI gates every merge.** CI is the only reviewer that never gets tired.
  → CODING_STANDARDS.md §6.3.

## 8. API Standards

- **P-36. The OpenAPI document is the contract.** Docs render from it, types generate
  from it, contract tests validate against it — disagreement is a bug in whichever
  changed last. → API_GUIDELINES.md §11.
- **P-37. Within a major version, changes are additive only.** Clients build on our API;
  breaking them quietly breaks trust loudly. → API_GUIDELINES.md §8.
- **P-38. One error envelope, everywhere.** Machine-readable `code`, human `message`,
  always a `request_id` — errors are part of the API surface. → API_GUIDELINES.md §6.
- **P-39. Side-effecting calls are idempotent by construction.** Idempotency keys make
  retries safe in a world of flaky networks and eager agents. → API_GUIDELINES.md §5.
- **P-40. Cursor pagination, never offsets.** Offsets break under concurrent writes and
  invite table scans. → API_GUIDELINES.md §3.

## 9. Database Standards

- **P-41. Every tenant table carries `workspace_id NOT NULL`.** Tenancy is a schema
  property, not an application convention. → DATABASE_DESIGN.md §1, ADR-0004.
- **P-42. Alembic only; one migration per PR; always reversible.** Manual DDL is
  untracked risk, and an irreversible migration is documented, not smuggled.
  → DATABASE_DESIGN.md §5.
- **P-43. Additive-first: expand → migrate → contract.** Destructive changes never ride
  in the release that introduces their replacement. → DATABASE_DESIGN.md §5.
- **P-44. Indexes lead with `workspace_id`; none are speculative.** Every access path is
  workspace-scoped, and unused indexes are pure write tax. → DATABASE_DESIGN.md §4.
- **P-45. Append-only tables stay append-only.** `tool_calls` and `usage_events` are
  never updated or deleted in-band; retention drops partitions. → DATABASE_DESIGN.md §1.

## 10. Scalability Principles

- **P-46. Stateless API, horizontal scale.** State lives in Postgres and Redis so any
  replica can serve any request. → SYSTEM_ARCHITECTURE.md §6.
- **P-47. Name future bottlenecks before they arrive.** Audit volume → partitions →
  ClickHouse; egress IPs → proxy pool — pre-planned exits beat panicked rewrites.
  → SYSTEM_ARCHITECTURE.md §6.
- **P-48. Scale by extraction, not by rewrite.** Domain boundaries plus the event bus
  make "make it a service" a deployment decision, not a project. → ADR-0001.
- **P-49. Fail closed on billing-relevant paths.** If Redis is down, quota checks refuse
  — security and revenue integrity over availability. → SYSTEM_ARCHITECTURE.md §7.

## 11. Error Handling Principles

- **P-50. Services raise domain exceptions; one handler maps them.** Routers never build
  error responses by hand, so the envelope stays uniform. → BACKEND_SPEC.md §6.
- **P-51. Expected upstream failures are results, not exceptions.** A third-party 404 is
  data the runtime normalizes, not a 500 we cause. → CODING_STANDARDS.md §2.4.
- **P-52. Never swallow, never echo.** No `except: pass`, and no upstream body relayed
  verbatim — it may carry secrets or injection payloads. → BACKEND_SPEC.md §6.
- **P-53. Every outbound call is bounded.** Timeout, bounded retries with jitter
  (idempotent operations only), circuit breaker per Connection.
  → SYSTEM_ARCHITECTURE.md §7.

## 12. Observability Principles

The strategy lives in docs/OBSERVABILITY.md; these are its constitutional anchors.

- **P-54. Observe the tool-call path first.** Instrumentation effort follows the
  product's critical path, not whatever was easiest to wire. → OBSERVABILITY.md §1.
- **P-55. Every unit of work carries `request_id` + `workspace_id`.** One identifier
  reconstructs a request across web, API, Celery, and outbound. → OBSERVABILITY.md §4.
- **P-56. Cardinality discipline in every metric and label.** Unbounded labels are a
  bill and a blur; high-cardinality questions go to SQL over `tool_calls`.
  → OBSERVABILITY.md §1.
- **P-57. An alert demands an action or it isn't an alert.** Alerts that fire without
  action get retuned or deleted — silence must mean healthy. → OBSERVABILITY.md §5.
- **P-58. The audit trail is a product feature, not a log file.** `tool_calls` is
  immutable, retained per plan, and customer-facing. → OBSERVABILITY.md §10.

## 13. Dependency Management Rules

- **P-59. Lockfiles are mandatory and committed.** Builds are reproducible or they are
  roulette — `uv.lock` and `pnpm-lock.yaml`, no exceptions. → SECURITY.md §7, ADR-0006.
- **P-60. No new dependency without a reason stated in the PR.** Every dependency is
  attack surface, upgrade burden, and bus-factor debt. → CLAUDE.md security checklist.
- **P-61. Security updates merge within the review SLA.** Dependabot's PRs age like
  vulnerabilities, because they are. → SECURITY.md §7, CODING_STANDARDS.md §6.4.
- **P-62. Pin what you deploy.** Version-pinned Actions (SHA-pinned before production
  credentials), no `latest` image tags in deploy manifests. → SECURITY.md §7.

## 14. Code Review Rules

- **P-63. Review the checklist, then the code.** Tenancy, credential paths, layering,
  tests, docs, names — the six-point reviewer list is the floor, not the ceiling.
  → CODING_STANDARDS.md §6.4.
- **P-64. First response within one business day; small PRs same-day.** Review latency
  is the team's largest hidden queue. → CODING_STANDARDS.md §6.4.
- **P-65. Question poor instructions; propose better before implementing.** A review
  culture that can't say "this is wrong" ships wrong things politely. → CLAUDE.md.
- **P-66. A rubber stamp is a review failure.** If the PR was too big to truly review,
  the correct response is "split it" (P-33), not "LGTM".

## 15. Definition of Done

The single authoritative checklist (expands Bible §10). Work is **done** when every
line holds; partially done is not done:

1. Code merged to `main` via PR, squash merge, green CI (P-32, P-35).
2. Tests cover the behavior change, including failure paths and — for anything touching
   tenant data — cross-workspace negative tests (P-27–P-29).
3. Alembic migration included if the schema changed, reversible, one per PR (P-42).
4. Docs updated in the same PR: CHANGELOG.md entry; ADR if architectural; the owning
   spec if a contract changed (P-23).
5. `.env.example` updated for any new configuration (P-11, P-18).
6. No secret, credential, or token anywhere in the diff or CI logs (P-18).
7. Observability in place for new behavior: canonical log events, and alert/dashboard
   updates when the change touches the tool-call path (P-54, P-57).
8. Canonical domain terms used throughout; new concepts added to Bible §4 first (P-8).

## 16. Long-term Maintainability Rules

- **P-67. Build for the team we have, not the team we imagine.** Two people; every
  process, tool, and on-call promise is sized accordingly. → OBSERVABILITY.md §9.
- **P-68. The system must be rebuildable from its docs.** Documentation discipline is
  the bus-factor mitigation, not a nicety. → RISKS.md R-06, Bible §6.8.
- **P-69. Every bet records its exit.** Celery, managed OAuth, MCP-as-adapter — each
  risky choice ships with a pre-planned escape that costs an ADR, not a rewrite.
  → RISKS.md §4, DECISIONS.md.
- **P-70. Roadmap discipline: build what's planned, or change the plan first.** Features
  outside the milestone need founder approval, not momentum. → Bible §10, ROADMAP.md.
- **P-71. Leave the repo better than found.** Green CI, clean `git status`, current
  docs — entropy is paid down continuously or it compounds. → CLAUDE.md.
