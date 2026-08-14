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

---

## ADR-0009 — Workspace RBAC: explicit role→permission mapping, deny by default
**Status:** Accepted · 2026-08-14

**Context:** SECURITY.md §4.1 has always carried a role matrix, but it was prose. Turning
it into executable policy forced three questions the document did not answer.

1. *What may a `viewer` do?* The role is storable (DATABASE_DESIGN.md §3) yet appears in no
   capability table, and PRD.md FR-CP-1 lists only owner/admin/member.
2. *What happens at runtime for a capability the table does not list?* §4.1 said "an
   unlisted capability requires owner", which read literally is a permissive fallback.
3. *Should roles inherit from one another?* The matrix is nearly a hierarchy, and
   expressing it as one would be shorter.

**Decision:**

1. **Explicit mapping, not inheritance.** Each role's permission set is enumerated in
   full. `admin` is not expressed as "owner minus `workspace:manage`" — under that shape a
   capability added to owner silently lands on admin, and the reviewer of that diff sees
   one line change while two roles gain power.
2. **Deny by default at runtime, including for owner.** An unmapped role holds nothing; an
   unknown permission is held by nobody. §4.1's "unlisted capability requires owner" is
   reinterpreted as *authoring guidance* — the column values to default to when adding a
   row — not a runtime rule. As a runtime rule it would let a typo in a permission name
   grant an owner access to an undefined capability.
3. **`viewer` holds no permissions**, recorded as an open question rather than settled
   policy. Inventing "read everything" would be exactly the speculative grant this module
   is supposed to avoid, and the affected reads (full audit log, Tool Calls) are
   security-relevant enough to deserve a deliberate decision.
4. **Policy is separate from enforcement.** `app/core/authz.py` is a pure function over
   static data — no database, cache, network, request object, or framework import — and
   exposes only decision functions. It deliberately provides no `require_*` helper and
   raises nothing; refusing a request belongs to the enforcement layer.
5. **Static and in source control**, not a database table or dynamic configuration. The
   entire security model is reviewable in one diff without running anything.

**Consequences:** Adding a capability is a two-file change — SECURITY.md §4.1 and
`ROLE_PERMISSIONS` — and forgetting the second means the permission is denied to everyone
rather than granted to someone by accident. Adding a role denies everything until it is
mapped, so an incomplete role is inert rather than dangerous. The `viewer` question stays
open and blocks nothing: a viewer can currently be stored but can do nothing, which is
safe but not useful, and needs either real values in §4.1 or removal from the role domain.

## ADR-0010 — API tokens are issued unscoped, without idempotency, until their vocabularies exist

**Status:** Accepted (2026-08-14) · **Context:** M1.2-F

**Context:** `POST /v1/api-tokens` is the first write endpoint in the system, and two
canonical documents describe behaviour for it that cannot yet be implemented honestly.

1. **Scopes.** PRD.md FR-IF-3 describes a token scope as "read/invoke, subset of
   Connections". Connections do not exist yet, so there is no vocabulary a submitted scope
   could be validated against and no runtime that could enforce one.
2. **Idempotency.** API_GUIDELINES.md §5 states that any POST with side effects — naming
   api-token issuance explicitly — accepts an `Idempotency-Key` header, with the response
   stored in Redis under a 24 h TTL.

**Decision:**

1. **Tokens are issued unscoped.** The endpoint does not accept a `scopes` field at all;
   the column keeps its `[]` default. Accepting free-form strings would manufacture a
   permission language by accident and mint credentials whose recorded authority means
   nothing — and, worse, would create an audit trail that *looks* like enforcement. `[]` is
   the deny-by-default value, not a placeholder meaning "everything". Machine authorization
   is deferred whole to the module that introduces Connections.
2. **`Idempotency-Key` is not implemented for this endpoint.** The canonical design stores
   the *response* against the key, and this response contains a bearer credential in
   plaintext. Implementing §5 as written would put a live secret in Redis for 24 hours —
   a second copy of the one thing the whole design keeps to a single moment in time — and
   would do so in a store with no encryption at rest, no RLS, and a much wider blast radius
   than Postgres. Retrying a creation without a key simply issues a second token, which is
   safe: tokens are not unique by name and the extra one can be revoked.

**Consequences:** A client cannot express least privilege for a token today; every token
carries the full authority of the workspace's machine plane. That is acceptable only
because there is currently nothing for a token to *do* beyond reading its own Workspace,
and it must be revisited before Connections ship — a token minted now would silently gain
authority as capabilities are added. Recorded as a blocking dependency for the Connections
milestone rather than a nice-to-have.

The idempotency deviation makes this endpoint inconsistent with API_GUIDELINES.md §5. The
resolution is a document change, not an implementation: §5 needs to state that
credential-issuing endpoints are exempt, or specify storing an idempotency *marker* (key →
token id) rather than the response body. Until then the guideline and the code disagree,
and the code is deliberately the stricter of the two.

## ADR-0011 — Keyset cursor pagination; cursors carry a position, not an authority

**Status:** Accepted (2026-08-14) · **Context:** M1.2-G, the first list endpoint

**Context:** API_GUIDELINES.md §3 mandates cursor pagination on every list endpoint and
forbids offset pagination, and requires cursors to be opaque — *"encoded internally, signed
if they ever carry state"*. It does not specify the cursor's contents, its ordering key, or
what "carry state" means in practice. The first list endpoint has to settle those.

**Decision:**

1. **Keyset pagination on `(created_at DESC, id DESC)`.** The sort key must be unique or the
   predicate is unsound: rows sharing a `created_at` would be skipped or served forever.
   `id` breaks the tie and, being UUIDv7, orders in agreement with creation time rather than
   scrambling tied rows. The predicate is expressed as a row comparison, which Postgres can
   satisfy as a single index range scan.
2. **`has_more` is computed by over-fetching one row**, never by `count(*)`. A count is a
   second scan of the tenant's rows on every page *and* is taken at a different instant from
   the page, so a concurrent insert makes the two disagree.
3. **Cursors encode only the sort key of a row the client was already served**, and are
   base64url-encoded so they read as opaque. They are **not signed**. §3's "signed if they
   ever carry state" is read as applying to cursors that carry *server-side* state — a
   snapshot id, a filter set, a privilege. A position the client has already seen is not
   such state: forging it lets a caller resume from an arbitrary point **inside their own
   tenant**, which is not a privilege since they may already page through all of it, and it
   cannot reach another tenant because the workspace predicate comes from the authenticated
   context and is applied independently.
4. **Every unusable cursor is a `validation_error`** — expired, truncated, hand-written, or
   from another endpoint. Silently serving page one would make a client loop forever or
   believe it had reached the end of a list it had barely started.
5. **Unknown query parameters are rejected**, per §4. FastAPI's default is to drop them, so a
   client that misspells a filter or asks for one the endpoint does not support would
   otherwise receive a 200 containing everything and believe it was filtered.

**Consequences:** Cursors cannot express "jump to page 7"; only sequential traversal is
possible. That is inherent to keyset pagination and acceptable — no canonical requirement
asks for random page access, and offset is forbidden precisely because it buys that ability
with correctness.

If a future list endpoint needs a cursor that *does* carry state — a frozen snapshot, an
encoded filter set, or anything a caller must not alter — point 3 no longer covers it and
signing must be decided then: a key, an algorithm, and a rotation policy, none of which any
canonical document currently establishes. Recorded here as the deferred question rather than
pre-emptively answered.

## ADR-0012 — Revocation is `DELETE` on the token resource, implemented as a state transition

**Status:** Accepted (2026-08-14) · **Context:** M1.2-H

**Context:** `api_tokens.revoked_at` already existed (M1.1) and authentication already
rejected revoked tokens, so the enforcement half of revocation was complete before this
module began; only the state transition was missing. Two questions had to be settled from
the canon rather than preference: which HTTP verb and path express revocation, and what
repeated revocation means.

API_GUIDELINES.md §1 lists `/v1/api-tokens` as a canonical resource and §2 defines
`DELETE → 204`, *"Idempotent: deleting a deleted resource is 204"*. §2 also permits
POST-as-action. No action-style sub-path (`/{id}/verb`) appears anywhere in the guidelines
or the codebase; the only instance-path precedents are plain `GET /v1/tool-calls/{id}` and
`GET /v1/operations/{id}`.

**Decision:**

1. **`DELETE /v1/api-tokens/{id}` → 204.** Choosing `POST /{id}/revoke` would invent a URL
   convention the guidelines do not establish, and §2's DELETE row already specifies
   idempotent semantics that match revocation exactly. From the client's side the
   credential ceases to exist, which is what DELETE means; row retention is an audit
   implementation detail. The tension is acknowledged: a revoked token *remains visible* in
   listings with `revoked_at` set, which is unusual for something "deleted" — that
   visibility is deliberate and is why `ApiTokenRead` carries the field.
2. **The row is retained, not deleted.** DATABASE_DESIGN.md §3's "no soft delete —
   revocation deletes the row" governs `credentials`, a different table; `api_tokens` was
   given a nullable `revoked_at` precisely so the record survives.
3. **Idempotent, preserving the first timestamp.** The UPDATE carries
   `WHERE revoked_at IS NULL`, so a second revocation matches nothing and leaves the
   original timestamp intact, and a follow-up existence check separates "already revoked"
   (204) from "not yours" (404).
4. **No un-revoke.** The guidelines define no such operation and one would let a
   compromised credential be restored. A replacement token is issued instead.
5. **Cross-tenant and nonexistent targets are indistinguishable** (`not_found`, per
   SECURITY.md §3).

**Consequences:** A client cannot tell from the API whether a 204 revoked the token or
found it already revoked. That is the point of idempotency and is the safer ambiguity: the
credential is dead either way. Operators who need to know *when* a token was cut off read
`revoked_at` from the listing, which is why preserving the original value matters.

Revocation is not retroactive: an in-flight request that already authenticated completes.
Making it retroactive would require a mechanism to interrupt running requests, which
nothing in the architecture provides and no canonical document asks for.

## ADR-0013 — Readiness answers 503 with a dependency-free body; ops endpoints sit outside the /v1 contract

**Status:** Accepted (2026-08-14) · **Context:** M1.2-K

**Context:** OBSERVABILITY.md §6 defines the health split completely — `/health` is
liveness with no dependency checks, `/health/ready` verifies "DB connectivity (cheap
`SELECT 1`) and Redis ping", and "Railway uses readiness for deploy gating; liveness for
restarts". It does not state the failure status code, the response body, or a probe
timeout, and those cannot be left undefined in an implementation.

**Decision:**

1. **503 when not ready.** Deploy gating functionally requires an unready process to answer
   non-2xx; RFC 9110 §15.6.4 defines 503 as exactly "currently unable to handle the request"
   with the condition expected to be temporary. This is applying an HTTP standard to satisfy
   a canonically stated requirement, not choosing product policy. `Retry-After` is omitted:
   nothing here can honestly predict when a dependency returns, and a wrong hint is worse
   than none.
2. **The body is `{"status": "ready"}` / `{"status": "not_ready"}` and names no dependency.**
   §6 has these endpoints monitored from the public internet, and they are unauthenticated.
   Which dependency is down is diagnosis — useful to an operator, and useful to an attacker
   choosing a moment — so it goes to the structured log the probes already emit, which is
   where OBSERVABILITY.md routes diagnosis anyway.
3. **Ops endpoints are outside the `/v1` API contract**, so a readiness failure does **not**
   use the `ApiError` envelope. API_GUIDELINES.md governs the versioned API at `/v1` and its
   error taxonomy has no code that fits "a dependency is down"; inventing one would widen a
   canonical contract to describe something that is not an API error but an infrastructure
   signal. The precedent already exists: `/health` returns a bare `{"status": "ok"}`.
4. **Each probe is bounded at 2 seconds and both run concurrently.** A readiness probe that
   can hang is worse than one that fails — the orchestrator's own timeout fires instead,
   every probe occupies a worker until it does, and a slow dependency becomes an outage of
   the process checking it. No canonical value exists; 2 s is derived from the in-repo
   precedent (docker-compose's API healthcheck uses `timeout: 5s`) and sits below it so the
   endpoint answers before the caller gives up even with both dependencies degraded.
5. **Redis is readiness-critical**, because §6 names it explicitly. It is not otherwise
   integrated — no application request path uses it — so this probe is the only place its
   availability currently matters. That is a faithful implementation of §6, not Redis
   integration.
6. **`check_readiness` is total.** Any exception escaping a probe is treated as "not ready"
   rather than propagating: a 500 from a readiness endpoint is ambiguous to an orchestrator
   and would render a traceback on an unauthenticated endpoint.

**Consequences:** An operator cannot tell from the HTTP response which dependency is down
and must read the logs. That is the intended trade and the reason the probes log
`readiness.database_unavailable` / `readiness.redis_unavailable` at warning level.

Because Redis is readiness-critical while nothing else uses it, a Redis outage withdraws
the API from the load balancer even though every implemented request path would still work.
That follows §6 as written. If it proves operationally wrong once real traffic exists, §6 is
the document to change — not this implementation.

The docker-compose API healthcheck deliberately still targets `/health`, not
`/health/ready`: compose health gates container restarts, which §6 assigns to liveness.
