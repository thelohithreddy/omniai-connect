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

## ADR-0014 — Better Auth owns a dedicated `identity` schema through its own role

**Status:** Accepted (2026-08-14) · **Context:** M1.3-D

**Context:** ADR-0002 makes Better Auth the human identity provider in the Next.js layer.
It does not say where Better Auth's tables live, which database role reaches them, or who
runs their migrations — and Better Auth creates and migrates its own schema, so those
questions have to be answered before it can be configured at all.

Three placements were available and two are unsafe:

- **`public`** is where every application table lives, and DATABASE_DESIGN.md §1 states the
  only tables there without `workspace_id` are `workspaces` itself and global reference
  data. Better Auth's five tables are global identity infrastructure and have no tenant
  column, so putting them in `public` contradicts the schema's stated invariant and puts
  them under Alembic's autogenerate.
- **`auth`** was the initially authorized choice and had to be revoked on discovery: it is
  already created by migration `0001_tenancy_foundation` for `auth.resolve_api_token`
  (ADR-0008), and that migration's downgrade executes `DROP SCHEMA auth CASCADE`. CI runs
  `alembic downgrade base` on every push, so Better Auth's users, sessions and signing keys
  would have been destroyed by a routine rollback — silently, since nothing asserted they
  were there.

**Decision:**

1. **Better Auth's tables live in a third schema, `identity`,** owned by a dedicated role
   `omniai_identity`. Neither is mentioned by any Alembic migration, and `env.py` sets
   `include_schemas=False`, so autogenerate cannot see the schema and `downgrade base`
   cannot reach it. Rollback safety is structural rather than a property of today's
   migrations happening to leave it alone.
2. **The two roles are granted nothing on each other's data.** `omniai_app` has no `USAGE`
   on `identity` — so a compromised application credential cannot read password hashes,
   sessions, or the JWT signing key — and `omniai_identity` cannot read `workspaces`,
   `members`, or `api_tokens`. The boundary is symmetric because protecting only the
   direction someone thought of is how half a boundary ships.
3. **Better Auth owns its own migrations,** applied by `pnpm --filter web migrate:identity`
   through the library's own `getMigrations`, not `@better-auth/cli`. The CLI's latest
   release (1.4.21) trails the installed library (1.6.28), and a migrator behind the runtime
   can generate a schema the runtime does not expect. The script imports the runtime's own
   config object, so the schema and the code reading it cannot disagree.
4. **The API never reads these tables.** It will authenticate a human by verifying a JWT
   against the JWKS Better Auth publishes (M1.3-B), which is what lets the privilege
   separation in (2) be total rather than aspirational.
5. **`BETTER_AUTH_URL` must be `https://` in production.** Better Auth derives the session
   cookie's `Secure` attribute and `__Secure-` prefix from the URL's scheme, so an `http://`
   value silently issues downgraded cookies. `advanced.useSecureCookies` is deliberately not
   set: overriding the derivation would pin one value across every environment.

**Consequences:** Two migration lifecycles now exist, and a fresh database needs both
(`alembic upgrade head` and `migrate:identity`) — CI runs both. Rotating
`BETTER_AUTH_SECRET` invalidates every stored signing key, because the private key in
`identity.jwks` is encrypted with it; rotation therefore requires clearing `identity.jwks`
and accepting that outstanding JWTs stop verifying.

## ADR-0015 — Human JWT verification: PyJWT, pinned EdDSA, bounded JWKS cache, membership-bootstrap resolution

**Status:** Accepted (2026-08-15) · **Context:** M1.3-B

**Context:** ADR-0002 decides *that* FastAPI verifies the human credential ("FastAPI
validates the signed session/JWT on every request via shared JWKS/secret and maps it to a
Member + Workspace context"), and ADR-0014 point 4 resolves the mechanism to a JWT verified
against the JWKS Better Auth publishes. Neither decides the verification library, the
accepted algorithm, the issuer/audience values, the JWKS cache behavior, or how a verified
subject becomes a workspace-bound context. M1.3-D built the real provider, so several of
those are now **observable facts** rather than open choices; the rest are engineering
decisions recorded here.

**Observed provider contract (recorded, not chosen).** Better Auth 1.6.28 with the default
`jwt()` plugin emits: `alg: EdDSA` (Ed25519), a `kid` header resolving into the JWKS at
`/api/auth/jwks` (`kty: OKP`, `crv: Ed25519`, public parameters only), `iss` and `aud` both
equal to `BETTER_AUTH_URL`, `sub` = the Better Auth user id (the same opaque string
`members.user_id` stores), `iat`/`exp` with a 900-second lifetime, and **no `nbf`**. The
web contract suite pins all of this on the provider side; the verifier pins it on the
consumer side, so drift breaks both ends visibly.

**Decision:**

1. **Library: PyJWT (`pyjwt[crypto]`), not python-jose, joserfc, or authlib.**
   python-jose is effectively unmaintained with open algorithm-confusion CVE history
   (CVE-2024-33663/33664) and is excluded outright. authlib imports an entire OAuth
   framework to verify one token shape. joserfc is sound but young. PyJWT is the narrow,
   ubiquitous choice: EdDSA via the `cryptography` extra, an **explicit `algorithms=[...]`
   allowlist required by its API** (algorithm confusion is structurally unrepresentable —
   the post-CVE-2022-29217 design), typed (`py.typed`), actively maintained. Its sync
   JWKS client is not used; the JWKS cache below is ours, over the already-present httpx.
2. **Algorithm allowlist: `("EdDSA",)`** — exactly what the provider emits. `alg=none`,
   HMAC confusion, and every RSA/EC variant fail the allowlist before any key material is
   touched.
3. **Issuer and audience: `settings.better_auth_url`.** These are the observed claim
   values, already configured (M1.3-D), and asserted by the provider's own contract tests.
   No new authority is invented; both are validated on every token.
4. **Required claims: `exp`, `iat`, `sub`, `iss`, `aud`.** `nbf` is validated when present
   but not required — the provider does not emit it. Leeway 30 s on time-based claims:
   containers and managed platforms are NTP-synced; 30 s absorbs real skew without
   materially extending the 900 s token lifetime.
5. **JWKS resolution: fetch only from configuration, never from the token.** The URL
   derives from `better_auth_url` (`{base}/api/auth/jwks`), overridable via
   `BETTER_AUTH_JWKS_URL` solely because container networking can make the fetch address
   differ from the public issuer string (`http://web:3000` vs `http://localhost:3000`).
   `jku`/`x5u`/embedded keys are never honored — PyJWT does not read them and the resolver
   selects keys exclusively by `kid` from the configured document.
6. **Cache policy: TTL 300 s, single-flight refresh, unknown-`kid` forced refresh behind a
   30 s cooldown, stale-on-error.** 300 s bounds how long a *removed* key keeps verifying
   (key removal is the revocation lever — ADR-0014's secret-rotation consequence). The
   cooldown bounds attacker-driven amplification: unknown `kid`s can force at most one
   fetch per 30 s process-wide. On refresh failure the last-good keys keep serving, with a
   warning — public keys are not secrets and do not expire; the alternative turns any
   control-plane blip into a human-auth outage. A process that has **never** fetched keys
   fails closed. Fetch timeout 2.0 s, the readiness-probe precedent (ADR-0013).
   This fetch is a first-party call to our own control plane — platform infrastructure per
   SECURITY.md §1.1, not tenant egress, so the Execution-Runtime-only rule (Bible §6.3)
   does not apply to it.
7. **Membership bootstrap follows ADR-0008 exactly.** Resolving *which* workspaces a
   verified subject belongs to is the same bootstrap problem as resolving an API token:
   the lookup discovers the workspace, so it cannot run under a policy that already needs
   one. Migration 0004 adds `auth.resolve_member_workspaces(p_user_id text)` — SECURITY
   DEFINER, owned by `omniai_auth`, `search_path` pinned, `EXECUTE` revoked from PUBLIC and
   granted to `omniai_app` alone, backed by a `FOR SELECT TO omniai_auth USING (true)`
   policy on `members` and an `ix_members_user_id` index (a bootstrap lookup cannot lead
   with `workspace_id`, the same exception `api_tokens.token_hash` already embodies).
8. **Workspace resolution: exactly-one-membership resolves; everything else fails closed.**
   The repository is explicit that "which Workspaces does this user belong to" as a *user
   feature* needs its own architectural decision, and no canonical workspace-*selection*
   mechanism (path, header, claim) exists anywhere. So: a verified subject with exactly one
   membership binds to that workspace — the degenerate case where no selection exists to
   perform, derived purely from persisted state, influenceable by nothing in the request.
   Zero memberships or more than one produce the uniform 401. The selection mechanism for
   multi-workspace humans is recorded as an Open Question in PROJECT_STATUS.md; it is a
   public-API-shape decision that belongs to the founder, and nothing here forecloses any
   answer.
9. **One composite resolver, no fallback between planes.** BACKEND_SPEC §3 already defines
   `get_workspace_context` as resolving both credential types. Discrimination is by shape:
   credentials bearing the `omc_` prefix take the machine path, everything else the human
   path, and neither path ever falls through to the other — a failed JWT is never retried
   as an API token, nor the reverse. Machine authentication is byte-for-byte unchanged.
10. **Uniform failure: every human-path validation failure returns the canonical 401 with
    one message, "Invalid or expired credentials."** Malformed token, bad signature, wrong
    issuer/audience, expiry, unknown `kid`, JWKS outage with no cache, no membership, and
    ambiguous membership are indistinguishable to the caller, matching the machine plane's
    single-message precedent. The specific reason goes to structured logs — event names
    only, never token material or claims.
11. **JWT claims confer no authorization.** The verified `sub` is used for exactly one
    thing: the membership lookup. Role comes from the persisted member row read under RLS
    by the existing `resolve_member_role`; permissions come from the existing static
    matrix (ADR-0009). Any other claim in the token — including Better Auth's `email`,
    `name`, `role`-shaped extras a future plugin might add — is ignored by construction.

**Revocation semantics (stated honestly).** A verified JWT is bearer-valid until `exp` —
at most 900 s. Logout deletes the Better Auth session but does not and cannot invalidate
outstanding JWTs, and FastAPI cannot observe logout (ADR-0014: the API never reads
`identity` tables). Rotating `BETTER_AUTH_SECRET` (clearing `identity.jwks`) invalidates
all outstanding tokens within one cache TTL of the next successful refresh. Removing a
Member takes effect at that user's next request — the membership row, not the token, is
what authorizes. Immediate JWT revocation is impossible under this stateless design; if it
is ever required, that is a new ADR (denylist or session-introspection), not a patch.

**Consequences:** Two new runtime dependencies (`pyjwt`, `cryptography`). One new
migration (0004) extending the `auth` schema — reversible, and `identity` remains
untouched by Alembic. Multi-workspace humans cannot authenticate until the selection
decision lands; that is deliberate deny-by-default, not an oversight, and it is the
recorded Open Question.

## ADR-0016 — Human workspace selection: the `X-Workspace-Id` header, verified against membership

**Status:** Accepted (2026-08-15) · **Context:** M1.3-C

**Context:** M1.3-B verified human JWTs into a `WorkspaceContext` but deferred one thing: a
human who belongs to more than one Workspace has no way to say *which* one a request targets.
M1.3-B failed such requests closed and recorded the mechanism as an Open Question, because
no canonical document defines it — confirmed by an exhaustive audit across the Bible,
BACKEND_SPEC, API_GUIDELINES, FRONTEND_SPEC, SYSTEM_ARCHITECTURE, PRD and every ADR: the
machine channel is canonical (the API token *is* the workspace), the human channel was
absent. This ADR closes that gap.

**Decision:**

1. **A human request selects its target Workspace with the `X-Workspace-Id: <uuid>` header.**
   It is the single canonical human workspace-selection mechanism. It is a **selection
   signal, never authority**: the server binds a workspace only after independently proving
   membership.

2. **Resolution (extends the M1.3-B human path; no parallel resolver).** verified JWT → `sub`
   → all of the subject's memberships (`auth.resolve_member_workspaces`) → the header names
   which membership to bind → persisted role (existing `resolve_member_role`, read under RLS
   after binding) → existing RBAC → RLS. `CallerIdentity.kind` stays `"member"`; only
   `WorkspaceContext.workspace_id`, and hence the resolved role and permissions, change with
   the selection.

3. **Exact semantics.**
   - *Zero memberships* → fail closed (uniform 401), header or not; never auto-create or
     auto-select.
   - *One membership, no header* → bind it (the M1.3-B auto-bind, preserved).
   - *One membership, header* → must match that membership, else fail closed.
   - *Many memberships, no header* → fail closed; the header is required, and the server
     never picks first/newest/oldest/previous/arbitrary.
   - *Header names a Workspace the subject is not a member of* (foreign, random, deleted,
     nonexistent) → fail closed, indistinguishable from any other human-auth failure.
   - *Malformed / duplicate / ambiguous header* → fail closed. Duplicate headers are
     rejected explicitly: Starlette's `Headers.get()` silently returns only the *first*
     repeated value, so the resolver reads the full list and denies anything that is not
     exactly one well-formed UUID — a repeated `X-Workspace-Id` never binds the first tenant
     by accident. This is "invalid, not silently reconciled", proven by a test that sends two
     headers on the wire.

4. **Uniform failure.** Every human context-resolution failure returns the one 401
   `HUMAN_AUTH_FAILED`, so a foreign selection is not an existence oracle — "you are not a
   member of workspace X" is indistinguishable from "that JWT is invalid". The reason goes
   to structured logs (reason codes only, never token material or foreign-tenant data).

5. **The header is authority for nothing but *which membership to check*.** Role, permission,
   `member_id`, `user_id`, and `kind` are never read from the request. A `workspace_id` in
   the JWT, the query string, the body, or a cookie remains inert (M1.3-B); activating any
   of them would be a second authorization channel.

6. **Machine authentication is untouched.** A machine token carries its Workspace implicitly;
   `X-Workspace-Id` is ignored on the machine path. The composite resolver still dispatches
   by the `omc_` prefix with no fallthrough.

7. **`GET /v1/workspaces` (my-workspaces).** A human-only listing of the authenticated
   subject's memberships as `{id, role}`, so a client can discover what it may select before
   selecting. Backed by a new bootstrap function `auth.resolve_member_workspace_roles`
   (migration 0005) that reuses the existing `members` RLS exemption — no new grant or policy
   on `workspaces`. Its `role` is for **display only**; authorization always flows through
   bind → `resolve_member_role` → RBAC, never through this listing. It returns only the
   caller's own workspaces; it discloses no other tenant's existence, name, members, or
   metadata. The set is a bounded personal list, returned whole in the standard envelope.

**Alternatives rejected** (each falsified against a released decision during the M1.3-C
discovery audit):

- **URL path** `/v1/workspaces/{id}/members` — contradicts API_GUIDELINES §1 (resources are
  flat, map 1:1, "nesting is shallow"; `/v1/members` is top-level) and would break the
  released M1.3-A routes. A header changes no path.
- **Query parameter** `?workspace_id=` — API_GUIDELINES §4 reserves query params for
  filters/sorts; a filter is not an authorization scope, and M1.3-B rejects unknown query
  params.
- **JWT claim** — ADR-0015 §11 forbids workspace-as-authority from the token; the Better
  Auth `jwt()` plugin emits none.
- **Better Auth session / cookie** — architecturally inaccessible: the API cannot read the
  `identity` schema or resolve the opaque session cookie (ADR-0014).
- **Arbitrary cookie / frontend (Zustand) state** — client state is explicitly "never the
  source of truth" (FRONTEND_SPEC §4); a malicious user edits it freely.

The header is the only option that fits the flat, context-scoped resource design, breaks no
released route, works uniformly across every method, and reuses the M1.3-B verify-don't-trust
chain unchanged.

**Consequences:** One migration (0005), additive, reversible, extending the `auth` schema in
the ADR-0008 pattern; `identity` untouched by Alembic. A frontend workspace switcher will
consume this contract when the dashboard is built — no UI ships in M1.3-C because none exists
yet (FRONTEND_SPEC's switcher is unbuilt). Multi-workspace humans can now authenticate; the
M1.3-B "fail closed for many memberships" becomes "fail closed unless a valid selection is
supplied."

## ADR-0017 — Workspace invitations: targeted, email-bound, hashed single-use token

**Status:** Accepted (2026-08-15) · **Context:** M1.3-F

**Context:** PRD FR-CP-1 (P0) requires "Member invitations with roles". No canonical
document defined the mechanism, and M1.3-A/F discovery found a genuine architectural gap:
an invitation addresses a *person by email* before they are a user, but the API cannot map
an email to a Better Auth subject — it has no access to the `identity` schema (ADR-0014) and
distrusts every JWT claim but `sub` (ADR-0015). The founder ratified the contract this ADR
records; it is not derived, it is decided.

**Decision:**

1. **Targeted email invitation only.** An invitation is created for one email address and
   one workspace. No open join codes, public links, or client-created memberships.

2. **The invitation is a temporary membership-establishment mechanism, never authority.**
   After acceptance the *membership row* is authoritative; the invitation confers nothing.
   The permanent authority chain is unchanged: verified `sub` → `members.user_id` →
   persisted role → centralized RBAC → RLS.

3. **Identity binding — the one narrow, explicitly-authorized exception to ADR-0015.**
   Acceptance requires a verified Better Auth JWT whose **provider-verified** email
   (`email_verified = true`) equals the invitation's `invited_email` (both normalized to
   lower-case). The email claim is used *only* to bind the invitation to the accepting
   identity — never for role, permission, workspace, or member identity. An unverified email
   can never accept, so an attacker who signs up under a victim's address without verifying
   it gains nothing. The resulting `members.user_id` is always the verified `sub`, never the
   email and never a request field.

4. **Token.** 256 bits from `secrets.token_urlsafe(32)` (OS CSPRNG), never derived from
   workspace/email/user/timestamp. Only `SHA-256(token)` is stored (reusing
   `core/security.hash_token`); the raw token exists only during creation, delivery, and
   acceptance processing, and is never logged or persisted. Resolution is by hash, in
   constant work, through a SECURITY DEFINER bootstrap function (below).

5. **7-day expiry, server-enforced; single-use; atomic.** Acceptance is one transaction:
   resolve the token pre-RLS, bind the invitation's workspace, create the membership, and
   consume the invitation (`status → accepted`) guarded by `WHERE status = 'pending'`. Two
   concurrent acceptances yield exactly one membership and one consumption — the guarded
   `UPDATE` and the `members` unique `(workspace_id, user_id)` are the DB-level arbiters, not
   an application lock. Any failure rolls the whole transaction back.

6. **Bootstrap resolution.** `auth.resolve_invitation(p_token_hash)` (migration 0006) is the
   SECURITY DEFINER twin of `auth.resolve_api_token`: an accepting user is not yet a member
   of the workspace, so the token lookup that *discovers* the workspace cannot run under a
   policy that needs one. Owned by `omniai_auth`, `search_path` pinned, EXECUTE to
   `omniai_app` only. Everything after the lookup runs under the bound workspace's RLS.

7. **Storage.** A tenant-owned `invitations` table (`workspace_id NOT NULL`, RLS
   ENABLE+FORCE, tenant policy), with `invited_email`, `role` (CHECK against the canonical
   domain), `invited_by` (composite intra-tenant FK to `members`, the M1.3 pattern),
   `token_hash` (unique), `status` (`pending|accepted|cancelled`), `expires_at`,
   `created_at`, `accepted_at`, `cancelled_at`. At most **one `pending` invitation per
   `(workspace_id, lower(invited_email))`** (partial unique index), so a fresh invite never
   lets a stale one grant a different role.

8. **Authorization.** Creating, listing, and cancelling invitations require
   `members:manage` (owner/admin) with the workspace from `X-Workspace-Id` — the existing
   centralized RBAC, no new permission and no endpoint-local role check. The invitation
   `role` is server-persisted at creation and the recipient can never see or change it. Role
   validity is checked against the canonical domain; **which** roles an inviter may assign
   is the same role-transition open question M1.3-A left to SECURITY.md §4.1 (an admin may
   already promote to owner), deliberately not narrowed here.

9. **Already a member → reject (409), do not consume.** The existing membership stays
   authoritative; the invitation is neither re-created nor role-changed.

10. **Delivery via Resend, a first-party control-plane operation.** The invitation email is
    platform mail sent by the API, not tenant egress through the Execution Runtime — the
    same class of first-party call as the JWKS fetch (ADR-0015 §6). The Resend key, the raw
    token, and the invite URL never appear in logs. Email verification is enabled on Better
    Auth so `email_verified` is a real, achievable signal; sign-in is not blocked by it, so
    existing flows are unchanged.

11. **No enumeration oracle.** Bad token, expired, cancelled, consumed, foreign, and
    wrong-user acceptances all fail with one uniform response; the create/list/cancel
    surfaces disclose only the caller's own workspace, never another tenant's invitations,
    emails, inviters, or roles.

**Consequences:** One migration (0006), additive and reversible; `identity` untouched by
Alembic. The verifier gains an identity-returning path (`resolve_human_subject` still
returns only `sub`; a sibling returns `sub + email + email_verified` used solely by
acceptance). No frontend UI ships (the dashboard is unbuilt); the accept URL targets a web
route the dashboard will implement.

---

## ADR-0018 — Human session security boundary and deferred lifecycle decisions

**Status:** Accepted (2026-08-15) · **Context:** M1.3-G

**Context:** M1.3-A…F released the human-auth architecture (Better Auth → EdDSA JWT/JWKS →
`X-Workspace-Id` → membership → persisted role → RBAC → RLS) and workspace invitations.
M1.3-G is *lifecycle hardening around that architecture*, not a redesign. Discovery (7-agent
static map + a live-stack probe of the running Better Auth and API) confirmed the core is
sound but that the **session/JWT revocation boundary was documented in prose (ADR-0015) yet
unpinned by tests**, that the credential-header parsing was asymmetric with the ratified
duplicate-header rule (ADR-0016 §3), and that a large set of lifecycle concerns are genuinely
**undefined and depend on a production deployment topology that is not yet decided**. The
founder ratified the scope below rather than have any undefined security semantic invented.

**Decision:**

1. **The revocation boundary is stateless and bounded, and is now a tested invariant.**
   Sign-out deletes the Better Auth session row and clears the session cookies; an
   **already-issued JWT remains a valid bearer credential on the API until its `exp`
   (900 s / 15 min)**, because the API verifies signatures and pinned claims against JWKS and
   deliberately holds **no session state** (it cannot even read the `identity` schema, ADR-0014).
   There is **no stateful JWT revocation**. Empirically verified and pinned by tests:
   `test_provider_logout_does_not_invalidate_an_outstanding_jwt` (JWT survives to exp),
   `test_logout_kills_the_session_so_no_new_jwt_can_be_minted` (session dead → no new JWTs),
   `test_the_issued_jwt_lifetime_is_the_documented_bounded_window` (== 900 s). The short TTL is
   the mitigation; immediate per-workspace lockout is **Member removal** (next-request effect,
   already tested). This ratifies ADR-0015's stated intent; it does **not** add a denylist.

2. **Break-glass revocation lever.** The only way to invalidate *all* outstanding JWTs before
   their exp is to remove the signing key from `identity.jwks` (rotating `BETTER_AUTH_SECRET`
   alone breaks *signing*, not verification); propagation is bounded by the 300 s JWKS TTL.
   This is an operator runbook step, documented in SECURITY.md, not an application feature.

3. **A duplicate `Authorization` header is rejected, fail-closed.** `extract_bearer_token`
   now reads the full header list and refuses anything that is not exactly one value — the
   identical treatment ADR-0016 §3 already mandates for `X-Workspace-Id`, extended to the
   credential header so a smuggled second `Bearer` can never be silently resolved to the
   first. This applies an existing ratified invariant; it introduces no new security semantic.

4. **The API is `Authorization: Bearer`-only.** It never reads the session cookie, so the
   browser credential is inert against it and the machine/human planes cannot be confused
   (reaffirming ADR-0002/0015; pinned by `test_a_session_cookie_alone_does_not_authenticate_the_api`).

5. **Session fixation resistance is delegated to Better Auth and pinned.** No cookie is set
   before authentication and each authentication mints a fresh session token
   (`test_each_login_mints_a_fresh_session_token`).

**Deferred by ratification (explicitly undecided — no invented defaults; each needs its own
decision/ADR before it ships):**

- **Deployment origin topology** — undecided. Until it is, the API stays server-to-server with
  **no CORS** (fail-safe: browsers cannot cross-origin-read a Bearer API), and no browser-direct
  cross-origin call is supported. This one decision gates CORS, Better Auth `trustedOrigins`,
  cookie `SameSite`/`Domain`, and security-header ownership.
- **Immediate JWT revocation (denylist / session-introspection)** — not built; the bounded
  15-min replay is accepted (decision 1). Revisit if the GA threat model requires sub-exp lockout.
- **Rate limiting / abuse controls** — deferred to the Cloudflare WAF (SECURITY.md §1.2) plus
  Better Auth's production limiter; a shared-store (Redis) limiter is tracked as tech debt. No
  parallel in-app mechanism is introduced (per the M1.3-G scope).
- **Security response headers (HSTS/CSP/X-Frame-Options/etc.)** — ownership (edge vs app)
  undecided; HSTS is an edge/TLS concern and CSP needs the (unbuilt) dashboard.
- **Session lifetime policy** — the Better Auth default (7-day rolling) stands; an absolute cap
  / idle timeout is a future UX+security decision.
- **Account-lifecycle features** — self-serve password reset, account disable/delete, social
  OAuth (PRD FR-CP-1, a later milestone), and a concurrent-session cap / "sign out everywhere"
  are unbuilt and out of this module.

**Consequences:** No migration and no schema change (`alembic check` clean). One production-code
change (`extract_bearer_token`, decision 3). New tests lock the boundary, the duplicate-header
rule, the cookie-is-not-a-credential rule, session rotation, and the non-string-`kid` no-crash
property. This ADR is the single reference for "what the human session security model actually
guarantees" and for the deferred decisions; SECURITY.md §4.8 mirrors it operationally.

---

## ADR-0019 — Connectors domain and the `connectors:manage` permission

**Status:** Accepted (2026-08-15) · **Context:** M1.4-A (Connector Engine v1, first slice)

**Context:** ROADMAP §M1 requires a Connector Engine (OpenAPI/Swagger ingestion → canonical
Tool Schema per ADR-0003; manual REST definition; per-Tool enable/disable). By strict
dependency ordering everything downstream — Connections, Credentials, Tool Calls, the
Execution Runtime, the audit log — needs Connectors and their Tools to exist first. The
founder ratified M1.4-A as the **smallest safe first slice**: the tenant-owned `connectors`
data model plus manual CRUD, with OpenAPI/Swagger **ingestion deferred** (it needs a Celery
worker service and R2 object storage, neither yet provisioned). This ADR records the domain,
its permission, and its boundary; it does not reopen ADR-0003/0004/0009.

**Decision:**

1. **A `connectors` domain (BACKEND_SPEC §1), tenant-owned.** Migration 0007 creates the
   canonical `connectors` table (DATABASE_DESIGN §3) with `workspace_id NOT NULL`, RLS
   `ENABLE`+`FORCE`, and the `tenant_isolation` policy — identical to every other tenant
   table. **No SECURITY DEFINER function**: unlike `api_tokens`/`invitations` (discovered
   pre-RLS from a token), a Connector is always accessed within an already-bound workspace,
   so no bootstrap resolver exists to widen.

2. **`connectors:manage` → owner/admin (founder-ratified).** A new `Permission` transcribed
   into SECURITY.md §4.1 and `authz.py` in the same change (ADR-0009), granted to owner and
   admin only (member/viewer denied), mirroring `connections:manage`. All four endpoints
   (`POST`/`GET`/`GET {id}`/`DELETE /v1/connectors`) are gated by it through the existing
   centralized `require_permission`; no router-local authorization.

3. **Server-established fields; the client is never authoritative.** `source_type` is fixed
   to `manual` by the service (a client cannot mint a Connector that falsely claims OpenAPI
   ingestion), `status` starts at `draft`, `workspace_id` comes from the bound context, and
   the request schema is `extra="forbid"`. `auth_config` holds auth *requirements* only —
   never secret values (CONNECTOR_ENGINE.md §8); secrets live in a Connection's Credential.

4. **`base_url` is SSRF-linted before storage (CONNECTOR_SPECIFICATION §11, SECURITY §6).**
   https only; no embedded credentials; no localhost/`.local`/private/loopback/link-local/
   reserved/metadata hosts. The lint lives in the service so non-HTTP callers (MCP, Celery)
   are guarded identically. Hostname→IP resolution is deliberately NOT done here (DNS
   rebinding is an egress-time concern the Execution Runtime owns); literal private addresses
   and obvious local hostnames are refused, which is exactly what §11 requires of a declared
   URL.

5. **Soft delete; slug unique per live workspace.** Deletion sets `deleted_at` (retained for
   audit, DATABASE_DESIGN §3). A partial unique index on `(workspace_id, slug) WHERE
   deleted_at IS NULL` makes at most one *live* connector per slug and frees the slug on
   delete. A foreign or soft-deleted id is a uniform 404 (no cross-tenant existence oracle).

6. **Deferred to later slices (not invented here):** OpenAPI/Swagger ingestion (`source_url`,
   the async importer, `connector_versions`, `tools`, the `current_version_id` FK — a bare
   nullable column for now, P-43), per-Tool enable/disable, and connection/credential wiring.
   Ingestion is blocked on provisioning a Celery worker service and R2 object storage.

**Consequences:** One additive, reversible migration (0007); `identity` untouched. One new
permission (7 total). No new identity, tenant-authority, or authorization mechanism. The
connectors-enforcement mutation audit (A01–A08) left zero survivors.

---

## ADR-0020 — Guarded egress fetcher for connector-spec ingestion (M1.4-B0)

**Status:** Accepted (2026-08-15) · **Context:** M1.4-B0 (ingestion infrastructure + security
foundation)

**Context:** Bible §6.3 / SECURITY.md §6 make the Execution Runtime the *only* egress for
**tenant** traffic, concentrating SSRF defense in one place. Connector-spec ingestion
(CONNECTOR_SPECIFICATION.md §18) introduces a **second, distinct egress class**: a Celery
worker fetches an operator-supplied — therefore attacker-influenced — spec URL (and its
external `$ref`s) *before any Connection or Credential exists*, so the runtime's
per-Connection egress allowlist cannot govern it. This is the one reconciliation the M1.4-B
discovery flagged. The founder ratified the infra-first (Option A) path; this ADR records the
guarded fetcher that is built and proven **ahead of** any importer consuming it.

**Decision:**

1. **Ingestion spec-fetch is egress-class, worker-only, and owned by one guarded fetcher**
   (`app/core/net.py`). Importers never perform egress themselves; they will receive the
   fetched bytes. This is the *second* sanctioned egress alongside the runtime, not a
   loophole in "runtime is the only egress" — it is a separate class with its own, equally
   strict, guard.

2. **DNS is validated and the validated IP is the one dialed (TOCTOU-closed).** A custom
   `httpcore` network backend resolves the host, validates **every** returned A/AAAA record,
   and connects to a *validated* IP; TLS still verifies the original hostname. A naive
   `resolve → validate → get(host)` re-resolves at connect time and is a rebinding TOCTOU —
   this is not that.

3. **The blocklist covers the forms Python 3.11's stdlib misses.** Loopback, unspecified,
   link-local (incl. 169.254.169.254 metadata), private, multicast, and reserved are rejected
   across IPv4 and IPv6, and **IPv4-mapped (`::ffff:`), NAT64 (`64:ff9b::/96`), and 6to4
   (`2002::/16`)** IPv6 forms are unwrapped to their embedded IPv4 and re-checked —
   `ipaddress.is_private` does not unwrap NAT64/6to4.

4. **`https` only; no embedded credentials; `trust_env=False`.** An `http` URL (incl. an
   `https→http` redirect downgrade) is refused; a `user:pass@host` URL is refused; the client
   never honors an `HTTP(S)_PROXY` (a proxy would do its own DNS/connect and bypass the guard).

5. **Redirects are bounded (≤5) and re-validated per hop** (scheme + credentials + the backend
   re-resolves/re-validates the new host).

6. **Response size is capped on decompressed bytes (10 MB) with a streaming early-abort**, and
   connect/read/total timeouts (5s/15s/30s) bound a hostile server. Every failure is
   fail-closed (`SSRFError` or timeout), never a partial/oversized body.

**Consequences:** No migration, no new dependency (httpx/httpcore already present). No importer,
normalization, `connector_versions`, or `tools` — those remain deferred. Proven by a 44-case
adversarial matrix (IP validation incl. NAT64/6to4/mapped, rebinding fail-closed, scheme/creds,
proxy isolation, redirect re-validation/downgrade/bounds, decompressed size cap). The remaining
M1.4-B0 foundations (Celery worker service + tenant-context, internal event bus, R2 client +
tenant-key isolation, local/CI object store) are separate slices under the same infra-first plan.

---

## ADR-0021 — Celery worker execution foundation (M1.4-B0.2)

**Status:** Accepted (2026-08-15) · **Context:** M1.4-B0.2 (Celery + worker execution
foundation), the second slice of the ingestion infrastructure. Implements the Celery substrate
ADR-0007 mandated; deliberately does NOT implement ingestion, tenant-context binding (B0.3), the
event bus (B0.4), or R2 (B0.5).

**Decision:**

1. **A dedicated Celery app** (`app/workers/celery_app.py`) with every security-sensitive
   setting explicit — Celery's defaults are not trusted:
   - **JSON only.** `task_serializer`/`result_serializer` = json, `accept_content` = ['json'].
     Pickle is remote code execution on the broker and can never be accepted.
   - **No result backend.** Correctness never depends on a persisted return value.
   - **One declared queue, `ingestion`, no auto-creation** (`task_create_missing_queues=False`)
     — a task cannot conjure or route itself to an arbitrary queue.
   - **At-least-once, late ack** (`task_acks_late` + `task_reject_on_worker_lost`): a crashed
     worker's job is redelivered, not lost — so tasks must be idempotent (owned from B0.3).
   - **Bounded execution:** hard/soft time limits (300/270s) and `worker_prefetch_multiplier=1`
     (one long job per slot, no hoarding).
   - **Never eager in production** (`task_always_eager=False`; eager is a test-only override).
   - **Retry foundation:** bounded (`max_retries=5`), exponential (`retry_backoff`, cap 60s),
     jittered — applied per task, not globally (a global would retry non-idempotent work).

2. **Redis broker via an explicit `CELERY_BROKER_URL`** (falls back to `redis_url` — the same
   canonical Redis, no second server). A dedicated logical DB for the broker is left to that
   setting in production. No result backend, so no persistent-result Redis dependency.

3. **The worker is not an HTTP surface and holds no authority.** It runs `celery worker`
   (not uvicorn), exposes no port, consumes only `ingestion`, and — critically — its
   environment is hand-scoped (NOT `env_file: .env`): it never inherits `BETTER_AUTH_SECRET`,
   `R2_*`, Stripe/Resend, or any frontend/API secret. Demo tasks (`ping`, `retry_probe`,
   `always_fails`) exist only to prove registration/routing/serialization/execution/retry —
   they touch no connector, DB, R2, or event bus, and no task payload is ever trusted for
   identity, role, or permission. **Binding a WorkspaceContext / GUC to a task is B0.3.**

4. **Deployment:** one image, a different command. The worker reuses the API image and runs the
   `celery worker` command (local compose service; the same prod image on Railway).

**Consequences:** No migration; no new dependency (celery/kombu already present). Broker-loss is
fail-closed (bounded reconnect retries, no crash-loop; verified). Proven by 15 config/security
tests, a real broker+worker execution+bounded-retry test (`start_worker`, not eager), and a
12-mutation B0.2 audit with zero survivors. The tenant-context, event-bus, and R2 foundations
remain separate slices.

## ADR-0022 — Worker tenant execution boundary (M1.4-B0.3)

**Status:** Accepted (2026-08-15) · **Context:** M1.4-B0.3, the third ingestion-infrastructure
slice. B0.2 (ADR-0021) established the Celery substrate and deliberately deferred tenant binding;
this ADR is that binding. A background task has no HTTP request, no JWT, and no membership lookup,
yet it still touches tenant tables — so it needs a way to establish *which* tenant it acts for
that does **not** reintroduce the payload as an authority. The governing invariant (SECURITY.md,
ADR-0004 RLS, ADR-0014 identity severance): **a worker task payload must never become
authorization** — a `workspace_id` selects **WHERE** (the tenant), never **WHO / ROLE /
PERMISSION / AUTHORITY**.

**Decision:**

1. **One boundary, reusing the request-path machinery** (`app/workers/context.py`,
   `worker_tenant_uow`). It reuses the *existing* `UnitOfWork` and `bind_workspace`
   (`SET LOCAL app.workspace_id` via `set_config(..., true)`) — **no second GUC, no second
   transaction system, no new migration, no new SECURITY DEFINER function, no new DB role**. The
   persisted database + RLS remain the sole authority; the worker runs as `omniai_app`
   (non-superuser, **non-BYPASSRLS**), exactly like the request path.

2. **Fail-closed context validation.** `validate_workspace_id` accepts *only* one canonical UUID
   string — `None`, `""`, whitespace, a non-string, or a malformed value raises
   `WorkerContextError` **before any DB access**. There is **no** default / first-workspace /
   system tenant to fall back to; a task without a valid tenant never opens a transaction. The
   error never carries the offending value into a message a caller might log.

3. **A load-bearing order:** *validate → BEGIN → SET LOCAL → read the binding back → yield*.
   Nothing tenant-scoped runs before the GUC is bound; a binding that does not read back is a
   fail-closed error, never a silent unbound execution. The transaction's end clears the GUC —
   **COMMIT** on success (a task's tenant writes persist), **ROLLBACK** on exception (nothing
   leaks). Because binding is transaction-local (`SET LOCAL`, not `SET`/session-global), it
   **cannot survive to the next task** on a reused pooled connection, and a rollback/retry cannot
   carry the previous tenant forward.

4. **The one worker-specific detail: a `NullPool` engine.** A prefork worker runs each task on a
   *fresh* event loop (`asyncio.run`), and an asyncpg connection is bound to the loop that opened
   it — so a pooled connection cannot cross tasks. `NullPool` opens a fresh connection per checkout
   on the current loop: fork-safe and loop-safe. Transaction-local binding still guarantees
   isolation independently of pooling.

5. **The payload is a selector, never an authority.** The boundary reads *only* `workspace_id`.
   There is no code path that reads a `role`, `permission`, `member_id`, or `kind` from a task
   payload; supplying them confers nothing. Identity/role decisions stay where ADR-0014 put them.

**Consequences:** No migration; no new dependency; no new SECURITY DEFINER function; no new DB
role; RLS ENABLE+FORCE and `omniai_app`'s non-superuser/non-BYPASSRLS status are unchanged
(catalog-verified). Proven by 18 real-Postgres worker-context tests (fail-closed validation;
RLS isolation A/B; RLS-*independent* binding-correctness; `SET LOCAL` non-leak across a reused
connection via a `pool_size=1` engine; rollback cleanup; commit-on-success; A×8/B×8 concurrency),
a **real Redis → worker → RLS** tenant task (`start_worker`, not eager), a deployed-compose-worker
end-to-end run, and a B0.3 mutation audit (6 constructible mutations killed; the lone survivor is
inert redundant defense-in-depth — the fail-closed read-back verify, kept as cheap insurance).
The event bus (B0.4) and R2 (B0.5) remain separate slices; the ingestion pipeline itself is M1.4-B1.

## ADR-0023 — Internal event bus: in-process, post-commit, buffered on the UoW (M1.4-B0.4)

**Status:** Accepted (2026-08-15) · **Context:** M1.4-B0.4, the fourth ingestion-infrastructure
slice. BACKEND_SPEC §4 (governed by ADR-0001) specifies an internal event bus that is
"in-process now, broker later (Redis Streams is the planned swap)"; this ADR builds the contract
and the in-process transport only. It publishes no domain event (`connector.ingested` and friends
are M1.4-B1), adds no table, and is deliberately **not** an authorization mechanism, a tenant
selector, a second transaction system, a job queue, or a durable-delivery guarantee.

**Decision:**

1. **A frozen Pydantic `Event` envelope** (`app/core/events.py`) carrying `event_id` (a
   server-generated UUIDv7 from `core/ids.py`), `event_type`, `version`, `workspace_id`,
   `occurred_at`, and a JSON-safe `payload` — the canon fields (BACKEND_SPEC §4) plus an explicit
   `version`. Immutability and validation are structural, not conventional:
   - `frozen=True` makes the envelope an immutable fact; `extra="forbid"` is a **security
     control** — a caller cannot smuggle a `role`, `member_id`, `token`, or any authority field
     into the envelope. The envelope carries WHERE (`workspace_id`) and WHAT (`event_type` +
     `payload`); WHO, when a domain needs it, rides in the typed payload as a non-authoritative
     reference, never as authority (canon lists no actor field; ADR-0022).
   - `event_type` must be a dotted namespace (`connector.ingested`); `version >= 1` (explicit,
     starting at 1; same type + higher version = contract evolution — the smallest mechanism, an
     integer, no schema registry, compatibility owned by the subscriber); `occurred_at` must be
     timezone-aware and is normalised to UTC (a naive wall-clock is refused); `payload` is typed
     `JsonValue`, so an ORM entity, a connection, or any arbitrary Python object is rejected. No
     payload **byte** bound is imposed: in B0.4 an event is authored only by trusted server code
     (there is no untrusted → payload path), so a size cap is not a security-critical bound to
     derive; a future module that accepts untrusted event input owns that limit.

2. **`bus.publish(event)` takes no transaction handle** — deliberately, so the future broker swap
   is invisible ("callers never notice the swap", BACKEND_SPEC §4). In-process, the ambient
   transaction is found through a **task-scoped `ContextVar`** (the same mechanism `core/logging.py`
   uses for `request_id`/`workspace_id`; it follows `await` and never bleeds between concurrent
   requests). `publish` buffers the event on that transaction's `UnitOfWork`; when the bus becomes
   a broker, the same call enqueues to Redis Streams instead.

3. **Handlers run after COMMIT, buffered on the UoW** (BACKEND_SPEC §4). The `UnitOfWork`
   (`core/db.py`) gains the buffer and dispatches it *after* its `session.begin()` block commits;
   an exception (handler error or a failed commit) propagates out of the block and skips dispatch,
   so **a rolled-back transaction emits nothing**. The bus never opens, commits, or rolls back a
   transaction — the UoW owns the lifecycle. Wired into both origins: the request path (`get_uow`)
   and the worker path (`worker_tenant_uow`).

4. **Tenant-match is fail-closed.** `UnitOfWork.buffer_event` refuses an event whose `workspace_id`
   is not the transaction's bound tenant (and refuses to publish before a workspace is bound) —
   event metadata can never become a tenant selector (ADR-0022), defence in depth over RLS.

5. **Explicit registration; type-scoped, isolated, bounded dispatch.** `subscribe(event_type,
   handler)` registers at startup (no filesystem scan, no import side effects); dispatch delivers
   only to a type's handlers, runs sync or async handlers, **isolates** a handler failure (logged
   with the non-secret envelope identifiers — never the payload — and never failing the
   already-committed publisher), and bounds nested re-dispatch with a depth guard.

6. **Explicit, honest semantics.** In-process delivery is **best-effort at-most-once** (a crash
   between COMMIT and dispatch loses the event); **at-least-once is a property of the *future*
   broker**, so handlers must be idempotent and this module claims **no exactly-once** guarantee
   and adds no dedup table. The bus is **not Celery** — heavy work is a Celery task a handler
   enqueues (ADR-0007), never the bus; customer-facing events use `webhooks_outbox`, not this bus.

**Consequences:** No migration; no new table; no new dependency (Pydantic already present); no new
SECURITY DEFINER function; no new DB privilege; RLS ENABLE+FORCE and `omniai_app`'s
non-superuser/non-BYPASSRLS status unchanged (catalog-verified). Proven by 54 tests — 48 unit
(envelope validation, immutability, JSON-safe payload, forbidden authority fields, type-scoped
dispatch, handler isolation, bounded reentrancy, fail-closed publish, secret-safe logging, and the
UoW buffer/tenant-match/drain) and 6 real-Postgres integration (buffered-until-commit,
rollback-emits-nothing, fail-closed tenant-match, A/B isolation, A×8/B×8/C×8 concurrency, and the
request-path emission) — plus a B0.4 mutation audit of 23 constructible mutations, **all killed, 0
survivors**, and a live in-process publish→commit→dispatch run. R2 (B0.5) remains a separate slice;
the ingestion pipeline that first publishes `connector.ingested` is M1.4-B1.

## ADR-0024 — Object storage: one S3-compatible boundary, tenant-isolated by object key (M1.4-B0.5)

**Status:** Accepted (2026-08-15) · **Context:** M1.4-B0.5, the fifth ingestion-infrastructure
slice. Canon (SYSTEM_ARCHITECTURE, CONNECTOR_ENGINE) stores spec files, export artifacts, and
oversized/binary runtime payloads in Cloudflare R2, referenced by a server-constructed object key
(`raw_spec_ref`). This ADR builds only the storage client and its **tenant-key isolation** — the
named B0.5 deliverable — and nothing else: no importer, no `raw_spec_ref` persistence (that column
lands with ingestion in B1), no DB row, no public route, no presigned URLs.

**Decision:**

1. **One `ObjectStore` abstraction over the S3 API** (`app/core/object_store.py`). Production is
   Cloudflare R2; local/CI is MinIO; the two differ only by `R2_ENDPOINT`. `aioboto3` (async, so
   the storage path is non-blocking like the rest of the worker/request path) is the only S3 SDK
   and is **confined to this module** — no application code imports boto3/botocore, and the untyped
   SDK surface never escapes the module's fully-typed public API. The store exposes exactly
   `put`/`get`/`head`/`delete` (+ a dev/CI-only `ensure_bucket`); no list, no versioning, no
   presigned URLs, no multipart — none are canon in B0.5.

2. **A single bucket is infrastructure; tenant isolation is the object key.** Every key is
   `ws/<workspace_id>/<relative_path>`, produced only by `TenantObjectKey.for_workspace` from a
   **trusted** workspace UUID (a resolved `WorkspaceContext` or worker tenant context — never a
   request body, payload, JWT claim, or task field) and an **explicit allowlist grammar** (not
   pathlib): each `/`-separated segment must match `[A-Za-z0-9._-]+` and never be `.`/`..`. That
   grammar rejects traversal, backslashes, encoded traversal (`%2e` has `%`), null bytes, control
   characters, whitespace, unicode, absolute/UNC paths, and empty segments — by construction, so a
   hostile path is refused before any provider call. `ObjectStore` operations take a
   `TenantObjectKey`, never a raw string, so a caller cannot present an unvalidated or cross-tenant
   key; even a relative path shaped like `ws/<B>/x` nests under the caller's own prefix and can
   never address tenant B. The provider is never the authorization system, and R2/MinIO
   credentials are never tenant credentials.

3. **Config is validated and fails closed.** `resolve_object_store_config` requires
   endpoint/bucket/access-key/secret and, in production, an `https://` endpoint — there is **no
   silent MinIO fallback in production**. Errors name the missing setting, never its value; the
   secret is a pydantic `SecretStr` unwrapped only at the SDK call, so a stray repr/log cannot leak
   it. New settings `R2_ENDPOINT`/`R2_REGION` were added (canon named neither).

4. **Errors are translated to a safe hierarchy** (`ObjectKeyError`/`ObjectNotFoundError`/
   `StorageConfigError`/`StorageProviderError`): a 404/NoSuchKey becomes not-found; anything else
   surfaces only the operation and the S3 error *code* — never the raw SDK string (which can embed
   the endpoint/bucket/signed request), never a credential. Storage retries are botocore's bounded
   `standard` mode (idempotent ops only); the store is never a second scheduler — Celery owns task
   retries (ADR-0021).

5. **Client lifecycle.** A client is opened per operation via `async with`, which both guarantees
   sockets are closed (no leak) and is loop-safe for the prefork ingestion worker (fresh
   `asyncio.run` loop per task, ADR-0022) — the same reasoning as B0.3's per-task DB connection.
   Ingestion is not a hot path; a lifespan-shared client is a future optimisation.

6. **Credential scoping.** Storage credentials reach only the services that need them: the API and
   the ingestion **worker** (which writes fetched specs to R2, CONNECTOR_SPECIFICATION §18). In
   compose these are dev-only MinIO credentials; MinIO itself receives no R2 secret. (The `web`
   service inherits the empty `R2_*` placeholders from the shared dev `.env` via its pre-existing
   broad `env_file`; those values are empty, Next.js does not read them, and production web on
   Vercel carries no R2 secret — tightening `web`'s env is a separate hardening task, out of the
   B0.5 storage-boundary scope.)

**Consequences:** One new dependency (`aioboto3`, pure-Python; mypy-scoped like celery/kombu). No
migration; no table; no SECURITY DEFINER; no new RLS policy or DB privilege (RLS/catalog unchanged,
migration head still 0007). No public bucket, no anonymous access, no presigned URLs, no public
file route (all deferred/absent). Proven by 72 tests — an adversarial `TenantObjectKey` grammar
matrix (traversal/encoding/absolute/UNC/null/control/prefix-collision), fail-closed config
resolution (TLS-in-prod, no secret leak), and **real-MinIO** integration (PUT/GET/HEAD/DELETE,
missing-object, cross-tenant isolation, A×8/B×8/C×8 concurrency, per-op client lifecycle,
unreachable-endpoint and wrong-credential failure without leakage) — plus a B0.5 mutation audit of
17 constructible mutations (16 killed; the lone survivor is inert, botocore selecting path-style for
a bare-host MinIO endpoint regardless), and a live cross-tenant isolation run. The importer that
first writes `raw_spec_ref` is M1.4-B1.

## ADR-0025 — Connector ingestion: OpenAPI 3.0 → canonical Tool Schema (M1.4-B1.1)

**Status:** Accepted (2026-08-16) · **Context:** M1.4-B1, the first real connector-ingestion
pipeline (ROADMAP §M1, ADR-0003). B1 as canonically specified is an epic (OpenAPI 3.0 **and** 3.1,
Swagger 2 → OpenAPI 3 conversion, remote `$ref` resolution, `diff_summary`/promotion, the `tools`
denormalization table, scheduled re-sync), and its endpoint + event-payload contracts are not
written in canon (§3 forbids inventing them). The founder ratified a bounded **first slice, B1.1**,
and the two undefined contracts below. This ADR records B1.1; the rest are explicit follow-on
slices (B1.2 upload + remote `$ref`; B1.3 Swagger→3; B1.4 diff/promotion + `tools`).

**Decision (B1.1 scope):**

1. **`connector_versions` (migration 0008).** The immutable ingested snapshot (DATABASE_DESIGN §5):
   `version` (monotonic int per connector), `spec_hash`, `raw_spec_ref` (R2 key), `normalized_schema`
   (jsonb Tool Schema set), `diff_summary` (jsonb, NULL until B1.4). RLS `ENABLE`+`FORCE` +
   `tenant_isolation`; grants are **INSERT/SELECT only** (immutability enforced at the privilege
   level — no UPDATE/DELETE). Composite intra-tenant FKs both ways (`(workspace_id, connector_id) →
   connectors`, and the previously-deferred `connectors.current_version_id → connector_versions`,
   P-43, `use_alter` for the cycle). No `tools` table (B1.4).

2. **A hostile-input OpenAPI 3.0 parser + deterministic normalizer** (`domains/connectors/
   openapi.py`), framework-free and with **no network capability** (it imports no HTTP library and
   the `$ref` resolver is synchronous). Safety: JSON or YAML via a hardened `SafeLoader` that
   refuses anchors/aliases (billion-laughs) and all `!!python/...` construction (no code execution);
   bounded raw size (10 MB), structural depth (64), `$ref` depth (32) and count (10 000); non-finite
   numbers refused; **local `$ref` only** (remote refs refused — and unfetchable regardless);
   cycles broken. Normalization maps one Tool per `(path, method)` to the canonical Tool Schema
   (CONNECTOR_SPECIFICATION §2): `name = {connector_slug}_{operation_slug}` (operationId → generated,
   deterministic `_N` suffixes), params+requestBody merged into `input_schema` with `endpoint.binding`,
   `security → auth`, `servers → base_url`, safety `annotations`. `spec_hash` = SHA-256 over the
   canonical JSON (sorted keys, no whitespace) of the ordered set — **version-independent**, so it
   dedupes no-op re-syncs (§3).

3. **The pipeline composes the proven foundation** (`domains/connectors/ingestion.py`): guarded
   fetch (B0.1, the only egress) → normalize → dedup → store raw (B0.5, key
   `ws/<workspace_id>/connectors/<id>/specs/v<n>.json`) → persist `connector_versions` + advance
   `connectors.current_version_id` and status `ingesting → active` → post-commit `connector.ingested`
   (B0.4), all under the worker tenant context (B0.3). Same `spec_hash` as the current version →
   no-op (no empty version); different → append version N+1. A hard `IngestionError` (safe
   `reason_code`, never a stack trace/URL/secret) rolls back and, in a fresh transaction, moves the
   connector to `failed` with a `connector.ingestion_failed` event. Ordering is honest: the spec is
   fetched before the transaction; the object is written before COMMIT (an orphan on rollback is
   documented, keyed by the not-yet-consumed version number so a retry overwrites it); no
   distributed transaction is claimed.

4. **Async endpoint** `POST /v1/connectors/{connector_id}/versions` (the ratified contract), gated
   by the existing `connectors:manage` (owner/admin) — no new authorization. It transitions the
   connector to `ingesting` and **buffers a post-commit trigger** that enqueues the Celery task, so
   the worker never reads the connector before the transition is durable and a rolled-back request
   enqueues nothing. Returns 202 with the connector in `ingesting`; the terminal state is the
   worker's. The `workspace_id` is the authenticated context — `source_url` names *where* to fetch,
   never *which tenant*.

5. **Ratified contracts (were undefined in canon).** `connector.ingested` payload =
   `{connector_id, connector_version, spec_hash}` (+ envelope); `connector.ingestion_failed` =
   `{connector_id, reason_code}` — no secrets, no raw spec. Endpoint as in (4).

**Consequences:** One migration (0008, reversible, one head); one dependency (`pyyaml`, `safe_load`
only, confined to `openapi.py`); no new SECURITY DEFINER, no new DB role, no new RBAC/auth, RLS/
catalog otherwise unchanged. `event_bus.publish`'s ambient-sink contextvar does not cross FastAPI's
DI boundary, so the request path buffers via the held `uow.buffer_event` (the worker path is
unaffected); the test `get_uow` override was made faithful to production (it now dispatches
post-commit). Proven by 55 tests — 37 parser/normalizer unit (adversarial: size/depth/alias/
non-finite/remote-cyclic-missing-ref bombs; determinism; mapping), 10 real-Postgres+MinIO pipeline
(persist/activate, dedup no-op, version append, tenant isolation under RLS, storage-key isolation,
failure→failed, A×8/B×8 concurrency), 8 real-HTTP endpoint (202/RBAC/404/409/400, no smuggled
workspace) — a 21-mutation B1.1 audit with **0 survivors**, and a live real-worker ingestion run.
Deferred to B1.2+: file upload, remote `$ref`, Swagger 2 → OpenAPI 3, OpenAPI 3.1, `diff_summary`/
promotion, the `tools` table, scheduled re-sync — none started.

## ADR-0026 — Connector ingestion: file upload + remote `$ref` (M1.4-B1.2)

**Status:** Accepted (2026-08-16) · **Context:** M1.4-B1.2, extending the released B1.1 OpenAPI 3.0
URL ingestion with the two remaining source/resolution capabilities canon defines: **file upload**
and **remote `$ref` resolution**. Both compose the existing pipeline (B0.1 fetcher, B0.5 ObjectStore,
B0.2/B0.3 worker, B0.4 events, ADR-0025 parser) — no new SSRF boundary, storage abstraction, queue,
event system, tenant mechanism, or authorization chain. The upload endpoint/wire contract and the
413/415 question were canon-silent (§3); the founder ratified the contract below. No migration.

**Decision:**

1. **Remote `$ref` through the one guarded fetcher.** The parser's resolver (`openapi.py`) is now
   async and resolves local **and** remote refs, but it still has **no network capability of its
   own** — a remote ref is fetched only through an **injected `fetch` callback** (§15's
   `ImportContext`), which the pipeline wires to the B0.1 guarded fetcher. So there remains exactly
   one SSRF boundary: HTTPS-only (prod), no embedded credentials, no proxy, private/loopback/
   link-local/metadata/IPv4-mapped/NAT64/6to4 rejected, ≤5 re-validated redirects, 10 MB/fetch,
   30 s (ADR-0020). Non-http schemes (`file://`, …) are refused *before* the fetcher is called.
   With `fetch=None` a remote ref is refused — the exact local-only behaviour B1.1 shipped.
   Everything is bounded (§11): resolution depth ≤32, total refs ≤10 000, **aggregate remote bytes
   ≤50 MB**, per-document ≤10 MB; cross-document cycles are detected by a `(url, fragment)` stack
   and broken; each distinct remote URL is fetched at most once per ingestion (in-memory dedup, so
   a fan-out of repeated refs is one fetch). Local refs inside a remote document resolve against
   *that* document. A remote-ref failure (SSRF/timeout/malformed/missing) is **fatal** — a hard
   `IngestionError` → connector `failed` — never a silent skip. Because refs are inlined before the
   Tool set is built, `spec_hash` depends only on the resolved content, not the ref origin: the
   same resolved content yields the same hash and dedupes; a changed remote dependency yields a new
   version. The §17 Redis cross-ingestion cache (`ws:{workspace_id}:spec:{sha256(url)}`, TTL ≤1h)
   is a documented perf optimisation, deferred — the in-memory per-ingestion dedup is the
   correctness/DoS bound this slice needs.

2. **File upload (ratified contract).** `POST /v1/connectors/{connector_id}/versions` becomes
   `multipart/form-data` accepting **exactly one** of a `source_url` field (URL ingestion,
   unchanged semantics) or a `file` upload; `connectors:manage`, still async, still 202 +
   `ingesting`. Upload is hostile input: the multipart part size is bounded **explicitly**
   (`request.form(max_part_size=10 MB+…, max_files=1, max_fields=3)` — never the 1 MB framework
   default), the file is validated (non-empty, ≤10 MB), unknown form fields are refused (a client
   cannot smuggle `workspace_id`/`status`), and the **filename is discarded** — never used for the
   storage key (a fresh `uuid`), the content type (parsing is byte-based in the worker), or a log
   line. The worker cannot re-fetch an upload (§18: fetch is worker-only egress), so the API
   **stages** the bytes to the tenant ObjectStore at `ws/<ws>/connectors/<id>/uploads/<uuid>.json`
   and the trigger carries that key; the worker reads it back through
   `TenantObjectKey.for_workspace` (confined to *this* tenant's prefix, traversal-rejecting) and
   runs the same pipeline, writing the canonical `raw_spec_ref` at `specs/v<n>.json`. Oversized/
   unsupported/malformed uploads map to **400 `validation_error`** (the closed API taxonomy has no
   413/415). A rejected request best-effort-deletes its staged object; the transient staging object
   on the happy path is a bounded, documented orphan (consistent with B1.1's rollback-orphan
   stance; an R2 lifecycle rule on the `uploads/` prefix is a future op concern).

3. **One dependency added** (`python-multipart`, required by Starlette for multipart parsing;
   parsing is bounded explicitly, not left to defaults). The `connector.ingested` /
   `connector.ingestion_failed` payloads are unchanged and carry no URL, key, spec body, or secret.

**Consequences:** No migration; `connector_versions` immutability (INSERT/SELECT-only grants) and
RLS unchanged; no new SECURITY DEFINER / role / RBAC / auth. The B1.1 endpoint's request encoding
changed from a JSON body to a multipart form field (its tests were updated); route, 202/ingesting
semantics, RBAC, tenant isolation, and the pipeline are otherwise intact. Making the resolver async
rippled a mechanical `await` through the parser and its 37 B1.1 tests (behaviour preserved: no
fetch → remote refused). Proven by 31 new tests — 18 remote-ref (resolution, local-in-remote,
nested/relative, dedup, cycle, count/depth/aggregate bounds, fatal failure, non-http-refused-before-
fetch, no-fetch-refused, location-independent hash), 8 upload endpoint (multipart, exactly-one,
empty/oversized/unknown-field, RBAC, filename-never-in-key), 5 real-Postgres+MinIO pipeline (upload
persist/dedup/missing-staged, remote-ref through the pipeline) — a 12-mutation B1.2 audit (11 killed;
1 inert redundant-guard survivor), a live real-worker upload run, and full regression **1028 passed**
at warning and debug. Deferred to B1.3+: Swagger 2 → OpenAPI 3, OpenAPI 3.1, `diff_summary`/
promotion, the `tools` table, the §17 remote-ref cache, scheduled re-sync — none started.

## ADR-0027 — Connector ingestion: Swagger 2 → OpenAPI 3 conversion (M1.4-B1.3)

**Status:** Accepted (2026-08-16) · **Context:** M1.4-B1.3, the last ingestion-format slice of the
Connector Engine v1. Canon is explicit (CONNECTOR_ENGINE §3.2, CONNECTOR_SPECIFICATION §6): a
Swagger 2.0 document is *converted to OpenAPI 3 as a single upfront step, then the OpenAPI 3
importer runs — no separate normalization logic to maintain*. `source_type` already admits
`swagger2` (ADR-0019). Two points were canon-silent; the founder ratified both (below). No migration.

**Decision:**

1. **A pure, network-free converter (`swagger.py`).** Conversion is a deterministic structural
   transform: a parsed Swagger 2.0 dict in, an equivalent OpenAPI 3.0.3 dict out. It performs **no
   I/O of any kind** — no network, DB, ObjectStore, or request/auth/tenant state — so it is
   independently testable and adds **no** new SSRF boundary, parser, `$ref` resolver, storage, queue,
   event system, tenant mechanism, or authorization chain. It is invoked by one new entry,
   `openapi.to_openapi3(document)`, which the pipeline calls *once* between `load_spec` and
   `normalize`: an OpenAPI 3.0.x document passes through; a Swagger 2.0 document is converted; the
   result is re-validated by the **same** OpenAPI-3 gate (`detect_version`) so a bad conversion can
   never reach the importer. **No new dependency** — a library would introduce a second parser and
   heavy transitive deps; the hand-written converter matches the framework-free `openapi.py`.

2. **Mapping (CONNECTOR_SPECIFICATION §6).** `definitions → components.schemas`; `parameters →
   components.parameters` (non-body) / `components.requestBodies` (reusable body); `responses →
   components.responses`; `securityDefinitions → components.securitySchemes` (basic → http/basic,
   apiKey unchanged, oauth2 flow → the OpenAPI-3 `flows` object); a **body parameter → requestBody**
   (content per `consumes`, default `application/json`); **formData → a form requestBody**
   (`multipart/form-data` when a `file` field is present, else `application/x-www-form-urlencoded`;
   `type: file → {type: string, format: binary}`); a non-body parameter's inline schema is lifted
   under `schema` and `collectionFormat → style/explode`; `discriminator` string → object. Only
   **local** `#/definitions|parameters|responses/*` refs are rewritten to `#/components/*`; **remote
   refs are left untouched** — a Swagger remote `$ref` keeps its `#/definitions/…` fragment and
   resolves, as-is, through B1.2's one resolver (which navigates a JSON-pointer fragment literally in
   whatever document it fetched). Only the root document is converted; there is nothing
   Swagger-specific to fetch.

3. **`host`/`schemes`/`basePath` → `servers` metadata only, never a fetch target (ratified strict
   detection).** These become the connector's `base_url` candidate exactly as OpenAPI `servers` do
   (https ordered first); because the converter performs no I/O and ingestion fetches only its own
   `source_url`, a Swagger `host` can **never** become an ingestion SSRF vector. Detection is strict:
   conversion happens **iff** top-level `swagger == "2.0"` (exact string; numeric `2.0`, `"1.0"`,
   etc. → `unsupported_format`); a document declaring **both** `swagger` and `openapi` is refused as
   **ambiguous** (an attacker must not steer parser selection); Swagger is never inferred from
   incidental fields (`host`, `definitions`). The **original Swagger bytes remain the canonical
   `raw_spec_ref`** — the converted document is a transient intermediate. `spec_hash` is unchanged
   (over the normalized Tool set): a Swagger document and its native OpenAPI-3 equivalent normalize
   to the **same** Tool set → the **same** hash → cross-format dedup; idempotency and versioning are
   B1.1/B1.2's, untouched. The error taxonomy is **reused** — no new reason code. Conversion is
   bounded (recursion depth-guarded on top of `load_spec`'s size/depth caps; O(size), no new
   unbounded path).

4. **Deferred (ratified).** Canon says conversion warnings should "surface as lint findings", but
   the lint-findings surface is part of the §4 stage-4 lint stage that B1.1/B1.2 never built (no
   column, no event field). Adding one would cross the DB/event-contract firewall, so the **warnings
   surface is deferred** with the rest of the lint stage; conversion itself is faithful and
   deterministic. `x-nullable → nullable` and richer collectionFormat/header fidelity are likewise
   deferred niceties (inert for the current normalizer).

**Consequences:** No migration; `connector_versions` immutability and RLS unchanged; no new SECURITY
DEFINER / role / RBAC / auth; the API surface (router/service/events/subscribers) is **untouched** —
conversion is entirely worker-side, so a Swagger file/URL flows through the existing multipart
endpoint and the worker converts. `detect_version` remains the OpenAPI-3 gate (converted docs never
carry `swagger`; a raw `swagger` reaching it is refused as defence in depth). Proven by 40 converter
unit tests (detection, every top-level/parameter/body/formData/schema/response mapping, ref
rewriting, deep-nesting rejection, no-network, determinism, and a Swagger-vs-native equal-hash
proof) + 3 real-Postgres+MinIO pipeline tests (convert-and-ingest with the original bytes retained,
cross-format dedup to one version, a Swagger remote `$ref` through the guarded fetcher), a
30-mutation B1.3 audit (0 meaningful survivors), a live real-worker Swagger ingestion, and full
regression at warning and debug. Deferred to B1.4: `diff_summary`, promotion gating, the `tools`
denormalization table; also OpenAPI 3.1, the §17 remote-ref cache, scheduled re-sync — none started.

## ADR-0028 — Connector diff, promotion gate, and tools projection (M1.4-B1.4)

**Status:** Accepted (2026-08-16) · **Context:** M1.4-B1.4, the final ingestion slice, closing the
Connector Engine v1 milestone. It lands the three capabilities B1.1–B1.3 deferred: version diffing,
promotion gating, and the `tools` denormalization table (CONNECTOR_SPECIFICATION §3/§4/§185,
CONNECTOR_ENGINE §3/§7, DATABASE_DESIGN §3). Two points were canon-silent because they depend on the
future **Connections** module; the founder ratified both (below). One new migration (`0009_tools`).

**Decision:**

1. **Deterministic diff (`diff.py`, pure).** `compute_diff(old_tools, new_tools) →
   {added, removed, changed, breaking}`, computed Tool-by-Tool on **source identity** — the
   canonical tool name, which encodes operationId/method+path with stable disambiguation (§5), so a
   re-described operation is a `changed` entry and a renamed operationId is a remove + add. A
   `changed` entry lists the content fields that moved (excluding version-specific / identity
   fields) and flags the `input_schema` change **breaking** per §185: *a required argument added, an
   argument removed, or an existing argument's type narrowed*. `breaking` (the gate input) is any
   removed tool OR any breaking change; additive edits (new tool, new optional argument, description/
   annotation/enum changes) are not breaking. Output is deterministic and content-only — no
   timestamps, ids, URLs, workspace ids, or secrets — persisted as `connector_versions.diff_summary`.

2. **Promotion gate (ratified).** Ingestion computes the diff against the current version. A **first
   version or a non-breaking (additive) diff auto-promotes** inside the ingestion transaction
   (§381). A **breaking diff is persisted with its `diff_summary` but NOT auto-promoted**: the
   connector keeps serving its current version (status returns to `active`), no tools are projected,
   and **no `connector.ingested` fires** (the live set is unchanged). An owner/admin then promotes
   explicitly via `POST /v1/connectors/{connector_id}/versions/{version}/promote`
   (`connectors:manage`, synchronous, idempotent, 200). Canon gates on breaking changes *"used by
   active Connections"*, but **Connections are a future module** — so the founder ratified the
   conservative reading: gate **all** breaking diffs (false caution is cheaper, §6/§13); the
   usage-based *narrowing* of the gate is deferred to the Connections module. Authorization is the
   existing chain only (JWT → X-Workspace-Id → membership → `connectors:manage` → connector
   ownership → RLS); no Connection / spec / version field ever influences authority.

3. **`tools` projection (`promotion.py`, migration `0009`).** `tools` is a **projection** of the
   *active* version's Tool set — `connector_versions.normalized_schema` stays authoritative (§3).
   Promotion **swaps the active set** and never mutates schema in place: the current live rows are
   soft-deleted (`deleted_at`), the new version's rows inserted (`connector_version_id` = the
   promoted version), and each Tool's `enabled` override re-applied on identity (name). The live set
   is `deleted_at IS NULL`; a removed Tool has no new row and stays soft-deleted — deprecated,
   retained for audit, failing `tool_not_found` (§13). The projection + pointer advance + event are
   one transaction shared by both callers (worker auto-promote and the explicit endpoint), so there
   is exactly one implementation. `tools` columns per DATABASE_DESIGN §3 (`name, description,
   input_schema, output_hints NULL, annotations` (carrying tags), `enabled` default true,
   `deleted_at`); RLS ENABLE+FORCE + `tenant_isolation`; two composite intra-tenant FKs (connector
   AND version in the same workspace); **SELECT/INSERT/UPDATE grants — no DELETE** (deprecation is a
   soft delete); partial unique `(connector_version_id, name) WHERE deleted_at IS NULL` so
   re-promotion never collides with history.

4. **Event (ratified) + idempotency + concurrency.** On activation/promotion, **reuse
   `connector.ingested`** (canon §343 — "promotion publishes connector.ingested"); no new event type
   is invented, and its payload is unchanged (connector id, version, spec_hash — no secrets). The
   auto-promote path dedupes on `spec_hash` (a no-op re-sync creates no version, no tools, no event);
   Celery redelivery re-runs to the same hash. Explicit promotion is idempotent (promoting the
   current version is a no-op) and concurrency-safe: the connector row is locked `FOR UPDATE`, so
   concurrent promotions (and a promotion racing the worker) serialize — the winner projects, the
   loser no-ops — with the partial-unique index as the correctness backstop against duplicate rows.

**Consequences:** One migration (`0009_tools`; up/down/up verified, `alembic check` clean); no
change to `connectors` / `connector_versions`, no historical migration rewritten. The event contract
is unchanged. The B1.1–B1.3 auto-promote-always behaviour changes only for **breaking** re-syncs
(now held pending) — one existing test that used a removal was split into an additive-auto-promote
test and a breaking-pending test. Proven by 19 diff unit tests + 11 real-Postgres+MinIO integration
tests (auto-promote, breaking-pending, tools projection, override persistence, explicit promotion,
concurrency) + 6 promote-endpoint API tests (RBAC, 404, 409, idempotency, swap), a 26-mutation B1.4
audit (0 meaningful survivors), migration up/down/up, and full regression at warning and debug.
**Deferred:** the usage-based gate refinement, an auto-promote-per-Connector setting, the
`deprecated`/`archived` states, scheduled re-sync, and the §4 lint surface — all belonging to later
modules.

## ADR-0029 — Connections: a workspace's authenticated instance of a Connector (M1-Connections-v1)

**Status:** Accepted (2026-08-17) · **Context:** M1-Connections-v1, the first slice of M1's
execution plane (after the audit that reconstructed the remaining M1 scope). A **Connection** binds
a Connector to a Workspace and carries the lifecycle and non-secret config that a Credential (next
module), the Execution Runtime, and the Tool-Call audit will all reference (Bible §4,
DATABASE_DESIGN §3, API_GUIDELINES §2). It holds **no secret**. One migration (`0010_connections`).

**Decision:**

1. **A structural, secret-free tenant entity.** `connections` (migration `0010`): `id, workspace_id,
   connector_id, name, status (pending_auth|active|error|revoked, default pending_auth),
   credential_id (nullable placeholder), config_overrides (jsonb), last_health_check_at, deleted_at,
   timestamps`. RLS ENABLE+FORCE + `tenant_isolation`; a composite intra-tenant FK
   `(workspace_id, connector_id) → connectors(workspace_id, id)` so a connection can only bind a
   connector in the **same** workspace (a cross-tenant binding is unrepresentable); a
   `UNIQUE(workspace_id, id)` target for the future credentials/tool_calls composite FKs; a **partial
   unique** `(workspace_id, name) WHERE deleted_at IS NULL` so a revoked name frees up and the DB —
   not an application check — is the arbiter under concurrency; grants **SELECT/INSERT/UPDATE, no
   DELETE** (revoke is a soft delete). Layered router→service→repository, reusing the connectors
   patterns exactly.

2. **`credential_id` is a forward-compatible placeholder (P-43).** The `credentials` table does not
   exist yet, so `credential_id` ships as a bare nullable UUID with **no FK** — exactly the pattern
   `connectors.current_version_id` used before `connector_versions` landed. The Credentials module
   adds the composite FK additively. No credential/encryption/KEK work is done here; credential
   attachment (→ `active`) is a later module.

3. **Authority is the existing chain; `config_overrides` is never authority.** Every endpoint is
   gated by `require_permission(CONNECTIONS_MANAGE)` (owner/admin; the permission already existed).
   The workspace is the authenticated context — `X-Workspace-Id` + membership for humans, the
   **token's own workspace** for machines (a machine token cannot be redirected by `X-Workspace-Id`,
   and holds no membership so it is denied `connections:manage`). `workspace_id`, `status`, and
   `credential_id` are never request fields (`extra="forbid"` → 400); `status` is server-set to
   `pending_auth`; PATCH mutates only `name`/`config_overrides`. `config_overrides` is stored
   opaquely and **never read as tenant/role/status**; its only security contract is a `base_url`
   override, which is **SSRF-linted by reusing `validate_base_url`** (never a second validator).
   Revoke is a scoped soft delete (`status=revoked` + `deleted_at`), idempotent, and a foreign/absent
   id is a uniform 404 (never a 403 oracle, P-17). Application `workspace_id` predicates are kept as
   defense-in-depth over RLS (P-14).

4. **Idempotency-Key (ratified minimal, canonical).** API_GUIDELINES §5 defines `Idempotency-Key`
   for side-effecting creates, but no platform mechanism existed. A **minimal, connections-scoped**
   Redis store was added (not a speculative platform subsystem): keyed per **workspace + endpoint +
   key**, the first request reserves the key (`SET NX`, short TTL) and stores its response (24 h);
   the same key + body replays it; the same key + a different body is a 409; a concurrent in-flight
   key is a 409. The Redis layer is a UX optimization **on top of** the real guarantee — the partial
   unique index means the DB never produces a duplicate connection even under a Redis/DB split. A
   fresh short-lived client per call (`async with`) avoids binding a pool across event loops.

**Consequences:** One migration (`0010_connections`; up/down/up verified, `alembic check` clean); no
change to any prior table or migration. A thin `app/core/redis.py` accessor was added (Redis is
already a stack service; readiness has its own probe). Proven by 18 unit + 12 real-Postgres+RLS
integration + 19 real-HTTP API tests, a 21-mutation audit (0 meaningful survivors; the RLS-redundant
predicate removals are inert defense-in-depth, verified by the catalog check), and full regression at
warning and debug. **Deferred (out of scope):** Credentials/encryption/KEK, the Execution Runtime,
`/v1/tool-calls`, `tool_calls`/audit, the Tools API + per-Tool enable/disable, connection health/
test-call (M2), OAuth, and self-serve workspace creation.

## ADR-0030 — Credential vault: envelope encryption with an env-provisioned master KEK (M1-Credentials-v1)

**Status:** Accepted (2026-08-17) · **Context:** M1-Credentials-v1, the radioactive slice of M1's
execution plane. SECURITY.md §2.1 already fixes the key architecture (a pre-implementation decision
gate confirmed it); this ADR ratifies it and the M1↔M2 boundary. A Credential is the encrypted
secret bound 1:1 to a Connection (Bible §4, DATABASE_DESIGN §3). One migration (`0011_credentials`).

**Decision:**

1. **Envelope encryption, env-provisioned KEK (SECURITY §2.1).** AES-256-GCM (`cryptography` only,
   never hand-rolled), in a vault module that is the **only** code touching plaintext. Per
   Credential: a fresh CSPRNG **256-bit DEK** encrypts the secret; the DEK is **wrapped by the master
   KEK**; fresh random nonces; the GCM tag is verified on every decrypt (fail-closed). The KEK never
   encrypts a payload directly. The **master KEK** is the env-provisioned `CREDENTIAL_MASTER_KEY`
   (already a `SecretStr` in config) — **base64 of exactly 32 bytes**, loaded and validated per
   operation and **fail-closed** on missing / default `change-me` / bad-base64 / wrong-length (never
   a fallback, never a regenerated key); production additionally validates it at startup and refuses
   to boot on a bad key. Local/CI use disposable non-production keys (compose + CI env). **KMS is
   M2+** Team/Enterprise hardening — because only wrapped DEKs depend on the KEK, that migration
   re-wraps DEKs behind a stable interface with no schema change.

2. **GCM AAD = workspace_id ‖ connection_id (ratified hardening).** The two UUIDs as raw 16-byte
   values, concatenated (fixed length, unambiguous, no secret), bound as associated data on **both**
   the payload encryption and the DEK wrap. A ciphertext transplanted to another workspace or
   connection fails authentication — defense-in-depth over RLS against cross-tenant ciphertext copy.
   `key_version = 1` in M1 (single active KEK); the column exists for the M2 rotation runbook (no
   multi-version keyring / background re-wrap here).

3. **`credentials` table (migration `0011`).** `id, workspace_id, connection_id, credential_type,
   ciphertext, encrypted_dek, key_version, nonce, expires_at, rotated_at, timestamps`
   (DATABASE_DESIGN §3). The CHECK admits all six canonical types for forward compatibility; **M1
   application flows support only `api_key`/`bearer`/`basic`** (schemas restrict it — no OAuth / JWT
   / custom-headers). RLS ENABLE+FORCE + `tenant_isolation`; a composite intra-tenant FK
   `(workspace_id, connection_id) → connections`; `UNIQUE(connection_id)` (1:1) and
   `UNIQUE(workspace_id, id)`; grants **SELECT/INSERT/UPDATE/DELETE** — the one table with DELETE,
   because **revocation hard-deletes the row** (no soft delete). This migration additively wires the
   pointer FK `connections.(workspace_id, credential_id) → credentials(workspace_id, id)` that
   Connections v1 left open (P-43) — with **NO ACTION** (a composite `SET NULL` would also null the
   NOT NULL `workspace_id`), so the service clears the pointer before deleting the credential.

4. **API, lifecycle, and decrypt boundary (ratified).** The Credential is a **1:1 sub-resource** —
   API_GUIDELINES §2 lists no top-level `/v1/credentials`, so it lives at
   `/v1/connections/{connection_id}/credential` (POST attach, GET metadata, PUT rotate, DELETE
   revoke), gated by `connections:manage`. **Responses are metadata only** — never ciphertext, DEK,
   nonce, or plaintext; the secret enters once (`SecretStr`) and is never returned, logged, or
   persisted in plaintext. **Attach transitions the Connection `pending_auth → active`** (honoring
   §3's "credential_id non-null only when not pending_auth"; the §382 health-check is a runtime
   refinement); rotate re-seals with a **fresh DEK + nonce** and stamps `rotated_at`; revoke
   hard-deletes and returns the Connection to `pending_auth`. **Decryption (`_unseal`) is private to
   the vault** — the future Execution Runtime is the only legitimate caller; no router / service /
   repository / worker path decrypts in M1 (SECURITY §2.2).

**Consequences:** One migration (`0011_credentials`; up/down/up verified, `alembic check` clean); no
prior table/migration rewritten; the `cryptography` dependency was already present (no new dep). A
thin `app/core/redis.py`-style vault module is scoped to the domain; a disposable KEK was added to
compose + CI (never production). Proven by 18 vault unit + 9 real-Postgres+RLS integration + 15
real-HTTP API tests, a 25-mutation audit (0 meaningful survivors; the RLS/unique-index-redundant
mutations are inert defense-in-depth), migration up/down/up, and full regression at warning and
debug. **Deferred:** KMS, per-Workspace data keys, the rotation background job, OAuth/JWT/custom
credential flows, the Execution Runtime (and its decrypt calls), `/v1/tool-calls`, and the audit log.

## ADR-0031 — Execution Runtime v1: the single synchronous REST Tool Call path (M1-Execution-Runtime)

**Status:** Accepted (2026-08-17) · **Context:** M1's critical path — turning the Connector +
Connection + Credential foundations into live REST execution. AI_RUNTIME.md defines a 7-stage
pipeline in a `runtime` domain and the internal `ToolCallRequest`/`ToolCallResult` contracts;
API_GUIDELINES §1 fixes `/v1/tool-calls`; DATABASE_DESIGN §3 defines the `tool_calls` audit table;
CONNECTOR_SPECIFICATION §8 fixes credential injection; SECURITY §2/§6 fixes decrypt + egress. This
ADR ratifies the four decisions those specs left open and the M1↔M2 boundary. One migration
(`0012_tool_calls`).

**Decision:**

1. **`POST /v1/tool-calls` (sync), `GET /v1/tool-calls/{id}` (audit read).** The invocation carries a
   canonical `tool_name`, an optional `connection_id` (explicit, else the Connector's single active
   Connection — ambiguity is a 400, never a guess), `arguments`, and `mode: "sync"` (async is M4).
   The pipeline runs inline in the request path (no Celery); the synchronous hot path is deliberately
   out of Celery (RISKS R-07, PRD FR-RT-1). Idempotency is the `Idempotency-Key` header (workspace-
   scoped Redis, 24h) reusing the Connections pattern; unlike Connections there is no DB uniqueness
   backstop, so the key is reserved **before** egress — a raced retry cannot double-execute.

2. **`tool_calls` — append-only, partitioned audit (migration `0012`).** `id, workspace_id,
   connection_id, tool_id, request_id, caller (jsonb), status (succeeded|failed|denied|timeout),
   input_summary (jsonb), output_summary (jsonb), error_code, duration_ms, created_at`;
   `PARTITION BY RANGE (created_at)` with composite PK `(id, created_at)` and a `DEFAULT` partition
   (no migration assumes a specific month, §5). RLS ENABLE+FORCE + `tenant_isolation`; grants
   **SELECT + INSERT only** — immutable, never updated or deleted in-band. `connection_id`/`tool_id`
   are **plain UUID columns, not composite FKs** (ratified): an immutable audit row must outlive the
   soft-deletion of its Tool or the removal of its Connection; DATABASE_DESIGN lists them as columns.
   Stage 7 is not best-effort — "no audit row, no result": *every* audited outcome (success or any
   failure) writes exactly one row and publishes `tool_call.completed`. Because the request
   transaction rolls back on a raised exception, audited failures are **not raised** — the service
   returns an `ExecutionOutcome` the router renders as the error envelope, so the row survives commit.

3. **Credential decrypt + injection (ratified §1, §3).** Decryption is the runtime's private boundary
   (`domains/runtime/secrets.py` is the *only* importer of `vault._unseal`, asserted by a test);
   plaintext lives only in memory for the single outbound request, in a `CredentialSecret` whose
   `repr` is redacted, never returned/logged/buffered/audited. Injection follows CONNECTOR_SPEC §8:
   `bearer`→`Authorization: Bearer`, `basic`→base64 at inject, `api_key`→`connectors.auth_config
   {key_name, location:header|query}`. **api_key is runtime-only in M1**: bearer/basic work
   everywhere; api_key works where `auth_config` is populated (manual connectors), and an ingested
   connector with empty `auth_config` fails closed with `connector_error`. The
   `securitySchemes → auth_config` importer projection is **deferred connectors-domain work**.

4. **One egress policy, one authz fork, per-call limits only (ratified §2, §4).** All outbound HTTP
   goes through a new general `net.request` that reuses `app.core.net`'s *same* SSRF/allowlist/size/
   timeout guard as the ingestion `fetch` — no second HTTP client. It adds a per-Connection host
   **egress allowlist** (re-checked on every redirect hop, so an injected credential can never follow
   a redirect to a foreign host) and truncates (not errors) at a 1 MiB per-call budget.
   Authorization forks by plane (ADR-0002): **humans** need `Permission.TOOLS_EXECUTE` (VIEWER
   denied); **machine tokens** are authorized by a valid, workspace-bound token (tokens are issued
   unscoped pending a scope vocabulary, so an unscoped token carries full machine authority — per-
   token scope-narrowing is deferred). An egress refusal is the new **`ssrf_blocked` (403)** code
   added to the API_GUIDELINES §6.1 taxonomy (a policy denial, `status: denied`; the message never
   carries the URL/address). **Rate limits, plan quotas, and the per-Connection circuit breaker are
   M2/M3** (ROADMAP:59/73) — M1 ships only the per-call timeout + response-size + enabled/status/authz
   policy stage.

**Consequences:** One migration (`0012_tool_calls`; the codebase's first partitioned table — `env.py`
gained partition-child exclusion for autogenerate; up/down/up verified, `alembic check` clean); no
prior table/migration rewritten; no new runtime dependency (a focused argument validator instead of
pulling `jsonschema`). `app.core.net` gained a general `request()` (the one egress policy) and
`app.core.exceptions` gained `UpstreamTimeoutError` (504, already-canonical) and `EgressBlockedError`
(the new `ssrf_blocked`, 403). Proven by 60 runtime unit + 18 real-Postgres+RLS+real-auth API tests,
a 47-killed mutation audit (0 meaningful survivors; the 2 RLS-redundant and mutually-redundant
credential-presence mutations are inert defense-in-depth), real-infrastructure egress verification
(a live GitHub 401→502 mapping, a live httpbin 200 with the injected header on the real wire, and a
live `169.254.169.254`→`ssrf_blocked` refusal), debug-level log inspection (0 plaintext/ciphertext),
and full regression at warning and debug. **Deferred:** async/long-running Tool Calls (M4), MCP + AI/
SDK exporters (M2/M4), OAuth/JWT/custom_headers injection + the `securitySchemes → auth_config`
projection, rate limits/quotas/circuit breaker (M2/M3), `usage_events` billing metering (M3), the
R2 pointer for truncated bodies, and destructive-operation confirmation.

## ADR-0032 — Tools administration v1: enable/disable lifecycle; description editing deferred (M1-Tools-v1)

**Status:** Accepted (2026-08-17) · **Context:** M1's Tools Administration surface — authorized users
inspecting and controlling already-normalized Tools. The Connector Engine produces Tools (ADR-0003/
0028) and the Execution Runtime (ADR-0031) executes the enabled ones; this slice sits between them and
owns the *administrative* lifecycle. FR-CE-4 (P0) names "per-Tool enable/disable **and description
editing**". No migration is required — the `tools.enabled` column, its `UPDATE` grant, and the
Runtime's `enabled` exclusion already exist. No new ADR-level architecture; this records two
non-obvious scope/authorization decisions.

**Decision:**

1. **Read/write authorization split, straight from the canonical matrix (SECURITY §4.1).** *Reading*
   Tools is `tools:execute` — the capability is literally "Execute Tool Calls, *view Tools* and own
   logs" (OWNER/ADMIN/MEMBER). *Enabling/disabling* a Tool is Connector configuration (FR-CE-4, "on a
   Connector") → `connectors:manage` (OWNER/ADMIN). VIEWER holds nothing → denied. The admin surface
   is the **human control plane** (ADR-0002): `require_permission` resolves membership, so a machine
   token — which has none — is denied on `/v1/tools` and administers nothing; machine identities
   execute via the Runtime, they do not administer. No new permission was invented (the fixed 7 hold).

2. **M1 ships enable/disable only; per-Tool description editing is deferred (founder-ratified).**
   `GET /v1/tools` (list, cursor-paginated, optional `?connector_id=`), `GET /v1/tools/{id}`, and
   `PATCH /v1/tools/{id}` `{enabled}` — the last is a single atomic conditional `UPDATE ... RETURNING`
   (race-safe, idempotent, never a read-modify-write). `enabled` is the only mutable field
   (`extra="forbid"` rejects any attempt to rewrite name/description/schema/connector identity, which
   originate from ingestion/promotion). **Description editing (also FR-CE-4) is deferred** because
   CONNECTOR_ENGINE §6 requires per-Tool overrides to "survive re-sync", but promotion (ADR-0028)
   currently re-applies *only* the `enabled` override by Tool identity — a description edit would be
   silently reset on the next re-ingest+promote. Shipping it correctly requires extending the
   connectors/promotion override-persistence (carry description overrides forward by identity), a
   distinct connectors-domain change out of this slice's scope. The seam is recorded as deferred M1
   work. The live set is `deleted_at IS NULL` throughout, so a deprecated Tool is a uniform 404 and
   cannot be listed, fetched, or re-enabled (no resurrection), and a disabled Tool cannot execute
   (the Runtime already excludes it) — proven end-to-end.

**Consequences:** No migration, no new event (MCP tool-list-cache invalidation on toggle is M2; there
is no M1 consumer), no new dependency. New `tools` domain (schemas/repository/service/router) wired at
`/v1/tools`. Proven by 5 schema unit + 21 real-Postgres+RLS+real-JWT API tests, a 12-killed mutation
audit (0 meaningful survivors; 4 inert — 3 RLS-redundant workspace predicates and 1 UPDATE-predicate
redundant with the `get()` re-fetch + transaction rollback), the Runtime cross-surface invariant
(enable → executes, disable → 404), and full regression at warning + debug. **Deferred M1 work:**
per-Tool description editing (needs promotion override-persistence) and the Audit-log viewer surface.

## ADR-0033 — Audit Log Viewer v1: the read-only `audit:read` view over the tool_calls ledger (M1-Audit-v1)

**Status:** Accepted (2026-08-18) · **Context:** the final M1 product surface (PRD FR-CP-3 / UJ-5) —
an authorized, tenant-isolated, read-only view of the Tool Call audit ledger the Execution Runtime
already writes (`tool_calls`, ADR-0031). No new table, no new event, no migration: the ledger, its
RLS, its append-only SELECT+INSERT grant, and the log-UI indexes (`ix_tool_calls_workspace_id_
created_at`, `ix_tool_calls_workspace_id_connection_id_created_at`) already exist. This records two
decisions the specs left open.

**Decision:**

1. **`GET /v1/tool-calls` — the full-log viewer, gated by `audit:read` (founder-ratified).** The
   canonical resource is `/v1/tool-calls` (API_GUIDELINES §1); the runtime already owns its `POST`
   (invoke) and `GET /{id}` (fetch a result), so the viewer adds only the **list**. The matrix
   distinguishes `audit:read` = "View full audit log — every member's activity, not just one's own"
   (OWNER/ADMIN) from `tools:execute` = "view **own logs**" (MEMBER). The M1 viewer is the FR-CP-3/
   UJ-5 **full-log** dashboard → `audit:read`; MEMBER, VIEWER, and machine tokens (no membership) are
   denied. The member "own logs" browse (a caller-scoped view under `tools:execute`) is **deferred**
   — it needs its own caller-identity-scoping decision. This keeps the endpoint's privilege exactly
   what the named viewer requires, no broader.

2. **A dedicated read-only `audit` domain; metadata-only; canonical UJ-5.3 filters.** A new
   `app/domains/audit/` (router/service/repository/schemas) reads `runtime.models.ToolCall` — it does
   not duplicate the ledger, create a second audit system, or touch the runtime pipeline, and issues
   **only SELECTs** (the app role holds no UPDATE/DELETE grant on `tool_calls`, and no mutation verb
   is registered — PATCH/PUT/DELETE are 405). Cursor pagination (§3) keyset on `(created_at, id)` DESC
   — deterministic (UUIDv7 tie-break), index-backed, bounded (LIMIT ≤ 100). Filters are exactly the
   UJ-5.3 set: `connection_id`, `tool_id`, `status` (validated against the closed enum), `interface`
   (`caller->>'interface'`), and `created_after`/`created_before`. The response is an **explicit
   `ToolCallLogRead` schema** (never raw-ORM), exposing only redacted audit metadata (Tool/Connection
   ids, `caller` identity, status, `error_code`, `duration_ms`, `request_id`, `created_at`, and the
   already-redacted `input_summary`/`output_summary`) — `workspace_id` and every ciphertext column
   are structurally absent, so a future `tool_calls` column cannot silently leak through this surface.

**Consequences:** No migration, no new event, no runtime change, no new dependency. The list shares
`/v1/tool-calls` with the runtime router (distinct method/path — no conflict). Proven by 2 schema unit
+ 14 real-Postgres+RLS+real-JWT API tests, a 13-killed mutation audit (0 meaningful survivors; 1 inert
RLS-redundant predicate), cross-tenant isolation, read-only-405, metadata-only (no secret/`workspace_
id`) assertions, and full regression at warning + debug. **Deferred M1 work:** the member "own logs"
(`tools:execute`) caller-scoped view; CSV export + the log-explorer UI (frontend, FRONTEND_SPEC). This
is the **final M1 product surface** — M1 is now feature-complete pending the final forensic audit.

## ADR-0034 — Connection & Tool lifecycle events: the MCP cache-eviction foundation (M2.1)

**Status:** Accepted (2026-08-18) · **Context:** M2's first slice. MCP `tools/list` (M2.2) will
cache per-workspace listings (`ws:{workspace_id}:mcp:tools`, MCP_RUNTIME §3) and must evict on
every transition that changes the active Tool set — a stale listing after a revocation is a
discovery/authorization divergence, not a performance bug. The bus (ADR-0023), its post-commit
UoW buffering, and the fail-closed tenant-match (ADR-0022) already exist; `connector.ingested`
already covers ingestion *and* promotion (`promotion.promote` buffers it). Missing were the
Connection and Tool lifecycle emissions. This records the decisions that discovery left open.

**Decision:**

1. **Five canonical lifecycle events, tied to persisted transitions — never to method names.**
   Declared in the owning domain's `events.py`, published via `event_bus.publish` (post-commit
   dispatch; a rolled-back request emits nothing): `connection.activated` (`pending_auth →
   active`; emitted where the transition lives — the credentials domain's attach, guarded on the
   prior persisted status); **`connection.deactivated`** (the Connection *left the active set
   without being revoked*: `active → pending_auth` on credential revoke today, `active → error`
   when the OAuth refresh worker lands — **founder-ratified 2026-08-18 as the 5th eviction
   event**, closing the stale-listing gap canon's eviction list missed; payload carries the new
   status word); `connection.revoked` (`* → revoked`, stamped from the revoking UPDATE's
   RETURNING identifiers — the event describes what the database did, never what the caller
   asked); `tool.enabled` / `tool.disabled` (persisted flips of `tools.enabled`).

2. **No-op mutations emit nothing (INVARIANT: no persisted transition → no event).** The Tools
   repository UPDATE is now value-guarded (`enabled != :desired`): a no-op PATCH stays an
   idempotent 200 but touches nothing — not even `updated_at` — and emits nothing; two concurrent
   identical PATCHes serialize on the row lock and exactly one emits. The idempotent second
   connection-revoke (no row moved) and a 409 attach likewise emit nothing.

3. **Payloads are non-secret identifiers only; the envelope is the tenant authority.** Payload =
   `connection_id`/`tool_id` + `connector_id` (+ the `status` word on deactivation). The
   workspace rides only in the trusted envelope `workspace_id`, cross-checked fail-closed against
   the transaction's bound tenant at buffer time (ADR-0022) — an event can never evict another
   workspace's cache namespace. Delivery is at-most-once in-process today, at-least-once under
   the future broker (ADR-0023): the eviction consumer must be idempotent (cache eviction is).

**Consequences:** No migration, no new dependency, no new bus, no new endpoint; MCP stays fully
decoupled (no `interfaces/` module exists — the bus is the boundary). `ConnectionRepository.
revoke` returns the moved row's identifiers instead of a bool; `ToolRepository.set_enabled`
returns `(tool, changed)`. Proven by 8 unit + 12 real-Postgres+RLS+real-JWT integration tests
(incl. service-level rollback-emits-nothing and cross-tenant no-event), a 13-mutation audit — 9
killed, 4 inert (2 defensively-unreachable prior-status guards awaiting the M2 `error` status; 2
RLS-redundant workspace predicates, same class as prior audits), 0 meaningful survivors — and
full regression (1332). **Deferred:** the eviction *consumer* (M2.2 MCP `tools/list`); the
`active → error` emission site (M2 OAuth refresh worker); broker durability (ADR-0023's swap).

## ADR-0035 — MCP tools/list: pinned protocol, minimal adapter, cached discovery (M2.2)

**Status:** Accepted (2026-08-18) · **Context:** the first MCP surface. Canon fixes the shape —
thin adapter (MCP_RUNTIME §1), api-token auth with token/slug binding (§2), the cached,
event-invalidated listing over active Connections' enabled Tools (§3), Streamable HTTP (§5),
explicit version pinning (§7) — but left three values open. All three were founder-ratified
2026-08-18. M2.1 (ADR-0034) supplied the six eviction events and flagged the at-most-once
lost-eviction gap this module's TTL closes.

**Decision:**

1. **Protocol pin (founder-ratified):** allowlist `{2025-06-18, 2025-11-25}`, advertising
   `2025-11-25` (`interfaces/mcp/protocol.py::SUPPORTED_PROTOCOL_VERSIONS`). `initialize`
   echoes a supported requested revision, otherwise answers with the advertised one; every
   post-initialize request must present `MCP-Protocol-Version` from the allowlist (the spec's
   2025-03-26 fallback is below our floor → 400, never a downgrade). `2026-07-28` (stateless
   core, MRTR, beta SDKs) is excluded until reconciled with MCP_RUNTIME's session model;
   adopting it is a deliberate upgrade PR with contract tests, never a dependency bump.

2. **Minimal in-house adapter, no FastMCP (founder-ratified deviation from MCP_RUNTIME §1).**
   `interfaces/mcp/` implements JSON-RPC over sessionless Streamable HTTP directly (JSON
   responses; GET/DELETE 405; single messages only — batching left the spec in 2025-06-18):
   `initialize`, `notifications/*` (202), `ping`, `tools/list`; everything else, including
   `tools/call`, is the protocol's method-not-found until M2.3. Rationale: zero new
   dependencies for a discovery-only surface, exact allowlist control, native reuse of the
   existing auth stack. FastMCP is re-evaluated at M2.3 (streaming/elicitation). Mounted at
   `/mcp/v1/{workspace_slug}` — outside REST `/v1` so user-chosen slugs can never collide with
   resource paths; the `mcp.omniaiconnect.com` edge maps its `/v1/*` here. `listChanged` is
   declared false (no server→client stream yet; deferred with tools/call).

3. **Auth = machine tokens only, slug-bound.** The `omc_` workspace token authenticates and
   selects the workspace (existing `get_workspace_context`); a human JWT gets the uniform 401
   (MCP is machine identity, ADR-0002); the path slug must name the token's own workspace —
   mismatch is the same uniform 401 before any listing (MCP_RUNTIME §2). Browser-origin
   requests are refused outright (Streamable HTTP DNS-rebinding guard; no CORS surface).

4. **Discovery = the Runtime-callable set, from the canonical schema.** One workspace-scoped
   RLS-backed query (`ToolRepository.list_discoverable`): live + enabled Tools whose Connector
   has ≥1 live `active` Connection — exactly what the Runtime will execute, so discovery and
   execution authority cannot diverge. Ordered `(created_at, id) DESC` (the canonical Tool
   listing order). The wire projection is a strict allowlist: `name`, `description`,
   `inputSchema`, and `annotations.{readonly,destructive,idempotent}` →
   `readOnlyHint/destructiveHint/idempotentHint`; ids, tenant, tags, rate_hints, endpoints,
   and all credential material are structurally absent.

5. **Cache = optimization only; TTL backstop = 300 s (founder-ratified).** Cache-aside on
   `ws:{workspace_id}:mcp:tools` (key from the server-derived context, value in a versioned
   envelope so shape drift reads as a miss). Evicted by the six ADR-0034 events, with the
   workspace taken only from the trusted envelope. Because the bus is at-most-once, the TTL
   (`settings.mcp_tools_cache_ttl_seconds`, default 300) is the guaranteed staleness bound for
   a lost eviction — stale discovery is bounded; stale execution is impossible (the Runtime
   re-authorizes every call). Redis failure degrades to the authoritative database — never an
   empty list, never an authorization input.

**Consequences:** No migration (`alembic check` clean), no new dependency, no Runtime/domain
behavior change; domains still never import interfaces. Proven by 8 protocol-unit + 18
real-Postgres+RLS+Redis+real-auth integration tests and a 17-mutation audit (15 killed, 2
inert RLS-redundant tenant predicates, 0 meaningful survivors). **Deferred:** `tools/call` +
result translation (M2.3); `listChanged` emission; FastMCP re-evaluation; per-token scope
narrowing of listings (blocked on the scope vocabulary); `2026-07-28` adoption.

## ADR-0036 — MCP tools/call: the execution bridge over the canonical Runtime (M2.3)

**Status:** Accepted (2026-08-18) · **Context:** the second and highest-risk MCP surface — remote
AI clients invoking real Tools is a confused-deputy boundary. Canon fixes the shape: MCP is a
thin adapter over the Execution Runtime (MCP_RUNTIME §1/§4), and the Runtime is already the sole
authority for authorization, Connection resolution, argument validation, credential
decrypt-at-use, SSRF/egress, timeout, and audit (ADR-0031). M2.3 adds only translation; it
introduces no execution, credential, SSRF, or audit mechanism, no new dependency, no migration.

**Decision:**

1. **One execution path.** `interfaces/mcp/execution.py` maps `tools/call` params →
   `ToolCallCreate` → the existing `RuntimeService.execute` → `ExecutionOutcome` → MCP tool
   result. The adapter performs no HTTP, imports no vault/crypto/net internals (proven by a
   structural grep in the mutation audit), validates nothing beyond protocol shape, and adds no
   second audit row. The workspace is the authenticated `ctx` alone — `tools/call` params carry
   only `name` + `arguments`; a `workspace_id`/`connection_id` placed inside `arguments` is inert
   tool data (tested), never tenant authority.

2. **The Runtime re-authorizes at execution time; the discovery cache is never execution
   authority.** A Tool listed by a stale `tools/list` cache but since disabled/deprecated or
   whose Connection went inactive/revoked is refused by the Runtime's resolve stage — the
   mandatory stale-cache test drives exactly this (list → disable without evicting → call →
   refused, no egress). Cross-tenant execution is impossible even when A knows B's exact Tool
   name: the Runtime resolves within A's RLS-bound tenant and finds nothing (uniform "Unknown
   tool.", no egress, no row in B).

3. **Error split (MCP_RUNTIME §4).** Failures the Runtime *raises* (pre-audit: unresolvable Tool
   → uniform phrase, never an oracle; ambiguous Connection) become JSON-RPC errors. Failures the
   Runtime *returns* (audited outcomes: bad arguments, upstream 4xx/5xx, timeout, egress denial,
   credential failure) become MCP tool results with `isError: true` carrying `<stable code>:
   <safe message>`. `ssrf_blocked` stays a distinct security refusal, never re-cast as an upstream
   error; no message carries a target URL, address, header, or `details`. `_meta` carries the
   audit correlation (`toolCallId`, `requestId`).

4. **No retries, one timeout, single audit.** Exactly one execution attempt per request (a Tool
   Call may be destructive — no automatic replay, no idempotency inference from annotations); the
   Runtime's existing timeout governs; the Runtime writes the one audit row, now tagged
   `caller.interface="mcp"` via a new server-set `RuntimeService(interface=...)` parameter
   (default `"rest"` — every M1 call unchanged).

**Consequences:** No migration (`alembic check` clean), no new dependency, no Runtime behavior
change (only an additive, server-set `interface` label). Verified by 4 mapping-unit + 13
real-Postgres+RLS+real-auth+real-Runtime integration tests, two live end-to-end runs against the
running stack (a real execution and a real `169.254.169.254` SSRF rejection — `ssrf_blocked`,
`denied`, no IP leaked, canary absent from response and audit), and a 11-mutation audit (10
killed, 1 inert: a name guard redundant with `ToolCallCreate` validation; 0 meaningful
survivors). **Deferred:** MCP `listChanged`, resources/prompts/sampling, async/streaming results,
per-token scope narrowing; FastMCP re-evaluation stands (ADR-0035).

## ADR-0037 — Tool-Call rate limits & quotas: the Runtime's stage-3 policy checks (M2.4)

**Status:** Accepted (2026-08-18) · **Context:** MCP tools/call opened the platform's first
broadly-exposed untrusted execution surface (R-08 egress-cost risk). Canon already fixed the
architecture — enforcement in the Runtime's policy stage (AI_RUNTIME §2.3; MCP_RUNTIME §1 keeps
adapters policy-free), a Redis token bucket on `ws:{workspace_id}:rl:*` seeded from
`rate_hints`, plan quota failing closed (SYSTEM_ARCH §7, SECURITY §6), dimensions per
Workspace/Connection (ROADMAP M2). The founder ratified the five open policy values 2026-08-18
(D1–D5). A small precursor (M2.4-pre) first closed the pre-existing DNS gap so every executed
call has an audit row before quota counts on them.

**Decision:**

1. **One enforcement point** — `RuntimeService.execute`, top of the audited region (after
   resolve/bind, before validation/decrypt/egress). REST and MCP share one budget structurally;
   `interface` stays audit metadata, never a counter dimension. Denials are audited outcomes:
   `status=denied` with `rate_limited` / `quota_exceeded` (D4 — now a distinct §6.1 code; the
   dormant `QuotaExceededError` activated, `RateLimitedError` added), mapped by the existing
   REST envelope (429 + `Retry-After` from non-secret details) and the existing M2.3 MCP
   contract (`isError: true`) with zero adapter changes.

2. **Atomic Lua token bucket on Redis TIME** — state `HASH{tokens,ts}` per key; refill math
   runs server-side in one script (no app clocks, no read-modify-write, no locks); malformed
   state resets to a full bucket; keys carry idle-expiry TTLs. D1 (Free): 60 Tool Calls/min
   sustained (1 token/s), burst 10; per-Connection buckets only when canonical
   `annotations.rate_hints.requests_per_minute` exists (advisory data — no hint, no fabricated
   bucket; a hint narrows within the workspace limit). Paid plans (`workspaces.plan`
   authoritative, read per call) are unenforced until M3 wires billing.

3. **Quota = executed calls only (D2)** — `ws:{workspace_id}:quota:{iso-week}` (UTC), checked
   at stage 3, consumed exactly once at audit-write for statuses `succeeded`/`failed`/
   `timeout`; `denied` and pre-audit failures never consume; idempotency replays never reach
   `execute()` so can never re-consume. Free quota 1,000/week (D1). Bounded in-flight overshoot
   near the boundary is accepted (check-then-execute; M3 reconciles from the audit ledger,
   which this design keeps 1:1 with consumption).

4. **Redis unavailable → fail closed for both checks (D3)** — the denial is a retryable 429
   with a generic message (`limits_unavailable` logged for alerting); the post-execution quota
   *increment* alone is logged-and-swallowed (the call already ran; an under-count never
   over-charges). Kill switch `rate_limiting_enabled` (default on) is an all-or-nothing
   operational rollback restoring exact pre-M2.4 behavior — it cannot partially weaken quota.

**Consequences:** No migration (state is canonically ephemeral in Redis; plan pre-exists), no
new dependency, no adapter changes, ~1–2 Redis ops per Tool Call. New settings in
`.env.example`. API_GUIDELINES §6.1 gains `quota_exceeded`; §7's **general per-token request
limiter and every-response `X-RateLimit-*` stamping are deferred (D5)** and documented as an
open contract. Proven by 6 period/plan/hint unit tests + 13 real-Redis+Postgres+RLS
integration tests (boundary, cross-surface shared budget, tenant isolation, 8-way concurrency
admits exactly the burst, refill, hints, quota semantics incl. failure/timeout consumption,
fail-closed outage on both surfaces, kill switch, idempotency-replay non-consumption, TTLs) and
a 16-mutation audit — 15 killed, 1 inert (bucket idle-TTL is memory hygiene, not admission), 0
meaningful survivors. M2.4-pre proven by resolver-injection unit + live-resolver integration
tests. **Deferred:** §7 general limiter; per-Connection in-flight concurrency + circuit
breaker; `usage_events` + paid-plan enforcement (M3); anomaly alerting (M3).

## ADR-0038 — OAuth 2.0 authorization-code + PKCE: the backend-owned flow (M2.5)

**Status:** Accepted (2026-08-21) · **Context:** M2's OAuth module, implemented from the frozen
M2.5 architecture after the founder ratified D1–D5. Canon fixed most of it already
(CONNECTOR_SPECIFICATION §5:215, CONNECTOR_ENGINE §8, PRD §74); this ADR records the five
ratified decisions and the implementation choices canon left derivable.

**Decision:**

1. **Backend owns the flow and the callback (D1).** `POST /v1/connections/{id}/oauth/authorize`
   (human, `connections:manage`) returns `{authorize_url, expires_at}`; the unauthenticated
   `GET /v1/oauth/callback` is the provider's redirect target. This satisfies PRD §74 (the
   callback lands in the credentials domain) and keeps `state` and the PKCE verifier entirely
   server-side. A dashboard, when it exists, simply redirects to the URL the API returns — no
   re-architecture. **Deferred:** the dashboard UX slice.

2. **`oauth_states` is the callback's only authority.** A provider redirect carries just `code`
   and `state`, both attacker-influencable, so workspace/connection are read from the row the
   request atomically consumes — never from the request. `state` is stored **SHA-256 hashed** (a
   database read cannot forge a callback); the PKCE `code_verifier` is stored **sealed** by the
   existing vault, because RFC 7636 §4.5 requires presenting it verbatim. The consume runs
   through `auth.consume_oauth_state`, the **same narrowly-scoped SECURITY DEFINER carve-out M1
   established for bearer tokens** (migration 0001) — never a weakened policy, never BYPASSRLS —
   with the conditional `UPDATE … RETURNING` inside the function, so single-use is a property of
   the database. The refresh sweep uses a second such function returning **identifiers only**.

3. **PKCE S256 only; public client.** `plain` is never generated or accepted. §215's auth-code
   contract names only `authorization_url`/`token_url`/`scopes` — no client secret — so M2.5
   speaks the RFC 6749 §2.1 public-client profile where PKCE replaces a secret. `auth_config`
   **refuses** `client_secret`/token-shaped keys outright, since it is public metadata (§219).
   **Grant scope (D3): `authorization_code` only** — `client_credentials` is refused explicitly
   and remains **M2/P1 deferred**, never silently moved to M3.

4. **One egress, one vault, one Runtime.** Token exchange and refresh go through
   `core.net.request` with the token host pinned as the allowlist — no second HTTP client, no
   second SSRF implementation (an `SSRFError` maps to the canonical `ssrf_blocked`). Tokens are
   sealed into the single Credential per Connection by the credentials domain. The Runtime gains
   **one** `oauth2` branch injecting `Authorization: Bearer`; there is no refresh-before-use, so
   an expired token surfaces as the canonical upstream failure. `vault.unseal_flow_secret` is
   added for the PKCE verifier only — ephemeral protocol material, not a Credential; the private
   `_unseal` stays Runtime-only and its encapsulation test still passes unchanged.

5. **Refresh: `runtime` queue, jittered, row-locked (D2/D5).** A beat-scheduled sweep discovers
   due credentials and fans out one task per credential with jitter; each task carries
   **identifiers only** (never a token — Celery arguments are JSON at rest in Redis). The refresh
   **claims the Connection with `SELECT … FOR UPDATE` and re-checks expiry inside the lock**, so
   concurrent workers perform exactly one exchange and a **rotated refresh token can never be
   lost**. A terminal failure sets `status='error'` and emits `connection.deactivated`;
   **`webhooks_outbox` is not built here — it belongs to Connection Health (D2)**. `needs_reauth`
   is **derived** (`status == 'error'` AND an oauth2 credential), not a fifth status and not an
   `error_reason` column (D5) — the released `status_valid` CHECK is untouched.

**Consequences:** One additive migration (`0013_oauth_states`), no change to released migrations,
no new dependency. New settings (`OAUTH_*`) plus two deployment processes: a `runtime`-queue
worker and exactly one beat scheduler. Proven by 21 config-unit + 30 real-Postgres+RLS+vault+
Celery integration tests (state replay/expiry/concurrency/cross-tenant, PKCE mismatch/downgrade,
redirect binding, provider 4xx/5xx/malformed, SSRF, refresh rotation + concurrency + outage,
terminal transition, REST **and** MCP execution, secret canaries in response/audit/logs) and an
18-mutation audit — 17 killed, 1 empirically-proven inert, 0 meaningful survivors.
**Deferred:** `client_credentials` (M2/P1), dashboard UX, `webhooks_outbox` + Connection Health,
vault hardening, MCP streaming/`listChanged`. **M2 is NOT complete after M2.5.**

---

## ADR-0039 — Credential Vault Hardening: local versioned keyring, derived workspace keys, log-based vault audit (M2.6)

**Status:** Accepted · **Date:** 2026-08-22 · **Supersedes:** nothing (extends ADR-0030)

**Context.** ROADMAP §56 asks for four things: key rotation, a derived per-workspace data key,
redaction hardening, and a vault access audit. EC3 additionally requires a deliberate red-team pass
finding zero plaintext. ADR-0030 shipped envelope encryption with a single env KEK and a
`key_version` column whose only purpose was this milestone. Five decisions were surfaced and
founder-ratified before implementation.

**Decision.**

1. **A1 — No KMS (ratified OUT).** AWS/GCP/Azure KMS and HSMs stay out of M2.6. Instead: a
   multi-version **local KEK keyring** behind a stable `KeyProvider` seam. This is the interface
   ADR-0030 promised — because only wrapped data keys depend on the KEK, a future KMS is a new
   implementation of this protocol plus a re-wrap pass, with no schema change and no ciphertext
   rewrite. Exactly one implementation ships (`LocalKeyringProvider`); the protocol exists so that
   stays true.

2. **A3 — Derived workspace keys via HKDF, no `workspace_keys` table.** A data key is wrapped by
   `HKDF-Expand(KEK_v, label ‖ version ‖ workspace_id)`, not by the KEK directly. RFC 5869 §3.3
   permits skipping Extract because the KEK is already a uniformly random 256-bit key. The key is
   derived on demand and never stored, so there is no new table, no new secret at rest, and nothing
   to keep in sync. The property this buys is worth stating plainly: a wrapped data key from
   workspace A is useless in workspace B **even if the AAD check above it were bypassed** — tenant
   isolation stops depending on the application layer getting `workspace_id` right.

   **Version 1 keeps M1's direct-KEK wrapping, permanently.** Redefining it would have made every
   credential already in production undecryptable — silent, total, unrecoverable. So introducing the
   hierarchy *is itself a KEK rotation*: rows migrate 1 → 2 through the ordinary runbook. The
   hierarchy is not bolted onto history; history is migrated into it. This is the single most
   load-bearing decision in M2.6 and it is pinned by a test that reconstructs an M1-era record
   byte-for-byte and requires the hardened vault to read it.

3. **P1 — Rotation runbook: INTRODUCE → RE-WRAP → PROVE COMPLETION → OVERLAP → RETIRE.** Annual as
   routine, immediate on compromise; 24h re-wrap target; ≥7-day overlap after completion. Re-wrap
   runs on the existing `runtime` queue with identifier-only task arguments and **never decrypts the
   payload** — `ciphertext` and `nonce` come out byte-identical, so an interrupted rotation cannot
   corrupt a secret. **Retirement is gated on `COUNT(key_version < target) = 0` measured in the
   database**, never on a timer, a scheduler's report, or a batch that looked successful. Reading
   a row whose key was retired raises `VaultKeyVersionError`, audited as `key_unavailable` and
   deliberately distinguishable from tampering: one says restore the key, the other says
   investigate an attack.

4. **A2 — Vault audit is structured logs + a bounded metric.** No new table, no second audit
   ledger, no `tool_calls` extension. Hooked at `open_credential_secret`, the single decrypt
   boundary and therefore the only place the record can be complete; every call is recorded,
   success and each distinct failure, because an audit that logs only successes reads as a full
   history while omitting exactly the events an investigation needs. The counter's labels are drawn
   from closed sets and an undeclared value **raises**, so cardinality is bounded by construction
   rather than by intention.

5. **P2 — Harden all four deployed sinks (api, worker, worker-runtime, scheduler); no Sentry.**
   The gap found was real and was verified before being fixed: structlog uses `PrintLoggerFactory`
   and never touches the stdlib tree, so a `celery.worker` record containing `api_key=…` was emitted
   verbatim. Redaction is now installed at `Logger.makeRecord` — the record factory was tried first
   and rejected because stdlib applies `extra={...}` *after* it, which a test caught. Sentry is not
   deployed and is not claimed as covered.

**Consequences.** One additive migration (`0014_key_rotation_discovery`) adding two SECURITY DEFINER
functions — the same sanctioned carve-out as `auth.resolve_api_token` (0001) and
`auth.due_oauth_refreshes` (0013), returning identifiers and counts only — plus an index on
`key_version`. No table, no column, no change to released migrations, no new dependency (HKDF comes
from `cryptography`, already present). New settings (`CREDENTIAL_MASTER_KEYS`,
`CREDENTIAL_KEY_VERSION`, `CREDENTIAL_ROTATION_*`) and one new beat entry; **default configuration
is behaviourally identical to M2.5** — single key, version 1, sweep idle at one indexed COUNT.

Proven by 1524 passing tests, including the M2.6 additions: keyring/derivation/rotation crypto
units, real-Postgres+RLS rotation integration (payload byte-identity, overlap readability, the
retirement gate across two tenants, cross-tenant refusal, RLS-independent repository scoping), the
vault-access audit, the stdlib redaction bridge, and a **red-team pass that drives a canary through
the full lifecycle and then searches every row of every table, the log stream, and Celery arguments
— finding zero**, with a companion test that plants the canary to prove the instrument works. A
24-mutation audit killed 23; the one survivor (`rewrap`'s target-version guard) was **empirically
proven inert** — the provider raises the identical `VaultKeyVersionError` one layer down — and is
kept because it fails before materializing a data key.

An **independent release audit** then re-derived every claim from code, database, and running
infrastructure, and ran a further 10-mutation subset weighted toward what the implementation had
not tried (rotation row lock, AAD, decrypt boundary, cross-milestone safety) — all killed. It
closed three genuine defects the implementation missed: `credential_type` was emitted as
«redacted» because its key matched the "credential" marker, gutting the very audit A2 ratified
(the unit tests observed the event *before* the redaction processor, so they could not see it —
now asserted on the rendered JSON line); a generated `celerybeat-schedule` artifact had been
committed; and a key-shaped test canary would have failed CI's secret scan. It also added the
rotation concurrency coverage the implementation lacked (2/4/8 workers, plus rotation racing a
concurrent re-seal), without which removing the `FOR UPDATE` claim went undetected.

**Deferred:** external KMS/HSM (Team/Enterprise), Sentry `before_send`, automatic key generation,
per-Connector credential field-name registration in the redactor, a metrics exporter (the counter is
a hook with a bound, not a backend). **M2 is NOT complete after M2.6.**

---

## ADR-0040 — Connection Health: a Tool Call through the Runtime; notifications blocked by ADR-0014 (M2.7-A)

**Status:** Accepted · **Date:** 2026-08-22 · **Relates to:** ADR-0014 (unchanged), ADR-0038

**Context.** ROADMAP §58 is one sentence: *"Connection health: test-call button, status states,
failure notifications (Resend)."* Discovery found that canon already answers the central design
question. AI_RUNTIME §2 stage 1 authenticates *"the workspace-scoped api token **or the session
Member for dashboard 'test call'**"*, and stage 2 resolves Tool + Connection — so a test call is an
ordinary Tool Call, not a Tool-less probe. That single fact removes the need for a new execution
path, a new audit ledger, and any change to `tool_calls`.

**Decision.**

1. **A health check is an ordinary Tool Call.** The endpoint `POST /v1/connections/{id}/test` is a
   thin door onto `RuntimeService.execute` (AI_RUNTIME §4, "one runtime, many doors"). It performs
   no HTTP, decrypts nothing, validates no egress, enforces no limits and writes no audit row.
   Consequently rate limits, quota, argument validation, credential decrypt-at-use, SSRF, timeout
   and the audit write are inherited unchanged, and a health check can never reach somewhere a
   Tool Call could not.

2. **Authorization is `tools:execute`, not `connections:manage`.** A health check executes a real
   Tool against a real third-party API with the Connection's real credential, so it must carry
   exactly Tool Call authority. Gating it on connection administration would let a role that may
   not execute Tools cause authenticated egress, and would deny a MEMBER who legitimately may.

3. **Probe selection is fail-closed and deterministic.** A Tool is eligible only when it is
   enabled, live, annotated `readonly: true`, **and** requires no arguments; missing annotations
   (the `'{}'` column default) mean *unsafe*. Eligible Tools are ordered by canonical name and the
   first is taken, so the same Connector probes the same endpoint on every check. Zero eligible
   Tools is the first-class outcome `health_check_unavailable` — refusing is correct, and the only
   alternative would be fabricating a request against a customer's live API.

4. **Health is derived; the released `status` CHECK is untouched.** `unknown | healthy | unhealthy
   | needs_reauth`, computed from authoritative state, exactly as M2.5 derived `needs_reauth`
   rather than adding a fifth status (ADR-0038 D5). `needs_reauth` — ratified in M2.5 and until now
   present only in docstrings — is finally surfaced, and `last_health_check_at`, a column that
   shipped in M1 and had never been written, is finally populated.

5. **"Completed check" means the Connection was actually evaluated.** An `ExecutionOutcome`
   exists only when an audit row was written, and that is the starting point — with one exception
   the release audit found and corrected: the **M2.4 stage-3 policy refusals** (`rate_limited`,
   `quota_exceeded`) are platform decisions taken before any Connection-specific work, so they say
   nothing about the Connection. They are still audited, but they report `unknown` and leave the
   previous verdict and timestamp untouched. Treating them as verdicts let an exhausted weekly
   quota — or a Redis outage failing closed down the same path — flip every Connection in a
   Workspace to `unhealthy` and destroy a known-good timestamp, a verdict that then outlived the
   incident. `EgressBlockedError` and `ConflictError` remain health facts (the Connector's own base
   URL is forbidden; the Connection is inactive or has no credential). Otherwise
   `last_health_check_at` is stamped — from the audit row's **own** `created_at`, which lets the
   projection join back to that specific check. Pre-audit failures raise and correctly leave the
   timestamp alone. A failed probe never changes `connection.status`: health is an observation, and
   letting it transition the lifecycle would hand anyone with `tools:execute` a way to deactivate a
   Connection by pointing it at a flaky endpoint.

6. **Failure notifications are DEFERRED — blocked by ADR-0014.** ROADMAP §58's Resend clause is
   *not* delivered. Notifying Workspace Owners and Admins requires their email addresses, which
   live in `identity.user`. ADR-0014 clause 2 grants the two roles **nothing on each other's data**
   and says so symmetrically; clause 4 states **"the API never reads these tables"**; clause 1
   makes rollback safety structural by ensuring **no Alembic migration mentions the schema**
   (verified: still zero). Both possible SECURITY DEFINER shapes breach it — one needs
   `omniai_identity` to read `public.members` (the reverse grant clause 2 forbids), the other hands
   `omniai_app` a `user_id → email` **user-enumeration primitive**. ADR-0014 is **not** amended
   here; the notification architecture requires a separate owner decision.

**Consequences.** **No migration** — `last_health_check_at` already existed and `tool_calls` is
unchanged (`alembic check` clean, zero migration files touched). One new setting
(`CONNECTION_HEALTH_ENABLED`); no new dependency, no new queue, no scheduled work, no MCP change
(zero files under `app/interfaces` touched). `ConnectionRead` gains `health` and `needs_reauth`
additively.

Proven by 1587 passing tests, including 33 domain-rule units over a hostile Tool inventory and 31
real-Postgres+RLS+Runtime integration tests (audit-exactly-once, zero-egress refusal, both flag
states, the full RBAC matrix, cross-tenant indistinguishability, OAuth injection reuse, SSRF,
timeout, rate-limit denial and Redis-outage fail-closed **through the health door**), plus a
26-mutation audit with **0 survivors**. Four mutations survived the first pass and were closed with
tests rather than explained away: a prose failure reason, an RLS-masked repository predicate, an
untested SQL liveness filter, and — the substantive one — a projection that would have let ordinary
Tool Call traffic flip a Connection's health.

**Deferred:** failure notifications (Resend) and recipient resolution, `webhooks_outbox`, the
dashboard test-call button (`apps/web` has no product dashboard), the per-Connection circuit
breaker (CONNECTOR_SPECIFICATION §254, canonically specified but outside ROADMAP's M2 scope), and
scheduled health checks (no canonical source requires them). **Connection Health is NOT complete,
and M2 is NOT complete.**

---

## ADR-0042 — Connection Health failure notifications: a workspace destination, a Redis window, one delivery path (M2.10)

**Status:** Accepted · **Date:** 2026-08-22 · **Relates to:** ADR-0014 (unchanged), ADR-0017,
ADR-0023, ADR-0034, ADR-0040 (completes its deferred clause 6) · **Depends on:** the M2 owner
ratification recorded on `docs/adr-0041-m2-owner-ratification` — this ADR implements decisions taken
there, and takes number 0042 rather than 0041 so the two branches cannot collide.

**Context.** ROADMAP §58's *"failure notifications (Resend)"* was the last unimplemented M2 clause.
ADR-0040 clause 6 deferred it correctly: notifying Workspace Owners and Admins needs their email
addresses, which live in `identity.user`, and ADR-0014 grants the two roles nothing on each other's
data — symmetrically and on purpose. The owner ratified the recipient substitution and the
architecture; this records what implementing it actually decided.

**Decision.**

1. **The destination is a Workspace column, and that is a reuse rather than an invention.** Migration
   `0015` adds one nullable `workspaces.notification_email VARCHAR(320)` — no FK, no default, no
   identity access, and no mention of the `identity` schema (ADR-0014 clause 1 keeps rollback safety
   structural by requiring exactly that). ADR-0017 already faced this problem and the founder already
   answered it: *"an invitation addresses a person by email before they are a user, but the API cannot
   map an email to a Better Auth subject."* The ratified answer was that a human supplies the address
   and it lives in `public`, which `invitations.invited_email` has done since M1.3-F. Same width, same
   `strip().lower()` normalization, so the two email columns cannot disagree about what the "same"
   address is. `workspaces` already carries RLS `ENABLE`+`FORCE`, so the column inherits tenant
   protection without this migration touching RLS at all.

2. **The recipient contract changed, deliberately, and is recorded as changed.** From *"notify
   workspace Owners and Admins"* to *"notify the Workspace's declared notification destination."*
   These are **not** equivalent and nothing downstream may describe them as such. `members` stores
   `user_id` only, deliberately (*"a FK is not merely unnecessary, it is unsatisfiable"*), and
   `HumanIdentity.email` is fenced by ADR-0017 §3 as the one narrow exception to ADR-0015's
   claims-confer-nothing rule — request-scoped, describing only the calling human, and therefore
   unavailable to a Celery worker that holds no JWT. Per-member preferences remain an additive M3
   extension.

3. **Configuration is OWNER-only, and this is `workspace:manage`'s first enforcement anywhere.**
   `PATCH /v1/workspaces/me` writes it; `GET /v1/workspaces/me/notification-settings` reads it. Both
   resolve the permission *before* the service, so authorization cannot be forgotten in a handler.
   Neither accepts a workspace id, so neither is aimable at another tenant, and the repository carries
   the tenant predicate inside the `UPDATE` rather than trusting whatever was loaded. `extra="forbid"`
   keeps `PATCH /me` from becoming a general workspace mutator — accepting-and-ignoring a `plan` field
   would look to the caller like a working billing change.

4. **`notification_email` is deliberately absent from `WorkspaceRead`.** `GET /v1/workspaces/me`
   authenticates with `CurrentWorkspace`, which every **machine token** satisfies — a token has no
   membership and therefore no permissions (ADR-0002). A field added there is a field handed to every
   MCP client holding a workspace token, so the destination gets its own OWNER-gated endpoint instead.

5. **Two triggers, one service.** A completed health check that finds the Connection unhealthy
   publishes `connection.health_check_failed`; the OAuth refresh worker's existing
   `connection.deactivated` is consumed with a **mandatory** `status == "error"` filter. That
   discriminator is not defensive: the same event is emitted with `pending_auth` when a user revokes
   their own credential, and notifying on it would email people for their own deliberate actions. The
   two paths share one service, one Redis key space, and one email template — a second implementation
   is how two triggers drift into two products.

6. **Notification is derived from the state entered, not from a state comparison.** Every "notify" row
   of the ratified matrix depends only on the state being entered and every "no" row likewise, so no
   prior state is derived: deduplication is the anti-spam mechanism, not edge detection. `unknown`
   never notifies, and that is load-bearing — it is exactly what a **platform** refusal reports
   (`rate_limited`, `quota_exceeded`, a fail-closed Redis), which says nothing about the Connection
   (ADR-0040 §5). Treating it as a failure would email a whole Workspace the moment a weekly quota ran
   out. There is no recovery email; canon requires none.

7. **Delivery is post-commit, over the existing bus — no outbox is invented.** The health service
   publishes a fact and stops: it sends nothing, knows no address, touches no Redis, and does not
   import the notifications domain. Events buffer on the `UnitOfWork` and dispatch only after COMMIT
   (ADR-0023), so a rolled-back check notifies nobody, and the bus isolates handler failures, so a
   notification problem can never surface as a failed health check or a failed token refresh.

8. **The worker gained its own event-bus composition root, and it had none.** `app/main.py` registered
   subscribers for the **API** process only — verified empirically: a worker-like import shows an empty
   handler map. Every event published inside a Celery task therefore dispatched to nobody. That is
   invisible for MCP cache eviction, whose TTL bounds a lost eviction by design (ADR-0035 §5), but it
   would have been fatal here, because `connection.deactivated` is published *in the worker* and is the
   unattended failure this feature exists for. `workers/celery_app.py` now registers the notification
   subscribers, and registration is idempotent (`EventBus.is_subscribed`) because a single process
   importing both roots would otherwise enqueue two tasks per failure — invisible in behaviour, since
   dedup still delivers one, while doubling broker traffic. **Deliberately scoped:** MCP's eviction
   handler is *not* registered in the worker here; that would change caching behaviour in a process
   that has never had it, which is outside M2.10. The gap is recorded rather than quietly fixed.

9. **Dedup is one atomic Redis round trip, and its guarantee is stated precisely.**
   `SET ws:{workspace_id}:health-notify:{connection_id}:{event} <task-id> NX GET EX 86400`. The key is
   scoped three ways on purpose: **workspace** so one tenant cannot suppress another, **connection** so
   one failing Connection does not silence the rest, and **event** so `unhealthy` and `needs_reauth`
   are separate windows — a Connection already reporting a provider failure must still be able to
   report that it now needs re-authorization. What this buys:

   > **exactly one notification winner within the TTL window**

   and **not** durable exactly-once email delivery. Both are stated because the second is what a
   reader will otherwise assume.

10. **`NX GET` rather than `SET NX` then `GET`, and the reason is a defect it prevents.** Plain `SET
    NX` gives mutual exclusion but cannot distinguish a *losing worker* from *this same task
    retrying*. `ResendEmailSender` raises on a non-2xx, so an attempt can claim the window and then
    fail to send; a retry blocked by its own claim would silently drop the very email dedup exists to
    protect. Celery preserves the task id across `self.retry` and the claim stores that id, so a retry
    re-enters its own window while a genuinely different worker is still refused — deduplication
    discriminates between *workers*, not between *attempts*. Reading the owner in the same atomic
    operation avoids the window a two-command version would open. Requires Redis ≥ 7.0 for `NX`+`GET`
    together; the deployment pins `redis:7-alpine`. The held path does not rewrite the key, so a loser
    cannot slide the window forward and a busy Connection cannot postpone its own next notification.

11. **Redis unreachable means "do not send", not "assume we won".** Ownership of the window is unknown,
    and sending anyway would convert a Redis outage into one message per worker per retry. The task
    raises and Celery retries; the health verdict, its timestamp, and the audit row are untouched.

12. **The destination is never a task argument.** Celery serializes arguments as JSON into the Redis
    broker, so an address there would be PII at rest — the same rule the OAuth and vault tasks apply to
    secrets. Arguments are two UUIDs and one member of a closed vocabulary, *validated* rather than
    trusted, because a crafted queue entry would otherwise reach a dedup key or a template. Reading the
    destination server-side from the Workspace row is also what makes the task structurally incapable
    of mailing an arbitrary address: there is no parameter through which one could be supplied.

13. **Email content is allowlisted and hostile to its own inputs.** Constants plus the Connection name
    — the one free-text value, which a user typed — HTML-escaped and length-capped. A failure is
    described by the Runtime's **stable enumerated error code**, never `str(exception)`, which for an
    upstream failure can carry provider text and with it a leaked secret. No credential, header, token,
    provider body, traceback, or third-party URL is representable in a message.

**Consequences.** One additive migration (`0015`), reversible, dropping only the column it added; no
existing migration touched and nothing in the `identity` schema mentioned. Three new settings, all with
safe defaults, so an unconfigured deployment behaves exactly as M2.7-A did: no destination means no mail.
One new domain package, one new Celery task on the existing `runtime` queue, and no new dependency,
queue, table, or Redis infrastructure. **ADR-0014 is unchanged**, and no SECURITY DEFINER function and no
`user_id → email` primitive were created.

Proven by 1717 passing tests — 41 domain units, 26 destination-API integration tests, and 42
real-Postgres+RLS+Redis+Runtime end-to-end tests covering both triggers, the platform-refusal row driven
through the real stage-3 enforcement seam, 2/4/8-worker concurrency, TTL and window non-extension, the
accepted Redis-flush duplicate, same-task retry re-entry with a different-worker negative control, Redis
outage, and a canary sweep of the email body, Redis and the Celery arguments with a validated positive
control — plus a 37-mutation audit.

Two defects the tests found and closed before release: an unbounded `notification_email` reached
`VARCHAR(320)` and raised a 500 rather than a validation error, and the task caught only `ValueError`
while `validate_workspace_id` raises `WorkerContextError`, so a malformed identifier crashed into the
retry ladder instead of being refused once.

**Accepted, and stated rather than discovered later:** delivery is best-effort. The bus is at-most-once
(ADR-0023), so a crash between COMMIT and dispatch loses a notification; Redis dedup is not durable, so a
flush or eviction permits one duplicate. Both are acceptable because a missed or duplicated notification
grants no capability — the opposite posture from rate limits and quota, which fail closed because they
are policy. Durable exactly-once delivery is `webhooks_outbox`, which remains **M3**.

**Deferred:** `webhooks_outbox` and durable delivery, per-member notification preferences, scheduled
health checks (no canonical source requires them), the dashboard surface for configuring the destination
(`apps/web` has no product dashboard — M3), and notification channels other than email.
**M2 is NOT complete until this slice is independently audited and promoted.**
