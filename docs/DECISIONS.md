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
