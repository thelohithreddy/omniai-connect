# Changelog

> Consistent with docs/MASTER_PROJECT_BIBLE.md.

All notable changes to OmniAI Connect are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Every PR
that changes behavior adds an entry under **Unreleased** in the same PR (Bible §6.8);
entries move into a versioned section at release tag time (ADR-0005).

## [Unreleased]

### Added

- **Connector ingestion: Swagger 2 → OpenAPI 3 conversion (M1.4-B1.3, ADR-0027).** The last
  ingestion-format slice: supported Swagger 2.0 documents now ingest through the existing surfaces.
  Canon (CONNECTOR_ENGINE §3.2) is a *single upfront conversion step, then the OpenAPI 3 importer
  runs — no separate normalization logic*. A new **pure, network-free converter** (`swagger.py`)
  transforms a parsed Swagger 2.0 dict into an equivalent OpenAPI 3.0.3 dict — no I/O, no DB, no
  ObjectStore, no request/auth/tenant state — invoked by one entry (`openapi.to_openapi3`) that the
  worker calls between parse and normalize; the converted doc is re-validated by the **same**
  OpenAPI-3 gate. **No new dependency, no migration, no API-surface change** (conversion is entirely
  worker-side). Mapping: `definitions → components.schemas`, `parameters →
  components.parameters/requestBodies`, `responses → components.responses`, `securityDefinitions →
  components.securitySchemes`, body param → `requestBody`, formData → form requestBody (multipart on
  a file field), `schemes/host/basePath → servers`, `consumes/produces →` media types,
  `collectionFormat → style/explode`, `discriminator` string → object; **local**
  `#/definitions|parameters|responses` refs are rewritten to `#/components/*` while **remote refs are
  left untouched** (they resolve as-is through B1.2's one resolver). **Security:** `host`/`schemes`
  become `servers` **metadata only** — never an ingestion fetch target (the converter does zero I/O;
  ingestion fetches only `source_url`), so a Swagger host can never become an SSRF vector. Detection
  is **strict** (`swagger == "2.0"` exact; a doc declaring both `swagger` and `openapi` is refused as
  ambiguous; never inferred from incidental fields). The **original Swagger bytes stay the canonical
  `raw_spec_ref`**; `spec_hash` is unchanged, so a Swagger doc and its native OpenAPI-3 equivalent
  produce the **same** Tool set and hash (cross-format dedup). Reuses the existing error taxonomy.
  Proven by 40 converter unit tests + 3 real-Postgres+MinIO pipeline tests, a 30-mutation B1.3 audit
  (0 meaningful survivors), a live real-worker Swagger ingestion, and full regression at warning and
  debug. Deferred to B1.4: `diff_summary`, promotion, the `tools` table (also OpenAPI 3.1, the §17
  remote-ref cache, scheduled re-sync, and the §4 lint-warnings surface).
- **Connector ingestion: file upload + remote `$ref` (M1.4-B1.2, ADR-0026).** Extends B1.1 with the
  two remaining source/resolution capabilities. `POST /v1/connectors/{id}/versions` is now
  `multipart/form-data` accepting **exactly one** of a `source_url` field or a `file` upload
  (`connectors:manage`, async, 202 + `ingesting`). Uploads are hostile input: the multipart part
  size is bounded **explicitly** (never the 1 MB framework default), the file is validated
  (non-empty, ≤10 MB), unknown form fields are refused, and the **filename is discarded** (never the
  storage key, the type, or a log line). The worker can't re-fetch an upload, so the API stages the
  bytes to the tenant ObjectStore and the worker reads them back through the tenant-key boundary.
  **Remote `$ref`s** are resolved through the **same one guarded fetcher** (B0.1) — the parser's
  async resolver has no network of its own; it uses an injected fetch callback (§15). All B0.1 SSRF
  rules hold (HTTPS-only prod, no creds/proxy, private/metadata/mapped-IPv6/NAT64 rejected, ≤5
  re-validated redirects); non-http schemes are refused before the fetcher; bounds are depth ≤32,
  ≤10 000 refs, aggregate ≤50 MB, per-doc ≤10 MB; cross-document cycles are broken; each URL is
  fetched once per ingestion (dedup); a remote-ref failure is **fatal**. Because refs are inlined
  before normalization, `spec_hash` depends only on resolved content (location-independent) — a
  changed remote dep → new version. One dependency (`python-multipart`); no migration; immutability/
  RLS/RBAC unchanged. Proven by 31 new tests (18 remote-ref + 8 upload endpoint + 5 real-MinIO
  pipeline), a 12-mutation audit (11 killed, 1 inert), a live real-worker upload run, and full
  regression **1028 passed** at warning and debug. Deferred to B1.3+: Swagger→3, OpenAPI 3.1,
  diff/promotion, the `tools` table, the §17 remote-ref cache.
- **Connector ingestion: OpenAPI 3.0 → canonical Tool Schema (M1.4-B1.1, ADR-0025).** The first
  real ingestion pipeline — `POST /v1/connectors/{id}/versions` (async, `connectors:manage`,
  returns 202 + `ingesting`) composes the foundation: guarded fetch (B0.1) → hostile-input parse +
  deterministic normalize → `spec_hash` dedup → store raw (B0.5) → persist an immutable
  `connector_versions` row (migration 0008, RLS `ENABLE`+`FORCE`, INSERT/SELECT-only grants,
  composite intra-tenant FKs) + advance the connector `ingesting → active` → post-commit
  `connector.ingested {connector_id, connector_version, spec_hash}` (B0.4), all under the worker
  tenant context (B0.3). The parser (`domains/connectors/openapi.py`) treats the spec as hostile:
  JSON/YAML via a hardened `SafeLoader` (no anchors/aliases, no `!!python/...` — no code execution),
  bounded raw size/depth/`$ref` depth+count, non-finite refused, **local `$ref` only** (remote
  refused and unfetchable — the resolver has no network capability), cycles broken. Normalization is
  deterministic (one Tool per `(path, method)`, `{connector_slug}_{op_slug}` names, params+body →
  `input_schema` + `endpoint.binding`, `security→auth`, `servers→base_url`, safety annotations);
  `spec_hash` is version-independent so a no-op re-sync creates no version, a changed spec appends
  the next monotonic version. A hard failure moves the connector to `failed` with a safe
  `reason_code` (no stack traces/URLs/secrets) + `connector.ingestion_failed`. Proven by 55 tests
  (37 adversarial parser + 10 real-Postgres+MinIO pipeline incl. tenant isolation + A×8/B×8
  concurrency + 8 real-HTTP endpoint), a 21-mutation audit with **0 survivors**, and a live
  real-worker run. One dependency (`pyyaml`, `safe_load` only). **Deferred to B1.2+:** file upload,
  remote `$ref`, Swagger 2 → OpenAPI 3, OpenAPI 3.1, `diff_summary`/promotion, the `tools` table.
- **Object storage + tenant-key isolation (M1.4-B0.5, ADR-0024).** One `ObjectStore` abstraction
  (`app/core/object_store.py`) over the S3 API — Cloudflare R2 in production, MinIO in local/CI,
  differing only by `R2_ENDPOINT`. `aioboto3` is the only S3 SDK and is confined to this module (no
  application code touches boto3/botocore). Tenant isolation is the **object key**: every key is
  `ws/<workspace_id>/<path>`, built only by `TenantObjectKey.for_workspace` from a *trusted*
  workspace UUID and an explicit allowlist grammar that rejects traversal, backslashes, encoded
  traversal, null/control chars, whitespace, unicode, absolute/UNC paths, and empty segments —
  before any provider call. `put`/`get`/`head`/`delete` take a `TenantObjectKey`, never a raw
  string, so a caller can never present a cross-tenant or unvalidated key; the single bucket is
  infrastructure, never the tenant boundary, and the provider is never the authorization system.
  Config fails closed (missing settings, and non-TLS in production, are refused — never a silent
  MinIO fallback), errors surface only the S3 code (never the raw SDK string or a credential), and
  the secret stays a `SecretStr`. A MinIO service + deterministic bucket init were added to compose
  and CI; storage credentials are scoped to the api + ingestion worker (dev-only MinIO creds
  locally). No migration, no table, no SECURITY DEFINER, no public bucket, no anonymous access, no
  presigned URLs. Proven by 72 tests (adversarial key grammar + fail-closed config + **real-MinIO**
  PUT/GET/HEAD/DELETE, cross-tenant isolation, A×8/B×8/C×8 concurrency, and failure modes), a
  17-mutation B0.5 audit (16 killed, 1 inert survivor), and a live cross-tenant isolation run. The
  importer that first writes `raw_spec_ref` is M1.4-B1.
- **Internal event bus (M1.4-B0.4, ADR-0023).** The shared-kernel domain-event transport
  (`app/core/events.py`): a frozen Pydantic `Event` envelope (`event_id` UUIDv7, `event_type`
  dotted namespace, `version`, `workspace_id`, `occurred_at` UTC-aware, JSON-safe `payload`) and
  an in-process bus. Per canon (BACKEND_SPEC §4, ADR-0001) it is **in-process now, broker later**:
  `bus.publish(event)` takes no transaction handle (so the future Redis-Streams swap is invisible),
  buffers the event on the ambient `UnitOfWork` via a task-scoped contextvar, and the UoW
  dispatches the buffer **after COMMIT** — a rolled-back transaction emits nothing. Security is
  structural: `extra="forbid"` rejects smuggled authority fields (role/member/token), `JsonValue`
  rejects arbitrary Python objects, `occurred_at` refuses naive timestamps, and
  `UnitOfWork.buffer_event` fails closed unless the event's `workspace_id` equals the transaction's
  bound tenant (ADR-0022 — an event selects WHERE, never WHO/ROLE). Explicit startup registration;
  type-scoped dispatch; handler failures are isolated and logged with envelope identifiers only
  (never the payload); nested dispatch is depth-bounded. Honest limits: best-effort **at-most-once**
  in-process (at-least-once is the future broker's property), **no exactly-once claim**, not a
  Celery replacement, and **no table / no migration / no SECURITY DEFINER**. Proven by 54 tests (48
  unit + 6 real-Postgres integration incl. rollback-emits-nothing, fail-closed tenant-match, and
  A×8/B×8/C×8 concurrency), a 23-mutation B0.4 audit with **0 survivors**, and a live
  publish→commit→dispatch run. No domain event is published yet (that is M1.4-B1).
- **Worker tenant execution boundary (M1.4-B0.3, ADR-0022).** `app/workers/context.py`
  (`worker_tenant_uow`) binds a background task to its tenant **fail-closed**, reusing the
  existing `UnitOfWork` + `SET LOCAL app.workspace_id` GUC — **no second GUC/transaction system,
  no migration, no new SECURITY DEFINER, no new DB role**. Core invariant: **a worker task
  payload must never become authorization** — `workspace_id` selects *WHERE* (the tenant), never
  *WHO/ROLE/PERMISSION*; the boundary reads only `workspace_id` (no `role`/`permission`/`member_id`
  code path). A missing/null/empty/malformed context raises `WorkerContextError` **before any DB
  access** (no default/first/system tenant). Order is load-bearing — *validate → BEGIN → SET
  LOCAL → read-back verify → yield*; the transaction COMMITs tenant writes on success and ROLLs
  BACK on error, and `SET LOCAL` cannot survive to the next task on a reused connection or across
  a rollback/retry. A `NullPool` engine keeps the prefork worker (fresh `asyncio.run` loop per
  task) fork-safe and loop-safe. The worker runs as `omniai_app` (non-superuser, non-BYPASSRLS);
  RLS remains the sole authority. Proven by 18 real-Postgres context tests (fail-closed validation,
  RLS isolation A/B, RLS-*independent* binding-correctness, `SET LOCAL` non-leak via a `pool_size=1`
  reuse proof, rollback cleanup, commit-on-success, A×8/B×8 concurrency), a **real Redis → worker →
  RLS** tenant task + a deployed-worker end-to-end run (returns the RLS-filtered count), and a B0.3
  mutation audit (6 killed, 0 meaningful survivors). No ingestion, event bus, or R2 (B0.4/B0.5/B1).
- **Celery worker execution foundation (M1.4-B0.2, ADR-0021).** The Celery substrate future
  ingestion runs on — `app/workers/celery_app.py` + a scoped `worker` compose service — with
  **no ingestion, tenant-context, event bus, or R2** (those are B0.3/B0.4/B0.5/M1.4-B1).
  Security-sensitive settings are all explicit: **JSON-only serialization (no pickle)**, no
  result backend, a single `ingestion` queue with **no auto-creation**, at-least-once with
  late ack + reject-on-worker-lost, `worker_prefetch_multiplier=1`, hard/soft time limits, a
  bounded/backed-off/jittered retry policy (`max_retries=5`), and **never eager in production**.
  The worker runs `celery worker` (one image, different command; no HTTP port) and its
  environment is hand-scoped so it inherits **no** `BETTER_AUTH_SECRET`/`R2_*`/Stripe/Resend
  secret. Demo tasks (`ping`/`retry_probe`/`always_fails`) prove the substrate only — no
  connector/DB/R2/event touched, no task payload trusted for authority. Proven by 15
  config/security tests, a **real broker+worker** execution + bounded-retry test (`start_worker`,
  not eager), broker-loss resilience (bounded reconnect, no crash-loop), and a 12-mutation B0.2
  audit with 0 survivors. No migration; no new dependency.

- **Guarded egress fetcher — ingestion SSRF foundation (M1.4-B0, ADR-0020).** The first,
  most security-critical slice of the ingestion infrastructure foundation: `app/core/net.py`,
  the one SSRF-safe fetcher connector-spec ingestion will use, built and proven **ahead of**
  any OpenAPI/Swagger importer. **No importer, normalization, `connector_versions`, or `tools`
  — those remain deferred.** Fail-closed properties: `https`-only, no embedded credentials,
  `trust_env=False` (env proxies cannot bypass); DNS resolved-and-validated with the validated
  IP pinned at connect (closes the rebinding TOCTOU) via a custom `httpcore` backend, TLS still
  verifying the real hostname; blocklist covering loopback/unspecified/link-local (incl.
  169.254.169.254 metadata)/private/multicast/reserved across IPv4+IPv6, **unwrapping the
  IPv4-mapped / NAT64 / 6to4 forms `ipaddress.is_private` misses on Python 3.11**; bounded
  (≤5) redirects re-validated per hop with no `https→http` downgrade; a decompressed 10 MB
  size cap with streaming early-abort; and connect/read/total timeouts. Proven by a 44-case
  adversarial matrix; no migration, no new dependency.

- **Connectors — Connector Engine v1, first slice (M1.4-A, ADR-0019).** The tenant-owned
  `connectors` domain: a Connector is a Workspace's definition of an external API (name, base
  URL, auth *requirements*, Tool-Schema status). Manual definition only — OpenAPI/Swagger
  ingestion is deferred (it needs a Celery worker + R2, neither provisioned yet).
  - **Endpoints (`/v1/connectors`):** `POST` (create), `GET` (list, cursor-paginated),
    `GET /{id}`, `DELETE /{id}` — all gated by the new `connectors:manage` permission
    (owner/admin; member/viewer denied), transcribed into SECURITY.md §4.1 and `authz.py`.
  - **Client is never authoritative:** `source_type` is server-fixed to `manual` (no
    client-claimed OpenAPI ingestion), `status` starts `draft`, `workspace_id` comes from the
    bound context, and the request schema is `extra="forbid"`. `auth_config` is requirements
    only — never secrets.
  - **`base_url` SSRF lint** (CONNECTOR_SPECIFICATION §11, SECURITY §6): https only; no
    embedded credentials; no localhost/`.local`/private/loopback/link-local/reserved/metadata
    hosts. Enforced in the service, so MCP/Celery callers are guarded too.
  - **Soft delete** (`deleted_at`) with a partial unique index on `(workspace_id, slug) WHERE
    deleted_at IS NULL` — one live connector per slug; a deleted slug frees up; a foreign or
    soft-deleted id is a uniform 404.
  - **Migration 0007** (additive, reversible; `identity` untouched): `connectors` table with
    RLS `ENABLE`+`FORCE` and the tenant policy. **No SECURITY DEFINER function** — connectors
    are always accessed within a bound workspace. 27 integration tests (authz matrix, contract,
    SSRF, slug-uniqueness, soft-delete, cross-tenant isolation with an RLS-bypassed repository
    proof, pagination, machine/human); connectors mutation audit (A01–A08) left zero survivors.

- **Human session security hardening (M1.3-G, ADR-0018).** Lifecycle hardening *around* the
  released human-auth architecture (Better Auth → EdDSA JWT/JWKS → `X-Workspace-Id` → membership
  → role → RBAC → RLS) — not a redesign. Discovery (7-agent map + a live-stack probe) confirmed
  the core is sound; this locks the settled behavior with tests and closes one asymmetry.
  - **Duplicate `Authorization` header is now rejected, fail-closed** (`extract_bearer_token`).
    A smuggled second `Bearer` can no longer be silently resolved to the first — the identical
    rule ADR-0016 §3 already applies to `X-Workspace-Id`. This is the only production-code change.
  - **The session/JWT revocation boundary is now a tested invariant (ADR-0018):** logout deletes
    the Better Auth session and clears cookies so **no new JWT can be minted**, but an
    already-issued JWT stays valid on the API until its **900 s (15 min)** `exp` — the API holds
    no session state (there is no stateful JWT revocation; the short TTL is the mitigation, Member
    removal is the immediate lever, and clearing `identity.jwks` is the break-glass lever).
  - **New regression/E2E tests** (real Better Auth) pin: the revocation boundary, the 900 s
    lifetime, logout→no-new-JWT, session-token rotation (fixation), the API being
    `Bearer`-only (a session cookie never authenticates it), and a non-string `kid` being a clean
    401 (never a 500).
  - **Adversarial G-series mutation audit (G01–G70): 0 meaningful survivors** (11 constructible
    mutations killed; 3 inert redundant-defense mutations classified honestly).
  - **Documented, not invented:** SECURITY.md §4.8 + ADR-0018 record the session model and every
    deferred, topology-/product-dependent decision (deployment origin topology & CORS,
    immediate revocation, rate limiting → Cloudflare WAF, security headers, session-lifetime cap,
    password reset, account disable/delete, social OAuth). No migration; no schema change.

- **Human workspace invitations (M1.3-F, ADR-0017).** A `members:manage` owner/admin invites
  a person to a Workspace by email; that person accepts with a verified Better Auth identity
  and becomes a Member. The invitation is a temporary membership-establishment mechanism — the
  resulting `members` row is the only authority; the invitation confers nothing.
  - **Endpoints (all `/v1`):** `POST /invitations` (create, `members:manage`),
    `GET /invitations` (list this workspace's pending, `members:manage`),
    `DELETE /invitations/{id}` (cancel, `members:manage`), and `POST /invitations/accept`
    (accept — authenticated human, not gated by membership, since the accepter is joining).
  - **Identity binding is the one narrow, explicitly-authorized exception to ADR-0015's
    claim-distrust rule (ADR-0017 §3).** Acceptance requires a verified JWT whose
    provider-verified email (`emailVerified = true`) equals the invitation's `invited_email`
    (both lower-cased). The email binds the invitation to the identity and nothing else —
    `members.user_id` is always the verified `sub`; role and workspace are server-established.
    An unverified email can never accept.
  - **Token:** 256-bit `secrets.token_urlsafe(32)`; only `SHA-256(token)` is stored; the raw
    token lives only in the delivered email and is never logged or persisted. 7-day expiry,
    server-enforced. Single-use and atomic: acceptance resolves the token pre-RLS through the
    `auth.resolve_invitation` SECURITY DEFINER bootstrap (twin of `auth.resolve_api_token`),
    binds the invitation's workspace, creates the membership, and consumes the invitation under
    `WHERE status = 'pending'` — concurrent acceptances yield exactly one membership.
  - **Already a member → 409, invitation not consumed;** the existing membership stays
    authoritative and its role is never silently changed. At most one pending invitation per
    `(workspace, lower(email))` (partial unique index), so a fresh invite cannot race a stale
    one to a different role.
  - **No enumeration oracle:** bad/expired/cancelled/consumed/foreign/wrong-email acceptances
    all fail with one uniform 404; create/list/cancel disclose only the caller's own tenant.
  - **Delivery via Resend**, a first-party control-plane call (not tenant egress through the
    Execution Runtime); the Resend key, raw token, and invite URL never appear in logs. Better
    Auth email verification enabled (`sendOnSignUp`, non-blocking for sign-in).
  - One additive, reversible migration (0006): the `invitations` table (`workspace_id NOT
    NULL`, RLS ENABLE+FORCE) and the `auth.resolve_invitation` bootstrap function; `identity`
    untouched. Invitation-layer mutation audit (F-series) left zero meaningful survivors.

- **Human authorization integration & hardening (M1.3-E).** Proves the released
  authorization chain (JWT → `X-Workspace-Id` → membership → persisted role → centralized
  RBAC → RLS) end-to-end on **every** protected endpoint through the real human path — not
  just `/v1/members` (M1.3-C) but the api-token endpoints, which shared the same
  `require_permission` dependency yet were unreachable before M1.3-B/C (only machine tokens
  existed, and machines resolve to no membership → always denied). No new authorization
  mechanism: the point is that one already exists and is correct.
  - Full (endpoint × role) matrix over real JWTs: `members:manage` and `api_tokens:manage`
    admit owner/admin and refuse member/viewer/machine; `/v1/workspaces/me` is any member;
    `GET /v1/workspaces` is any human. Plus machine/human separation, cross-tenant fail-
    closed, request-spoofing (JWT/header/query/body-claimed authority all inert), token
    provenance (`created_by_member_id` = the creator's real member row), and a real-provider
    E2E. Enforcement-layer mutation audit (E-series) left zero meaningful survivors.
  - Fixes stale documentation that predated human auth: `authorization.py`'s "the only
    authentication path today issues `kind='api_token'` … deliberately not attached to any
    endpoint" and SECURITY.md's "until human authentication lands (M1.2-G)" — both now false.
  - No production code change beyond the doc corrections; the authorization architecture was
    already complete. No new endpoints, permissions, roles, or migration.

- **Human multi-workspace selection (M1.3-C).** A human who belongs to more than one
  Workspace now names their target with the `X-Workspace-Id` header (ADR-0016). It is a
  *selection*, verified against persisted membership, never authority: the JWT proves who,
  the header states where, the server proves membership, the persisted row proves role,
  RBAC proves what, RLS is the final boundary.
  - `get_workspace_context`'s human path (not a parallel resolver) reads the header, looks
    the subject's memberships up via `auth.resolve_member_workspaces`, and binds only a
    matched one. One membership auto-binds (M1.3-B preserved); many require the header; a
    foreign, absent, malformed, or **duplicate** selector fails closed as the uniform 401,
    with no existence oracle. Duplicate headers are rejected explicitly — Starlette's
    `.get()` returns only the first, so the resolver reads the whole list and denies more
    than one. The role is always re-resolved from the bound member row under RLS; no JWT,
    query, body, cookie, or header claim ever sets role, member_id, or identity.
  - New `GET /v1/workspaces`: a human-only listing of the caller's own memberships as
    `{id, role}` (display role only), so a client can discover what it may select. Backed by
    `auth.resolve_member_workspace_roles` (migration 0005), which reuses migration 0004's
    `members` exemption — no new grant or policy on `workspaces`, and no other tenant's
    existence, name, or metadata is disclosed.
  - Machine authentication is unchanged: a machine token ignores `X-Workspace-Id` (its
    workspace is the token's), and the two planes never cross.
  - Tests: a pure-function policy suite (RLS-independent proof), a full cross-tenant matrix
    with a three-user/two-workspace world (owner/admin/member/viewer), workspace switching,
    membership revocation, role changes, header-parsing edge cases, GUC/connection safety,
    genuine concurrency, a log audit, and a real-provider E2E (live login → JWT →
    `X-Workspace-Id` → RBAC → RLS). Mutation audit C01–C48 left zero meaningful survivors.
  - Resolves the workspace-selection Open Question recorded in M1.3-B. No frontend UI ships
    (none exists yet); the switcher will consume this contract when the dashboard is built.

- **Human JWT authentication in the API (M1.3-B).** FastAPI now verifies Better Auth's
  EdDSA JWTs against the published JWKS and resolves them to a tenant-scoped
  `WorkspaceContext`, completing the human half of ADR-0002. This is the first time an
  authenticated *human* can call the API — every prior request was a machine API token.
  - New `app/core/human_auth.py`: a pinned-EdDSA verifier (algorithm allowlist,
    issuer/audience/lifetime validation, `sub`-only output) over a bounded JWKS cache
    (300 s TTL, single-flight, unknown-`kid` refresh with a cooldown, stale-on-error,
    fail-closed cold). `get_workspace_context` is now the composite resolver BACKEND_SPEC §3
    describes — dispatch by the `omc_` prefix, no fallthrough between planes. Machine
    authentication is byte-for-byte unchanged. Library: `pyjwt[crypto]` (ADR-0015).
  - Migration 0004 adds `auth.resolve_member_workspaces` (SECURITY DEFINER bootstrap twin of
    `auth.resolve_api_token`) and `ix_members_user_id`. A verified subject with exactly one
    membership binds to it; **JWT claims never confer role, permission, or workspace** —
    authorization stays the persisted Member row + the RBAC matrix (ADR-0009).
  - Multi-workspace humans fail closed (uniform 401) pending a workspace-selection decision,
    now a recorded Open Question. Revocation is honest: a JWT is valid until `exp` (≤ 900 s);
    removing the Member is the immediate lockout.
  - Tests: 50-case negative verifier matrix (unit), 22 integration tests (RBAC, tenancy,
    machine/human separation, concurrency/single-flight, log audit), and 4 real-provider
    E2E tests (live Better Auth login → real JWKS → real RLS). CI's API job now builds and
    starts the provider so the E2E tests run for real rather than skip.
  - No FastAPI change to M1.2 machine auth, M1.3-A endpoints, or M1.3-D — verified by the
    full 590-test suite at both log levels.

- **Better Auth human authentication (M1.3-D).** The control plane now has real human
  identity: sign-up, sign-in, sign-out, sessions, and a JWKS document at
  `/api/auth/jwks` that the API will verify against in M1.3-B. Better Auth is mounted at
  the catch-all route `apps/web/src/app/api/auth/[...all]/route.ts`.
  - Its tables live in a dedicated `identity` schema owned by a dedicated `omniai_identity`
    role (ADR-0014). `omniai_app` is granted nothing there and `omniai_identity` cannot read
    tenant tables, so neither credential can reach the other's data. `identity` is invisible
    to Alembic, so `alembic downgrade base` cannot destroy human identity data — the hazard
    that ruled out the `auth` schema, which migration 0001 drops with `CASCADE`.
  - Better Auth owns its own migrations: `pnpm --filter web migrate:identity`, run through
    the library's own `getMigrations` rather than the version-skewed `@better-auth/cli`.
  - Sessions are DB-backed and opaque; JWTs are EdDSA (Ed25519), 15-minute, with `iss`/`aud`
    derived from `BETTER_AUTH_URL` and the signing private key encrypted at rest.
  - `BETTER_AUTH_URL` must be `https://` in production, asserted at construction: Better Auth
    derives the cookie's `Secure` attribute from the scheme, so an http URL would silently
    downgrade every session cookie.
  - Adds an auth contract suite (`pnpm --filter web test`, 20 tests, real Postgres) and a
    database boundary suite (`tests/integration/test_identity_boundary.py`, 11 tests). CI
    gained a Postgres service on the web job and identity provisioning on both.
  - No FastAPI JWT verification yet — that is M1.3-B.

- **Member management endpoints (M1.3-A).** `GET /v1/members`, `PATCH /v1/members/{id}`,
  `DELETE /v1/members/{id}` behind `members:manage` — the router layer M1.2-C deliberately
  left unbuilt. No migration; no change to `MemberService`'s business rules.
  - Keyset cursor pagination per API_GUIDELINES.md §3, ordered `(created_at DESC, id DESC)`,
    reusing `core/pagination.py` from M1.2-G. Unknown query parameters are a
    `validation_error` (§4).
  - `MemberRoleUpdate.role` is a plain `str`, not a `Literal`: the canonical role domain
    already exists as the `members.role` CHECK constraint and `MEMBER_ROLES`, and a third
    copy in a schema could drift from the database.
  - A role change binds on the target's next request — proven by promoting a member and
    watching a previously-403 call return 200.
  - `DELETE` answers 404 for a Member that is absent *or* foreign, byte-identical. §2's
    "deleting a deleted resource is 204" cannot hold simultaneously with its own
    cross-tenant-404 rule for a hard-deleted row; security wins, matching ADR-0012.
  - 53 tests; 22 adversarial mutations with zero survivors.

- **Readiness probe (M1.2-K).** `GET /health/ready` verifies the two dependencies
  OBSERVABILITY.md §6 names — PostgreSQL `SELECT 1` and a Redis `PING` — each bounded at 2 s
  and run concurrently. 200 `{"status":"ready"}` / 503 `{"status":"not_ready"}`.
  - `/health` is unchanged and still checks nothing external, which is the point: a
    dependency blip must withdraw a process from the load balancer, not convince the
    orchestrator to kill every healthy process. Proven by stopping PostgreSQL and Redis for
    real — liveness stayed 200 while readiness returned 503, and both recovered.
  - Unauthenticated, no tenant context, no writes, no transaction left open, and no
    `app.workspace_id` left on a pooled connection.
  - The failure body names no dependency; diagnosis goes to the structured log (ADR-0013).
  - `check_readiness` is total: a probe that raises yields 503, never a 500 with a traceback
    on an unauthenticated endpoint. That defect was found by this module's own tests.
  - 21 tests; 19 adversarial mutations with zero survivors.

- **Token lifecycle verification (M1.2-J).** 18 integration tests exercising create →
  authenticate → list → revoke → denied as one system, through the real endpoints, the real
  resolver and real PostgreSQL. Test-only: no production code changed.
  - Covers what module suites structurally cannot: that the plaintext `POST /v1/api-tokens`
    *returns* authenticates against the real resolver; that a rolled-back creation leaves no
    usable credential and a rolled-back revocation leaves the credential live; that a
    revoked token is inert on every bearer-authenticated route; that pooled connections
    carry no tenant into the next transaction, asserted by reading the GUC directly.
  - Two genuine gaps in the lifecycle suite were found by mutation and closed: it could not
    distinguish application-level tenant scoping from RLS (added an RLS-bypassed check), and
    its pooled-connection test could not detect a session-scoped tenant binding because
    every request rebinds (added a direct GUC observation).
  - One vacuous assertion in the first draft was found and fixed: under `ASGITransport` a
    failing request *raises* rather than returning 500, so an assertion placed after such a
    call never executed.
  - 25 adversarial mutations run against the lifecycle suite alone, with zero survivors.

- **API token revocation (M1.2-H).** `DELETE /v1/api-tokens/{id}` → 204 stops a credential
  working immediately. No migration: `revoked_at` already existed and authentication already
  rejected revoked tokens, so this module supplies only the state transition.
  - A state transition, not a row deletion — the token stays listed with `revoked_at` set,
    which is what makes post-incident review possible. ADR-0012 records the reasoning,
    including why `DELETE` rather than a `/{id}/revoke` action path.
  - Idempotent per API_GUIDELINES.md §2, **preserving the first `revoked_at`**: the UPDATE
    carries `WHERE revoked_at IS NULL`, so a retry cannot rewrite the audit record to the
    time of the retry. Proven with five concurrent revocations producing exactly one
    transition.
  - Requires `api_tokens:manage`. A machine token cannot revoke anything, including itself,
    so a stolen credential cannot cut off the operator's own tokens mid-incident.
  - Cross-tenant and nonexistent targets return byte-identical 404s, so the endpoint is not
    an existence oracle. Creating a token grants no authority over it.
  - 35 tests; 24 adversarial mutations run with zero survivors.

- **API token listing (M1.2-G).** `GET /v1/api-tokens` returns a page of the Workspace's
  token metadata, newest first.
  - Keyset cursor pagination per API_GUIDELINES.md §3 (`limit` default 50, max 100;
    `data`/`next_cursor`/`has_more`), ordered `(created_at DESC, id DESC)` so the sort key is
    unique and pages cannot skip or repeat a row. `has_more` comes from over-fetching one
    row rather than a `count(*)`. ADR-0011 records the design.
  - Requires `api_tokens:manage`, so a machine token cannot enumerate the Workspace's
    credentials — the same boundary that stops it minting one.
  - Metadata only: `ApiTokenRead` has no field able to carry a secret or its digest, asserted
    against the raw response bytes rather than the expected key set.
  - Unknown query parameters are a `validation_error` rather than being silently dropped
    (§4), so a caller cannot believe a misspelled or unsupported filter was applied.
  - No schema change: the existing `(workspace_id, created_at DESC)` index serves the query.
  - 44 tests; 21 adversarial mutations run with zero survivors.

- **API token creation (M1.2-F).** `POST /v1/api-tokens` mints a workspace-scoped machine
  credential and returns its plaintext exactly once.
  - Schema (`alembic/versions/0003_api_token_creator.py`): `api_tokens.created_by_member_id`
    with a **composite** intra-tenant foreign key
    `(workspace_id, created_by_member_id) → members (workspace_id, id)` and column-scoped
    `ON DELETE SET NULL (created_by_member_id)`. Foreign keys are validated with RLS
    bypassed, so a single-column reference would have permitted a creator owned by another
    Workspace. Index leads with `workspace_id` and serves the FK's delete-time scan.
  - `ApiTokenService.issue` generates the secret, hashes it with SHA-256, and persists only
    the digest and a 12-character display prefix. `ApiTokenRepository.create` has no
    parameter capable of accepting a plaintext or a `workspace_id`, so neither storing a
    usable credential nor writing into another tenant is expressible.
  - The endpoint requires `api_tokens:manage` (ADR-0009), so only an `owner` or `admin` may
    mint. A machine token resolves to no membership and is therefore denied: **a token
    cannot mint another token**, so a leaked credential cannot issue a successor that
    outlives revoking the original.
  - Provenance comes from the authenticated Member, never the request. `ApiTokenCreate`
    forbids unknown fields, so supplying `created_by_member_id`, `scopes`, or a chosen
    `token` is a `400 validation_error` rather than a silent no-op.
  - `Cache-Control: no-store` on the creation response (RFC 6749 §5.1).
  - 49 tests, and 36 adversarial mutations run against them with zero survivors.

- **Tenancy foundation and machine identity (M1.1).** First vertical slice of M1: a
  workspace-scoped API token authenticates a caller, binds tenant context, and returns the
  Workspace — with tenant isolation enforced by three independent layers.
  - Schema (`alembic/versions/0001_tenancy_foundation.py`): `workspaces` and `api_tokens`
    with UUIDv7 primary keys, `workspace_id NOT NULL`, and indexes leading with
    `workspace_id`. Row-Level Security is `ENABLE`d **and** `FORCE`d on both, with
    `tenant_isolation` policies keyed on a transaction-local `app.workspace_id`.
  - The application connects as `omniai_app` — neither superuser nor table owner, no
    `BYPASSRLS` — so RLS actually constrains it. The migration refuses to run if that role
    is missing or is a superuser.
  - `auth.resolve_api_token`: a single `SECURITY DEFINER` function with a pinned
    `search_path`, owned by a `NOLOGIN` role, resolving bearer tokens before a workspace is
    known. The only RLS exemption in the schema.
  - Application spine: `core/db.py` (async engine, `UnitOfWork`), `core/logging.py`
    (structlog + `request_id`/`workspace_id` contextvars + secret redaction),
    `core/exceptions.py`, `core/middleware.py`, `core/security.py`, `core/ids.py`.
  - `GET /v1/workspaces/me`, the `workspaces` domain (router → service → repository), and
    the API error envelope applied to every failure path including FastAPI's own.
  - Alembic scaffolding (async `env.py`); `scripts/bootstrap_workspace.py` for local seeding.
  - 42 tests: tenant-isolation integration suite (superuser guard, `FORCE` assertion,
    cross-tenant read/write, connection-reuse leak), token-hashing unit tests, and contract
    tests for the error envelope.

### Changed

- `Settings` now declares every `.env.example` variable and uses `extra="forbid"` with
  `SecretStr`; a misspelled or renamed variable is a boot failure rather than a silent
  fallback to a development default.
- `api.Dockerfile` split into `dev`/`prod` targets. Production no longer runs
  `uvicorn --reload`, installs from `uv.lock` with `--frozen`, and omits dev tooling.
- CI: Postgres + Redis service containers for the integration tier; frozen lockfiles for
  both ecosystems; single-`alembic heads` check; migration up/down/up verification;
  Docker jobs now build the **prod** targets.
- `GET /health` no longer returns `app_env` — it is unauthenticated, so every field is public.

### Fixed

- **A security test was asserting against an empty buffer.** The first version of the
  token log-leak test used pytest's `caplog`, but `configure_logging` installs
  `structlog.PrintLoggerFactory`, which writes to stdout and never reaches stdlib logging —
  so it captured nothing and passed vacuously. Found by mutation testing (deliberately
  logging the secret left the suite green). Now redirects stdout, forces a debug level, and
  asserts that something was emitted before asserting the secret was not.
- **`GeneratedToken` rendered its plaintext in `repr()`.** A dataclass's generated `repr`
  prints every field, and structlog calls `repr()` on non-primitive values, so
  `log.info("issued", token=generated)` or a traceback rendering locals would have emitted
  a live credential. `plaintext` is now excluded from both carriers' reprs.
- **`DATABASE_DESIGN.md` §6 specified a cross-tenant leak.** The RLS section called for a
  *session-scoped* `app.workspace_id`, which survives a pooled connection's return to the
  pool and is inherited by the next tenant's request; it is also unsupported under
  transaction-mode poolers (PgBouncer, Neon's pooled endpoint). Corrected to
  transaction-local `SET LOCAL`, with `FORCE ROW LEVEL SECURITY`, role separation, and the
  token-resolution exemption documented. A regression test asserts the behavior.
- **The web production image could never build.** `web.Dockerfile`'s `prod` stage copies
  `.next/standalone`, which Next.js only emits when `output: "standalone"` is configured —
  it was not. CI built only the `dev` target, so this was invisible.
- `.dockerignore` added: build context dropped from ~453 MB to ~5 kB.
- Credential master key naming reconciled to `CREDENTIAL_MASTER_KEY` across `.env.example`
  and `SECURITY.md` (was `CREDENTIAL_ENCRYPTION_KEY` in the former).
- `apps/api/app/db/` removed in favour of `core/db.py` as specified in BACKEND_SPEC.md §1.

### Added — engineering-foundation documents

- `CLAUDE.md` (AI engineering instruction manual),
  `AGENTS.md` (specialized engineering agent roles), `PROJECT_STATUS.md` (living project
  tracker) at the repository root; `docs/ENGINEERING_PRINCIPLES.md` (engineering
  constitution, P-1…P-71), `docs/CONNECTOR_SPECIFICATION.md` (authoritative Connector
  Engine specification expanding CONNECTOR_ENGINE.md), and `docs/OBSERVABILITY.md`
  (monitoring strategy, SLOs/SLIs/error budgets). Documentation index updated in the
  Bible §9. No code, architecture, or business logic changed.

## [0.1.0] - 2026-08-02

### Added

- Monorepo foundation: `apps/web` (Next.js control plane), `apps/api` (FastAPI modular
  monolith + Celery workers), `packages/types`, `packages/config` (Bible §8).
- Core documentation set: Master Project Bible, System Architecture, Decisions
  (ADR-0001–0007), Security, API Guidelines, Coding Standards, Changelog, Meeting Notes.
- Shared `ApiError` envelope contract in `@omniai/types`.
- Docker images for api and web under `infra/docker/`.
- CI pipeline (GitHub Actions): web lint/typecheck/build, api ruff/mypy/pytest,
  Gitleaks secret scan, Docker image builds.
- Engineering standards locked: uv for Python deps (ADR-0006), trunk-based branching
  with squash merges (ADR-0005), Conventional Commits.

### Notes

- Foundation release only — no business features. Product milestones begin at M1
  (see docs/ROADMAP.md).

[Unreleased]: https://github.com/omniai-connect/omniai-connect/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/omniai-connect/omniai-connect/releases/tag/v0.1.0
