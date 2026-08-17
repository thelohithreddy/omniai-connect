# PROJECT_STATUS.md

> Living tracker. Updated after every major milestone (and at sprint boundaries).
> AI engineers: read this at session start (per CLAUDE.md). Detail lives in the linked
> docs — this file is the dashboard, not the archive.
>
> **Last updated:** 2026-08-15 · **Updated by:** CTO Agent

## Current phase

**M1 — Core platform: IN PROGRESS.** M0 complete. M1.1 (tenancy foundation + machine
identity) merged; the API now authenticates a workspace-scoped token, binds tenant
context, and serves `GET /v1/workspaces/me` with tenant isolation enforced by repository
scoping, Postgres RLS (`FORCE`d, transaction-local GUC), and role separation.

**Deliberate sequencing change:** M1 starts with *machine* identity rather than Better
Auth. The runtime authenticates with workspace-scoped API tokens, not human sessions
(MCP_RUNTIME.md §2, AI_RUNTIME.md §2.1), so tokens unblock the product's actual hot path
while leaving the contested half of ADR-0002 — the cross-language shared-secret split —
open until dashboard work forces the decision. Better Auth moves to M1.2.

## Current sprint

Sprint 1 (2026-08-03 → 2026-08-07): M1.1 merged to `main` as 35e1e91; CI green — see docs/SPRINTS.md.

## Completed work

- Monorepo (pnpm + Turborepo; apps/web Next.js shell, apps/api FastAPI shell with
  passing smoke test), Docker Compose stack, multi-stage Dockerfiles
- CI: lint, typecheck, tests, secret scan (Gitleaks), Docker build (.github/workflows/ci.yml)
- Documentation set: 21 docs in docs/ + CLAUDE.md, AGENTS.md, PROJECT_STATUS.md at root
- Engineering standards locked: coding, API, security, database, branching (ADR-0005)
- Git repo initialized; foundation committed
- **M1.1 — tenancy foundation + machine identity** (2026-08-04): `workspaces` and
  `api_tokens` tables with UUIDv7 PKs and RLS (`ENABLE` + `FORCE`); least-privileged
  `omniai_app` role; `auth.resolve_api_token` SECURITY DEFINER carve-out; application
  spine (UnitOfWork, structlog + `request_id`, domain exceptions, error envelope,
  middleware); `GET /v1/workspaces/me`; Alembic scaffolding; 42 tests including the
  cross-tenant and connection-reuse isolation suite; CI integration lane on real Postgres

## Pending work (next up)

**M1.2** — Better Auth in apps/web + FastAPI session verification (ADR-0002), `members`
table and role matrix, `api_tokens` issue/revoke endpoints, `/health/ready`.
**M1.3+** — OpenAPI ingestion with api_key auth, Execution Runtime v1, audit log, minimal
dashboard slice. docs/ROADMAP.md remains authoritative for M1 scope.

_M1.3-A/B/C/D/E/F/G (member endpoints, human JWT verification, X-Workspace-Id selection, Better Auth web integration, human authorization integration, workspace invitations, session security hardening) **merged to main as c641794** (--no-ff release merge of RC 5fdad07, M1.3-MAINLINE: PASS; 705 tests, CI 4/4 green)._

_M1.4-B0 ingestion infrastructure foundation in progress on `feat/m14-b0-ingestion-foundation` (off main da55652), infra-first per the M1.4-B discovery: **B0.1** guarded SSRF egress fetcher (app/core/net.py, ADR-0020), **B0.2** Celery worker execution foundation (app/workers/, ADR-0021, worker compose service), **B0.3** worker tenant execution boundary (app/workers/context.py `worker_tenant_uow`, ADR-0022 — fail-closed `workspace_id` → existing `SET LOCAL` GUC + `UnitOfWork`, NullPool for the prefork loop; payload is a tenant selector, never authority), and **B0.4** internal event bus (app/core/events.py, ADR-0023 — frozen Pydantic `Event` envelope; in-process now, broker later per BACKEND_SPEC §4; `bus.publish(event)` buffers on the ambient `UnitOfWork` and dispatches after COMMIT so a rollback emits nothing; fail-closed tenant-match; extra=forbid + JsonValue reject authority/arbitrary fields; best-effort at-most-once, no exactly-once claim, not Celery; no migration, no table, no SECURITY DEFINER), and **B0.5** object storage + tenant-key isolation (app/core/object_store.py, ADR-0024 — one `ObjectStore` over the S3 API: R2 in prod, MinIO local/CI via `R2_ENDPOINT`; `aioboto3` confined to the module; tenant isolation is the object key `ws/<workspace_id>/<path>` built only by `TenantObjectKey` from a trusted workspace UUID + explicit allowlist grammar; put/get/head/delete take the key type, never a raw string; config fails closed, TLS-in-prod, no secret leak; MinIO added to compose + CI, storage creds scoped to api+worker; no migration, no table, no public bucket, no presigned URLs) landed with an adversarial key-grammar matrix + fail-closed config + real-MinIO integration (isolation, A×8/B×8/C×8 concurrency, failure modes). main untouched._

_M1.4-B1.1 (OpenAPI 3.0 ingestion, first slice of the importer, ADR-0025) in progress on `feat/m14-b0-ingestion-foundation`: `connector_versions` (migration 0008, immutable, RLS+FORCE, composite intra-tenant FKs) + a hostile-input OpenAPI 3.0 parser/normalizer (`domains/connectors/openapi.py`, safe-YAML/bounded/local-$ref-only/deterministic → canonical Tool Schema) + the async pipeline `POST /v1/connectors/{id}/versions` composing guarded-fetch (B0.1) → normalize → `spec_hash` dedup → store raw (B0.5) → persist version + advance connector → post-commit `connector.ingested` (B0.4) under the worker tenant context (B0.3); `connectors:manage` gate; failure → `failed` + `connector.ingestion_failed`. 55 tests (adversarial parser + real-Postgres+MinIO pipeline + real-HTTP endpoint), 21-mutation audit (0 survivors), live real-worker run. Founder-ratified slice boundary + endpoint/event contracts. main untouched._

_M1.4-B1.2 (file upload + remote `$ref`, ADR-0026) in progress on `feat/m14-b0-ingestion-foundation`: `POST /v1/connectors/{id}/versions` is now multipart/form-data (exactly one of `source_url` or a `file`); uploads are bounded (explicit multipart part-size, ≤10MB, non-empty, unknown fields refused, filename discarded) and staged to the tenant ObjectStore for the worker to read; remote `$ref`s resolve through the SAME one guarded fetcher (B0.1) via an injected callback — the parser's async resolver has no network of its own; all SSRF rules hold, bounds depth≤32/≤10000/≤50MB-aggregate/≤10MB-per-doc, cross-doc cycles broken, per-ingestion URL dedup, remote failure fatal; `spec_hash` is location-independent. One dependency (`python-multipart`); no migration; immutability/RLS/RBAC unchanged. 31 new tests (18 remote-ref + 8 upload endpoint + 5 real-MinIO pipeline), 12-mutation audit (11 killed, 1 inert), live real-worker upload run, full regression 1028 passed. **Deferred to B1.3+:** Swagger 2 → OpenAPI 3, OpenAPI 3.1, `diff_summary`/promotion, the `tools` table, the §17 remote-ref cache, scheduled re-sync. main untouched._

_M1.4-B1.3 (Swagger 2 → OpenAPI 3 conversion, ADR-0027) in progress on `feat/m14-b0-ingestion-foundation`: a **pure, network-free converter** (`domains/connectors/swagger.py`) transforms a parsed Swagger 2.0 dict → an equivalent OpenAPI 3.0.3 dict (no I/O, no DB/ObjectStore/auth/tenant state) as the *single upfront step* of CONNECTOR_ENGINE §3, invoked by one entry (`openapi.to_openapi3`) between parse and normalize; the converted doc is re-validated by the SAME OpenAPI-3 gate, so the ONE importer runs unchanged. **No new dependency, no migration, no API-surface change** (conversion is worker-side). Mapping: definitions/parameters/responses/securityDefinitions → components.*, body → requestBody, formData → form requestBody (multipart on a file field), schemes/host/basePath → servers (metadata, never fetched), consumes/produces → media types, collectionFormat → style/explode, discriminator string → object; local refs rewritten to `#/components/*`, remote refs left untouched (resolve through B1.2's one resolver). Strict detection (`swagger=="2.0"`; both-keys → ambiguous; never inferred from incidental fields); original Swagger bytes stay the canonical `raw_spec_ref`; `spec_hash` unchanged, so Swagger and its native OpenAPI-3 equivalent dedup to one version. 43 new tests (40 converter unit + 3 real-Postgres+MinIO pipeline), 30-mutation audit (0 meaningful survivors), live real-worker Swagger ingestion, full regression at warning+debug. **Deferred to B1.4:** `diff_summary`, promotion, the `tools` table (also OpenAPI 3.1, §17 remote-ref cache, scheduled re-sync, §4 lint-warnings surface). main untouched._

_M1.4-B1.4 (diff + promotion gate + tools projection, ADR-0028 — the FINAL M1.4 slice) in progress on `feat/m14-b0-ingestion-foundation`: a pure deterministic diff engine (`domains/connectors/diff.py` → `{added,removed,changed,breaking}` on source identity; breaking = required-arg-added / arg-removed / type-narrowed per §185) persisted as `connector_versions.diff_summary`; a **promotion gate** — first/additive diffs auto-promote during ingestion, a **breaking** diff is persisted un-promoted (connector keeps serving its current version, no `connector.ingested`) and an owner/admin activates it via `POST /v1/connectors/{id}/versions/{version}/promote` (`connectors:manage`, idempotent, `FOR UPDATE`-serialized); and the **`tools`** table (migration `0009`, RLS+FORCE, composite intra-tenant FKs, SELECT/INSERT/UPDATE grants — no DELETE, partial-unique `(connector_version_id,name) WHERE deleted_at IS NULL`) as a projection of the active version's Tool set (`connector_versions.normalized_schema` authoritative). Promotion swaps the active set (soft-delete old rows, insert new, re-apply `enabled` on identity; removed tools soft-deleted/deprecated). Canon's "used by active Connections" gate refinement + auto-promote setting deferred (Connections are a later module); activation **reuses `connector.ingested`** (§343). 36 new tests (19 diff unit + 11 real-Postgres+MinIO integration + 6 promote-endpoint API), 26-mutation audit (0 meaningful survivors), migration up/down/up, full regression 1101 at warning+debug. **After B1.4: M1.4 is implementation-complete** — the next phase is a dedicated M1.1–M1.4 learning/review, not more features. main untouched._

_M1-Connections-v1 (ADR-0029 — first slice of M1's execution plane, per the M1 master-control audit) in progress on `feat/m14-b0-ingestion-foundation`: a **Connection** = a workspace's authenticated instance of a Connector (Bible §4). New `connections` table (migration `0010`, RLS+FORCE + `tenant_isolation`, composite intra-tenant FK `(workspace_id,connector_id)→connectors`, partial-unique `(workspace_id,name) WHERE deleted_at IS NULL`, SELECT/INSERT/UPDATE grants — no DELETE) + `connections` domain (router→service→repository) at `/v1/connections` (POST/GET/GET{id}/PATCH/DELETE), gated by `connections:manage` (owner/admin). Starts `pending_auth`; binds only a live connector in the same workspace (foreign/deleted → 404). Holds **no secret** — `credential_id` is a nullable placeholder (composite FK added by the future Credentials module, P-43). `status`/`credential_id`/`workspace_id` server-controlled (`extra="forbid"`→400); PATCH mutates name/config only; `base_url` override SSRF-linted via `validate_base_url`; revoke = idempotent soft-delete. Machine tokens denied (`X-Workspace-Id` inert). **Idempotency-Key** honored on create via a minimal connections-scoped Redis store (replay / 409-on-mismatch), with the DB partial-unique as the ultimate dedup. 49 new tests (18 unit + 12 real-Postgres+RLS integration + 19 real-HTTP API), 21-mutation audit (0 meaningful survivors), migration up/down/up, full regression at warning+debug. **M1 status: still INCOMPLETE** — next modules: Credentials → Execution Runtime → REST tool-invocation → Audit. main untouched._

_M1-Credentials-v1 (ADR-0030 — the radioactive execution-plane slice; KEK architecture ratified by the pre-implementation decision gate) in progress on `feat/m14-b0-ingestion-foundation`: an envelope-encrypted secret bound 1:1 to a Connection. New `credentials` table (migration `0011`, RLS+FORCE, composite intra-tenant FK → connections, `UNIQUE(connection_id)`, SELECT/INSERT/UPDATE/**DELETE** grants — hard-delete on revoke) + the additive `connections.credential_id` FK (P-43, NO ACTION). Vault (`domains/credentials/vault.py`): AES-256-GCM, fresh 256-bit DEK per credential wrapped by the env master KEK (`CREDENTIAL_MASTER_KEY`, base64-32, fail-closed on default/short/bad; prod won't boot on a bad key), fresh nonces, GCM tag verified, **AAD=workspace‖connection** (transplant fails). `key_version=1` (M2 rotation deferred; KMS deferred). Endpoints `/v1/connections/{connection_id}/credential` (POST/GET/PUT/DELETE), `connections:manage`; **api_key/bearer/basic only**. **Metadata-only responses** — the secret is never returned/logged/stored in plaintext; decrypt is **private to the vault** (Runtime-only; no router/service/repo/worker decrypts). Attach → `pending_auth→active`; revoke → `pending_auth`. 42 new tests (18 vault unit + 9 real-Postgres+RLS integration + 15 real-HTTP API), 25-mutation audit (0 meaningful survivors), migration up/down/up, full regression at warning+debug. Disposable dev/CI KEK added to compose + CI (never production). **M1 status: still INCOMPLETE** — remaining: Execution Runtime → REST tool-invocation → Audit. main untouched._

_M1.4-A (Connector Engine v1, first slice, ADR-0019) in progress on `feat/m1.4-a-connectors`: the tenant-owned `connectors` domain + manual CRUD + `connectors:manage` (owner/admin) + `base_url` SSRF lint + soft-delete; migration 0007. OpenAPI/Swagger ingestion deferred to M1.4-B (blocked on provisioning a Celery worker service + R2 object storage)._

_M1.3-G (session security hardening, ADR-0018) locked the human session/JWT revocation boundary with tests, hardened the duplicate-`Authorization` header (fail-closed), and recorded the deferred, topology-/product-dependent decisions (deployment origin topology & CORS, immediate JWT revocation, rate limiting, security headers, session-lifetime cap, account-lifecycle) rather than inventing them. No migration; one production-code change._

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
5. **[RESOLVED 2026-08-15 — ADR-0016]** ~~Human workspace-selection mechanism (raised M1.3-B).~~ Decided: the `X-Workspace-Id` header, a selection verified against membership. Implemented in M1.3-C.  
   _Original question, for history:_ When a human belongs
   to more than one Workspace, how does a request select which one it acts in? No canonical
   document defines a mechanism (path segment, header, an "active workspace" in the Better
   Auth session, or a selection endpoint), and FRONTEND_SPEC.md's client-side "workspace
   switcher" is UI state, not server authority. Until this is decided, `get_workspace_context`
   binds a single-membership human to their one workspace and **fails closed (uniform 401)
   for multi-workspace humans** (ADR-0015 §8) — deny-by-default, never a guess. This is a
   public-API-shape decision: it needs a canonical answer before multi-workspace humans can
   authenticate, and whatever the answer, the server must establish membership independently
   of any request-supplied workspace id (a request is a *selection*, never *authority*).

## Technical debt (known, accepted, tracked)

| Item | Why accepted | Pay down by |
|---|---|---|
| ~~No lockfiles committed~~ | **Paid down 2026-08-04**: `uv.lock` committed, CI frozen for both ecosystems | done |
| `api_tokens` has no `created_by_member_id` | The `members` table lands in M1.2; adding the column + FK later is additive (P-43), and an unconstrained UUID nothing populates is dead weight | M1.2 |
| Token `scopes` stored but not enforced | Enforcement belongs to the runtime's policy stage, which does not exist yet. Any valid token currently has full workspace access | M1.3 (Execution Runtime v1) |
| `api_tokens.last_used_at` never written | A write on every authenticated request is write amplification on the hot path; needs throttling or batching before it earns its place | M2, with rate-limit work |
| `scripts/bootstrap_workspace.py` is a privileged seeding path | Refuses to run when `APP_ENV=production`; deleted once the dashboard can create Workspaces | M1.2 |
| @omniai/types hand-written | OpenAPI not stable yet | Generate from spec at M2 |
| packages/config is a placeholder | Only one consumer per config today | When second consumer appears |
| CI also triggers on `develop` | Transition allowance (ADR-0005) | Remove once staging auto-deploy is live |
| Frontend has no test lane | No UI logic to test yet | First interactive dashboard feature |

## Upcoming milestones

M1 core loop → M2 MCP + vault + OAuth → M3 billing + private beta → M4 interfaces +
GraphQL + public launch → M5 scale/enterprise. Exit criteria per milestone: docs/ROADMAP.md.

## High-priority tasks

1. Enable branch protection on `main` (CODEOWNERS is inert without it). Note: branch
   protection is unavailable on this plan for a private repo — either upgrade or accept
   that merges are unguarded.
3. M1.2: Better Auth + `members` + role matrix; revisit ADR-0002 before writing code
   against the cross-language shared-secret split.
4. Decide the private-network egress strategy (ADR-0008). The stated wedge — internal APIs
   no catalog carries — is currently unimplementable: `CONNECTOR_SPECIFICATION.md` §11
   hard-fails RFC 1918 hosts at ingestion, and there is no static egress IP pool, VPC
   peering, or tunnel agent anywhere in the design.

## Blocked tasks

| Task | Blocked on |
|---|---|
| Branch protection on `main` | GitHub plan — unavailable for private repos on the current tier |
| Sentry/PostHog/Better Stack project setup | Account provisioning (founder) |
| Production `omniai_app` role provisioning | Neon project creation; the role is created outside Alembic (it needs a password — P-18) |

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
| CI | 🟢 4 jobs green on `main` @ 35e1e91 (run 31727376094), incl. the integration lane on real Postgres |
| Tests | 🟢 26 passing; isolation suite mutation-tested (reintroducing session-scoped `SET` fails it) |
| Docs ↔ reality drift | 🟡 DATABASE_DESIGN §6 corrected (specified a cross-tenant leak); SPRINTS Sprint 0 corrected (claimed a worker service that does not exist) |
| Security posture | 🟢 tenant isolation enforced and tested in three layers; no secrets in repo; credential vault still unbuilt (M2) |
| Delivery risk | 🟡 single engineer-founder pair; bus factor tracked in RISKS.md |
