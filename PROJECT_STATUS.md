# PROJECT_STATUS.md

> Living tracker. Updated after every major milestone (and at sprint boundaries).
> AI engineers: read this at session start (per CLAUDE.md). Detail lives in the linked
> docs — this file is the dashboard, not the archive.
>
> **Last updated:** 2026-08-18 · **Updated by:** CTO Agent

## Current phase

**M2 — MCP Interface, credential vault, OAuth: IN PROGRESS.** **M2.6 (Credential Vault Hardening,
ADR-0039; A1/A2/A3/P1/P2 founder-ratified 2026-08-22) is implemented on
`feat/m26-vault-hardening`** — the four ROADMAP §56 vault deliverables: a multi-version local KEK
keyring behind a stable `KeyProvider` seam (no KMS, per ratified A1), HKDF-derived per-workspace
data keys with **version 1 preserved as M1's direct-KEK wrapping forever** (so the hierarchy
arrives *as* a rotation instead of orphaning every stored credential), the five-step rotation
runbook with retirement gated on a database `COUNT(key_version < target) = 0`, a vault access audit
as structured logs + a bounded counter, and redaction extended to the **stdlib logging tree** in all
four deployed processes — a gap verified leaking `api_key=…` from `celery.worker` before the fix.
Migration 0014 is additive (two SECURITY DEFINER functions + a `key_version` index; no table, no
column). 1516 tests green, 24-mutation audit (23 killed, 1 empirically-proven inert, 0 meaningful
survivors), EC3 red-team pass finding **zero** plaintext across every table, the log stream, and
Celery arguments. Default configuration is behaviourally identical to M2.5. Not yet promoted to
`main`.

**M2.5 (OAuth 2.0) is RELEASED to `main`** as the `--no-ff` merge `82cd651` (2026-08-21; implementation `f3d7e35`, audited tree
`d568022`, tree byte-identical to the audited SHA), after an independent adversarial release audit:
post-merge CI 4/4 green, 1457 regression tests, independent mutation subset 7/7 killed (0
survivors) on top of the implementation's 18-mutation audit, Gitleaks clean, `alembic check` clean
with migrations 0001–0012 untouched. The audit found and closed two **test-coverage** defects
(state replay was passing for the wrong reason; the kill switch's refresh half was untested) and
added the M2.4-regression gates proving OAuth opened no bypass around the rate limiter.
**M2 is NOT complete** — vault hardening, Connection Health, MCP streaming/`listChanged`, and
`client_credentials` (M2/P1) remain. **The MCP slice (M2.1 events +
M2.2 tools/list + M2.3 tools/call) is COMPLETE and RELEASED to `main`** as the `--no-ff` merge
`93d9a72` (2026-08-18; tree byte-identical to the verified `63531ae`), post-merge CI 4/4 green,
1375 regression tests, 0 meaningful mutation survivors across the M2.1/2.2/2.3 audits, adversarial
security subset green (cross-tenant, stale-cache-cannot-authorize, SSRF, credential canary,
no-retry). **M1 was COMPLETE and RELEASED to `main`** earlier (final verified SHA `630daf9`,
merged as `7141b2c`, post-merge CI green, 1312 regression tests, 0 meaningful mutation survivors).

**Resolved (M2.4-pre, on `feat/m24-rate-limits-quotas`):** the DNS gap found in the M2.3 release
smoke — `resolve_and_validate` now maps resolver `socket.gaierror` → `SSRFError
("unresolvable-address")`, so an unresolvable-host Tool Call is an audited `ssrf_blocked` denial
on REST and MCP instead of an `internal` 500 with no audit row (resolver-injection unit test +
live-resolver end-to-end test). The M2 decision
gate ran 2026-08-18: MCP auth (workspace `omc_` Bearer token) and the OAuth `auth_config`
contract are canonically defined; the MCP protocol-version pin and Free-tier rate/quota numbers
await founder ratification. Validated M2 order: cache-eviction events (M2.1, done) → MCP
`tools/list` → MCP `tools/call` → rate limits/quotas → OAuth → vault hardening → connection
health. M2.1 (lifecycle events, ADR-0034) is implemented on `feat/m2-cache-eviction-events`;
M2.2 (MCP tools/list, ADR-0035) is implemented on `feat/m22-mcp-tools-list` — the protocol pin
({2025-06-18, 2025-11-25} advertising 2025-11-25), the minimal no-FastMCP adapter, and the
300 s cache TTL were founder-ratified 2026-08-18. M2.3 (MCP tools/call, ADR-0036) is implemented
on `feat/m23-mcp-tools-call` — the execution bridge over the existing Runtime. M2.4 (rate
limits & quotas, ADR-0037; D1–D5 founder-ratified 2026-08-18) is implemented on
`feat/m24-rate-limits-quotas`, together with the M2.4-pre DNS remediation. M2.5 (OAuth 2.0,
ADR-0038; its own D1–D5 ratified 2026-08-21) is implemented on `feat/m25-oauth2`. M2.6 (credential
vault hardening, ADR-0039; A1/A2/A3/P1/P2 ratified 2026-08-22) is implemented on
`feat/m26-vault-hardening`.

**M2 is NOT complete after M2.6.** Remaining: Connection Health (test-call, status states, Resend
notifications), MCP streaming transport + `listChanged`, and `client_credentials` (P1).

<details><summary>M1 phase summary (historical)</summary>

M0 complete. M1.1 (tenancy foundation + machine
identity) merged; the API now authenticates a workspace-scoped token, binds tenant
context, and serves `GET /v1/workspaces/me` with tenant isolation enforced by repository
scoping, Postgres RLS (`FORCE`d, transaction-local GUC), and role separation.</details>

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

_M1-Execution-Runtime (ADR-0031 — M1's critical path: live REST Tool Call execution) in progress on `feat/m14-b0-ingestion-foundation`: the `runtime` domain implements the 7-stage pipeline (AI_RUNTIME §2) behind `POST /v1/tool-calls` (sync) + `GET /v1/tool-calls/{id}`. Resolve Tool by canonical name + bind Connection (RLS-scoped; explicit or single-active, ambiguity→400) → authorize (humans need `tools:execute`/VIEWER denied; a valid workspace-bound machine token qualifies — unscoped=full authority, scope-narrowing deferred) → validate arguments vs `input_schema` → decrypt Credential **in memory only** (`runtime/secrets.py` is the ONLY importer of `vault._unseal`) → build request from `normalized_schema.endpoint` + inject auth per CONNECTOR_SPEC §8 (bearer→`Authorization: Bearer`, basic→base64, api_key→`connectors.auth_config{key_name,location}`) → guarded outbound via a new general `app.core.net.request` (the ONE SSRF policy reused; per-Connection host allowlist re-checked per redirect hop; 1 MiB truncation) → normalize/sanitize response → write the mandatory immutable audit row + publish `tool_call.completed`. New **partitioned** `tool_calls` table (migration `0012`, `PARTITION BY RANGE(created_at)`, composite PK `(id,created_at)`, DEFAULT partition, RLS+FORCE, **SELECT+INSERT grants only**; `connection_id`/`tool_id` plain UUIDs so audit outlives them; `env.py` gained partition-child autogenerate exclusion). Audited failures are **returned, not raised**, so the row survives the request commit ("no audit row, no result"). New `ssrf_blocked` (403) + `upstream_timeout` (504) codes. **api_key runtime-only** (ingested-connector `auth_config` projection deferred); rate limits/quotas/circuit-breaker/async/usage_events deferred M2–M4. 78 new tests (60 unit + 18 real-Postgres+RLS+real-auth API), 47-killed mutation audit (0 meaningful survivors; 2 inert RLS/redundant), real-infra egress (live GitHub 401→502, live httpbin 200 with injected header on the wire, live 169.254.169.254→ssrf_blocked), debug-log scan 0 plaintext, migration up/down/up + `alembic check` clean, full regression at warning+debug. **M1 status: still INCOMPLETE** — remaining: Tools API (list/enable-disable) + audit-log viewer surface, then M2. main untouched._

_M1-Tools-v1 (ADR-0032 — Tools administration API) in progress on `feat/m14-b0-ingestion-foundation`: the control-plane surface for the Tool lifecycle. New `tools` domain (schemas/repository/service/router) at `/v1/tools`: `GET /v1/tools` (list, cursor-paginated, optional `?connector_id=`, unknown params→400), `GET /v1/tools/{id}`, `PATCH /v1/tools/{id}` `{enabled}`. **No migration** — reuses the existing `tools.enabled` column + UPDATE grant; the Runtime already excludes disabled/deprecated tools. Authorization splits by the canonical matrix: **read** = `tools:execute` ("view Tools", owner/admin/member); **enable/disable** = `connectors:manage` (owner/admin); VIEWER + machine tokens denied (admin surface is the human control plane, ADR-0002). Enable/disable is a single atomic conditional UPDATE (race-safe, idempotent); `enabled` is the only mutable field (`extra="forbid"` rejects rewriting name/description/schema/connector identity). Live set = `deleted_at IS NULL` → a deprecated tool is a uniform 404 (no resurrection); a disabled tool cannot execute (proven via the Runtime cross-surface invariant: enable→executes, disable→404). 26 new tests (5 schema unit + 21 real-Postgres+RLS+real-JWT API), 12-killed mutation audit (0 meaningful survivors; 4 inert RLS/refetch-redundant), ruff/format/mypy/alembic clean, full regression at warning+debug. **Deferred:** per-Tool description editing (also FR-CE-4 — needs promotion override-persistence, connectors-domain) and the Audit-log viewer. **M1 status: still INCOMPLETE** — remaining: the Audit-log viewer surface, then M2. main untouched._

_M1-Audit-v1 (ADR-0033 — Audit Log Viewer; the FINAL M1 product surface) in progress on `feat/m14-b0-ingestion-foundation`: a read-only, tenant-isolated view over the existing `tool_calls` ledger (PRD FR-CP-3 / UJ-5). New read-only `audit` domain (schemas/repository/service/router) reading `runtime.models.ToolCall` — **no migration, no new table, no new event** (reuses the ledger + its RLS + append-only SELECT+INSERT grant + the day-one log-UI indexes); issues only SELECTs (PATCH/PUT/DELETE on the resource → 405). New `GET /v1/tool-calls` (list) gated by `audit:read` (owner/admin — "view full audit log"; MEMBER/VIEWER/machine-token denied — the member "own logs" tools:execute view is deferred). Cursor pagination keyset on `(created_at,id)` DESC (deterministic UUIDv7 tie-break, index-backed, LIMIT≤100); canonical UJ-5.3 filters (connection_id, tool_id, status[closed-enum-validated], interface[caller->>'interface'], created_after/before; unknown param/bad status → 400). Explicit `ToolCallLogRead` schema (never raw ORM) — redacted metadata only; `workspace_id`/ciphertext structurally absent. 16 new tests (2 schema unit + 14 real-Postgres+RLS+real-JWT API), 13-killed mutation audit (0 meaningful survivors; 1 inert RLS-redundant), ruff/format/mypy/alembic clean, full regression at warning+debug. **Deferred:** member own-logs view; CSV export + log-explorer UI (frontend). **M1 product surfaces are now COMPLETE** — pending only the final forensic M1 audit. main untouched._

_**M1 RELEASED (2026-08-18):** final forensic audit passed; the verified branch head `630daf9` was merged into `main` as the `--no-ff` merge `7141b2c` (tree byte-identical to the verified SHA); post-merge CI green (4/4 jobs); 1312-test regression green; learning review + M2 architecture discovery complete. The M2 decision gate then ratified: MCP auth = workspace `omc_` Bearer token and the OAuth `auth_config` contract are **canonically defined**; the MCP protocol-version pin (recommended allowlist {2025-06-18, 2025-11-25}) and Free-tier rate/quota numbers **await founder ratification**._

_M2.1 (Cache-eviction event foundation, ADR-0034) on `feat/m2-cache-eviction-events`: the five canonical lifecycle events MCP `tools/list` (M2.2) will consume to evict `ws:{workspace_id}:mcp:tools` — `connection.activated` (credential attach), **`connection.deactivated`** (left the active set un-revoked: credential revoke now, OAuth `error` later; founder-ratified 5th eviction event), `connection.revoked` (stamped from the UPDATE's RETURNING), `tool.enabled`/`tool.disabled` (value-guarded UPDATE: no-op PATCH → 200, no row touch, no event). All on the existing bus (ADR-0023): post-commit dispatch, rollback emits nothing, fail-closed tenant-match (ADR-0022), non-secret identifier payloads. **No migration, no new dependency, no MCP code** (the consumer is M2.2). 20 new tests (8 unit + 12 real-Postgres+RLS+real-JWT integration incl. service-level rollback + cross-tenant no-event), 13-mutation audit (9 killed, 4 inert, 0 meaningful survivors), full regression 1332. main untouched._

_M2.2 (MCP tools/list, ADR-0035) on `feat/m22-mcp-tools-list`: the first MCP surface — `POST /mcp/v1/{workspace_slug}` (sessionless Streamable HTTP JSON-RPC; edge maps mcp.omniaiconnect.com/v1/* here). Founder-ratified: protocol allowlist {2025-06-18, 2025-11-25} advertising 2025-11-25 (2026-07-28 excluded until reconciled with the session model); minimal in-house adapter (no FastMCP — re-evaluated at M2.3); cache TTL 300 s. Machine `omc_` tokens only + token/slug binding + browser-origin refusal; `tools/list` = the Runtime-callable set (live+enabled Tools with an active Connection) via one RLS-backed workspace-scoped query, `(created_at,id) DESC`, strict metadata-only projection (name/description/inputSchema/safety hints). Cache-aside `ws:{id}:mcp:tools` (versioned envelope) evicted by the six ADR-0034 events (trusted-envelope tenant), TTL-bounded against at-most-once event loss; Redis outage degrades to Postgres — never an empty list, never an authz input. `initialize`/`ping`/notifications live; `tools/call` = method-not-found until M2.3. **No migration, no new dependency.** 26 new tests (8 protocol unit + 18 real-Postgres+RLS+Redis+real-auth integration; plus a live-stack smoke), 17-mutation audit (15 killed, 2 inert RLS-redundant, 0 meaningful survivors), full regression 1358. main untouched._

_M2.5 (OAuth 2.0 authorization-code + PKCE, ADR-0038) on `feat/m25-oauth2`: backend-owned dance and callback (D1). New `oauth_states` (migration 0013): single-use, tenant-bound, RLS ENABLE+FORCE + composite intra-tenant FK; `state` SHA-256-hashed, PKCE verifier vault-sealed, consumed atomically via `auth.consume_oauth_state` — the same SECURITY DEFINER carve-out M1 uses for bearer tokens (a second such function returns identifiers only for the refresh sweep). PKCE **S256 only**; server-configured exact-match redirect URI; `auth_config` refuses `client_secret`/token keys; **D3 = authorization_code only, client_credentials remains M2/P1 deferred**. Token exchange/refresh reuse `core/net` (host-pinned allowlist; SSRF → canonical `ssrf_blocked`); tokens sealed into the one Credential per Connection by the credentials domain (PRD §74); **one** new Runtime `oauth2` injection branch serves REST and MCP alike. Refresh on the canonical Celery **`runtime` queue** + beat sweep with jitter; `SELECT … FOR UPDATE` claim + in-lock re-check ⇒ exactly one exchange under concurrency and **no lost rotated refresh token**; terminal failure → `error` + `connection.deactivated`; **`needs_reauth` derived, no fifth status, released CHECK untouched (D5)**; **no `webhooks_outbox` — that is Connection Health (D2)**. 51 new tests (21 config unit + 30 real-Postgres+RLS+vault+Celery integration incl. replay/expiry/concurrency/cross-tenant, PKCE mismatch & downgrade, provider 4xx/5xx/malformed, SSRF, rotation, outage, REST **and** MCP OAuth execution, secret canaries in response/audit/**logs**); 18-mutation audit (17 killed, 1 empirically-proven inert, 0 meaningful survivors); full regression 1448. **RELEASED to main as `82cd651`** after an independent audit that added 9 further gates and closed 2 test-coverage defects (final: 1457 tests, 7/7 independent mutations killed, CI 4/4). **M2 is NOT complete: vault hardening, Connection Health, MCP streaming/listChanged and client_credentials (P1) remain.**_

_M2.4 (Tool-Call rate limits & quotas, ADR-0037) on `feat/m24-rate-limits-quotas`: the Runtime's stage-3 policy checks — one enforcement point in `RuntimeService.execute` (REST and MCP share one budget structurally; adapters untouched). Atomic Redis Lua token bucket on server-side `TIME` (`ws:{id}:rl:tools`, per-Connection `ws:{id}:rl:conn:{cid}` only when canonical `rate_hints` exist); founder-ratified D1–D5: Free = 60/min burst 10 + 1,000 executed calls/ISO-week (UTC), paid plans unenforced until M3; quota consumes executed calls only (succeeded/failed/timeout, exactly once at audit-write; denials/pre-audit/replays never consume); Redis down → **fail closed** both checks; distinct `quota_exceeded` code (§6.1 row added, dormant exception activated); REST 429+`Retry-After`, MCP `isError` via the existing M2.3 mapping; kill switch `RATE_LIMITING_ENABLED` restores exact pre-M2.4 behavior; §7 general request limiter explicitly deferred (D5). **M2.4-pre** shipped first as its own commit: `core/net.py` maps resolver `gaierror` → `SSRFError` — unresolvable hosts are now audited `ssrf_blocked` denials, closing the M2.3-audit gap. **No migration, no new dependency.** 21 new tests (6 period/plan/hint unit + 1 resolver-injection unit + 13 real-Redis+Postgres+RLS integration + 1 DNS end-to-end incl. cross-surface shared budget, 8-way concurrency admitting exactly the burst, fail-closed outage, idempotency non-consumption) + DNS remediation tests; 16-mutation audit (15 killed, 1 inert bucket-TTL-hygiene, 0 meaningful survivors); full regression 1396. main untouched._

_M2.3 (MCP tools/call, ADR-0036) on `feat/m23-mcp-tools-call`: the execution bridge — `tools/call` translates into the *existing* Execution Runtime (`ToolCallCreate` → `RuntimeService.execute` → MCP tool result). One execution authority: the Runtime alone does authorization, Connection resolution, argument validation, credential decrypt-at-use, SSRF/egress, timeout, audit; the MCP adapter (`interfaces/mcp/execution.py`) is pure translation — no HTTP, no vault/crypto imports (structurally grep-verified), no second audit. Re-authorized at execution time → a stale discovery cache can never authorize a disabled/revoked Tool (mandatory test); cross-tenant execution impossible even given B's Tool name; `workspace_id` in arguments is inert. Error split: unresolvable Tool/ambiguous Connection → JSON-RPC error (uniform "Unknown tool."); audited failures (upstream/timeout/ssrf_blocked/credential/bad-args) → `isError:true` result with the stable code, no target/secret/details leaked. No retries (one attempt); audit tagged `caller.interface="mcp"` (new server-set `RuntimeService(interface=...)`, default "rest"). **No migration, no new dependency.** 17 new tests (4 mapping unit + 13 real-Postgres+RLS+real-auth+real-Runtime integration) + two live E2E runs (real execution + real 169.254.169.254 SSRF rejection), 11-mutation audit (10 killed, 1 inert, 0 meaningful survivors), full regression 1375. main untouched._

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
| Token `scopes` stored but not narrowed-on | The runtime's policy stage now exists (ADR-0031) and authorizes any valid workspace-bound token to execute Tool Calls; per-token scope *narrowing* (restricting a token to a subset of Connections/Tools) still awaits the scope vocabulary (PRD FR-IF-3), so an unscoped token has full workspace machine access | Deferred until the scope vocabulary lands |
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
