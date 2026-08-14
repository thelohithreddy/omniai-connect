# Changelog

> Consistent with docs/MASTER_PROJECT_BIBLE.md.

All notable changes to OmniAI Connect are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Every PR
that changes behavior adds an entry under **Unreleased** in the same PR (Bible §6.8);
entries move into a versioned section at release tag time (ADR-0005).

## [Unreleased]

### Added

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
