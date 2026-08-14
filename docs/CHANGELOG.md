# Changelog

> Consistent with docs/MASTER_PROJECT_BIBLE.md.

All notable changes to OmniAI Connect are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Every PR
that changes behavior adds an entry under **Unreleased** in the same PR (Bible §6.8);
entries move into a versioned section at release tag time (ADR-0005).

## [Unreleased]

### Added

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
