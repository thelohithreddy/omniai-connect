# Database Design

> Consistent with docs/MASTER_PROJECT_BIBLE.md. Tenancy model per ADR-0004; migration
> tooling per Bible §7 (Alembic, SQLAlchemy 2 async, PostgreSQL on Neon).
>
> Version 1.0 · 2026-08-02

This document defines the schema conventions, the core entity-relationship model, the
indexing strategy, and the migration rules for the OmniAI Connect PostgreSQL database.
It is a specification: tables described here WILL be created by Alembic migrations as
their owning domains are built (see ROADMAP.md milestones).

## 1. Conventions

- **Naming.** `snake_case` for tables, columns, indexes, and constraints. Tables are
  plural nouns from the canonical domain model (Bible §4): `workspaces`, `connectors`,
  `connections`, `tools`, `tool_calls`, `credentials`. Indexes: `ix_<table>_<cols>`;
  unique constraints: `uq_<table>_<cols>`; foreign keys: `fk_<table>_<col>`.
- **Primary keys.** `id UUID` using **UUIDv7** (time-ordered), generated
  application-side. UUIDv7 keeps B-tree inserts append-friendly (unlike UUIDv4) while
  remaining non-guessable and safe to expose in URLs and API responses.
- **Timestamps.** Every table carries `created_at timestamptz NOT NULL DEFAULT now()`
  and `updated_at timestamptz NOT NULL` (maintained by the SQLAlchemy base mixin).
  All times are UTC; `timestamp without time zone` is forbidden.
- **Tenancy.** Every tenant-owned table carries `workspace_id UUID NOT NULL` referencing
  `workspaces.id`. The only tables without it are `workspaces` itself and global
  reference data (none in v1). Enforced by the shared `WorkspaceScopedBase` mixin and by
  Postgres RLS (§6).
- **Soft delete.** Applied **only where the product requires undo or historical
  integrity**: `connectors`, `connections`, and `tools` use `deleted_at timestamptz NULL`
  (a deleted Connection must not orphan its audit history). Everything else is
  hard-deleted; `tool_calls` and `usage_events` are append-only and never deleted in-band
  (retention is handled by partition dropping, §5). Credentials are hard-deleted on
  revocation — we do not keep dead secrets, even encrypted.
- **Enums.** Stored as `text` with a `CHECK` constraint, not native Postgres enums
  (native enums make additive migrations awkward). Allowed values live in one Python
  module per domain.
- **Intra-tenant foreign keys are composite.** A foreign key from one tenant table to
  another carries `workspace_id` in the key, targeting a `UNIQUE (workspace_id, id)` on
  the referenced table — not a bare reference to its `id`:

  ```sql
  UNIQUE (workspace_id, id),                       -- on the referenced table
  FOREIGN KEY (workspace_id, invited_by)
      REFERENCES members (workspace_id, id)
      ON DELETE SET NULL (invited_by)              -- column-scoped; Postgres 15+
  ```

  This is a tenant-isolation control, not a stylistic preference. **Postgres validates
  referential integrity internally with RLS bypassed**, so a single-column FK lets
  workspace A store a reference to workspace B's row and no policy ever sees it. Carrying
  `workspace_id` into the key makes a cross-tenant reference structurally impossible
  rather than merely unlikely (ADR-0008).

  The `ON DELETE SET NULL` must name its column: a bare `SET NULL` also targets
  `workspace_id`, which is `NOT NULL`, so every parent deletion would fail.

## 2. Core ERD

```mermaid
erDiagram
    workspaces ||--o{ members : "has"
    workspaces ||--o{ api_tokens : "issues"
    workspaces ||--o{ connectors : "owns"
    workspaces ||--o{ connections : "owns"
    workspaces ||--o{ tool_calls : "scopes"
    workspaces ||--o{ usage_events : "scopes"
    workspaces ||--o{ webhooks_outbox : "scopes"
    connectors ||--o{ connector_versions : "versioned as"
    connector_versions ||--o{ tools : "defines"
    connectors ||--o{ connections : "instantiated as"
    connections ||--|| credentials : "authenticates via"
    connections ||--o{ tool_calls : "executes through"
    tools ||--o{ tool_calls : "invoked as"
    members ||--o{ api_tokens : "created by"
```

## 3. Table-by-table

### workspaces
The tenant root (Bible §4). Columns: `id`, `name`, `slug` (unique, URL-safe), `plan`
(`free|pro|team|enterprise`), `stripe_customer_id NULL`, timestamps. No `workspace_id`
on itself. Billing state beyond the plan pointer lives with Stripe, not here.

### members
A user's membership in a Workspace with a role. Columns: `id`, `workspace_id`,
`user_id` (Better Auth subject identifier — identity itself lives in the Next.js layer
per ADR-0002), `role` (`owner|admin|member|viewer`), `invited_by NULL`, timestamps.
Unique on `(workspace_id, user_id)`. Human identity maps to a Member on every API
request; machine identity does not (see `api_tokens`).

### api_tokens
Workspace-scoped machine credentials for AI clients and Interfaces (MCP, REST, SDKs) —
distinct from human sessions per ADR-0002. Columns: `id`, `workspace_id`,
`created_by_member_id`, `name`, `token_hash` (SHA-256 of the secret; plaintext shown
once at creation, never stored), `token_prefix` (first 12 chars — the `omc_` marker plus
8 random chars — for display; lookup is by `token_hash`),
`scopes` (`jsonb`), `last_used_at NULL`, `expires_at NULL`, `revoked_at NULL`,
timestamps. Unique on `token_hash`.

`created_by_member_id` is nullable and stays nullable: a Workspace's first token is minted
before any Member exists, so requiring a creator would make bootstrap impossible. It uses
the composite intra-tenant foreign key convention (§1) —
`(workspace_id, created_by_member_id) REFERENCES members (workspace_id, id)` — because
foreign keys are validated with RLS bypassed, so a single-column reference to `members.id`
would let one Workspace record a creator owned by another. The referential action is
`ON DELETE SET NULL (created_by_member_id)`, column-scoped (PG 15+): a bare `SET NULL`
would also target `NOT NULL` `workspace_id` and make member removal fail, while `CASCADE`
would silently revoke every token an offboarded member issued. Tokens are workspace-owned;
revocation is a separate, explicit act.

### connectors
A definition of an external API: its Tools, auth requirements, and base config
(Bible §4). Columns: `id`, `workspace_id`, `name`, `slug` (unique per workspace),
`source_type` (`openapi3|swagger2|graphql|manual`), `source_url NULL`, `base_url`,
`auth_config` (`jsonb` — auth *requirements*, never secrets), `status`
(`draft|ingesting|active|failed`), `current_version_id NULL` (FK to
`connector_versions`), `deleted_at NULL`, timestamps.

### connector_versions
Immutable snapshots of a Connector's ingested definition (CONNECTOR_ENGINE.md §6).
Columns: `id`, `workspace_id`, `connector_id`, `version` (monotonic integer per
connector), `spec_hash` (content hash of the normalized spec — dedupes no-op re-syncs),
`raw_spec_ref NULL` (R2 object key for the original document), `normalized_schema`
(`jsonb` — the canonical Tool Schema set), `diff_summary` (`jsonb NULL` — added/removed/
changed tools vs. previous version), `created_at`. Rows are never updated or deleted.
Unique on `(connector_id, version)`.

### tools
One callable operation exposed by a Connector (Bible §4), denormalized from its
`connector_version` for query and export speed. Columns: `id`, `workspace_id`,
`connector_id`, `connector_version_id`, `name` (canonical tool name, unique per
connector version), `description`, `input_schema` (`jsonb`, JSON Schema),
`output_hints` (`jsonb NULL`), `annotations` (`jsonb` — read-only vs destructive,
rate hints, tags per CONNECTOR_ENGINE.md), `enabled boolean NOT NULL DEFAULT true`,
`deleted_at NULL`, timestamps.

### connections
A workspace's authenticated instance of a Connector (Bible §4). Columns: `id`,
`workspace_id`, `connector_id`, `name`, `status`
(`pending_auth|active|error|revoked`), `credential_id NULL` (FK to `credentials`;
NULL only while `pending_auth`), `config_overrides` (`jsonb` — e.g. base URL override,
per-connection tool enablement), `last_health_check_at NULL`, `deleted_at NULL`,
timestamps.

### credentials
An encrypted secret bound to a Connection — radioactive per Bible tenet 2. Columns:
`id`, `workspace_id`, `connection_id`, `credential_type`
(`api_key|bearer|basic|jwt|oauth2|custom_headers`), `ciphertext bytea NOT NULL`
(AES-256-GCM envelope-encrypted blob), `encrypted_dek bytea NOT NULL` (data key wrapped
by the master KEK), `key_version int NOT NULL` (which KEK wrapped the DEK — enables
rotation), `nonce bytea NOT NULL`, `expires_at NULL` (OAuth token expiry, drives the
refresh worker), `rotated_at NULL`, timestamps. **Plaintext never touches this table,
logs, or API responses**; decryption happens only inside the Execution Runtime
(AI_RUNTIME.md). No soft delete — revocation deletes the row.

### tool_calls
Append-only audit of every Tool Call (Bible §4: "always audit-logged"). High-volume
and **partition-ready from day one**: declared `PARTITION BY RANGE (created_at)` with
monthly partitions, so the ClickHouse/partition-pruning path in SYSTEM_ARCHITECTURE.md
§6 needs no re-DDL. Columns: `id`, `workspace_id`, `connection_id`, `tool_id`,
`request_id` (correlates with logs), `caller` (`jsonb` — interface type, api_token_id
or member_id), `status` (`succeeded|failed|denied|timeout`), `input_summary`
(`jsonb` — redacted/truncated arguments), `output_summary` (`jsonb` — truncated
response metadata, never raw secrets), `error_code NULL`, `duration_ms int`,
`created_at`. No `updated_at`: rows are immutable. PK is `(id, created_at)` as
partitioning requires the partition key in the PK.

### usage_events
Billing meter feed (Bible §11: usage metered per Tool Call). Columns: `id`,
`workspace_id`, `event_type` (`tool_call_executed|...`), `tool_call_id NULL`,
`quantity int NOT NULL DEFAULT 1`, `occurred_at timestamptz`, `reported_at NULL`
(when pushed to Stripe), `created_at`. Append-only; aggregated by a Celery task.
Kept separate from `tool_calls` so billing semantics can evolve without touching the
audit trail.

### webhooks_outbox
Transactional outbox for outbound notifications (async tool-call completion, connection
health alerts). Columns: `id`, `workspace_id`, `event_type`, `payload` (`jsonb`),
`destination_url`, `status` (`pending|delivering|delivered|dead`), `attempts int`,
`next_attempt_at NULL`, `delivered_at NULL`, timestamps. Written in the same
transaction as the domain change; drained by a Celery worker with exponential backoff.
This is the same outbox pattern the event bus will lean on when the in-process bus
moves to a broker (ADR-0001).

## 4. Indexing strategy

- **Composite indexes lead with `workspace_id`.** Every access path is
  workspace-scoped (Bible tenet 1), so indexes are `(workspace_id, <selective col>)`:
  e.g. `ix_tools_workspace_connector (workspace_id, connector_id)`,
  `ix_connections_workspace_status (workspace_id, status)`,
  `ix_tool_calls_workspace_created (workspace_id, created_at DESC)` for the log UI.
- Lookups that arrive without workspace context first — `api_tokens.token_hash`,
  `workspaces.slug` — get their own unique indexes; the resolved workspace scopes
  everything after.
- `tool_calls` gets `(workspace_id, connection_id, created_at DESC)` for per-connection
  drill-down; partition pruning on `created_at` keeps these small.
- `jsonb` columns get GIN indexes only when a real query needs them (none in v1);
  we do not index speculatively.
- Foreign keys always get a supporting index (Postgres does not create one implicitly).

## 5. Migration rules

1. **Alembic only.** No manual DDL against any environment, ever. Schema-first per
   Bible tenet 5: the migration lands in the same PR as the model change.
2. **One migration per PR.** Multiple heads are a merge failure; CI checks
   `alembic heads` returns exactly one.
3. **Always reversible** — every migration ships a real `downgrade()`. If a migration
   is genuinely irreversible (e.g. dropping a column with data), the `downgrade()`
   raises with an explicit message and the PR description documents why.
4. **No data migrations mixed with schema migrations.** Backfills are separate
   migrations (or Celery one-off tasks for large tables) so schema changes stay fast
   and lock-light on Neon.
5. **Additive-first.** Expand → migrate → contract for renames and type changes; no
   destructive change in the same release that introduces its replacement.
6. Partitioned tables (`tool_calls`): partition creation is automated (a scheduled task
   creates the next month ahead of time); migrations never assume a specific partition
   exists.

## 6. Row-Level Security (per ADR-0004)

RLS is **defense-in-depth**, not the primary isolation mechanism — the repository layer
(BACKEND_SPEC.md §3) remains responsible for scoping every query by `workspace_id`.
From milestone M1, every tenant table gets:

```sql
ALTER TABLE tools ENABLE ROW LEVEL SECURITY;
ALTER TABLE tools FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tools
  USING      (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid)
  WITH CHECK (workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid);
```

This is the exact expression the migrations use; copy it verbatim. Each piece is
load-bearing:

- **`current_setting(..., true)`** — the second argument is `missing_ok`. Without it, an
  unset GUC *raises*, so every query outside a bound request becomes a 500 instead of an
  empty result set.
- **`NULLIF(..., '')`** — `current_setting` can yield `''` rather than `NULL`, and
  `''::uuid` raises. `NULLIF` converts it to `NULL`, and `workspace_id = NULL` is `NULL`,
  which the policy treats as false. Fail closed to zero rows.
- **`WITH CHECK`** — `USING` alone filters reads. Without `WITH CHECK`, a bound tenant can
  still *insert* rows attributed to another workspace: a write-side leak that read-only
  tests never catch.

**`FORCE` is not optional.** `ENABLE` alone exempts the table *owner* from its own
policies. Without `FORCE`, an app connecting as the owner reads every tenant's rows while
the policy sits there looking correct.

**The `app.workspace_id` GUC is transaction-local (`SET LOCAL`), never session-scoped.**
The UnitOfWork issues `SET LOCAL app.workspace_id = …` inside the request's transaction,
so the value dies at COMMIT/ROLLBACK. A session-scoped `SET` survives the connection's
return to the pool, and the next checkout — a different tenant — silently inherits it;
that is a cross-tenant read with a green test suite. Transaction-local scoping is also the
only variant that works through a transaction-mode pooler (PgBouncer, and therefore Neon's
pooled endpoint), where session state is not preserved between transactions.

**Role separation.** Tables are owned by the migration role; the application connects as a
separate role that is neither superuser nor owner. There are **two** unconditional RLS
bypasses and both must be excluded:

| Bypass | Stopped by `FORCE`? | How we exclude it |
|---|---|---|
| `rolsuper` (superuser) | No | App role is not a superuser; migration preflight refuses otherwise |
| `rolbypassrls` | No | App role does not hold `BYPASSRLS`; migration preflight refuses otherwise |
| Table ownership | Yes | App role owns nothing, *and* `FORCE` is set anyway |

`BYPASSRLS` is the easy one to miss: a role can be a non-superuser, own nothing, and still
read every tenant's rows. A suite that asserts only `rolsuper = false` passes green while
isolation is entirely disabled. The integration suite therefore asserts **both** flags are
false for its own connection before asserting anything about isolation.

**Documented exemption.** Credentials that arrive without a workspace context (§4:
`api_tokens.token_hash`) cannot be resolved under RLS, since the policy needs the workspace
the lookup is trying to discover. Exactly one `SECURITY DEFINER` function per such lookup
performs it, and its shape is deliberate: the function is owned by a dedicated **`NOLOGIN`
role** (`omniai_auth`) that no one can connect as, and the table carries a second policy
targeted `TO` that role alone. This grants the exemption through ordinary policy targeting
rather than through `BYPASSRLS` — which needs superuser to grant and is frequently
unavailable on managed Postgres. The function pins `SET search_path`, without which a
caller controlling `search_path` could shadow the target table and have the function read
it under another role's privileges. `EXECUTE` is revoked from `PUBLIC` and granted only to
the application role. No other code path is exempt, and each exemption is reviewed as a
security change.

RLS policies are created in Alembic migrations like any other DDL and covered by
integration tests that assert cross-tenant reads return zero rows, including after
connection reuse.
