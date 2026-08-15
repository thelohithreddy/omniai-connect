# Backend Specification

> Consistent with docs/MASTER_PROJECT_BIBLE.md. Architecture style per ADR-0001
> (modular monolith); auth boundary per ADR-0002; async work per ADR-0007.
>
> Version 1.0 · 2026-08-02

This document specifies how the FastAPI application in `apps/api` is structured and how
code inside it must behave. It is the contract that code review enforces.

## 1. Application layout

```
apps/api/app/
├── main.py               # App factory: middleware, routers, exception handlers
├── core/
│   ├── config.py         # Typed Settings — the ONLY reader of env vars
│   ├── db.py             # Async engine, session factory, UnitOfWork
│   ├── events.py         # Event bus (publish/subscribe contract)
│   ├── logging.py        # structlog configuration
│   ├── security.py       # Token verification (Better Auth JWT + api_tokens)
│   └── exceptions.py     # Domain exception hierarchy + envelope mapping
├── domains/              # One package per domain (see domains/README.md)
│   ├── workspaces/  ├── connectors/  ├── connections/  ├── credentials/
│   ├── tools/       ├── runtime/     ├── billing/      └── audit/
├── interfaces/           # Thin adapters: rest_v1/, mcp/, manifests/
└── workers/              # Celery app, task registration, beat schedule
```

Every domain follows the layout in `apps/api/app/domains/README.md`:
`router.py → service.py → repository.py`, plus `models.py`, `schemas.py`, `events.py`.

## 2. Layering rules

| Layer | Owns | Forbidden |
|---|---|---|
| **Router** | HTTP concerns: path, status codes, request/response schemas, deps | Business logic, DB access, calling another domain |
| **Service** | Business logic, orchestration, publishing domain events | FastAPI imports, raw SQL, HTTP objects |
| **Repository** | All DB access via SQLAlchemy 2 async | Business decisions, cross-domain queries |

- Routers call services, services call repositories. **Never skip a layer.**
- Cross-domain interaction happens through the other domain's **service interface**
  (a plain Python protocol) or through **domain events** — never by importing another
  domain's repository or models. This is the extraction seam ADR-0001 depends on.
- The `interfaces/` adapters (REST v1, MCP, manifests) contain zero business logic
  (Bible tenet 4); they translate protocol messages to service/runtime calls.

## 3. Dependency injection

FastAPI `Depends` is the composition root. Nothing constructs its own session, settings,
or client.

- **`get_uow()`** yields a per-request **UnitOfWork** wrapping one async SQLAlchemy
  session: one request = one session = one transaction, committed on success, rolled
  back on any exception. Services receive the UoW; repositories are constructed from it.
- **`get_workspace_context()`** resolves the caller into a `WorkspaceContext`. For
  machines, a workspace-scoped API token implies the Workspace (ADR-0002). For humans,
  a verified Better Auth JWT (EdDSA/JWKS, ADR-0015) proves identity and the
  `X-Workspace-Id` header selects which of the subject's Workspaces to bind — verified
  against persisted membership, never trusted (ADR-0016). One membership auto-binds;
  many require the header; a foreign/absent/ambiguous selection fails closed. Repositories **require**
  a `WorkspaceContext` to be constructed — an unscoped query is unrepresentable
  (Bible tenet 1). The UoW also sets the `app.workspace_id` GUC for RLS
  (DATABASE_DESIGN.md §6).
- Provider functions live next to what they provide (`core/db.py`, `core/security.py`);
  routers depend on service factories, e.g.
  `service: ConnectorService = Depends(get_connector_service)`.
- Tests override providers via `app.dependency_overrides` — no monkeypatching.

## 4. Internal event bus

Per ADR-0001 the bus is **in-process now, broker later** (Redis Streams is the planned
swap). The contract is designed so callers never notice the swap.

- **Contract:** `bus.publish(event)` where every event is a frozen Pydantic model with
  `event_id` (UUIDv7), `event_type` (e.g. `connector.ingested`,
  `connection.activated`, `tool_call.completed`), `workspace_id`, `occurred_at`, and a
  typed payload. Events are declared in the owning domain's `events.py`.
- **Semantics:** publish is fire-and-forget from the publisher's view; handlers run
  after the publishing transaction commits (buffered on the UoW), so a rolled-back
  request emits nothing. Handlers must be idempotent — the future broker gives
  at-least-once delivery.
- **Subscriptions:** other domains register handlers at startup
  (`bus.subscribe("connector.ingested", handler)`). A handler that needs heavy work
  enqueues a Celery task rather than blocking the request.
- Events crossing the process boundary to customers go through `webhooks_outbox`
  (DATABASE_DESIGN.md), not the internal bus.

## 5. Celery task conventions (ADR-0007)

- Tasks live in `workers/` and the owning domain's task module; queues per concern:
  `ingestion`, `runtime`, `billing`, `outbox`.
- **Every task payload carries `workspace_id` and `request_id`** (SYSTEM_ARCHITECTURE.md
  §7) and only scalar/JSON-safe identifiers — never ORM objects or secrets. The task
  re-loads state and re-binds a WorkspaceContext.
- **Idempotent by design:** tasks check current state before acting (e.g. ingestion
  skips if `spec_hash` unchanged; token refresh skips if not near expiry). Where a
  natural check is absent, a Redis idempotency key (`ws:{workspace_id}:task:{request_id}`)
  guards re-execution.
- **Retry policy:** `autoretry_for` transient errors only (network, 5xx, lock timeout),
  exponential backoff with jitter, `max_retries=5`, then dead-letter with a Sentry
  event. Non-transient failures (validation, 4xx) fail fast — retrying a bad spec five
  times helps nobody.
- Long-running tool calls follow the async contract in AI_RUNTIME.md §5.

## 6. Error handling

- Services raise **domain exceptions** from a shared hierarchy in `core/exceptions.py`:
  `NotFoundError`, `PermissionDeniedError`, `ConflictError`, `QuotaExceededError`,
  `UpstreamAPIError`, `ValidationFailedError` — each with a stable machine `code`.
- A single exception handler in `main.py` maps them to the API error envelope defined
  in API_GUIDELINES.md:

  ```json
  { "error": { "code": "quota_exceeded", "message": "...", "request_id": "..." } }
  ```

- Routers never build error responses by hand; `HTTPException` outside the central
  mapping is a review reject. Unexpected exceptions become a generic `internal_error`
  envelope (no stack traces to clients) and go to Sentry with `request_id`.
- Upstream third-party failures inside the runtime are normalized to
  `UpstreamAPIError` with sanitized detail — upstream bodies may contain secrets or
  prompt-injection payloads (AI_RUNTIME.md §7) and are never echoed verbatim.

## 7. Structured logging (Bible tenet 6)

- **structlog**, JSON output in staging/production, pretty console in development.
- Middleware binds `request_id` (generated or propagated from `X-Request-ID`) and,
  once resolved, `workspace_id` to a contextvar — every log line in the request, and
  every Celery task via its payload, carries both.
- Never logged: credential plaintext or ciphertext, API token secrets, full tool-call
  arguments/responses (summaries only, per DATABASE_DESIGN.md `tool_calls`),
  `Authorization` headers. A redaction processor enforces a denylist of key names.
- Errors → Sentry; product events → PostHog (server-side, keyed by workspace);
  uptime/log drains → Better Stack.

## 8. Testing pyramid

| Level | Scope | Infra |
|---|---|---|
| **Unit** | Services with fake repositories/bus; pure logic, fast, majority of tests | none |
| **Integration** | Repositories + migrations + RLS against a real test Postgres; Celery tasks eagerly executed | Dockerized Postgres/Redis (Neon branch in CI) |
| **Contract** | Each interface adapter (REST v1, MCP, manifests) against recorded expectations, so adapters prove they translate — not reinterpret — runtime behavior | app instance, fake runtime |

- Every bugfix lands with a regression test. Every migration runs upgrade + downgrade
  in CI. Tenant-isolation tests (cross-workspace access attempts) are mandatory for
  every new repository.

## 9. Settings

All configuration flows through `app/core/config.py` (`Settings`, pydantic-settings).
**No other module reads `os.environ`** — new config means a new typed field with a safe
default or explicit requirement, plus a `.env.example` entry (Bible tenet 7). Settings
are injected where practical (`Depends(get_settings)`) so tests can override them.
