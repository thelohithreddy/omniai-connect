"""OmniAI Connect API entrypoint.

App factory: middleware, routers, exception handlers (BACKEND_SPEC.md §1).

Every error leaves this application through one of the handlers below, in exactly the
envelope defined in API_GUIDELINES.md §6. That is not stylistic: clients branch on
`error.code`, and support traces incidents by `request_id`, so an endpoint that invents
its own error shape breaks both (P-38, P-50).
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import settings
from app.core.exceptions import DomainError
from app.core.logging import configure_logging, get_logger
from app.core.middleware import REQUEST_ID_HEADER, RequestContextMiddleware
from app.core.readiness import check_readiness
from app.domains.workspaces.router import api_tokens_router
from app.domains.workspaces.router import router as workspaces_router

configure_logging()
log = get_logger(__name__)

app = FastAPI(
    title="OmniAI Connect API",
    version="0.1.0",
    # Interactive docs expose every endpoint and schema. Useful in development, free
    # reconnaissance in production.
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    openapi_url=None if settings.is_production else "/openapi.json",
)

app.add_middleware(RequestContextMiddleware)
app.include_router(workspaces_router)
app.include_router(api_tokens_router)


def _envelope(
    *,
    status_code: int,
    code: str,
    message: str,
    request_id: str,
    details: dict[str, Any] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {"error": {"code": code, "message": message, "request_id": request_id}}
    if details:
        body["error"]["details"] = details
    return JSONResponse(
        status_code=status_code,
        content=body,
        # Repeated here because exception responses bypass the middleware's success path.
        headers={REQUEST_ID_HEADER: request_id},
    )


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "")


@app.exception_handler(DomainError)
async def handle_domain_error(request: Request, exc: DomainError) -> JSONResponse:
    """Expected failures. Logged at warning: actionable, but not our bug."""
    log.warning("request.domain_error", code=exc.code, status=exc.http_status)
    return _envelope(
        status_code=exc.http_status,
        code=exc.code,
        message=exc.message,
        request_id=_request_id(request),
        details=exc.details,
    )


@app.exception_handler(RequestValidationError)
async def handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    """FastAPI's own validation failures, remapped into our envelope.

    Left in FastAPI's default shape they would be the one endpoint family emitting a
    different error format — the exact inconsistency P-38 exists to prevent.
    """
    return _envelope(
        status_code=400,
        code="validation_error",
        message="Request validation failed.",
        request_id=_request_id(request),
        details={"fields": exc.errors()},
    )


@app.exception_handler(StarletteHTTPException)
async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """404s on unrouted paths, 405s, and anything Starlette raises internally."""
    code = {401: "unauthorized", 403: "forbidden", 404: "not_found", 429: "rate_limited"}.get(
        exc.status_code, "internal" if exc.status_code >= 500 else "validation_error"
    )
    return _envelope(
        status_code=exc.status_code,
        code=code,
        message=str(exc.detail),
        request_id=_request_id(request),
    )


@app.exception_handler(Exception)
async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    """Our bug. Generic message outward, full detail to the logs (and Sentry, at M1.2).

    Stack traces and exception text can carry connection strings, query fragments, and
    credential material, so nothing about `exc` reaches the client — only the
    `request_id`, which is enough for support to find everything (P-52).
    """
    log.exception("request.unhandled_error")
    return _envelope(
        status_code=500,
        code="internal",
        message="An unexpected error occurred.",
        request_id=_request_id(request),
    )


@app.get(
    "/health/ready",
    tags=["ops"],
    responses={
        200: {"description": "Every required dependency answered."},
        503: {"description": "A required dependency is unavailable; send no traffic here."},
    },
)
async def readiness(response: Response) -> dict[str, str]:
    """Readiness probe: can this process actually serve production traffic?

    Verifies the two dependencies OBSERVABILITY.md §6 names — PostgreSQL with a cheap
    `SELECT 1`, and a Redis `PING` — and reports one boolean. §6 assigns the two probes
    different jobs: *"Railway uses readiness for deploy gating; liveness for restarts."*
    Failing readiness withdraws this process from the load balancer; failing liveness gets
    it killed. That is why `/health` above checks nothing external and this one does.

    **503 on failure**, because deploy gating requires an unready process to answer
    non-2xx and RFC 9110 §15.6.4 defines 503 as exactly "temporarily unable to handle the
    request". `Retry-After` is deliberately omitted: nothing here can honestly predict when
    a dependency will return, and a wrong hint is worse than none.

    **The body names no dependency.** This endpoint is unauthenticated and, per §6,
    monitored from the public internet; which dependency is failing is diagnosis, and
    diagnosis belongs in the structured log the probes already emit. The orchestrator needs
    the status code, and an operator needs the log line.

    No authentication, no tenant context, no database *state*. Infrastructure must be able
    to call this before any credential exists, and a probe that bound a workspace would
    leave that binding on a pooled connection for the next request to inherit.
    """
    report = await check_readiness()
    if not report.ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        log.warning("readiness.not_ready", **report.as_log_fields())
        return {"status": "not_ready"}
    return {"status": "ready"}


@app.get("/health", tags=["ops"])
async def health() -> dict[str, str]:
    """Liveness probe: the process is up and the event loop is responsive.

    Deliberately checks no dependencies — a Neon or Upstash blip must not restart-loop
    otherwise-healthy processes (OBSERVABILITY.md §6). Readiness (`/health/ready`), which
    does check them, lands with the first dependency the request path actually needs.

    Returns no environment detail: it is unauthenticated, so every field is public.
    """
    return {"status": "ok"}
