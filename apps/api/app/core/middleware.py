"""Request-scoped middleware: correlation id in, canonical log line out.

`request_id` is generated per request, or propagated from an inbound `X-Request-Id`
(API_GUIDELINES.md §1) so a caller can correlate across their own systems and ours.

Propagating a client-supplied value into logs is a log-injection vector: a header
containing newlines can forge log entries in a line-oriented sink, and an unbounded one is
a cheap memory-amplification trick. Inbound values are therefore length-capped and
restricted to an alphanumeric charset; anything else is discarded in favour of a fresh id
rather than sanitized in place, because a half-accepted identifier is worse than none.
"""

from __future__ import annotations

import re
import time
from collections.abc import Awaitable, Callable

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.ids import new_request_id
from app.core.logging import get_logger

REQUEST_ID_HEADER = "X-Request-Id"
# `\Z`, not `$`. In Python `$` also matches immediately *before* a trailing newline, so
# `^...$` accepts "abc\n" — and a header value ending in a newline is precisely the
# response-splitting / log-forging primitive this check exists to reject. `\Z` anchors to
# the true end of the string.
_SAFE_REQUEST_ID = re.compile(r"\A[A-Za-z0-9_-]{1,64}\Z")

log = get_logger(__name__)


def _resolve_request_id(raw: str | None) -> str:
    if raw and _SAFE_REQUEST_ID.match(raw):
        return raw
    return new_request_id()


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Bind correlation context, emit one canonical line per request.

    One line per unit of work, not one per step (OBSERVABILITY.md §2): log volume is both
    a cost and a search-noise problem.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = _resolve_request_id(request.headers.get(REQUEST_ID_HEADER))

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)
        request.state.request_id = request_id

        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            # The exception handlers in main.py own the response shape; this only records
            # that the request died, then re-raises so they can do their job.
            log.exception(
                "http.request",
                method=request.method,
                path=request.url.path,
                status=500,
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )
            raise

        response.headers[REQUEST_ID_HEADER] = request_id
        log.info(
            "http.request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
        )
        return response
