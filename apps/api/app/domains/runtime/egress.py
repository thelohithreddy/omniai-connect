"""Outbound egress for the runtime (AI_RUNTIME.md §2 stage 5) — the tenant layer over net.request.

Every Tool Call's outbound HTTP goes through here alone, so the SSRF/allowlist/size/timeout
policy in `app.core.net` is the single egress control (Bible tenet 3). This module adds the
per-Connection **egress allowlist** (may only reach the Connection's own host, re-checked
on every redirect hop) and maps low-level failures onto the runtime's error taxonomy — always with a
safe, secret-free message. It never logs the URL (which may carry a query-placed api_key) or the
request headers/body.
"""

from __future__ import annotations

import httpx

from app.core import net
from app.core.exceptions import EgressBlockedError, UpstreamAPIError, UpstreamTimeoutError
from app.domains.runtime.build import BuiltRequest

#: Per-call response byte budget (AI_RUNTIME.md §2.6 "per-call byte budget"). A fixed 1 MiB in M1:
#: comfortably fits normal JSON tool responses, stays far under the runtime's memory ceiling, and
#: anything larger is truncated with `truncated=True`. The per-Connector-configurable 10 MB hard cap
#: (SECURITY.md §6) and the R2 full-payload pointer for truncated bodies are deferred.
RESPONSE_BYTE_BUDGET = 1 * 1024 * 1024


async def execute_outbound(built: BuiltRequest) -> net.GuardedResponse:
    """Issue the built request under the full guarded-egress policy + the Connection allowlist.

    Translates: an egress-policy refusal → `EgressBlockedError` (ssrf_blocked); a timeout →
    `UpstreamTimeoutError`; any other transport failure → `UpstreamAPIError` (connector_error).
    """
    try:
        return await net.request(
            built.method,
            built.url,
            headers=built.headers,
            content=built.content,
            allowed_hosts=frozenset({built.allowed_host}),
            max_bytes=RESPONSE_BYTE_BUDGET,
        )
    except net.SSRFError as exc:
        raise EgressBlockedError("The outbound request was blocked by egress policy.") from exc
    except httpx.TimeoutException as exc:
        raise UpstreamTimeoutError("The upstream API did not respond in time.") from exc
    except httpx.HTTPError as exc:
        raise UpstreamAPIError("The upstream API could not be reached.") from exc


__all__ = ["RESPONSE_BYTE_BUDGET", "execute_outbound"]
