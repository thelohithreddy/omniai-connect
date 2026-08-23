/**
 * The single server-only boundary between the control plane and the API (ADR-0044 D2).
 *
 * `import "server-only"` is the first line for a reason. It is not documentation: the package
 * resolves to a module that throws when bundled for the browser, so a `"use client"` component
 * that imports this file — directly or through any depth of re-export — **fails the build**.
 * That is the mechanically-enforced half of "the browser never receives the backend JWT"; the
 * other half is that there is no CORS middleware on FastAPI, so a browser could not use the
 * token even if it had one.
 *
 * Everything the API needs is attached here and nowhere else:
 *
 * - **Authorization.** A short-lived EdDSA JWT minted by Better Auth from the caller's session
 *   (ADR-0002, ADR-0015). It is requested per call, never cached, never returned, never logged,
 *   and never placed in a cookie, store, prop, or URL.
 * - **`X-Workspace-Id`.** A *selection signal, never authority* (ADR-0016). The API independently
 *   proves membership and resolves the role under RLS. This module refuses to guess one.
 *
 * What this module deliberately does **not** do:
 *
 * - **No retries.** Not for `POST`, `PATCH`, `DELETE` — and not for `GET` either. A generic
 *   retry wrapper is how a single "create Connection" becomes two, and the backend's idempotency
 *   contract is per-endpoint (`Idempotency-Key`), not something a transport may assume.
 * - **No caching.** Every request is `no-store`. Workspace-sensitive data must never land in a
 *   shared cache, and MC1.1 owns no data layer that would justify the risk (ADR-0044 §6).
 * - **No fallback workspace.** Missing selection fails closed rather than picking one.
 */

import "server-only";

import { serverEnv } from "@/lib/env";
import { ApiFailure, failureFromResponse, failureFromThrown } from "@/lib/api/errors";

/** HTTP methods that may not be retried, ever, by anything built on this transport. */
export const UNSAFE_METHODS = ["POST", "PUT", "PATCH", "DELETE"] as const;
export type UnsafeMethod = (typeof UNSAFE_METHODS)[number];
export type HttpMethod = "GET" | UnsafeMethod;

/** True when a method mutates. Exported so tests assert the classification, not a comment. */
export function isUnsafeMethod(method: string): boolean {
  return (UNSAFE_METHODS as readonly string[]).includes(method.toUpperCase());
}

/**
 * How the caller's identity is established for one backend request.
 *
 * `workspaceId` is optional because two endpoints are legitimately pre-selection:
 * `GET /v1/workspaces` (list my memberships) and the invitation-accept flow. Every other
 * control-plane call is workspace-scoped and must pass one.
 */
export interface RequestIdentity {
  /** The caller's inbound request headers — Better Auth reads the session cookie from these. */
  headers: Headers;
  /** The selected Workspace, when the surface is workspace-scoped. */
  workspaceId?: string;
}

export interface ApiRequest<TBody = unknown> {
  method: HttpMethod;
  /** Path only, e.g. `/v1/workspaces/me`. Never an absolute URL — see `resolveUrl`. */
  path: string;
  identity: RequestIdentity;
  /** Serialized as JSON when present. Never included for `GET`. */
  body?: TBody;
  /** Appended as a query string. `undefined` values are dropped, not rendered as "undefined". */
  query?: Record<string, string | number | boolean | undefined>;
  /**
   * Set only when the endpoint is workspace-scoped but the caller genuinely has no selection —
   * currently just `GET /v1/workspaces`. Requires an explicit opt-out so "I forgot" and "this
   * endpoint has no workspace" cannot look the same at a call site.
   */
  allowMissingWorkspace?: boolean;
}

/**
 * Builds the absolute backend URL from a **path**, refusing anything that could redirect the
 * request somewhere else.
 *
 * A caller-supplied absolute URL, a protocol-relative `//evil.example`, or a `..` traversal
 * would each turn this transport into a request forwarder pointed at an attacker's host, with
 * a valid `Authorization` header attached. The API base is the only origin this module will
 * ever dial.
 */
export function resolveUrl(
  base: string,
  path: string,
  query?: ApiRequest["query"],
): string {
  if (!path.startsWith("/") || path.startsWith("//")) {
    throw new ApiFailure({
      kind: "unexpected",
      message: "Invalid API path.",
    });
  }

  const url = new URL(base.replace(/\/+$/, "") + path);

  // `new URL` resolves `..` itself; comparing origins afterwards catches any construction that
  // escaped the intended base.
  if (url.origin !== new URL(base).origin) {
    throw new ApiFailure({ kind: "unexpected", message: "Invalid API path." });
  }

  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined) url.searchParams.set(key, String(value));
  }
  return url.toString();
}

/**
 * Mint a backend JWT for the caller's session.
 *
 * Deferred import: `@/lib/auth` constructs a `pg.Pool` on first use, and pulling that into the
 * module graph of every route that merely imports the transport would open identity-database
 * connections for requests that never authenticate.
 *
 * A missing or rejected session is `unauthenticated` — never a 500, and never anything that
 * hints at *why*, matching the API's own uniform human-auth failure (ADR-0016 §4).
 */
async function mintToken(headers: Headers): Promise<string> {
  const { getAuth } = await import("@/lib/auth");
  let token: string | undefined;
  try {
    const result = await getAuth().api.getToken({ headers });
    token = (result as { token?: string } | null)?.token;
  } catch {
    // Swallowed deliberately. The thrown value can carry Better Auth internals; the caller
    // gets the same uniform failure whether the session was absent, expired, or malformed.
    token = undefined;
  }
  if (!token) {
    throw new ApiFailure({
      kind: "unauthenticated",
      message: "Your session has expired. Sign in again to continue.",
    });
  }
  return token;
}

/**
 * Perform one backend request. The only way the control plane talks to FastAPI.
 *
 * Returns parsed JSON on 2xx, `undefined` on 204, and throws `ApiFailure` on anything else.
 * Throwing rather than returning a result union is deliberate: a forgotten `if (result.ok)`
 * silently renders an error as data, whereas a forgotten `try` surfaces in `error.tsx`.
 */
export async function apiRequest<TResponse, TBody = unknown>(
  request: ApiRequest<TBody>,
): Promise<TResponse> {
  const env = serverEnv();

  if (!request.identity.workspaceId && !request.allowMissingWorkspace) {
    // Fail closed. Never fall back to "the first workspace" — that is precisely the confused
    // deputy ADR-0016 refuses at the API, and the frontend must not reintroduce it.
    throw new ApiFailure({
      kind: "forbidden",
      message: "No workspace is selected.",
    });
  }

  const token = await mintToken(request.identity.headers);
  const url = resolveUrl(env.API_BASE_URL, request.path, request.query);

  const headers = new Headers({
    Authorization: `Bearer ${token}`,
    Accept: "application/json",
  });
  if (request.identity.workspaceId) {
    headers.set("X-Workspace-Id", request.identity.workspaceId);
  }
  if (request.body !== undefined && request.method !== "GET") {
    headers.set("Content-Type", "application/json");
  }

  let response: Response;
  try {
    response = await fetch(url, {
      method: request.method,
      headers,
      ...(request.body !== undefined && request.method !== "GET"
        ? { body: JSON.stringify(request.body) }
        : {}),
      // Workspace-sensitive by default. Nothing here may enter a shared cache (ADR-0044 §6).
      cache: "no-store",
      // Bounded by construction; an unbounded server fetch stalls the render that awaits it.
      signal: AbortSignal.timeout(env.API_TIMEOUT_MS),
      // No `redirect: "follow"` beyond the default: the API never redirects a JSON endpoint,
      // and following one would replay the Authorization header at a new origin.
      redirect: "manual",
    });
  } catch (cause) {
    throw failureFromThrown(cause);
  }

  if (!response.ok) {
    throw await failureFromResponse(response);
  }

  if (response.status === 204) {
    return undefined as TResponse;
  }

  try {
    return (await response.json()) as TResponse;
  } catch {
    throw new ApiFailure({
      kind: "unexpected",
      message: "An unexpected response was received.",
      status: response.status,
    });
  }
}
