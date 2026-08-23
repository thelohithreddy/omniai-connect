/**
 * The one normalized API failure model for the control plane (ADR-0044 D2, FRONTEND_SPEC §8).
 *
 * Every backend failure — envelope, transport, or timeout — becomes exactly one `ApiFailure`.
 * A single shape is what lets a route render `error.tsx` without each surface inventing its own
 * interpretation of a 403, and it is what keeps raw backend text away from the browser.
 *
 * Two rules the rest of the app depends on:
 *
 * 1. **`kind` drives behaviour, `message` is for humans.** `kind` is a closed union derived from
 *    the HTTP status; the backend's `code` is preserved separately for the cases that need it
 *    (`quota_exceeded` → upgrade prompt). Branching on a stringly-typed backend code at call
 *    sites would spread contract knowledge across the UI.
 * 2. **`requestId` is preserved wherever the backend sent one.** It is the only handle support
 *    has to correlate a customer's screenshot with the structured logs, and the API returns it
 *    on every envelope (docs/API_GUIDELINES.md).
 *
 * What is deliberately absent: stack traces, exception strings, upstream provider text, database
 * errors, resolved addresses, and the backend's internal URL. `message` comes from the API's own
 * envelope — which the backend already constrains to a safe, non-secret phrase — or from a fixed
 * string here. Nothing else is ever copied out of a response.
 */

import type { ApiError } from "@omniai/types";

/**
 * The closed set of failure kinds a control-plane surface can encounter.
 *
 * Named by meaning rather than by status code so a surface reads `unauthorized` instead of
 * `401`, and so a future backend status change is a one-line mapping edit here.
 */
export type ApiFailureKind =
  /** No valid human session, or the JWT was rejected. The caller should re-authenticate. */
  | "unauthenticated"
  /** Authenticated, but the role lacks the permission. Re-authenticating will not help. */
  | "forbidden"
  /** The resource does not exist *in this Workspace* — the API does not distinguish. */
  | "not_found"
  /** Request shape rejected. The backend maps validation to 400 (not 422). */
  | "validation"
  /** State conflict — duplicate name, idempotency clash, connection not active. */
  | "conflict"
  /** Rate limited. Retryable later, never automatically here. */
  | "rate_limited"
  /** The Workspace's quota is exhausted. Drives an upgrade prompt rather than a retry. */
  | "quota_exceeded"
  /** The backend failed. Never surfaces backend detail. */
  | "server_error"
  /** The request never completed: DNS, connection reset, TLS. */
  | "network"
  /** The request exceeded the bounded timeout and was aborted. */
  | "timeout"
  /** A response that does not match the contract at all. */
  | "unexpected";

/**
 * A normalized failure. Deliberately a class so `instanceof` works across the server boundary
 * and so a thrown failure keeps a stack for *server-side* logging while carrying nothing
 * sensitive in the fields a page might render.
 */
export class ApiFailure extends Error {
  readonly kind: ApiFailureKind;
  /** HTTP status, when there was a response at all. */
  readonly status: number | undefined;
  /** The backend's stable error `code`, when the envelope carried one. */
  readonly code: string | undefined;
  /** The backend's `request_id`, for support correlation. */
  readonly requestId: string | undefined;

  constructor(init: {
    kind: ApiFailureKind;
    message: string;
    status?: number;
    code?: string;
    requestId?: string;
  }) {
    super(init.message);
    this.name = "ApiFailure";
    this.kind = init.kind;
    this.status = init.status;
    this.code = init.code;
    this.requestId = init.requestId;
  }

  /**
   * The safe projection for anything that crosses into a client component.
   *
   * Explicitly omits `stack` and `cause`. A server component may pass this object to a client
   * component as props; passing the `Error` itself would serialize a stack trace into the HTML
   * payload, which is exactly the leak this class exists to prevent.
   */
  toClient(): { kind: ApiFailureKind; message: string; code?: string; requestId?: string } {
    return {
      kind: this.kind,
      message: this.message,
      ...(this.code ? { code: this.code } : {}),
      ...(this.requestId ? { requestId: this.requestId } : {}),
    };
  }
}

/** Fixed, non-revealing messages. Used when the backend gave us nothing safe to show. */
const FALLBACK_MESSAGE: Record<ApiFailureKind, string> = {
  unauthenticated: "Your session has expired. Sign in again to continue.",
  forbidden: "You do not have permission to do that.",
  not_found: "That item could not be found.",
  validation: "The request was not valid.",
  conflict: "That conflicts with the current state.",
  rate_limited: "Too many requests. Try again shortly.",
  quota_exceeded: "This workspace has reached its quota.",
  server_error: "Something went wrong on our side.",
  network: "Could not reach the service.",
  timeout: "The request took too long and was cancelled.",
  unexpected: "An unexpected response was received.",
};

/** HTTP status → failure kind. The backend maps validation failures to 400, not 422 (§6). */
export function kindForStatus(status: number, code?: string): ApiFailureKind {
  // `quota_exceeded` and rate limiting share 429; only the backend's code separates them, and
  // the difference matters because one is retryable and the other needs a plan change.
  if (status === 429) return code === "quota_exceeded" ? "quota_exceeded" : "rate_limited";
  if (status === 401) return "unauthenticated";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status === 409) return "conflict";
  if (status === 400 || status === 422) return "validation";
  if (status >= 500) return "server_error";
  return "unexpected";
}

/** True when `value` is the canonical envelope rather than some other JSON body. */
function isEnvelope(value: unknown): value is ApiError {
  if (typeof value !== "object" || value === null) return false;
  const error = (value as { error?: unknown }).error;
  if (typeof error !== "object" || error === null) return false;
  const { code, message } = error as { code?: unknown; message?: unknown };
  return typeof code === "string" && typeof message === "string";
}

/**
 * Build an `ApiFailure` from a non-2xx response.
 *
 * The body is read defensively: a backend that returns HTML from a proxy, an empty body, or
 * malformed JSON must still produce a usable failure rather than throwing inside the error
 * path. Only `code`, `message` and `request_id` are ever copied out — never the whole body,
 * and never `details`, which is free-form and could carry echoed input.
 */
export async function failureFromResponse(response: Response): Promise<ApiFailure> {
  let envelope: ApiError | undefined;
  try {
    const parsed: unknown = await response.json();
    if (isEnvelope(parsed)) envelope = parsed;
  } catch {
    // Not JSON, or no body. Deliberately ignored: the status alone still classifies it.
  }

  const code = envelope?.error.code;
  const kind = kindForStatus(response.status, code);
  const requestId = envelope?.error.request_id;

  // A 5xx message is never taken from the backend even when the envelope carries one: that is
  // the one class where an unhandled exception's text can reach the envelope.
  const message =
    kind === "server_error" || !envelope ? FALLBACK_MESSAGE[kind] : envelope.error.message;

  return new ApiFailure({
    kind,
    message,
    status: response.status,
    ...(code ? { code } : {}),
    ...(requestId ? { requestId } : {}),
  });
}

/**
 * Build an `ApiFailure` from a thrown transport error.
 *
 * `AbortError` is how `AbortSignal.timeout()` surfaces, so it maps to `timeout`; anything else
 * is a network-layer failure. The original error's message is **not** propagated — it can
 * contain the internal API host, which must not reach a browser.
 */
export function failureFromThrown(cause: unknown): ApiFailure {
  const aborted =
    cause instanceof Error && (cause.name === "AbortError" || cause.name === "TimeoutError");
  const kind: ApiFailureKind = aborted ? "timeout" : "network";
  return new ApiFailure({ kind, message: FALLBACK_MESSAGE[kind] });
}

export { FALLBACK_MESSAGE };
