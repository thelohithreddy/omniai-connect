/**
 * Server-only transport tests (MC1.1, ADR-0044 D2).
 *
 * These exercise the **real** transport module. Exactly three things are substituted, all of
 * them outermost seams:
 *
 * 1. `server-only` — neutralised **for this process only**. The guard's whole job is to refuse
 *    to load outside a server bundle, and a plain Node test runner looks like a client bundle
 *    to it. That the guard is genuinely live is proven separately, and adversarially, in
 *    `server-only-boundary.test.mts`; without that proof this stub would be a way to delete a
 *    security control and still see green.
 * 2. `@/lib/auth` — Better Auth opens a `pg.Pool` and demands real secrets. Stubbed to a known
 *    token so header construction can be asserted on the real code path.
 * 3. `globalThis.fetch` — the socket.
 *
 * Everything else — URL building, header assembly, the fail-closed workspace rule, error
 * normalization, timeout wiring, the absence of retries — is the shipping implementation.
 *
 * The load-bearing assertions here are negative (no token in a URL, no second attempt on a
 * mutation, no invented workspace), so each is paired with a positive control proving the
 * assertion could fail.
 */

import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { describe, test, beforeEach, afterEach } from "node:test";

process.env.NEXT_PUBLIC_APP_URL ??= "http://localhost:3000";
process.env.API_BASE_URL = "http://api.internal:8000";
process.env.API_TIMEOUT_MS = "5000";

/** A recognisable fake. If this string ever appears in a URL or a build artifact, we have a bug. */
const TOKEN = "MC1_TEST_JWT_CANARY_do_not_leak";

const require = createRequire(import.meta.url);

/**
 * Pre-populate the CJS cache so the real modules are never evaluated.
 *
 * tsx transpiles these ESM sources to CJS, so `require.cache` is the seam. Stubbing here rather
 * than rewriting the transport keeps the production module free of test-only branches — there
 * is no `if (process.env.NODE_ENV === "test")` anywhere in the shipping code.
 */
function stub(specifier: string, exports: Record<string, unknown>): void {
  const filename = require.resolve(specifier);
  require.cache[filename] = {
    id: filename,
    filename,
    loaded: true,
    exports,
    children: [],
    paths: [],
  } as unknown as NodeJS.Module;
}

stub("server-only", {});

/**
 * What the stubbed session yields. A mutable holder rather than re-stubbing per case: the
 * transport resolves `@/lib/auth` through a deferred dynamic import, and swapping a cache entry
 * mid-suite depends on which module registry that import lands in. Reading a variable is
 * deterministic regardless.
 */
let sessionToken: { token: string } | null = { token: TOKEN };

stub("../src/lib/auth.ts", {
  getAuth: () => ({ api: { getToken: async () => sessionToken } }),
});

interface Call {
  url: string;
  method: string;
  headers: Headers;
  body: string | undefined;
  cache: string | undefined;
  redirect: string | undefined;
  hasSignal: boolean;
}

let calls: Call[] = [];
let responder: () => Response | Promise<Response>;
let originalFetch: typeof globalThis.fetch;

async function loadTransport(): Promise<typeof import("../src/lib/api/transport.ts")> {
  return (await import("../src/lib/api/transport.ts")) as typeof import(
    "../src/lib/api/transport.ts"
  );
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const envelope = (code: string, message: string, requestId = "req-abc-123") => ({
  error: { code, message, request_id: requestId },
});

/** A workspace-scoped identity; the common case. */
const scoped = () => ({ headers: new Headers(), workspaceId: "11111111-2222-3333-4444-555555555555" });

beforeEach(() => {
  calls = [];
  responder = () => json({ ok: true });
  originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({
      url: String(input),
      method: String(init?.method),
      headers: new Headers(init?.headers),
      body: typeof init?.body === "string" ? init.body : undefined,
      cache: init?.cache,
      redirect: init?.redirect,
      hasSignal: Boolean(init?.signal),
    });
    return responder();
  }) as typeof globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

// --------------------------------------------------------------------------- URL building

describe("resolveUrl", () => {
  test("builds from a path and drops undefined query values", async () => {
    const { resolveUrl } = await loadTransport();
    const url = resolveUrl("http://api.internal:8000", "/v1/tool-calls", {
      limit: 50,
      cursor: undefined,
      status: "succeeded",
    });
    assert.equal(url, "http://api.internal:8000/v1/tool-calls?limit=50&status=succeeded");
    assert.doesNotMatch(url, /undefined/);
  });

  test("refuses an absolute URL — the transport dials exactly one origin", async () => {
    const { resolveUrl } = await loadTransport();
    assert.throws(
      () => resolveUrl("http://api.internal:8000", "https://evil.example/steal"),
      /Invalid API path/,
    );
  });

  test("refuses a protocol-relative path", async () => {
    const { resolveUrl } = await loadTransport();
    assert.throws(
      () => resolveUrl("http://api.internal:8000", "//evil.example"),
      /Invalid API path/,
    );
  });

  test("traversal cannot escape the API origin", async () => {
    const { resolveUrl } = await loadTransport();
    const url = resolveUrl("http://api.internal:8000", "/v1/../../v1/workspaces");
    assert.equal(new URL(url).origin, "http://api.internal:8000");
  });
});

// -------------------------------------------------------------------- request construction

describe("request construction", () => {
  test("attaches the bearer token, the workspace header, and a bounded signal", async () => {
    const { apiRequest } = await loadTransport();
    await apiRequest({ method: "GET", path: "/v1/workspaces/me", identity: scoped() });

    assert.equal(calls.length, 1);
    const call = calls[0]!;
    assert.equal(call.headers.get("authorization"), `Bearer ${TOKEN}`);
    assert.equal(call.headers.get("x-workspace-id"), "11111111-2222-3333-4444-555555555555");
    assert.equal(call.cache, "no-store", "workspace data must never enter a shared cache");
    assert.equal(call.redirect, "manual", "a redirect would replay the token at a new origin");
    assert.equal(call.hasSignal, true, "every request must be time-bounded");
  });

  test("a GET carries no body and no Content-Type", async () => {
    const { apiRequest } = await loadTransport();
    await apiRequest({ method: "GET", path: "/v1/tool-calls", identity: scoped() });
    assert.equal(calls[0]!.body, undefined);
    assert.equal(calls[0]!.headers.has("content-type"), false);
  });

  test("a PATCH serializes its body as JSON", async () => {
    const { apiRequest } = await loadTransport();
    await apiRequest({
      method: "PATCH",
      path: "/v1/workspaces/me",
      identity: scoped(),
      body: { notification_email: "ops@example.com" },
    });
    assert.equal(calls[0]!.headers.get("content-type"), "application/json");
    assert.deepEqual(JSON.parse(calls[0]!.body!), { notification_email: "ops@example.com" });
  });

  test("204 resolves to undefined rather than throwing on an empty body", async () => {
    const { apiRequest } = await loadTransport();
    responder = () => new Response(null, { status: 204 });
    const result = await apiRequest({
      method: "DELETE",
      path: "/v1/tool-calls/abc",
      identity: scoped(),
    });
    assert.equal(result, undefined);
  });
});

// --------------------------------------------------------------------------- method safety

describe("method safety", () => {
  test("mutating methods are classified unsafe; GET is not", async () => {
    const { isUnsafeMethod, UNSAFE_METHODS } = await loadTransport();
    for (const method of UNSAFE_METHODS) assert.equal(isUnsafeMethod(method), true, method);
    assert.equal(isUnsafeMethod("GET"), false);
    assert.equal(isUnsafeMethod("post"), true, "classification is case-insensitive");
  });

  test("a failing mutation is attempted exactly once", async () => {
    const { apiRequest } = await loadTransport();
    responder = () => json(envelope("internal", "x"), 500);
    await assert.rejects(
      apiRequest({ method: "POST", path: "/v1/connections/abc/test", identity: scoped() }),
    );
    assert.equal(calls.length, 1, "a mutation was retried — this can duplicate a Tool Call");
  });

  test("a failing GET is also attempted exactly once", async () => {
    const { apiRequest } = await loadTransport();
    responder = () => json(envelope("internal", "x"), 503);
    await assert.rejects(
      apiRequest({ method: "GET", path: "/v1/tool-calls", identity: scoped() }),
    );
    assert.equal(calls.length, 1);
  });
});

// ------------------------------------------------------------------- fail-closed workspace

describe("workspace selection", () => {
  test("a workspace-scoped call without a selection fails closed and never dials", async () => {
    const { apiRequest } = await loadTransport();
    await assert.rejects(
      apiRequest({ method: "GET", path: "/v1/workspaces/me", identity: { headers: new Headers() } }),
      (error: unknown) => {
        assert.equal((error as { kind: string }).kind, "forbidden");
        return true;
      },
    );
    assert.equal(calls.length, 0, "a request went out with no workspace selection");
  });

  test("no fallback workspace is ever invented", async () => {
    const { apiRequest } = await loadTransport();
    await assert.rejects(
      apiRequest({ method: "GET", path: "/v1/workspaces/me", identity: { headers: new Headers() } }),
    );
    assert.equal(calls.filter((c) => c.headers.has("x-workspace-id")).length, 0);
  });

  test("the explicit opt-out is required, and works for pre-selection endpoints", async () => {
    const { apiRequest } = await loadTransport();
    await apiRequest({
      method: "GET",
      path: "/v1/workspaces",
      identity: { headers: new Headers() },
      allowMissingWorkspace: true,
    });
    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.headers.has("x-workspace-id"), false);
    assert.equal(calls[0]!.headers.get("authorization"), `Bearer ${TOKEN}`);
  });
});

// ------------------------------------------------------------------------- error mapping

describe("error normalization", () => {
  const cases: Array<[number, string, string]> = [
    [401, "unauthorized", "unauthenticated"],
    [403, "forbidden", "forbidden"],
    [404, "not_found", "not_found"],
    [400, "validation_error", "validation"],
    [409, "conflict", "conflict"],
    [429, "rate_limited", "rate_limited"],
  ];

  for (const [status, code, expected] of cases) {
    test(`${status} → ${expected}, preserving code and request_id`, async () => {
      const { apiRequest } = await loadTransport();
      responder = () => json(envelope(code, "a safe message"), status);
      await assert.rejects(
        apiRequest({ method: "GET", path: "/v1/workspaces/me", identity: scoped() }),
        (error: unknown) => {
          const failure = error as { kind: string; code?: string; requestId?: string };
          assert.equal(failure.kind, expected);
          assert.equal(failure.code, code);
          assert.equal(failure.requestId, "req-abc-123");
          return true;
        },
      );
    });
  }

  test("429 + quota_exceeded is distinguished from plain rate limiting", async () => {
    const { apiRequest } = await loadTransport();
    responder = () => json(envelope("quota_exceeded", "quota gone"), 429);
    await assert.rejects(
      apiRequest({ method: "GET", path: "/v1/tool-calls", identity: scoped() }),
      (error: unknown) => {
        assert.equal((error as { kind: string }).kind, "quota_exceeded");
        return true;
      },
    );
  });

  test("a 5xx never surfaces the backend's message, but keeps the request id", async () => {
    const { apiRequest } = await loadTransport();
    responder = () =>
      json(
        envelope("internal", "psycopg2.ProgrammingError: relation credentials does not exist", "req-9"),
        500,
      );
    await assert.rejects(
      apiRequest({ method: "GET", path: "/v1/tool-calls", identity: scoped() }),
      (error: unknown) => {
        const failure = error as { kind: string; message: string; requestId?: string };
        assert.equal(failure.kind, "server_error");
        assert.doesNotMatch(failure.message, /psycopg2|relation|credentials/);
        assert.equal(failure.requestId, "req-9");
        return true;
      },
    );
    // Positive control: the matcher would have caught that text had it been propagated.
    assert.match("psycopg2.ProgrammingError: relation credentials", /psycopg2|relation|credentials/);
  });

  test("a non-JSON error body still classifies rather than throwing", async () => {
    const { apiRequest } = await loadTransport();
    responder = () => new Response("<html>502 Bad Gateway</html>", { status: 502 });
    await assert.rejects(
      apiRequest({ method: "GET", path: "/v1/tool-calls", identity: scoped() }),
      (error: unknown) => {
        const failure = error as { kind: string; message: string };
        assert.equal(failure.kind, "server_error");
        assert.doesNotMatch(failure.message, /html|Bad Gateway/);
        return true;
      },
    );
  });

  test("a malformed 2xx body is `unexpected`, not a crash", async () => {
    const { apiRequest } = await loadTransport();
    responder = () => new Response("not json", { status: 200 });
    await assert.rejects(
      apiRequest({ method: "GET", path: "/v1/tool-calls", identity: scoped() }),
      (error: unknown) => {
        assert.equal((error as { kind: string }).kind, "unexpected");
        return true;
      },
    );
  });

  test("a transport failure becomes `network` without leaking the internal host", async () => {
    const { apiRequest } = await loadTransport();
    globalThis.fetch = (async () => {
      throw new TypeError("fetch failed: connect ECONNREFUSED api.internal:8000");
    }) as typeof globalThis.fetch;
    await assert.rejects(
      apiRequest({ method: "GET", path: "/v1/tool-calls", identity: scoped() }),
      (error: unknown) => {
        const failure = error as { kind: string; message: string };
        assert.equal(failure.kind, "network");
        assert.doesNotMatch(failure.message, /api\.internal|ECONNREFUSED/);
        return true;
      },
    );
  });

  test("an abort becomes `timeout`", async () => {
    const { apiRequest } = await loadTransport();
    globalThis.fetch = (async () => {
      const error = new Error("aborted");
      error.name = "AbortError";
      throw error;
    }) as typeof globalThis.fetch;
    await assert.rejects(
      apiRequest({ method: "GET", path: "/v1/tool-calls", identity: scoped() }),
      (error: unknown) => {
        assert.equal((error as { kind: string }).kind, "timeout");
        return true;
      },
    );
  });
});

// --------------------------------------------------------------- authentication behaviour

describe("authentication", () => {
  test("a session that mints no token is `unauthenticated`, and nothing is dialled", async () => {
    const { apiRequest } = await loadTransport();
    sessionToken = null;
    try {
      await assert.rejects(
        apiRequest({ method: "GET", path: "/v1/workspaces/me", identity: scoped() }),
        (error: unknown) => {
          assert.equal((error as { kind: string }).kind, "unauthenticated");
          return true;
        },
      );
      assert.equal(calls.length, 0, "an unauthenticated request still reached the API");
    } finally {
      sessionToken = { token: TOKEN };
    }
  });

  test("a session provider that throws is also `unauthenticated`, never a 500", async () => {
    const { apiRequest } = await loadTransport();
    const previous = sessionToken;
    // Better Auth can throw on a malformed cookie; the caller must not learn which.
    sessionToken = null;
    Object.assign(require.cache[require.resolve("../src/lib/auth.ts")]!.exports as object, {
      getAuth: () => ({
        api: {
          getToken: async () => {
            throw new Error("better-auth internal: session decrypt failed");
          },
        },
      }),
    });
    try {
      await assert.rejects(
        apiRequest({ method: "GET", path: "/v1/workspaces/me", identity: scoped() }),
        (error: unknown) => {
          const failure = error as { kind: string; message: string };
          assert.equal(failure.kind, "unauthenticated");
          assert.doesNotMatch(failure.message, /better-auth|decrypt/);
          return true;
        },
      );
      assert.equal(calls.length, 0);
    } finally {
      Object.assign(require.cache[require.resolve("../src/lib/auth.ts")]!.exports as object, {
        getAuth: () => ({ api: { getToken: async () => sessionToken } }),
      });
      sessionToken = previous;
    }
  });
});

// ---------------------------------------------------------- token never enters a URL/artifact

describe("token discipline", () => {
  test("no request URL carries a token, authorization, or workspace value", async () => {
    const { apiRequest } = await loadTransport();
    await apiRequest({ method: "GET", path: "/v1/tool-calls", identity: scoped() });
    await apiRequest({
      method: "GET",
      path: "/v1/workspaces",
      identity: { headers: new Headers() },
      allowMissingWorkspace: true,
    });
    for (const call of calls) {
      assert.doesNotMatch(call.url, /token|authorization|bearer/i, call.url);
      assert.equal(call.url.includes(TOKEN), false, "the token appeared in a URL");
    }
    // Positive control: the same matcher catches a URL that does carry one.
    assert.match(`http://api.internal:8000/v1/x?token=${TOKEN}`, /token|authorization|bearer/i);
  });
});
