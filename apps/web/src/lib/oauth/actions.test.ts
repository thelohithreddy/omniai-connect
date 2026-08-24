import { beforeEach, describe, expect, test, vi } from "vitest";

import { ApiFailure } from "@/lib/api/errors";

/**
 * OAuth authorization initiation (MC1.5, ADR-0038).
 *
 * A Server Action is a public POST endpoint, so every case here calls it directly with hostile
 * input rather than through the button that normally renders it.
 *
 * The property under test is that **nothing the caller sends can influence which workspace or
 * which connection is authorized**, and that no PKCE or state material passes through this
 * process at all — ADR-0038 keeps both in the API.
 */

const startOAuthAuthorization = vi.fn();
const getSessionOrNull = vi.fn();
const resolveWorkspace = vi.fn();

class RedirectError extends Error {
  constructor(readonly to: string) {
    super(`redirect:${to}`);
  }
}

vi.mock("react", async (importOriginal) => ({
  ...(await importOriginal<typeof import("react")>()),
  cache: <T>(fn: T): T => fn,
}));
vi.mock("next/navigation", () => ({
  redirect: (to: string) => {
    throw new RedirectError(to);
  },
}));
vi.mock("next/headers", () => ({ headers: async () => new Headers() }));
vi.mock("@/lib/api/client", () => ({
  startOAuthAuthorization: (...args: unknown[]) => startOAuthAuthorization(...args),
}));
vi.mock("@/lib/session", () => ({ getSessionOrNull: () => getSessionOrNull() }));
vi.mock("@/lib/workspace/context", () => ({ resolveWorkspace: () => resolveWorkspace() }));

const { beginAuthorization } = await import("./actions");

const WORKSPACE = "aaaaaaaa-1111-2222-3333-444444444444";
const CONNECTION = "bbbbbbbb-1111-2222-3333-444444444444";
const AUTHORIZE_URL = "https://provider.example/oauth/authorize?client_id=abc";

function form(connectionId: unknown): FormData {
  const data = new FormData();
  if (connectionId !== undefined) data.set("connectionId", connectionId as string);
  return data;
}

/** Run the action, returning either its value or the redirect target it threw. */
async function run(data: FormData): Promise<{ result?: unknown; redirect?: string }> {
  try {
    return { result: await beginAuthorization(data) };
  } catch (caught) {
    if (caught instanceof RedirectError) return { redirect: caught.to };
    throw caught;
  }
}

beforeEach(() => {
  startOAuthAuthorization.mockReset();
  getSessionOrNull.mockReset().mockResolvedValue({ user: { id: "u1" } });
  resolveWorkspace
    .mockReset()
    .mockResolvedValue({ ok: true, context: { workspaceId: WORKSPACE, role: "OWNER", memberships: [] } });
});

describe("the action authorizes independently", () => {
  test("an unauthenticated caller never reaches the API", async () => {
    getSessionOrNull.mockResolvedValue(null);

    const { result } = await run(form(CONNECTION));
    expect(result).toEqual({ status: "unauthenticated" });
    expect(startOAuthAuthorization).not.toHaveBeenCalled();
  });

  test("no bound workspace fails closed and never reaches the API", async () => {
    // ADR-0016: several memberships and no valid selection must refuse rather than pick one.
    resolveWorkspace.mockResolvedValue({ ok: false, reason: "selection-required", memberships: [] });

    const { result } = await run(form(CONNECTION));
    expect(result).toEqual({ status: "no-workspace" });
    expect(startOAuthAuthorization).not.toHaveBeenCalled();
  });

  test("the workspace comes from the server resolution, never from the request", async () => {
    startOAuthAuthorization.mockResolvedValue({ authorize_url: AUTHORIZE_URL });
    const data = form(CONNECTION);
    // A crafted POST trying to name another tenant.
    data.set("workspaceId", "99999999-9999-9999-9999-999999999999");

    await run(data);

    const [identity, connectionId] = startOAuthAuthorization.mock.calls[0]!;
    expect((identity as { workspaceId: string }).workspaceId).toBe(WORKSPACE);
    expect(connectionId).toBe(CONNECTION);
  });

  test.each([
    ["missing", undefined],
    ["empty", ""],
  ])("a %s connection id is refused without calling the API", async (_label, value) => {
    const { result } = await run(form(value));

    expect(result).toEqual({ status: "not-found" });
    expect(startOAuthAuthorization).not.toHaveBeenCalled();
  });

  test("a File value is rejected rather than coerced", async () => {
    const data = new FormData();
    data.set("connectionId", new File(["x"], "c.txt"));

    const { result } = await run(data);
    expect(result).toEqual({ status: "not-found" });
    expect(startOAuthAuthorization).not.toHaveBeenCalled();
  });
});

describe("the redirect target", () => {
  test("a valid https URL redirects the browser to the provider", async () => {
    startOAuthAuthorization.mockResolvedValue({ authorize_url: AUTHORIZE_URL });

    const { redirect } = await run(form(CONNECTION));
    expect(redirect).toContain("https://provider.example/oauth/authorize");
  });

  test.each([
    ["javascript:", "javascript:alert(1)"],
    ["data:", "data:text/html,<script>alert(1)</script>"],
    ["plain http", "http://provider.example/authorize"],
    ["relative", "/authorize"],
    ["empty", ""],
  ])("a %s authorize_url is refused and never navigated to", async (_label, url) => {
    // Defence in depth: the API is trusted, but a compromised connector config must not become a
    // redirect we perform.
    startOAuthAuthorization.mockResolvedValue({ authorize_url: url });

    const { result, redirect } = await run(form(CONNECTION));
    expect(redirect).toBeUndefined();
    expect(result).toEqual({ status: "unsafe-url" });
  });
});

describe("API failures map to a closed set of states", () => {
  test.each([
    ["forbidden", "forbidden"],
    ["not_found", "not-found"],
    ["conflict", "unavailable"],
    ["validation", "unavailable"],
    ["unauthenticated", "unauthenticated"],
  ])("a %s response becomes %s", async (kind, expected) => {
    startOAuthAuthorization.mockRejectedValue(
      new ApiFailure({ kind: kind as "forbidden", message: "denied" }),
    );

    const { result } = await run(form(CONNECTION));
    expect((result as { status: string }).status).toBe(expected);
  });

  test("the API's 404 text is never echoed, so ids cannot be probed", async () => {
    startOAuthAuthorization.mockRejectedValue(
      new ApiFailure({ kind: "not_found", message: "no connection 99999999 in workspace 1111" }),
    );

    const { result } = await run(form(CONNECTION));
    expect(JSON.stringify(result)).not.toContain("99999999");
    expect(JSON.stringify(result)).not.toContain("1111");
  });

  test("a transient failure keeps the request id for support", async () => {
    startOAuthAuthorization.mockRejectedValue(
      new ApiFailure({ kind: "server_error", message: "Something went wrong.", requestId: "req_1" }),
    );

    const { result } = await run(form(CONNECTION));
    expect(result).toEqual({ status: "error", message: "Something went wrong.", requestId: "req_1" });
  });
});

describe("no protocol material passes through this process", () => {
  test("nothing returned by the action carries state, a verifier or a token", async () => {
    // ADR-0038 keeps `state` and the PKCE verifier server-side in the API. Even if a future
    // response carried them, they must not reach a rendered outcome.
    startOAuthAuthorization.mockResolvedValue({
      authorize_url: AUTHORIZE_URL,
      state: "STATE-CANARY",
      code_verifier: "VERIFIER-CANARY",
    });

    const { redirect } = await run(form(CONNECTION));
    expect(redirect).not.toContain("VERIFIER-CANARY");

    startOAuthAuthorization.mockRejectedValue(
      new ApiFailure({ kind: "server_error", message: "boom" }),
    );
    const { result } = await run(form(CONNECTION));
    expect(JSON.stringify(result)).not.toContain("STATE-CANARY");
    expect(JSON.stringify(result)).not.toContain("VERIFIER-CANARY");
  });

  test("one activation performs exactly one authorization call", async () => {
    // Each call mints a single-use oauth_states row; a duplicate would orphan one.
    startOAuthAuthorization.mockResolvedValue({ authorize_url: AUTHORIZE_URL });

    await run(form(CONNECTION));
    expect(startOAuthAuthorization).toHaveBeenCalledTimes(1);
  });
});
