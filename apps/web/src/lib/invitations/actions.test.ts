import { beforeEach, describe, expect, test, vi } from "vitest";

import { ApiFailure } from "@/lib/api/errors";

/**
 * Invitation acceptance (MC1.3, ADR-0017; Phase 12 §15–§18).
 *
 * Two properties matter here and neither is about the happy path:
 *
 *  1. **The token never leaves server custody.** It is read from an `httpOnly` cookie, sent in a
 *     request body, and never returned to the caller in any shape — including inside an error.
 *  2. **The API's uniform 404 is preserved.** Unknown, expired, revoked and already-consumed all
 *     answer identically, and the UI must not reconstruct the oracle the backend removed.
 */

const acceptInvitation = vi.fn();
const getSessionOrNull = vi.fn();
const cookieStore = new Map<string, string>();
const deleted: string[] = [];
const written: Array<{ name: string; value: string; options: Record<string, unknown> }> = [];

vi.mock("react", async (importOriginal) => ({
  ...(await importOriginal<typeof import("react")>()),
  cache: <T>(fn: T): T => fn,
}));

vi.mock("next/headers", () => ({
  headers: async () => new Headers(),
  cookies: async () => ({
    get: (name: string) => {
      const value = cookieStore.get(name);
      return value === undefined ? undefined : { name, value };
    },
    set: (name: string, value: string, options: Record<string, unknown>) => {
      written.push({ name, value, options });
      cookieStore.set(name, value);
    },
    delete: (name: string) => {
      deleted.push(name);
      cookieStore.delete(name);
    },
  }),
}));

vi.mock("@/lib/api/client", () => ({
  acceptInvitation: (...args: unknown[]) => acceptInvitation(...args),
}));
vi.mock("@/lib/session", () => ({ getSessionOrNull: () => getSessionOrNull() }));

const { acceptPendingInvitation, discardPendingInvitation } = await import("./actions");
const { INVITE_COOKIE } = await import("./token");
const { WORKSPACE_COOKIE } = await import("@/lib/workspace/context");

const TOKEN = "invitation-token-value-do-not-leak";
const WORKSPACE = "33333333-3333-3333-3333-333333333333";

beforeEach(() => {
  cookieStore.clear();
  deleted.length = 0;
  written.length = 0;
  acceptInvitation.mockReset();
  getSessionOrNull.mockReset();
  getSessionOrNull.mockResolvedValue({ user: { id: "u1" } });
});

describe("token custody", () => {
  test("the token is read from the cookie and sent in the request body", async () => {
    cookieStore.set(INVITE_COOKIE, TOKEN);
    acceptInvitation.mockResolvedValue({ workspace_id: WORKSPACE, role: "MEMBER" });

    await acceptPendingInvitation();

    // Second argument, not a path or query segment — the API's schema puts it in the body
    // precisely so it stays out of access logs and `Referer` headers.
    expect(acceptInvitation).toHaveBeenCalledWith(expect.any(Headers), TOKEN);
  });

  test("no result ever carries the token", async () => {
    cookieStore.set(INVITE_COOKIE, TOKEN);

    for (const outcome of [
      () => acceptInvitation.mockResolvedValue({ workspace_id: WORKSPACE, role: "MEMBER" }),
      () => acceptInvitation.mockRejectedValue(new ApiFailure({ kind: "not_found", message: "x" })),
      () => acceptInvitation.mockRejectedValue(new ApiFailure({ kind: "conflict", message: "x" })),
      () =>
        acceptInvitation.mockRejectedValue(
          new ApiFailure({ kind: "server_error", message: "boom", requestId: "req_1" }),
        ),
    ]) {
      cookieStore.set(INVITE_COOKIE, TOKEN);
      outcome();
      const result = await acceptPendingInvitation();
      expect(JSON.stringify(result)).not.toContain(TOKEN);
    }
  });

  test("a spent token is deleted on success", async () => {
    cookieStore.set(INVITE_COOKIE, TOKEN);
    acceptInvitation.mockResolvedValue({ workspace_id: WORKSPACE, role: "MEMBER" });

    await acceptPendingInvitation();

    // Leaving it would let a refresh replay the request and keep a spent secret in the browser.
    expect(deleted).toContain(INVITE_COOKIE);
  });

  test.each([
    ["not_found", "unusable"],
    ["conflict", "already-member"],
  ])("a %s response also discards the token", async (kind, _status) => {
    cookieStore.set(INVITE_COOKIE, TOKEN);
    acceptInvitation.mockRejectedValue(new ApiFailure({ kind: kind as "not_found", message: "x" }));

    await acceptPendingInvitation();
    expect(deleted).toContain(INVITE_COOKIE);
  });

  test("a transient failure keeps the token so the user can retry", async () => {
    cookieStore.set(INVITE_COOKIE, TOKEN);
    acceptInvitation.mockRejectedValue(new ApiFailure({ kind: "timeout", message: "slow" }));

    const result = await acceptPendingInvitation();

    expect(result.status).toBe("error");
    expect(deleted).not.toContain(INVITE_COOKIE);
  });

  test("discarding removes the token without calling the API", async () => {
    cookieStore.set(INVITE_COOKIE, TOKEN);

    await discardPendingInvitation();

    expect(deleted).toContain(INVITE_COOKIE);
    expect(acceptInvitation).not.toHaveBeenCalled();
  });
});

describe("no oracle", () => {
  test("unknown, expired and consumed invitations are indistinguishable", async () => {
    // The API answers all three with the same 404 ("uniform, no oracle" in its own contract).
    // Rendering three different states here would rebuild exactly what it removed.
    const results = [];
    for (const message of ["not found", "expired", "already consumed"]) {
      cookieStore.set(INVITE_COOKIE, TOKEN);
      acceptInvitation.mockRejectedValue(new ApiFailure({ kind: "not_found", message }));
      results.push(await acceptPendingInvitation());
    }

    expect(results.every((r) => r.status === "unusable")).toBe(true);
    expect(new Set(results.map((r) => JSON.stringify(r))).size).toBe(1);
  });

  test("a missing invitation is reported as missing, and the API is never called", async () => {
    const result = await acceptPendingInvitation();

    expect(result.status).toBe("missing");
    expect(acceptInvitation).not.toHaveBeenCalled();
  });
});

describe("authorization", () => {
  test("an unauthenticated caller is refused before the token is read", async () => {
    getSessionOrNull.mockResolvedValue(null);
    cookieStore.set(INVITE_COOKIE, TOKEN);

    const result = await acceptPendingInvitation();

    // A Server Action is a public POST endpoint; it authorizes itself rather than assuming the
    // page that rendered the button did.
    expect(result.status).toBe("unauthenticated");
    expect(acceptInvitation).not.toHaveBeenCalled();
  });
});

describe("workspace binding after acceptance", () => {
  test("the joined workspace is selected, from the API's response", async () => {
    cookieStore.set(INVITE_COOKIE, TOKEN);
    acceptInvitation.mockResolvedValue({ workspace_id: WORKSPACE, role: "MEMBER" });

    const result = await acceptPendingInvitation();

    expect(result).toEqual({ status: "accepted", workspaceId: WORKSPACE, role: "MEMBER" });
    const selection = written.find((entry) => entry.name === WORKSPACE_COOKIE);
    // Membership was just proven by the API, so this is a legitimate selection rather than a
    // guess — and it is still re-checked against the membership list on the next request.
    expect(selection?.value).toBe(WORKSPACE);
    expect(selection?.options.httpOnly).toBe(true);
    expect(selection?.options.sameSite).toBe("lax");
  });
});
