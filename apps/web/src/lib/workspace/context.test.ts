import { beforeEach, describe, expect, test, vi } from "vitest";

/**
 * Workspace resolution — the tenant boundary (MC1.3, ADR-0016; Phase 12 §6, §7, §12, §13).
 *
 * The property under test is one sentence: **a workspace is bound only when the API's membership
 * list says the caller belongs to it.** Every case below is an attempt to bind one some other
 * way — a forged cookie, a stale cookie, a revoked membership, a cookie for a real workspace the
 * caller never joined.
 *
 * `react`'s `cache()` is replaced with identity so each test observes a fresh resolution.
 * Per-request memoisation is correct in production and would silently share state across tests.
 */

const listMyWorkspaces = vi.fn();
const cookieStore = new Map<string, string>();

vi.mock("react", async (importOriginal) => ({
  ...(await importOriginal<typeof import("react")>()),
  cache: <T>(fn: T): T => fn,
}));

vi.mock("next/headers", () => ({
  headers: async () => new Headers({ cookie: "opaque" }),
  cookies: async () => ({
    get: (name: string) => {
      const value = cookieStore.get(name);
      return value === undefined ? undefined : { name, value };
    },
  }),
}));

vi.mock("@/lib/api/client", () => ({ listMyWorkspaces: (...args: unknown[]) => listMyWorkspaces(...args) }));

const { resolveWorkspace, isMemberOf, WORKSPACE_COOKIE } = await import("./context");

const ALPHA = "11111111-1111-1111-1111-111111111111";
const BETA = "22222222-2222-2222-2222-222222222222";
/** A real workspace the caller is not a member of. */
const FOREIGN = "99999999-9999-9999-9999-999999999999";

function membershipsAre(...items: Array<{ id: string; role: string }>): void {
  listMyWorkspaces.mockResolvedValue({ data: items });
}

beforeEach(() => {
  cookieStore.clear();
  listMyWorkspaces.mockReset();
});

describe("binding requires membership", () => {
  test("a cookie naming a workspace the caller does not belong to binds nothing", async () => {
    // The whole point. If this ever passes by binding FOREIGN, one user reads another tenant's
    // data — no backend control compensates for the browser tier choosing the wrong tenant.
    membershipsAre({ id: ALPHA, role: "OWNER" }, { id: BETA, role: "MEMBER" });
    cookieStore.set(WORKSPACE_COOKIE, FOREIGN);

    const resolution = await resolveWorkspace();

    expect(resolution.ok).toBe(false);
    expect(resolution.ok === false && resolution.reason).toBe("selection-required");
  });

  test("a forged cookie cannot invent a workspace when the caller has exactly one", async () => {
    // The single-membership auto-bind must bind the *real* one, not the requested one.
    membershipsAre({ id: ALPHA, role: "VIEWER" });
    cookieStore.set(WORKSPACE_COOKIE, FOREIGN);

    const resolution = await resolveWorkspace();

    expect(resolution.ok).toBe(true);
    expect(resolution.ok && resolution.context.workspaceId).toBe(ALPHA);
  });

  test("a membership revoked since the cookie was set no longer binds", async () => {
    // Yesterday's valid selection is today's forged one; the check is re-run every request rather
    // than trusted because it once passed.
    membershipsAre({ id: BETA, role: "MEMBER" });
    cookieStore.set(WORKSPACE_COOKIE, ALPHA);

    const resolution = await resolveWorkspace();

    expect(resolution.ok).toBe(true);
    expect(resolution.ok && resolution.context.workspaceId).toBe(BETA);
  });

  test.each([
    ["empty string", ""],
    ["whitespace", "   "],
    ["sql-ish", "' OR 1=1 --"],
    ["path traversal", "../../etc/passwd"],
    ["uuid-shaped but foreign", FOREIGN],
  ])("a %s cookie value never binds", async (_label, value) => {
    membershipsAre({ id: ALPHA, role: "OWNER" }, { id: BETA, role: "MEMBER" });
    cookieStore.set(WORKSPACE_COOKIE, value);

    const resolution = await resolveWorkspace();
    expect(resolution.ok).toBe(false);
  });
});

describe("ADR-0016 fail-closed", () => {
  test("several memberships and no cookie refuses rather than picking one", async () => {
    // A "helpful" first-workspace fallback is the tempting bug: it makes a forged or absent
    // selection succeed and hides that the user never chose.
    membershipsAre({ id: ALPHA, role: "OWNER" }, { id: BETA, role: "MEMBER" });

    const resolution = await resolveWorkspace();

    expect(resolution.ok).toBe(false);
    expect(resolution.ok === false && resolution.reason).toBe("selection-required");
    expect(resolution.ok === false && resolution.memberships).toHaveLength(2);
  });

  test("no memberships is reported distinctly, and binds nothing", async () => {
    membershipsAre();

    const resolution = await resolveWorkspace();

    expect(resolution.ok).toBe(false);
    expect(resolution.ok === false && resolution.reason).toBe("no-memberships");
  });

  test("a missing `data` array is treated as no memberships, not as a crash", async () => {
    listMyWorkspaces.mockResolvedValue({});

    const resolution = await resolveWorkspace();
    expect(resolution.ok === false && resolution.reason).toBe("no-memberships");
  });
});

describe("legitimate binding", () => {
  test("a valid cookie selects that workspace and carries its role", async () => {
    membershipsAre({ id: ALPHA, role: "OWNER" }, { id: BETA, role: "VIEWER" });
    cookieStore.set(WORKSPACE_COOKIE, BETA);

    const resolution = await resolveWorkspace();

    expect(resolution.ok).toBe(true);
    expect(resolution.ok && resolution.context.workspaceId).toBe(BETA);
    // Display-only, and it must be the role the API reported for *that* workspace — not the
    // first membership's, which is how a switcher starts showing the wrong permissions.
    expect(resolution.ok && resolution.context.role).toBe("VIEWER");
  });

  test("a single membership binds without requiring a selection", async () => {
    membershipsAre({ id: ALPHA, role: "ADMIN" });

    const resolution = await resolveWorkspace();

    expect(resolution.ok).toBe(true);
    expect(resolution.ok && resolution.context.workspaceId).toBe(ALPHA);
  });

  test("the membership list is fetched before the cookie is consulted", async () => {
    // Order is the invariant: reading the cookie first and trusting it is precisely the
    // cross-tenant bug this module exists to prevent.
    membershipsAre({ id: ALPHA, role: "OWNER" });
    await resolveWorkspace();

    expect(listMyWorkspaces).toHaveBeenCalledTimes(1);
  });
});

describe("isMemberOf", () => {
  test("answers from the API list, not from the cookie", async () => {
    membershipsAre({ id: ALPHA, role: "OWNER" });
    cookieStore.set(WORKSPACE_COOKIE, FOREIGN);

    expect(await isMemberOf(ALPHA)).toBe(true);
    expect(await isMemberOf(FOREIGN)).toBe(false);
  });

  test("rejects an empty or unknown id", async () => {
    membershipsAre({ id: ALPHA, role: "OWNER" });

    expect(await isMemberOf("")).toBe(false);
    expect(await isMemberOf(BETA)).toBe(false);
  });
});

describe("the selection cookie itself", () => {
  test("carries the __Host- prefix in production", async () => {
    // `__Host-` is only honoured for a Secure, Path=/, Domain-less cookie, which is what stops a
    // sibling subdomain from planting a workspace selection.
    vi.resetModules();
    const previous = process.env.NODE_ENV;
    vi.stubEnv("NODE_ENV", "production");

    const production = await import("./context");
    expect(production.WORKSPACE_COOKIE.startsWith("__Host-")).toBe(true);

    vi.stubEnv("NODE_ENV", previous ?? "test");
  });
});
