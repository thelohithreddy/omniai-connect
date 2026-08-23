import { beforeEach, describe, expect, test, vi } from "vitest";

/**
 * Workspace switching (MC1.3, ADR-0016; Phase 12 §6, §7, §12, §13).
 *
 * A Server Action is a public POST endpoint: Next gives it an id and the browser can invoke it
 * with any arguments. These tests treat it that way — every case calls it directly with hostile
 * input rather than through the form that normally renders it.
 */

const getSessionOrNull = vi.fn();
const isMemberOf = vi.fn();
const written: Array<{ name: string; value: string; options: Record<string, unknown> }> = [];
const deleted: string[] = [];

class RedirectError extends Error {
  constructor(readonly to: string) {
    super(`redirect:${to}`);
  }
}

vi.mock("next/navigation", () => ({
  redirect: (to: string) => {
    // The real `redirect()` throws to unwind the render; modelling that is what lets a test
    // assert the action stopped rather than merely returned.
    throw new RedirectError(to);
  },
}));

vi.mock("next/headers", () => ({
  cookies: async () => ({
    set: (name: string, value: string, options: Record<string, unknown>) =>
      written.push({ name, value, options }),
    delete: (name: string) => deleted.push(name),
  }),
}));

vi.mock("@/lib/session", () => ({ getSessionOrNull: () => getSessionOrNull() }));
vi.mock("@/lib/workspace/context", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./context")>()),
  isMemberOf: (id: string) => isMemberOf(id),
}));

const { selectWorkspace, clearWorkspaceSelection } = await import("./actions");
const { WORKSPACE_COOKIE } = await import("./context");

const ALPHA = "11111111-1111-1111-1111-111111111111";
const FOREIGN = "99999999-9999-9999-9999-999999999999";

function form(workspaceId: unknown): FormData {
  const data = new FormData();
  if (workspaceId !== undefined) data.set("workspaceId", workspaceId as string);
  return data;
}

async function capture(action: () => Promise<unknown>): Promise<string> {
  try {
    await action();
    return "(no redirect)";
  } catch (caught) {
    if (caught instanceof RedirectError) return caught.to;
    throw caught;
  }
}

beforeEach(() => {
  written.length = 0;
  deleted.length = 0;
  getSessionOrNull.mockReset().mockResolvedValue({ user: { id: "u1" } });
  isMemberOf.mockReset().mockResolvedValue(true);
});

describe("the action authorizes independently", () => {
  test("an unauthenticated caller is sent to sign-in and writes no cookie", async () => {
    getSessionOrNull.mockResolvedValue(null);

    expect(await capture(() => selectWorkspace(form(ALPHA)))).toBe("/sign-in");
    expect(written).toEqual([]);
  });

  test("a workspace the caller is not a member of is refused", async () => {
    // The membership check is the authorization. Without it, a crafted POST would rebind the
    // browser to another tenant.
    isMemberOf.mockResolvedValue(false);

    expect(await capture(() => selectWorkspace(form(FOREIGN)))).toBe(
      "/dashboard?error=invalid-workspace",
    );
    expect(written).toEqual([]);
  });

  test("membership is checked against the API, not the submitted value", async () => {
    await capture(() => selectWorkspace(form(ALPHA)));
    expect(isMemberOf).toHaveBeenCalledWith(ALPHA);
  });

  test("refusal is uniform, so workspace ids cannot be enumerated", async () => {
    isMemberOf.mockResolvedValue(false);

    const outcomes = await Promise.all(
      [FOREIGN, "not-a-uuid", "00000000-0000-0000-0000-000000000000"].map((id) =>
        capture(() => selectWorkspace(form(id))),
      ),
    );

    expect(new Set(outcomes).size).toBe(1);
  });
});

describe("input handling", () => {
  test.each([
    ["missing field", undefined],
    ["empty string", ""],
  ])("%s is rejected without an authorization call", async (_label, value) => {
    expect(await capture(() => selectWorkspace(form(value)))).toBe(
      "/dashboard?error=invalid-workspace",
    );
    expect(isMemberOf).not.toHaveBeenCalled();
    expect(written).toEqual([]);
  });

  test("a File value is rejected rather than coerced to a string", async () => {
    const data = new FormData();
    data.set("workspaceId", new File(["x"], "w.txt"));

    expect(await capture(() => selectWorkspace(data))).toBe("/dashboard?error=invalid-workspace");
    expect(isMemberOf).not.toHaveBeenCalled();
  });
});

describe("the cookie it writes", () => {
  test("is httpOnly, lax and path-scoped, and holds the authorized id", async () => {
    await capture(() => selectWorkspace(form(ALPHA)));

    const cookie = written.find((entry) => entry.name === WORKSPACE_COOKIE)!;
    expect(cookie.value).toBe(ALPHA);
    expect(cookie.options.httpOnly).toBe(true);
    expect(cookie.options.sameSite).toBe("lax");
    expect(cookie.options.path).toBe("/");
    // Session-scoped on purpose: a persisted selection outlives the membership that justified it.
    expect(cookie.options.maxAge).toBeUndefined();
    expect(cookie.options.expires).toBeUndefined();
  });

  test("switching redirects to a full server navigation", async () => {
    // Not a client state update: everything workspace-scoped re-renders on the server from the
    // newly bound workspace, so nothing from the previous one can survive the switch.
    expect(await capture(() => selectWorkspace(form(ALPHA)))).toBe("/dashboard");
  });

  test("clearing the selection deletes it", async () => {
    await clearWorkspaceSelection();
    expect(deleted).toContain(WORKSPACE_COOKIE);
  });
});
