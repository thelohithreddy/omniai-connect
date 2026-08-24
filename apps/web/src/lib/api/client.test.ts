import { beforeEach, describe, expect, test, vi } from "vitest";

/**
 * Pre-selection API calls (MC1.3, ADR-0016 §7).
 *
 * The transport fails closed when no workspace is bound — correct for every workspace-scoped
 * call, and wrong for the two that happen *before* a workspace can exist:
 *
 *   - `listMyWorkspaces` is how the caller discovers which workspaces they have;
 *   - `acceptInvitation` is what creates the membership in the first place.
 *
 * Both opt out explicitly. This file exists because a mutation removing that opt-out survived the
 * MC1.3 audit: nothing failed, yet a brand-new user — the only kind that ever accepts an
 * invitation — would have been refused with "No workspace is selected". The bug is invisible to
 * anyone who tests while already a member, which is everyone developing the feature.
 */

const apiRequest = vi.fn();

vi.mock("@/lib/api/transport", () => ({
  apiRequest: (...args: unknown[]) => apiRequest(...args),
}));

const { acceptInvitation, listMyWorkspaces, getCurrentWorkspace, listToolCalls } = await import(
  "./client"
);

beforeEach(() => {
  apiRequest.mockReset().mockResolvedValue({});
});

describe("calls that must work before a workspace is bound", () => {
  test("acceptInvitation opts out of the workspace requirement", async () => {
    await acceptInvitation(new Headers(), "token-value");

    const request = apiRequest.mock.calls[0]![0] as Record<string, unknown>;
    expect(
      request.allowMissingWorkspace,
      "a new member has no workspace yet; requiring one makes acceptance impossible",
    ).toBe(true);
  });

  test("listMyWorkspaces opts out of the workspace requirement", async () => {
    await listMyWorkspaces(new Headers());

    const request = apiRequest.mock.calls[0]![0] as Record<string, unknown>;
    expect(request.allowMissingWorkspace).toBe(true);
  });
});

describe("the invitation token stays out of the URL", () => {
  test("it travels in the body, not the path or the query", async () => {
    await acceptInvitation(new Headers(), "token-value");

    const request = apiRequest.mock.calls[0]![0] as Record<string, unknown>;
    expect(request.body).toEqual({ token: "token-value" });
    // A token in either would land in access logs, `Referer` headers and every proxy in between.
    expect(request.path).toBe("/v1/invitations/accept");
    expect(JSON.stringify(request.query ?? {})).not.toContain("token-value");
    expect(request.method).toBe("POST");
  });
});

describe("the audit log call stays workspace-bound (MC1.4)", () => {
  test("listToolCalls does not opt out of the workspace requirement", async () => {
    // The whole point of the audit surface: without a bound workspace the transport must refuse
    // rather than ask the API for "the caller's tool calls" with nothing selected.
    await listToolCalls({ headers: new Headers(), workspaceId: "w1" }, { limit: 25 });

    const request = apiRequest.mock.calls[0]![0] as Record<string, unknown>;
    expect(request.allowMissingWorkspace).toBeUndefined();
    expect(request.method).toBe("GET");
    expect(request.path).toBe("/v1/tool-calls");
  });

  test("the opaque cursor is passed through verbatim, never reconstructed", async () => {
    const cursor = "eyJvZmZzZXQiOjI1fQ==";
    await listToolCalls({ headers: new Headers(), workspaceId: "w1" }, { limit: 25, cursor });

    const request = apiRequest.mock.calls[0]![0] as Record<string, unknown>;
    expect((request.query as Record<string, unknown>).cursor).toBe(cursor);
  });

  test("a caller cannot smuggle a workspace override into the query", async () => {
    // `workspaceId` travels as a header the transport controls. Even if a query key named
    // `workspace_id` were supplied, it must not become the tenant — the transport's own tests
    // assert the header wins, and this asserts the client never invents such a key itself.
    await listToolCalls({ headers: new Headers(), workspaceId: "w1" }, { limit: 25 });

    const query = (apiRequest.mock.calls[0]![0] as Record<string, unknown>).query as Record<
      string,
      unknown
    >;
    expect(Object.keys(query)).not.toContain("workspace_id");
    expect(Object.keys(query)).not.toContain("workspaceId");
  });
});

describe("workspace-scoped calls keep the requirement", () => {
  test("getCurrentWorkspace does not opt out", async () => {
    // The opt-out is dangerous by default: a workspace-scoped call that proceeds unbound would
    // ask the API for "the caller's workspace" with nothing selected.
    await getCurrentWorkspace({ headers: new Headers(), workspaceId: "w1" });

    const request = apiRequest.mock.calls[0]![0] as Record<string, unknown>;
    expect(request.allowMissingWorkspace).toBeUndefined();
  });
});
