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

const { acceptInvitation, listMyWorkspaces, getCurrentWorkspace } = await import("./client");

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

describe("workspace-scoped calls keep the requirement", () => {
  test("getCurrentWorkspace does not opt out", async () => {
    // The opt-out is dangerous by default: a workspace-scoped call that proceeds unbound would
    // ask the API for "the caller's workspace" with nothing selected.
    await getCurrentWorkspace({ headers: new Headers(), workspaceId: "w1" });

    const request = apiRequest.mock.calls[0]![0] as Record<string, unknown>;
    expect(request.allowMissingWorkspace).toBeUndefined();
  });
});
