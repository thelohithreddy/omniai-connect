import { describe, expect, test } from "vitest";

import { ApiFailure, type ApiFailureKind } from "@/lib/api/errors";

import { presentAuditFailure, REQUIRES_ELEVATED_ROLE_MESSAGE } from "./authorization";

/**
 * Audit-log authorization presentation (MC1.4, ADR-0044 D5).
 *
 * `audit:read` is OWNER/ADMIN only, so MEMBER and VIEWER receive a 403 during entirely normal use.
 * D5 requires that to render as an explicit "requires Owner or Admin" state carrying **no data and
 * no shape of data** — and not as an error, because dressing a correct answer in red reads as a
 * broken product and trains users to ignore real failures.
 *
 * This file exists because the rule was inline in JSX and a mutation deleting it survived the
 * MC1.4 mutation audit. It is asserted directly now.
 */

function failure(kind: ApiFailureKind, message = "denied", requestId?: string): ApiFailure {
  return new ApiFailure({ kind, message, ...(requestId ? { requestId } : {}) });
}

describe("a 403 is the ratified role state, not an error", () => {
  test("forbidden renders the explicit elevated-role state", () => {
    const presentation = presentAuditFailure(failure("forbidden"));

    expect(presentation.kind).toBe("requires-elevated-role");
    expect(presentation.message).toBe(REQUIRES_ELEVATED_ROLE_MESSAGE);
  });

  test("the wording names both permitted roles, as D5 specifies", () => {
    expect(REQUIRES_ELEVATED_ROLE_MESSAGE).toMatch(/Owner/);
    expect(REQUIRES_ELEVATED_ROLE_MESSAGE).toMatch(/Admin/);
  });

  test("the API's own 403 text is never echoed", () => {
    // The backend's 403 body is uniform by design; echoing it would let a future wording change
    // alter what this surface discloses.
    const presentation = presentAuditFailure(
      failure("forbidden", "member lacks audit:read on workspace 1111-2222"),
    );

    expect(presentation.message).toBe(REQUIRES_ELEVATED_ROLE_MESSAGE);
    expect(JSON.stringify(presentation)).not.toContain("1111-2222");
    expect(JSON.stringify(presentation)).not.toContain("audit:read");
  });

  test("the role state carries no request id and no data shape", () => {
    // A refusal must disclose nothing about the log — not its size, not its columns, not whether
    // any records exist.
    const presentation = presentAuditFailure(failure("forbidden", "denied", "req_01JABC"));

    expect(presentation).toEqual({
      kind: "requires-elevated-role",
      message: REQUIRES_ELEVATED_ROLE_MESSAGE,
    });
  });
});

describe("every other failure is an error state", () => {
  test.each<ApiFailureKind>([
    "unauthenticated",
    "not_found",
    "validation",
    "conflict",
    "rate_limited",
    "quota_exceeded",
    "server_error",
    "network",
    "timeout",
    "unexpected",
  ])("%s is presented as an error, never as the role state", (kind) => {
    const presentation = presentAuditFailure(failure(kind));

    // Only `forbidden` may take the informational path. Widening it would show "you need Owner or
    // Admin" for a timeout, which sends the user to ask for a permission they already have.
    expect(presentation.kind).toBe("error");
  });

  test("an error keeps the request id for support", () => {
    const presentation = presentAuditFailure(failure("server_error", "Something went wrong.", "req_01JXYZ"));

    expect(presentation.kind).toBe("error");
    expect(presentation.kind === "error" && presentation.requestId).toBe("req_01JXYZ");
  });

  test("a missing request id is omitted rather than rendered as undefined", () => {
    const presentation = presentAuditFailure(failure("timeout", "Timed out."));

    expect(presentation.kind === "error" && "requestId" in presentation).toBe(false);
  });

  test("the error title names the surface", () => {
    const presentation = presentAuditFailure(failure("network", "Network error."));
    expect(presentation.kind === "error" && presentation.title).toMatch(/Tool Call log/);
  });
});

describe("the function is total", () => {
  test("no failure kind throws or returns undefined", () => {
    const kinds: ApiFailureKind[] = [
      "unauthenticated",
      "forbidden",
      "not_found",
      "validation",
      "conflict",
      "rate_limited",
      "quota_exceeded",
      "server_error",
      "network",
      "timeout",
      "unexpected",
    ];

    for (const kind of kinds) {
      const presentation = presentAuditFailure(failure(kind));
      expect(presentation, kind).toBeDefined();
      expect(["requires-elevated-role", "error"]).toContain(presentation.kind);
    }
  });
});
