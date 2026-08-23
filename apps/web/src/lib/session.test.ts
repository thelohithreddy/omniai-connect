import { describe, expect, test } from "vitest";

import { safeNextPath } from "./session";

/**
 * Open-redirect defence (MC1.3, Phase 12 §19).
 *
 * `safeNextPath` guards the one place a caller-supplied string is used to navigate. The rejection
 * cases below are the interesting half: a naive `startsWith("/")` check accepts three of them and
 * turns a trusted sign-in link into a phishing hop.
 */
describe("safeNextPath", () => {
  describe("rejects anything that could leave this origin", () => {
    test.each([
      ["protocol-relative", "//evil.example/x"],
      ["protocol-relative with credentials", "//user:pass@evil.example"],
      ["absolute https", "https://evil.example/x"],
      ["absolute http", "http://evil.example/x"],
      ["javascript scheme", "javascript:alert(1)"],
      ["data scheme", "data:text/html,<script>alert(1)</script>"],
      ["backslash pair", "\\\\evil.example"],
      ["slash-backslash", "/\\evil.example"],
      ["scheme after slash", "/https:evil"],
      ["bare relative", "dashboard"],
      ["empty", ""],
    ])("%s", (_label, candidate) => {
      expect(safeNextPath(candidate)).toBeNull();
    });

    test("control characters, which can split a header downstream", () => {
      // Built from char codes so this file contains no literal control bytes.
      for (const code of [0, 9, 10, 13, 31, 127]) {
        expect(safeNextPath(`/dash${String.fromCharCode(code)}board`)).toBeNull();
      }
    });

    test("null and undefined", () => {
      expect(safeNextPath(null)).toBeNull();
      expect(safeNextPath(undefined)).toBeNull();
    });
  });

  describe("accepts genuine local paths", () => {
    test.each([
      "/dashboard",
      "/accept-invite",
      "/dashboard?tab=logs",
      "/a/b/c",
      "/dashboard#section",
    ])("%s", (candidate) => {
      // Hyphens and query strings must survive: `/accept-invite` is a real route, and an
      // over-strict filter that dropped it would silently send invited users to the wrong place.
      expect(safeNextPath(candidate)).toBe(candidate);
    });
  });

  test("never returns a value it was not given", () => {
    // Guards against a "sanitising" implementation that rewrites input into something adjacent —
    // the result must be the original string or nothing at all.
    for (const candidate of ["/dashboard", "//evil.example", "https://evil.example"]) {
      const result = safeNextPath(candidate);
      expect(result === null || result === candidate).toBe(true);
    }
  });
});
