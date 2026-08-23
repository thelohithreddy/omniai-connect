import { describe, expect, test } from "vitest";

import { buildContentSecurityPolicy, buildCspDirectives } from "./csp";

/**
 * CSP tests (MC1.2, ADR-0044 D4).
 *
 * These assert the policy **structurally** rather than by substring. `expect(policy).toContain(
 * "connect-src 'self'")` would still pass for `connect-src 'self' https://attacker.example`,
 * which is precisely the regression worth catching — so every directive is compared as an exact
 * array of sources.
 */

const NONCE = "dGVzdC1ub25jZS12YWx1ZQ==";

describe("content security policy", () => {
  describe("the load-bearing invariant: the browser cannot reach the API directly", () => {
    test("connect-src is exactly 'self' in production", () => {
      const directives = buildCspDirectives({ nonce: NONCE });

      // Exact equality, not containment. The API has no CORS middleware, so a browser cannot
      // call FastAPI cross-origin today; this makes the browser enforce that rather than relying
      // on the absence of a header elsewhere. Any additional source re-opens the hole.
      expect(directives["connect-src"]).toEqual(["'self'"]);
    });

    test("no directive admits a wildcard or an off-origin host in production", () => {
      const directives = buildCspDirectives({ nonce: NONCE });

      for (const [name, sources] of Object.entries(directives)) {
        for (const source of sources) {
          expect(source, `${name} admits a wildcard`).not.toBe("*");
          expect(source, `${name} admits an http(s) origin`).not.toMatch(/^https?:/);
        }
      }
    });
  });

  describe("script execution is nonce-locked", () => {
    test("script-src carries the nonce and strict-dynamic", () => {
      const directives = buildCspDirectives({ nonce: NONCE });

      expect(directives["script-src"]).toEqual(["'self'", `'nonce-${NONCE}'`, "'strict-dynamic'"]);
    });

    test("production never permits unsafe-eval or unsafe-inline script", () => {
      const policy = buildContentSecurityPolicy({ nonce: NONCE });
      const scriptSrc = buildCspDirectives({ nonce: NONCE })["script-src"]!;

      expect(scriptSrc).not.toContain("'unsafe-eval'");
      expect(scriptSrc).not.toContain("'unsafe-inline'");
      // Guard the serialized form too: the concession must not arrive via another directive.
      expect(policy).not.toContain("'unsafe-eval'");
    });

    test("a development build's relaxations cannot leak into production", () => {
      const dev = buildCspDirectives({ nonce: NONCE, isDevelopment: true });
      const prod = buildCspDirectives({ nonce: NONCE, isDevelopment: false });

      // React Refresh needs eval and HMR needs a websocket; both are real framework requirements
      // and both are absent from the production policy. Asserting the difference explicitly is
      // what stops "it works in dev" from becoming the production policy.
      expect(dev["script-src"]).toContain("'unsafe-eval'");
      expect(dev["connect-src"]).toContain("ws:");
      expect(prod["script-src"]).not.toContain("'unsafe-eval'");
      expect(prod["connect-src"]).toEqual(["'self'"]);
    });

    test("the nonce reaches the serialized header verbatim", () => {
      expect(buildContentSecurityPolicy({ nonce: NONCE })).toContain(`'nonce-${NONCE}'`);
    });
  });

  describe("clickjacking, injection and navigation surface", () => {
    test.each([
      ["frame-ancestors", ["'none'"]],
      ["object-src", ["'none'"]],
      ["base-uri", ["'none'"]],
      ["form-action", ["'self'"]],
      ["default-src", ["'self'"]],
      ["font-src", ["'self'"]],
    ])("%s is %j", (directive, expected) => {
      expect(buildCspDirectives({ nonce: NONCE })[directive]).toEqual(expected);
    });

    test("img-src allows data: and blob: but no remote host", () => {
      // Inline avatars and generated previews need these two schemes; neither can execute script.
      expect(buildCspDirectives({ nonce: NONCE })["img-src"]).toEqual(["'self'", "data:", "blob:"]);
    });
  });

  describe("the documented style-src exception (ADR-0044 D4)", () => {
    test("style-src permits unsafe-inline and nothing else beyond self", () => {
      // Next's App Router emits inline style *attributes* during streaming and hydration, which a
      // nonce cannot cover. Recorded as an exception rather than silently accepted; the risk is
      // CSS injection, which is materially lower severity than script injection.
      expect(buildCspDirectives({ nonce: NONCE })["style-src"]).toEqual(["'self'", "'unsafe-inline'"]);
    });
  });

  describe("serialization", () => {
    test("production upgrades insecure requests; development does not", () => {
      expect(buildContentSecurityPolicy({ nonce: NONCE })).toContain("upgrade-insecure-requests");
      // Locally it would rewrite http://localhost to https:// and break the dev server outright.
      expect(buildContentSecurityPolicy({ nonce: NONCE, isDevelopment: true })).not.toContain(
        "upgrade-insecure-requests",
      );
    });

    test("directives are separated by '; ' and none is empty", () => {
      const parts = buildContentSecurityPolicy({ nonce: NONCE }).split("; ");

      expect(parts.length).toBeGreaterThan(5);
      for (const part of parts) expect(part.trim()).not.toBe("");
    });
  });
});
