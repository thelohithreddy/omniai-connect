import { describe, expect, test } from "vitest";

import { buildSecurityHeaders, HSTS_VALUE } from "./headers";

describe("security headers", () => {
  test("every header ADR-0044 D4 requires is present", () => {
    const headers = buildSecurityHeaders({ enableHsts: true });

    // Named individually rather than snapshotted: a snapshot silently accepts a *removed* header
    // the moment someone updates it, which is the failure this file exists to prevent.
    expect(headers["X-Content-Type-Options"]).toBe("nosniff");
    expect(headers["Referrer-Policy"]).toBe("strict-origin-when-cross-origin");
    expect(headers["X-Frame-Options"]).toBe("DENY");
    expect(headers["Permissions-Policy"]).toBe(
      "camera=(), microphone=(), geolocation=(), payment=()",
    );
    expect(headers["Strict-Transport-Security"]).toBe(HSTS_VALUE);
  });

  test("HSTS is omitted where TLS does not terminate", () => {
    // Sending it over plain http is ignored by browsers, but pinning `localhost` from a dev
    // server produces failures that are very hard to diagnose later.
    expect(buildSecurityHeaders({ enableHsts: false })).not.toHaveProperty(
      "Strict-Transport-Security",
    );
  });

  test("HSTS carries a two-year max-age, subdomains and preload", () => {
    expect(HSTS_VALUE).toMatch(/max-age=63072000/);
    expect(HSTS_VALUE).toContain("includeSubDomains");
    expect(HSTS_VALUE).toContain("preload");
  });

  test("frame protection is stated twice, deliberately", () => {
    // `frame-ancestors 'none'` in the CSP is the real control; X-Frame-Options covers user agents
    // that predate it. Losing the header while keeping the directive is fine; losing both is not,
    // so the pair is asserted together here and in the CSP suite.
    expect(buildSecurityHeaders({ enableHsts: false })["X-Frame-Options"]).toBe("DENY");
  });

  test("Permissions-Policy denies every powerful feature the control plane never uses", () => {
    const policy = buildSecurityHeaders({ enableHsts: false })["Permissions-Policy"]!;

    for (const feature of ["camera", "microphone", "geolocation", "payment"]) {
      expect(policy).toContain(`${feature}=()`);
    }
  });
});
