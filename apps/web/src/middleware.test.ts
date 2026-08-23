import { NextRequest } from "next/server";
import { describe, expect, test } from "vitest";

import { middleware, CSP_REPORT_ONLY_HEADER } from "./middleware";

/**
 * Middleware tests (MC1.2, ADR-0044 D4).
 *
 * The policy content is asserted in `lib/security/csp.test.ts`. This file asserts *delivery*:
 * that the header actually reaches the response, that it is report-only rather than enforcing,
 * and that the nonce is fresh per request and forwarded to the renderer.
 */

function request(path = "/"): NextRequest {
  return new NextRequest(new URL(path, "https://app.example.com"));
}

/** Read the CSP that middleware forwards to the renderer via `NextResponse.next({request})`. */
function forwardedRequestHeader(response: Response, name: string): string | null {
  return response.headers.get(`x-middleware-request-${name.toLowerCase()}`);
}

describe("security middleware", () => {
  test("responds with a report-only policy, not an enforcing one", () => {
    const response = middleware(request());

    expect(response.headers.get(CSP_REPORT_ONLY_HEADER)).toBeTruthy();
    // ADR-0044 D4 sequences observation before enforcement; enforcing early would break the app
    // on real traffic with no violation data to act on. Enforcement is MC1.8's gate.
    expect(response.headers.get("Content-Security-Policy")).toBeNull();
  });

  test("every security header is applied to the response", () => {
    const response = middleware(request());

    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(response.headers.get("Referrer-Policy")).toBe("strict-origin-when-cross-origin");
    expect(response.headers.get("X-Frame-Options")).toBe("DENY");
    expect(response.headers.get("Permissions-Policy")).toContain("camera=()");
  });

  test("the nonce is fresh on every request", () => {
    // A reused nonce lets injected markup carry a valid nonce attribute, which defeats the whole
    // mechanism. Sampled rather than compared twice: a low-entropy generator would collide.
    const nonces = new Set(
      Array.from({ length: 50 }, () => {
        const policy = middleware(request()).headers.get(CSP_REPORT_ONLY_HEADER)!;
        return /'nonce-([^']+)'/.exec(policy)?.[1];
      }),
    );

    expect(nonces.size).toBe(50);
    expect(nonces.has(undefined)).toBe(false);
  });

  test("the nonce is at least 128 bits of base64", () => {
    const policy = middleware(request()).headers.get(CSP_REPORT_ONLY_HEADER)!;
    const nonce = /'nonce-([^']+)'/.exec(policy)![1]!;

    expect(nonce).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
    // 16 bytes → 24 base64 characters. Anything shorter is guessable at scale.
    expect(nonce.length).toBeGreaterThanOrEqual(24);
  });

  test("the same nonce is forwarded to the renderer", () => {
    // Next discovers the nonce by reading the CSP from the *request* headers and stamps it onto
    // its own script tags. If the response advertised a nonce the rendered scripts did not carry,
    // the app would boot fine under report-only and break the moment the policy was enforced —
    // one release after the change that caused it.
    const response = middleware(request());

    const responsePolicy = response.headers.get(CSP_REPORT_ONLY_HEADER)!;
    const forwardedPolicy = forwardedRequestHeader(response, CSP_REPORT_ONLY_HEADER);
    const forwardedNonce = forwardedRequestHeader(response, "x-nonce");

    expect(forwardedPolicy).toBe(responsePolicy);
    expect(forwardedNonce).toBeTruthy();
    expect(responsePolicy).toContain(`'nonce-${forwardedNonce}'`);
  });

  test("connect-src stays 'self' on every route it protects", () => {
    for (const path of ["/", "/dashboard", "/api/auth/session", "/accept-invite?token=abc"]) {
      const policy = middleware(request(path)).headers.get(CSP_REPORT_ONLY_HEADER)!;

      expect(policy, path).toContain("connect-src 'self';");
      expect(policy, path).not.toMatch(/connect-src[^;]*https?:/);
    }
  });

  describe("invitation token relocation (MC1.3, ADR-0017)", () => {
    const TOKEN = "invitation-token-value-do-not-leak";

    test("a token in the URL is redirected away and stored in an httpOnly cookie", () => {
      const response = middleware(request(`/accept-invite?token=${TOKEN}`));

      // 307 preserves the method; the point is that the address bar, history and every
      // subsequent `Referer` lose the token on the very first request that carries it.
      expect([307, 308]).toContain(response.status);

      const location = response.headers.get("location")!;
      expect(location).not.toContain(TOKEN);
      expect(location).toContain("/accept-invite");
      expect(new URL(location).searchParams.get("token")).toBeNull();

      const cookie = response.cookies.get("omniai_invite");
      expect(cookie?.value).toBe(TOKEN);
      // Never readable from document.cookie: an XSS foothold must not be able to lift it.
      expect(cookie?.httpOnly).toBe(true);
      expect(cookie?.sameSite).toBe("lax");
    });

    test("the redirect still carries every security header", () => {
      // A response that skips the header pass is a hole that only appears on one route.
      const response = middleware(request(`/accept-invite?token=${TOKEN}`));

      expect(response.headers.get(CSP_REPORT_ONLY_HEADER)).toContain("connect-src 'self';");
      expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
      expect(response.headers.get("X-Frame-Options")).toBe("DENY");
      expect(response.headers.get("Referrer-Policy")).toBe("strict-origin-when-cross-origin");
    });

    test("the bare acceptance path is left alone", () => {
      const response = middleware(request("/accept-invite"));

      expect(response.headers.get("location")).toBeNull();
      expect(response.cookies.get("omniai_invite")).toBeUndefined();
    });

    test("a token on any other path is ignored, not harvested", () => {
      // Only the acceptance route is treated as invitation delivery; a `?token=` elsewhere is
      // someone else's parameter and must not be copied into our cookie.
      for (const path of ["/", "/dashboard?token=x", "/sign-in?token=x"]) {
        const response = middleware(request(path));
        expect(response.cookies.get("omniai_invite"), path).toBeUndefined();
      }
    });
  });

  test("no request input can influence the policy", () => {
    // The policy is built from a server constant and a fresh nonce. Nothing a caller sends may
    // reach it — a reflected directive would be a CSP bypass handed to the attacker.
    const hostile = new NextRequest(new URL("https://app.example.com/?x=%27unsafe-inline%27"), {
      headers: {
        "x-nonce": "attacker-supplied",
        "content-security-policy-report-only": "default-src *",
        referer: "https://evil.example/'unsafe-eval'",
      },
    });

    const policy = middleware(hostile).headers.get(CSP_REPORT_ONLY_HEADER)!;

    expect(policy).not.toContain("attacker-supplied");
    expect(policy).not.toContain("default-src *");
    expect(policy).not.toContain("'unsafe-eval'");
    expect(policy).toContain("connect-src 'self';");
  });
});
