/**
 * Security header middleware (MC1.2, ADR-0044 D4).
 *
 * This is the per-request nonce delivery point the ADR calls for. Before MC1.2 no `middleware.ts`
 * existed, so there was nowhere for a nonce to come from and `next.config.ts` set no security
 * headers at all.
 *
 * **Why the policy is written onto the *request* as well as the response.** Next reads the CSP
 * from the incoming request headers to discover the nonce, and then stamps that same nonce onto
 * every `<script>` it emits. Without the request-header write the response would advertise a nonce
 * that none of Next's own scripts carry, and under `'strict-dynamic'` the application would fail
 * to boot the moment the policy moved from report-only to enforcing — the failure would appear
 * one release *after* the change that caused it. Next accepts either the enforcing or the
 * report-only header name here, which is what makes a nonced report-only rollout possible at all.
 *
 * **Report-only, deliberately.** ADR-0044 D4 requires observation before enforcement. Enforcement
 * is MC1.8's gate, not this one. The policy shipped here is the policy that will be enforced —
 * report-only changes the header name, not the content — so the observation period tests the real
 * thing rather than a placeholder.
 */

import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

import { buildContentSecurityPolicy } from "@/lib/security/csp";
import { buildSecurityHeaders } from "@/lib/security/headers";

/**
 * The report-only header name. Named once so the middleware, the tests, and any future
 * enforcement switch all agree on a single string.
 */
export const CSP_REPORT_ONLY_HEADER = "Content-Security-Policy-Report-Only";

/**
 * Generate a 128-bit nonce as base64.
 *
 * `crypto.getRandomValues` rather than `node:crypto` because middleware runs on the Edge runtime,
 * where the Node module is unavailable. A nonce must be unpredictable per response: a reused or
 * guessable nonce lets injected markup carry a valid nonce attribute, which defeats the entire
 * point of nonce-based CSP.
 */
function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

export function middleware(request: NextRequest): NextResponse {
  const nonce = generateNonce();
  const isDevelopment = process.env.NODE_ENV === "development";
  const policy = buildContentSecurityPolicy({ nonce, isDevelopment });

  // Forwarded to the renderer so Next can find the nonce and stamp its own script tags.
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set(CSP_REPORT_ONLY_HEADER, policy);
  requestHeaders.set("x-nonce", nonce);

  const response = NextResponse.next({ request: { headers: requestHeaders } });

  response.headers.set(CSP_REPORT_ONLY_HEADER, policy);
  // HSTS only where TLS actually terminates. `NODE_ENV` is the signal available in the Edge
  // runtime; the reverse proxy in front of production must not strip or duplicate these.
  for (const [name, value] of Object.entries(buildSecurityHeaders({ enableHsts: !isDevelopment }))) {
    response.headers.set(name, value);
  }

  return response;
}

export const config = {
  /**
   * Everything except Next's own immutable static output and the favicon.
   *
   * Those are fingerprinted, cacheable, and carry no HTML, so a nonce would be meaningless and a
   * per-request header would defeat their caching. Application routes and route handlers are all
   * matched — including `/api/auth/*`, where `nosniff` and `frame-ancestors` still matter.
   */
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
