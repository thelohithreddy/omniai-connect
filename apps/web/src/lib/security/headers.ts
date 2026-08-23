/**
 * Security response headers (MC1.2, ADR-0044 D4).
 *
 * Kept beside the CSP builder and equally pure, for the same reason: these are asserted in
 * `headers.test.ts` rather than eyeballed in a config file. A missing header is invisible in
 * review and obvious in a test.
 *
 * HSTS is deliberately conditional. Sending `Strict-Transport-Security` over plain HTTP is
 * ignored by browsers, but sending it from a local development server that a developer later
 * visits on `localhost:3000` over http can pin the host and produce confusing failures. It is
 * emitted for production only, which is also the only place TLS terminates.
 */

export interface SecurityHeaderOptions {
  /** Emit HSTS. Production/TLS only — see the module note. */
  readonly enableHsts: boolean;
}

/**
 * Two years, subdomains included, preload-eligible — the value ADR-0044 D4 specifies.
 * Preload is a one-way door for the apex domain, so it is stated here explicitly rather than
 * assembled from parts somewhere a reviewer would not see it.
 */
export const HSTS_VALUE = "max-age=63072000; includeSubDomains; preload";

/**
 * Headers applied to every response.
 *
 * `X-Frame-Options: DENY` duplicates `frame-ancestors 'none'` on purpose: the CSP directive is
 * the real control, and this covers user agents that predate it. `Referrer-Policy` is
 * `strict-origin-when-cross-origin` so a workspace-scoped path never leaves in a `Referer` to a
 * third party — relevant the moment an OAuth provider is navigated to.
 */
export function buildSecurityHeaders({ enableHsts }: SecurityHeaderOptions): Record<string, string> {
  const headers: Record<string, string> = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  };
  if (enableHsts) headers["Strict-Transport-Security"] = HSTS_VALUE;
  return headers;
}
