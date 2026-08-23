/**
 * Content Security Policy (MC1.2, ADR-0044 D4).
 *
 * A pure function rather than a string literal inside `middleware.ts`, because a policy that
 * cannot be unit-tested is a policy nobody can prove. Every directive below is asserted in
 * `csp.test.ts`; the release gate treats "CSP is documented" and "CSP is verified" as different
 * things.
 *
 * **`connect-src 'self'` is the load-bearing line.** The API has no CORS middleware, so a browser
 * already cannot call FastAPI cross-origin — this makes the browser *enforce* that invariant
 * rather than relying on the absence of a header elsewhere. Combined with the server-only
 * transport (MC1.1), a client-side call to the API is a build error first and a CSP violation
 * second. Widening this directive silently re-opens the exact hole both mechanisms exist to close.
 *
 * ---
 *
 * **KNOWN CONSTRAINT — read before enforcing this policy (MC1.2 finding F6).**
 *
 * A nonce can only be applied to markup rendered *per request*. Next stamps the nonce onto its
 * script tags during dynamic rendering; a **statically prerendered** route is generated at build
 * time, when no nonce exists, so its scripts carry none. Because `'strict-dynamic'` causes
 * browsers to ignore the `'self'` source expression, enforcing this policy would block every
 * script on a static route and the page would not boot.
 *
 * Measured on this build: static `/` → 0 of 11 script tags carried the nonce; the same page with
 * dynamic rendering → 9 of 9 carried it.
 *
 * This is harmless today because the policy ships **report-only**, which is precisely the phase
 * ADR-0044 D4 sequences first in order to surface issues like this one. It is **not** harmless at
 * MC1.8, which flips enforcement on. Resolving it requires an architectural decision ADR-0044
 * does not make — whether public/marketing routes render dynamically, or whether static routes
 * receive a different policy — so it is recorded rather than decided here.
 *
 * ADR-0044 §6 already forbids static rendering for `(dashboard)`, so the authenticated control
 * plane is unaffected.
 */

/** Directive sources, kept as data so tests can assert structure rather than parse a string. */
export type CspDirectives = Record<string, readonly string[]>;

export interface CspOptions {
  /** Per-request nonce, base64. Generated in middleware; never reused across responses. */
  readonly nonce: string;
  /**
   * Development relaxations. Next's dev server evaluates code for React Refresh and opens a
   * websocket for HMR, neither of which exists in a production build. Kept behind an explicit
   * flag so the production policy cannot inherit a development concession by accident — the
   * tests assert the production policy contains neither.
   */
  readonly isDevelopment?: boolean;
}

/**
 * Build the policy as structured directives.
 *
 * Exported separately from the serialized form so tests can make precise assertions
 * ("`connect-src` is exactly `['self']` in production") instead of substring-matching a string,
 * where `connect-src 'self' https://evil` would still contain `connect-src 'self'`.
 */
export function buildCspDirectives({ nonce, isDevelopment = false }: CspOptions): CspDirectives {
  return {
    "default-src": ["'self'"],
    // 'strict-dynamic' makes the nonce authoritative: scripts loaded by a nonced script inherit
    // trust, so Next's chunk loading works without host allowlisting. Modern browsers ignore
    // host expressions once 'strict-dynamic' is present, which is why no CDN host is listed.
    // 'unsafe-eval' is a development-only concession for React Refresh; asserted absent in prod.
    "script-src": isDevelopment
      ? ["'self'", `'nonce-${nonce}'`, "'strict-dynamic'", "'unsafe-eval'"]
      : ["'self'", `'nonce-${nonce}'`, "'strict-dynamic'"],
    // Documented exception (ADR-0044 D4). Next's App Router injects inline style attributes and
    // tags during streaming and hydration, and a nonce cannot cover a style *attribute*. Risk is
    // CSS injection (selector-based exfiltration, UI redressing) — materially lower severity than
    // script injection, which stays nonce-locked. Mitigated by `frame-ancestors 'none'`, no
    // user-controlled style input, and design tokens confined to the Tailwind config.
    "style-src": ["'self'", "'unsafe-inline'"],
    "img-src": ["'self'", "data:", "blob:"],
    "font-src": ["'self'"],
    // The websocket is Next's HMR channel and exists only under `next dev`.
    "connect-src": isDevelopment ? ["'self'", "ws:", "wss:"] : ["'self'"],
    "frame-ancestors": ["'none'"],
    "form-action": ["'self'"],
    "base-uri": ["'none'"],
    "object-src": ["'none'"],
  };
}

/** Directives that carry no value; serialized as bare keywords. */
const VALUELESS_DIRECTIVES = ["upgrade-insecure-requests"] as const;

/**
 * Serialize to a header value.
 *
 * `upgrade-insecure-requests` is omitted in development: it forces the browser to rewrite
 * `http://localhost` to `https://`, which breaks local development outright. It is present in
 * every production policy, and the tests assert exactly that.
 */
export function buildContentSecurityPolicy(options: CspOptions): string {
  const directives = buildCspDirectives(options);
  const parts = Object.entries(directives).map(([name, values]) => `${name} ${values.join(" ")}`);
  if (!options.isDevelopment) parts.push(...VALUELESS_DIRECTIVES);
  return parts.join("; ");
}
