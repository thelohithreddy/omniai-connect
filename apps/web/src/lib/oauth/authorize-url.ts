/**
 * Provider authorization URL validation (MC1.5, ADR-0038).
 *
 * ADR-0038 says a dashboard "simply redirects to the URL the API returns", and that is what
 * happens — but *simply* is not the same as *unchecked*. This is the one place in the product
 * where a value that originated outside the frontend becomes a browser navigation, so it gets a
 * scheme allowlist before it is used.
 *
 * The URL comes from the Connector's `auth_config`, which is operator-set public metadata rather
 * than attacker-set. The check is therefore defence in depth, and it is cheap: if that
 * configuration were ever compromised — or a connector were imported from an untrusted OpenAPI
 * document — a `javascript:` or `data:` URL in this position would be stored XSS delivered by our
 * own redirect. An allowlist costs one function and removes the whole class.
 *
 * `https:` only. OAuth authorization endpoints are HTTPS by definition (RFC 6749 §3.1 requires
 * TLS), so permitting `http:` would buy nothing except a downgrade path for the one navigation
 * that carries a `state` parameter.
 *
 * Pure and dependency-free so it can be unit tested directly; no `server-only` guard because it
 * holds no credential and no environment access.
 */

/** Why an authorization URL was refused. */
export type AuthorizeUrlRejection = "malformed" | "insecure-scheme";

export type AuthorizeUrlCheck =
  | { readonly ok: true; readonly url: string }
  | { readonly ok: false; readonly reason: AuthorizeUrlRejection };

export function checkAuthorizeUrl(candidate: unknown): AuthorizeUrlCheck {
  if (typeof candidate !== "string" || candidate.trim().length === 0) {
    return { ok: false, reason: "malformed" };
  }

  let parsed: URL;
  try {
    // `new URL` without a base rejects relative and scheme-less values outright, which is what we
    // want: an authorization endpoint is always absolute.
    parsed = new URL(candidate);
  } catch {
    return { ok: false, reason: "malformed" };
  }

  // Compared against the parsed protocol rather than the raw string, so `JavaScript:`,
  // `java\tscript:` and percent-encoded variants all normalise before the check rather than
  // sneaking past a `startsWith`.
  if (parsed.protocol !== "https:") {
    return { ok: false, reason: "insecure-scheme" };
  }

  // Returned as the *parsed* href rather than the original: normalisation removes ambiguity
  // between what was validated and what is navigated to, which is where bypasses usually live.
  return { ok: true, url: parsed.href };
}
