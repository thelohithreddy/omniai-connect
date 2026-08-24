/**
 * Invitation token custody (MC1.3, ADR-0017).
 *
 * The backend emails `{app_url}/accept-invite?token=…`, so the token necessarily arrives in a URL.
 * A URL is the worst place for a bearer-shaped secret to stay: it lands in browser history, in the
 * `Referer` of any subsequent navigation, in shared screenshots, and in the access log of every
 * proxy in front of the app.
 *
 * So it does not stay there. Middleware moves it into an `httpOnly` cookie on first sight and
 * redirects to the bare path, which is the earliest point in the request lifecycle where that is
 * possible — a Server Component cannot set a cookie during render, and doing it in a client
 * component would mean the token had already reached browser JavaScript.
 *
 * No `server-only` import here on purpose: middleware runs on the Edge runtime and shares these
 * constants. The module holds names and cookie options only — it never reads, logs or transmits a
 * token value.
 */

/** `__Host-` in production: Secure, Path=/, no Domain, so no sibling subdomain can plant one. */
export const INVITE_COOKIE =
  process.env.NODE_ENV === "production" ? "__Host-omniai_invite" : "omniai_invite";

/**
 * Ten minutes. Long enough to sign in or verify an email in another tab, short enough that a
 * token left on a shared machine expires before it is useful. Acceptance clears it immediately;
 * this bounds only the abandoned case.
 */
export const INVITE_COOKIE_MAX_AGE_SECONDS = 600;

export const INVITE_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  // `lax`, not `strict`: the user arrives by clicking a link in an email client, which is a
  // cross-site navigation. `strict` would withhold the cookie on exactly that first hop.
  sameSite: "lax",
  path: "/",
  maxAge: INVITE_COOKIE_MAX_AGE_SECONDS,
} as const;

/** The query parameter the API's invitation email uses. */
export const INVITE_QUERY_PARAM = "token";

/** The path invitation emails point at. */
export const ACCEPT_INVITE_PATH = "/accept-invite";
