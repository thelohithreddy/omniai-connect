import "server-only";

import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { cache } from "react";

import { getAuth } from "@/lib/auth";

/**
 * Server-side human session resolution (MC1.3, ADR-0002, ADR-0044).
 *
 * `server-only`, deliberately. The session object carries the user's identity and the request
 * headers used to mint a backend JWT; neither may be reachable from a client bundle. The guard
 * makes that a build error rather than a review comment — the same mechanism MC1.1 uses for the
 * transport.
 *
 * **This is the only place the web tier asks who the caller is.** Better Auth owns human identity
 * (ADR-0002) and there is no second authentication system here: no parallel session store, no
 * token minted from anything but the live session, no role decided in the browser.
 *
 * Wrapped in React `cache()`, which memoises **per request** and is explicitly permitted by
 * ADR-0044 §6. This is not a data cache: a layout, a page and a component in the same render all
 * ask for the session, and without memoisation each would re-validate it against Postgres. It is
 * scoped to one request, so it cannot leak one user's session into another's render — the failure
 * mode a module-level cache would have.
 */

export type HumanSession = NonNullable<
  Awaited<ReturnType<ReturnType<typeof getAuth>["api"]["getSession"]>>
>;

/**
 * The current session, or `null`.
 *
 * Returns `null` rather than throwing on a missing *or malformed* session: an expired cookie, a
 * tampered signature and no cookie at all are the same answer — "not authenticated" — and must be
 * indistinguishable to the caller. Better Auth verifies the signature and expiry; a session it
 * rejects arrives here as `null`.
 */
export const getSessionOrNull = cache(async (): Promise<HumanSession | null> => {
  const requestHeaders = await headers();
  try {
    const session = await getAuth().api.getSession({ headers: requestHeaders });
    return session ?? null;
  } catch {
    // Fail closed. A provider error must read as "not authenticated", never as "allow through":
    // an exception here would otherwise become a 500 on a protected route, and a caught-and-
    // ignored one would become an open door. Nothing is logged — the exception can carry
    // session material.
    return null;
  }
});

/**
 * The session, or a redirect to sign-in.
 *
 * Called from a layout **before any protected markup is produced**, so an unauthenticated visitor
 * never receives a frame of the dashboard. `redirect()` throws, so there is no path where this
 * returns for an unauthenticated caller — the type says `HumanSession`, not `HumanSession | null`,
 * and that is load-bearing rather than convenient.
 *
 * `nextPath` is echoed back as a `next` parameter so the user lands where they were going.
 * It is validated in `safeNextPath` before it is ever used to navigate — an unvalidated one is an
 * open redirect, which is the classic way this convenience becomes a phishing primitive.
 */
export async function requireSession(nextPath?: string): Promise<HumanSession> {
  const session = await getSessionOrNull();
  if (session) return session;

  const target = safeNextPath(nextPath);
  redirect(target ? `/sign-in?next=${encodeURIComponent(target)}` : "/sign-in");
}

/**
 * Reduce a caller-supplied return path to something that can only navigate within this origin.
 *
 * Returns `null` for anything it cannot prove is a local path. The rejections matter more than
 * the acceptance:
 *
 * - `//evil.example/x` is protocol-relative — a browser reads it as another **origin**, which is
 *   why a bare `startsWith("/")` check is not enough and is the single most common open-redirect
 *   bug in this shape of code.
 * - `https://evil.example` and `javascript:alert(1)` carry a scheme.
 * - `\\evil.example` and `/\evil.example` are normalised to `//` by some user agents.
 * - A control character or newline can split a header further down the stack.
 *
 * Anything surviving all of that is a single-slash, same-origin path.
 */
export function safeNextPath(candidate: string | null | undefined): string | null {
  if (!candidate) return null;
  if (!candidate.startsWith("/")) return null;
  if (candidate.startsWith("//")) return null;
  if (candidate.startsWith("/\\") || candidate.startsWith("\\")) return null;
  if (/[\u0000-\u001f\u007f]/.test(candidate)) return null;
  // A colon before the first slash would be a scheme; after `startsWith("/")` that cannot happen,
  // but `/\t/evil` style trickery and encoded schemes still get rejected by the control check
  // above. Reject an embedded scheme anywhere for good measure.
  if (/^\/[^/]*:/.test(candidate)) return null;
  return candidate;
}
