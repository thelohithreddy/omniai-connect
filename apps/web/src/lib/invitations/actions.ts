"use server";

import { cookies, headers } from "next/headers";

import { acceptInvitation } from "@/lib/api/client";
import { ApiFailure } from "@/lib/api/errors";
import { getSessionOrNull } from "@/lib/auth/session";
import { INVITE_COOKIE } from "@/lib/invitations/token";
import { WORKSPACE_COOKIE } from "@/lib/workspace/context";

/**
 * Accept the invitation held in the invitation cookie (MC1.3, ADR-0017).
 *
 * **Deliberately a Server Action, never a GET.** Accepting is a state change that consumes a
 * single-use token, and a GET would be triggered by every link scanner, prefetcher and antivirus
 * proxy that touches the email — burning the invitation before the human ever clicked. It is also
 * CSRF-shaped: Next's action protocol requires a POST with an action id and enforces an Origin
 * check, which a plain page render does not.
 *
 * The token is read from the `httpOnly` cookie, not from a form field, so it never appears in
 * rendered HTML or in browser JavaScript. It is never logged, and it is never included in a
 * message returned to the caller.
 */

/** What the acceptance surface renders. No invitation detail, by construction. */
export type AcceptInvitationResult =
  | { readonly status: "accepted"; readonly workspaceId: string; readonly role: string }
  /** Not signed in — the caller must authenticate first. */
  | { readonly status: "unauthenticated" }
  /** No invitation in custody: never presented one, or it aged out of the cookie. */
  | { readonly status: "missing" }
  /**
   * Uniform terminal failure. Covers unknown, expired, revoked and already-consumed alike,
   * because the API answers all of them with the same 404 "no oracle" response and the UI must
   * not reconstruct the distinction the backend removed on purpose.
   */
  | { readonly status: "unusable" }
  /** Already a member — safe to disclose, since the caller can see the workspace anyway. */
  | { readonly status: "already-member" }
  /** The API could not be reached or failed unexpectedly. Retrying is reasonable. */
  | { readonly status: "error"; readonly message: string; readonly requestId?: string };

export async function acceptPendingInvitation(): Promise<AcceptInvitationResult> {
  if (!(await getSessionOrNull())) return { status: "unauthenticated" };

  const jar = await cookies();
  const token = jar.get(INVITE_COOKIE)?.value;
  if (!token) return { status: "missing" };

  try {
    const accepted = await acceptInvitation(await headers(), token);

    // Consume the token as soon as it has been used. Leaving it would let a refresh replay the
    // request and would keep a spent secret in the browser for the rest of its lifetime.
    jar.delete(INVITE_COOKIE);

    // Bind the workspace just joined. Membership was proven by the API's own response, so this is
    // a legitimate selection rather than a guess — and it means the new member lands somewhere
    // useful instead of on ADR-0016's "choose a workspace" screen.
    jar.set(WORKSPACE_COOKIE, accepted.workspace_id, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
    });

    return { status: "accepted", workspaceId: accepted.workspace_id, role: accepted.role };
  } catch (caught) {
    if (!(caught instanceof ApiFailure)) throw caught;

    // The token is spent or unusable in every one of these cases; keeping it would only invite a
    // pointless retry loop against the API.
    if (caught.kind === "not_found") {
      jar.delete(INVITE_COOKIE);
      return { status: "unusable" };
    }
    if (caught.kind === "conflict") {
      jar.delete(INVITE_COOKIE);
      return { status: "already-member" };
    }
    if (caught.kind === "unauthenticated") return { status: "unauthenticated" };

    // Transient: leave the cookie in place so the user can try again.
    return { status: "error", message: caught.message, requestId: caught.requestId };
  }
}

/** Discard a held invitation without accepting it. */
export async function discardPendingInvitation(): Promise<void> {
  (await cookies()).delete(INVITE_COOKIE);
}
