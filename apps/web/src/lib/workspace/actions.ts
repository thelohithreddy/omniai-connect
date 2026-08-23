"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { getSessionOrNull } from "@/lib/session";
import { isMemberOf, WORKSPACE_COOKIE } from "@/lib/workspace/context";

/**
 * Workspace switching (MC1.3, ADR-0016, ADR-0044 §6).
 *
 * A Server Action is a **public POST endpoint**. Next generates an id for it and the browser can
 * invoke it with any arguments it likes, so this authorizes from scratch rather than assuming the
 * page that rendered the form did any checking. Treating an action as "internal" is how
 * server-side authorization quietly becomes client-side authorization.
 *
 * Two independent checks, in order:
 *   1. there is a live human session;
 *   2. the requested workspace is one the **API** says this human belongs to.
 *
 * Only then is the selection cookie written. The cookie never grants access — it is replayed
 * through `resolveWorkspace`, which intersects it with the membership list again on every
 * request. Forging it therefore achieves nothing.
 */
export async function selectWorkspace(formData: FormData): Promise<void> {
  const session = await getSessionOrNull();
  if (!session) redirect("/sign-in");

  const requested = formData.get("workspaceId");
  // Reject a non-string outright: `FormData` can carry a File, and coercing one to a string
  // would produce a value that is neither what the user chose nor obviously wrong.
  if (typeof requested !== "string" || requested.length === 0) {
    redirect("/dashboard?error=invalid-workspace");
  }

  if (!(await isMemberOf(requested))) {
    // Uniform outcome for "not a member", "no such workspace" and "membership revoked". A
    // distinguishable response here would let a signed-in user enumerate which workspace ids
    // exist by watching the difference.
    redirect("/dashboard?error=invalid-workspace");
  }

  (await cookies()).set(WORKSPACE_COOKIE, requested, {
    // Never readable from document.cookie: the browser has no reason to read its own selection,
    // and an XSS foothold should not be able to enumerate or rewrite it.
    httpOnly: true,
    // `__Host-` requires Secure; in development the prefix is dropped and so is this.
    secure: process.env.NODE_ENV === "production",
    // `lax` rather than `strict`: the selection must survive following an emailed link back into
    // the app, and it is not a credential — it selects among workspaces the caller already has.
    sameSite: "lax",
    path: "/",
    // Session-scoped deliberately. A long-lived selection outlives the membership that justified
    // it; re-selecting after a browser restart costs one click.
  });

  // A full server navigation, not a client-side state update. Everything workspace-scoped is
  // rendered on the server from the newly bound workspace, so nothing from the previous one can
  // survive the switch — there is no client store holding server data to go stale (ADR-0044 §6).
  redirect("/dashboard");
}

/**
 * Clear the selection.
 *
 * Used on sign-out so the next human to use the browser does not inherit a selection. Harmless if
 * none is set.
 */
export async function clearWorkspaceSelection(): Promise<void> {
  (await cookies()).delete(WORKSPACE_COOKIE);
}
