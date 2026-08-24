"use server";

import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { startOAuthAuthorization } from "@/lib/api/client";
import { ApiFailure } from "@/lib/api/errors";
import { getSessionOrNull } from "@/lib/session";
import { checkAuthorizeUrl } from "@/lib/oauth/authorize-url";
import { resolveWorkspace } from "@/lib/workspace/context";

/**
 * Begin an OAuth authorization (MC1.5, ADR-0038).
 *
 * A Server Action is a public POST endpoint — Next gives it an id and a browser can invoke it with
 * any arguments — so this authorizes from scratch rather than trusting the page that rendered the
 * button. Three checks, in order, none of which the caller can influence:
 *
 *   1. a live human session;
 *   2. a workspace bound by intersecting the API's membership list with the selection cookie
 *      (ADR-0016) — never a workspace named in the request;
 *   3. `connections:manage` on that workspace, which the **API** enforces. A 403 is rendered, not
 *      pre-empted here; a client-side permission check would be a second authorization authority.
 *
 * **The PKCE verifier and `state` never touch this process.** ADR-0038 keeps both server-side in
 * the API: this action receives only `authorize_url` and sends the browser there. There is nothing
 * here for an attacker to read, replay or downgrade — the S256 challenge, the state row and its
 * single-use consume are all properties of the backend and the database.
 */

/** Rendered outcomes. A redirect never returns, so success is absent from this union by design. */
export type AuthorizationStart =
  | { readonly status: "unauthenticated" }
  | { readonly status: "no-workspace" }
  /** The caller lacks `connections:manage`, per the API. */
  | { readonly status: "forbidden" }
  /** No such live Connection in this workspace — the API's uniform 404. */
  | { readonly status: "not-found" }
  /** The Connector is not oauth2, OAuth is disabled, or the Connection is revoked. */
  | { readonly status: "unavailable" }
  /** The API returned a URL this application refuses to navigate to. */
  | { readonly status: "unsafe-url" }
  | { readonly status: "error"; readonly message: string; readonly requestId?: string };

export async function beginAuthorization(formData: FormData): Promise<AuthorizationStart> {
  if (!(await getSessionOrNull())) return { status: "unauthenticated" };

  const resolution = await resolveWorkspace();
  // Fail closed rather than binding a workspace on the caller's behalf (ADR-0016).
  if (!resolution.ok) return { status: "no-workspace" };

  const connectionId = formData.get("connectionId");
  // Reject a non-string outright: FormData can carry a File, and coercing one would produce a
  // value that is neither what the user chose nor obviously wrong.
  if (typeof connectionId !== "string" || connectionId.length === 0) {
    return { status: "not-found" };
  }

  let authorizeUrl: string;
  try {
    const started = await startOAuthAuthorization(
      { headers: await headers(), workspaceId: resolution.context.workspaceId },
      connectionId,
    );

    /*
      The one place an externally-sourced value becomes a navigation. The API is trusted, but a
      scheme allowlist is cheap and removes the whole class: a `javascript:` URL reaching this
      position would be stored XSS delivered by our own redirect.
    */
    const checked = checkAuthorizeUrl(started.authorize_url);
    if (!checked.ok) return { status: "unsafe-url" };
    authorizeUrl = checked.url;
  } catch (caught) {
    if (!(caught instanceof ApiFailure)) throw caught;

    // Mapped to a closed set of rendered states. The API's own message is never surfaced for
    // these: 404 is deliberately uniform ("no such live Connection in this Workspace"), and
    // echoing it would let a caller probe which connection ids exist in other workspaces.
    if (caught.kind === "forbidden") return { status: "forbidden" };
    if (caught.kind === "not_found") return { status: "not-found" };
    if (caught.kind === "conflict" || caught.kind === "validation") return { status: "unavailable" };
    if (caught.kind === "unauthenticated") return { status: "unauthenticated" };

    return {
      status: "error",
      message: caught.message,
      ...(caught.requestId ? { requestId: caught.requestId } : {}),
    };
  }

  /*
    Navigate. `redirect()` throws, so nothing after this runs and no success value is returned —
    the browser goes to the provider and comes back to the API's callback, which is the only place
    the code is redeemed. Placed outside the try so a `redirect()` is never caught and
    reinterpreted as an API failure.
  */
  redirect(authorizeUrl);
}
