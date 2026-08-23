import "server-only";

import { cookies, headers } from "next/headers";
import { cache } from "react";

import type { MembershipRead } from "@omniai/types";

import { listMyWorkspaces } from "@/lib/api/client";

/**
 * Workspace selection and authorization context (MC1.3, ADR-0016, ADR-0044 §6).
 *
 * **The single rule this module exists to enforce: the browser never decides which workspace it
 * is in.** A cookie, a query parameter and a form field are all *requests* to select a workspace.
 * The authority is `GET /v1/workspaces`, which the API answers from the caller's JWT subject and
 * their real memberships. Selection is the intersection of the two — never the browser's half
 * alone.
 *
 * ADR-0016 states this as "`X-Workspace-Id` is a selection signal, never authority", and requires
 * a caller with several memberships and no valid selection to **fail closed**. That is
 * implemented literally below: no "first workspace" fallback, because silently picking one would
 * make a stale or forged cookie resolve to a real workspace and would make the failure invisible.
 *
 * `role` travels with the selection for rendering only. Authorization is the API's answer — it
 * re-resolves the role under RLS after the workspace binds (ADR-0044 §5). Nothing here is allowed
 * to become a second authorization authority.
 */

/**
 * The selection cookie.
 *
 * `__Host-` prefix: a browser accepts it only when it is `Secure`, has `Path=/` and carries **no
 * `Domain`**, which makes it impossible for a sibling subdomain to write one. Session fixation
 * via an attacker-planted workspace cookie is the threat; the prefix removes the mechanism rather
 * than guarding it. Dropped in development, where there is no TLS and the browser would reject
 * the cookie outright.
 */
export const WORKSPACE_COOKIE =
  process.env.NODE_ENV === "production" ? "__Host-omniai_workspace" : "omniai_workspace";

/** Why no workspace is bound, when none is. */
export type WorkspaceContextFailure =
  /** The caller belongs to no workspace at all. */
  | "no-memberships"
  /** Several memberships and no valid selection — ADR-0016's fail-closed case. */
  | "selection-required";

export interface WorkspaceContext {
  /** The bound workspace. Safe to send as `X-Workspace-Id`: membership is already proven. */
  readonly workspaceId: string;
  /** The caller's role here. **Display only** — never an authorization input. */
  readonly role: string;
  /** Every workspace the caller belongs to, for the switcher. */
  readonly memberships: readonly MembershipRead[];
}

export type WorkspaceResolution =
  | { readonly ok: true; readonly context: WorkspaceContext }
  | { readonly ok: false; readonly reason: WorkspaceContextFailure; readonly memberships: readonly MembershipRead[] };

/**
 * Resolve the caller's memberships from the API.
 *
 * Per-request memoised (ADR-0044 §6 permits React `cache()` precisely because its lifetime is one
 * request). The layout, the switcher and any page in the same render share one call instead of
 * three. It is **not** a data cache: nothing survives the response, so no workspace list can be
 * served to a different user.
 */
export const getMemberships = cache(async (): Promise<readonly MembershipRead[]> => {
  const requestHeaders = await headers();
  const list = await listMyWorkspaces(requestHeaders);
  return list.data ?? [];
});

/**
 * Resolve the active workspace, or explain why there is none.
 *
 * The order is deliberate: memberships are fetched **first**, and the cookie is only ever used to
 * pick from that list. Reading the cookie first and trusting it would be the cross-tenant bug this
 * whole module is built to prevent.
 *
 * A single membership binds automatically — the caller has exactly one answer, so demanding they
 * choose it would be friction with no security value, and the API auto-binds in the same case
 * (ADR-0016). Several memberships require a *valid* selection; an absent, stale, forged or
 * no-longer-authorized cookie all resolve identically to `selection-required`.
 */
export const resolveWorkspace = cache(async (): Promise<WorkspaceResolution> => {
  const memberships = await getMemberships();

  if (memberships.length === 0) {
    return { ok: false, reason: "no-memberships", memberships };
  }

  const requested = (await cookies()).get(WORKSPACE_COOKIE)?.value;

  // The intersection. `find` over the authoritative list is the entire authorization check:
  // a workspace id that is not in it cannot be selected, whatever the cookie says.
  const selected = requested
    ? memberships.find((membership) => membership.id === requested)
    : undefined;

  if (selected) {
    return { ok: true, context: { workspaceId: selected.id, role: selected.role, memberships } };
  }

  if (memberships.length === 1) {
    const only = memberships[0]!;
    return { ok: true, context: { workspaceId: only.id, role: only.role, memberships } };
  }

  // Fail closed. No "pick the first one" — that would turn a forged or stale cookie into a
  // successful bind and hide the fact that the caller never chose.
  return { ok: false, reason: "selection-required", memberships };
});

/**
 * Is this workspace one the caller may select?
 *
 * Exported so the workspace-switch action re-checks membership itself rather than trusting that
 * whoever called it already did. The action is a public HTTP endpoint in every meaningful sense —
 * anything reachable from a form post is — so it must authorize independently.
 */
export async function isMemberOf(workspaceId: string): Promise<boolean> {
  const memberships = await getMemberships();
  return memberships.some((membership) => membership.id === workspaceId);
}
