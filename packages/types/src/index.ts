/**
 * @omniai/types — the frontend's authoritative view of the backend contract (ADR-0044 D2).
 *
 * The backend owns the contract. `openapi.json` is exported from the running FastAPI
 * application (`scripts/export-openapi.py`) and committed so a contract change is visible in
 * the same diff as the Python that caused it; `src/generated/api.ts` is produced from that
 * document by `openapi-typescript` and is **never hand-edited**. `openapi:check` fails the
 * build if the two disagree.
 *
 * This module is the curated surface. It re-exports the generated shapes and gives the
 * endpoints MC1 actually consumes stable names, so a call site says `WorkspaceRead` rather than
 * indexing eight levels into a generated tree — and so a backend rename surfaces here, once, as
 * a compile error rather than in every component that touched it.
 *
 * It contains **types only**. No credentials, no JWTs, no runtime, no authorization logic, no
 * duplicated business rules. Anything with behaviour belongs in the server-only transport
 * (`apps/web/src/lib/api`), and anything that is UI state rather than an API contract does not
 * belong in this package at all.
 */

export type { components, operations, paths } from "./generated/api.ts";

import type { components } from "./generated/api.ts";

type Schemas = components["schemas"];

// ---------------------------------------------------------------------------- error envelope
//
// Hand-written rather than generated, deliberately. The envelope is defined in
// docs/API_GUIDELINES.md and produced by the application's exception handlers, not by a route's
// response_model, so FastAPI does not emit it into the OpenAPI document. It is the one contract
// the generator cannot see.

/** The canonical API error envelope — see docs/API_GUIDELINES.md. */
export interface ApiError {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    request_id: string;
  };
}

// ------------------------------------------------------------------- MC1-consumed contracts
//
// Only the surfaces ADR-0043 assigned to MC1 are named here. Adding an alias for an endpoint no
// control-plane surface consumes would invite a component to reach for it before its milestone.

/** A Workspace as returned to an authenticated caller. Never carries `notification_email`. */
export type WorkspaceRead = Schemas["WorkspaceRead"];

/** One of the authenticated human's own memberships — the workspace switcher's data source. */
export type MembershipRead = Schemas["MembershipRead"];
export type MembershipList = Schemas["MembershipList"];

/**
 * What an invitation recipient joined (MC1.3, ADR-0017): the workspace and the granted role.
 * Deliberately carries no invitation detail — the API discloses nothing about the invitation
 * itself, and the acceptance surface has nothing extra to leak.
 */
export type AcceptedInvitation = Schemas["AcceptedInvitation"];

/** The Workspace's notification destination. OWNER-only on read and write (ADR-0042). */
export type WorkspaceNotificationSettings = Schemas["WorkspaceNotificationSettings"];
export type WorkspaceNotificationUpdate = Schemas["WorkspaceNotificationUpdate"];

/** Tool Call audit records — `audit:read`, OWNER/ADMIN only. */
export type ToolCallLogRead = Schemas["ToolCallLogRead"];
export type ToolCallLogList = Schemas["ToolCallLogList"];

/**
 * A Connection as the control plane sees it (MC1.5).
 *
 * `needs_reauth` is **derived** by the API (`status == 'error'` and an oauth2 credential), not a
 * fifth status — ADR-0038 D5. The frontend renders it and never recomputes it.
 */
export type ConnectionRead = Schemas["ConnectionRead"];
export type ConnectionList = Schemas["ConnectionList"];

/** One Connection health check result. Classified metadata only — never a provider body. */
export type ConnectionHealthRead = Schemas["ConnectionHealthRead"];

/** Where to send the user agent to begin an OAuth authorization, and when the link expires. */
export type AuthorizeStartRead = Schemas["AuthorizeStartRead"];
