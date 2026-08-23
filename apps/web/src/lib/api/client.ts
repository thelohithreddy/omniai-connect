/**
 * Typed operations for the endpoints MC1 consumes (ADR-0044 D2).
 *
 * Every function is a thin, named wrapper over the one server-only transport. The value is not
 * abstraction — it is that a renamed backend field becomes a **compile error here**, once,
 * instead of a runtime `undefined` in whichever surface happened to touch it.
 *
 * Server-only by inheritance: this module imports the transport, which imports `server-only`,
 * so a `"use client"` component that reaches for any of these fails the build.
 *
 * Scope is exactly ADR-0043's MC1 surfaces plus the workspace resolution they need. There is no
 * wrapper for connectors, tools, members, api-tokens or Tool Call *execution*: those belong to
 * later milestones, and an unused wrapper is an invitation to build a surface out of turn.
 */

import "server-only";

import type {
  AuthorizeStartRead,
  ConnectionHealthRead,
  MembershipList,
  ToolCallLogList,
  ToolCallLogRead,
  WorkspaceNotificationSettings,
  WorkspaceNotificationUpdate,
  WorkspaceRead,
} from "@omniai/types";

import { apiRequest, type RequestIdentity } from "@/lib/api/transport";

// ------------------------------------------------------------------------------- workspaces

/**
 * The authenticated human's own memberships — the workspace switcher's data source.
 *
 * The one genuinely pre-selection call: it authenticates by JWT subject and binds no workspace
 * (ADR-0016 §7), so it opts out of the workspace requirement explicitly rather than by omission.
 * `role` here is display-only and is never an authorization input.
 */
export function listMyWorkspaces(headers: Headers): Promise<MembershipList> {
  return apiRequest<MembershipList>({
    method: "GET",
    path: "/v1/workspaces",
    identity: { headers },
    allowMissingWorkspace: true,
  });
}

/** The selected Workspace. Carries no `notification_email` — that is OWNER-only (ADR-0042). */
export function getCurrentWorkspace(identity: RequestIdentity): Promise<WorkspaceRead> {
  return apiRequest<WorkspaceRead>({
    method: "GET",
    path: "/v1/workspaces/me",
    identity,
  });
}

// -------------------------------------------------------------------- notification settings
//
// OWNER-only on read *and* write. The frontend does not pre-check the role: it calls, and a
// non-OWNER receives the API's 403, which the surface renders. A client-side role check would
// be a second authorization authority (ADR-0044 §5).

export function getNotificationSettings(
  identity: RequestIdentity,
): Promise<WorkspaceNotificationSettings> {
  return apiRequest<WorkspaceNotificationSettings>({
    method: "GET",
    path: "/v1/workspaces/me/notification-settings",
    identity,
  });
}

/** `notification_email: null` disables notifications; the field is required, not optional. */
export function updateNotificationSettings(
  identity: RequestIdentity,
  body: WorkspaceNotificationUpdate,
): Promise<WorkspaceNotificationSettings> {
  return apiRequest<WorkspaceNotificationSettings, WorkspaceNotificationUpdate>({
    method: "PATCH",
    path: "/v1/workspaces/me",
    identity,
    body,
  });
}

// ------------------------------------------------------------------------------- audit log
//
// `audit:read` — OWNER/ADMIN only. Cursors are opaque and are echoed back verbatim; the
// frontend never constructs or decodes one.

export interface ToolCallLogQuery {
  limit?: number;
  cursor?: string;
  connection_id?: string;
  tool_id?: string;
  status?: string;
  interface?: string;
  created_after?: string;
  created_before?: string;
}

export function listToolCalls(
  identity: RequestIdentity,
  query: ToolCallLogQuery = {},
): Promise<ToolCallLogList> {
  return apiRequest<ToolCallLogList>({
    method: "GET",
    path: "/v1/tool-calls",
    identity,
    query: { ...query },
  });
}

export function getToolCall(
  identity: RequestIdentity,
  toolCallId: string,
): Promise<ToolCallLogRead> {
  return apiRequest<ToolCallLogRead>({
    method: "GET",
    path: `/v1/tool-calls/${encodeURIComponent(toolCallId)}`,
    identity,
  });
}

// ------------------------------------------------------------------------ connection health

/**
 * Run one health check. Requires `tools:execute`.
 *
 * A real Tool Call against the provider with the Connection's real credential, so it is a
 * mutation in every sense that matters and is never retried. The frontend renders the returned
 * classification and does not recompute health (ADR-0044 §5).
 */
export function testConnection(
  identity: RequestIdentity,
  connectionId: string,
): Promise<ConnectionHealthRead> {
  return apiRequest<ConnectionHealthRead>({
    method: "POST",
    path: `/v1/connections/${encodeURIComponent(connectionId)}/test`,
    identity,
  });
}

// ---------------------------------------------------------------------------------- OAuth

/**
 * Begin an OAuth authorization. Requires `connections:manage`.
 *
 * Returns the provider URL to send the user agent to, and when it stops being redeemable. The
 * PKCE verifier and the state never leave the backend — the browser only ever navigates.
 * The callback is the provider's redirect target and is not called from this client.
 */
export function startOAuthAuthorization(
  identity: RequestIdentity,
  connectionId: string,
): Promise<AuthorizeStartRead> {
  return apiRequest<AuthorizeStartRead>({
    method: "POST",
    path: `/v1/connections/${encodeURIComponent(connectionId)}/oauth/authorize`,
    identity,
  });
}
