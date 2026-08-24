import type { ConnectionRead } from "@omniai/types";

/**
 * How a Connection's authorization state reads to a human (MC1.5, ADR-0038).
 *
 * **Derived from the API's answer, never recomputed.** ADR-0038 D5 makes `needs_reauth` a derived
 * field the backend owns (`status == 'error'` and an oauth2 credential) rather than a fifth
 * status. Re-deriving it here from `status` and `credential_id` would create a second definition
 * that drifts — and the copy that drifts is the one that tells a customer their integration is
 * fine when it is not.
 *
 * Total, like the audit formatters: an unrecognised `status` produces a neutral, honest state
 * rather than being guessed into "connected". Claiming a broken integration works is the worst
 * failure this surface has.
 */

export type ConnectionAuthorizationState =
  /** Authorized and working. */
  | "connected"
  /** Authorized once, but the API says it must be authorized again (ADR-0038 D5). */
  | "needs-reauth"
  /** No credential attached yet — the first-authorization case. */
  | "not-connected"
  /** The Connection is not usable: revoked, disabled, or otherwise inactive. */
  | "inactive"
  /** A status this build does not recognise. Never presented as working. */
  | "unknown";

export interface ConnectionPresentation {
  readonly state: ConnectionAuthorizationState;
  readonly label: string;
  /** Whether starting an authorization is a sensible action right now. */
  readonly canAuthorize: boolean;
  /** Announced alongside the label so state is never carried by colour alone. */
  readonly srDescription: string;
}

const PRESENTATION: Record<ConnectionAuthorizationState, Omit<ConnectionPresentation, "state">> = {
  connected: {
    label: "Connected",
    canAuthorize: false,
    srDescription: "Connected and authorized",
  },
  "needs-reauth": {
    label: "Reauthorization required",
    // The whole point of surfacing this state: the fix is to authorize again.
    canAuthorize: true,
    srDescription: "Reauthorization required",
  },
  "not-connected": {
    label: "Not connected",
    canAuthorize: true,
    srDescription: "Not connected — authorization has not been completed",
  },
  inactive: {
    label: "Inactive",
    // Authorizing a revoked Connection would fail at the API anyway (409); offering the button
    // would invite a pointless round trip and a confusing error.
    canAuthorize: false,
    srDescription: "Inactive — this connection cannot be authorized",
  },
  unknown: {
    label: "Unknown",
    canAuthorize: false,
    srDescription: "Unrecognised connection state",
  },
};

/** Statuses this build understands, mirroring the backend's `status_valid` CHECK. */
const ACTIVE = "active";
const REVOKED_OR_ERROR = ["revoked", "error", "disabled"] as const;

export function presentConnection(connection: ConnectionRead): ConnectionPresentation {
  const state = deriveState(connection);
  return { state, ...PRESENTATION[state] };
}

function deriveState(connection: ConnectionRead): ConnectionAuthorizationState {
  // Checked first and taken at face value. It is the API's own derivation (ADR-0038 D5), and it
  // is the one state a user must act on, so nothing below may mask it.
  if (connection.needs_reauth === true) return "needs-reauth";

  const status = typeof connection.status === "string" ? connection.status : "";

  if (status === ACTIVE) {
    // An active Connection with no credential has never completed an authorization.
    return connection.credential_id ? "connected" : "not-connected";
  }

  if ((REVOKED_OR_ERROR as readonly string[]).includes(status)) return "inactive";

  // A status outside this build's vocabulary. Neutral and non-actionable rather than assumed
  // working — a future value must be additive, not silently reported as healthy.
  return "unknown";
}
