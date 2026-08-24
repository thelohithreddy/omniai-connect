/**
 * Tool Call status vocabulary (MC1.4, ADR-0044).
 *
 * ADR-0044's deferred decisions require the audit viewer to "render `status` from a closed
 * vocabulary so a future value is additive". This module is that closed vocabulary, and the
 * emphasis is on what happens to a value that is *not* in it.
 *
 * The backend's constraint is `status IN ('succeeded','failed','denied','timeout')`
 * (`TOOL_CALL_STATUSES`), but the OpenAPI schema types the field as a bare `string` — so the
 * contract permits a value this build has never seen. When M4 adds an approval flow, `pending` is
 * the obvious candidate. A viewer that switched on the four known values and fell through to
 * `undefined` would render a blank cell, or crash on a lookup, for exactly the rows an operator
 * most needs to see.
 *
 * So an unknown status is a **first-class outcome**: it renders the raw value as inert text with
 * neutral styling and no invented meaning. It is never mapped to "failed" or "succeeded" — a
 * guess about severity in an audit log is worse than an honest "unrecognised".
 *
 * No `server-only` guard: this is pure presentation logic with no credential, no environment
 * access and no I/O, and it is used from both server and client components.
 */

/** The statuses this build understands. Mirrors the backend's CHECK constraint. */
export const KNOWN_TOOL_CALL_STATUSES = ["succeeded", "failed", "denied", "timeout"] as const;

export type KnownToolCallStatus = (typeof KNOWN_TOOL_CALL_STATUSES)[number];

/** How a status should read to a human, and how it should look. */
export interface StatusPresentation {
  /** The label shown in the cell. For an unknown value this is the raw string. */
  readonly label: string;
  /**
   * Severity, used only to pick a token pair. `neutral` covers both "informational" and
   * "we do not recognise this", because inventing a severity for an unknown value would put a
   * wrong signal in front of an operator reading an audit trail.
   */
  readonly tone: "success" | "danger" | "warning" | "neutral";
  /** False when the value is outside this build's vocabulary. */
  readonly isKnown: boolean;
  /**
   * Text a screen reader hears in place of colour. FRONTEND_SPEC §7 and WCAG 1.4.1 both forbid
   * colour as the only carrier of meaning, and a status badge is the classic violation.
   */
  readonly srDescription: string;
}

const PRESENTATION: Record<KnownToolCallStatus, Omit<StatusPresentation, "isKnown">> = {
  succeeded: { label: "Succeeded", tone: "success", srDescription: "Succeeded" },
  failed: { label: "Failed", tone: "danger", srDescription: "Failed" },
  // `denied` is an authorization refusal, not a provider fault — a different thing for an
  // operator to act on, so it does not share `failed`'s tone.
  denied: { label: "Denied", tone: "warning", srDescription: "Denied by authorization" },
  timeout: { label: "Timed out", tone: "warning", srDescription: "Timed out" },
};

export function isKnownToolCallStatus(status: string): status is KnownToolCallStatus {
  return (KNOWN_TOOL_CALL_STATUSES as readonly string[]).includes(status);
}

/**
 * Resolve a status to something safe to render.
 *
 * Total by construction: every possible string returns a presentation, so no caller needs a
 * fallback branch and none can forget one.
 */
export function presentToolCallStatus(status: string): StatusPresentation {
  if (isKnownToolCallStatus(status)) {
    return { ...PRESENTATION[status], isKnown: true };
  }

  // Rendered verbatim as inert text — never interpreted, never styled as success or failure.
  // React escapes it, and the length cap stops a pathological value from breaking the layout.
  const raw = status.trim();
  const label = raw.length === 0 ? "Unknown" : raw.slice(0, 32);
  return {
    label,
    tone: "neutral",
    isKnown: false,
    srDescription: `Unrecognised status: ${label}`,
  };
}
