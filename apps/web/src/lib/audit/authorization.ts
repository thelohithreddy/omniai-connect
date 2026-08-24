import { ApiFailure } from "@/lib/api/errors";

/**
 * How an audit-log failure is presented (MC1.4, ADR-0044 D5).
 *
 * Extracted from the page as a pure function because it encodes a **ratified authorization
 * decision**, not styling. ADR-0044 D5 states it precisely: `audit:read` is OWNER/ADMIN only, so a
 * MEMBER or VIEWER receives the API's 403, and the route must render an explicit "requires Owner
 * or Admin" state — with no data and no shape of data. Inline in JSX that rule was untestable, and
 * a mutation removing it survived the MC1.4 audit. Here it is asserted directly.
 *
 * The distinction that matters: a 403 is a **correct answer**, not a fault. Three of five roles
 * will see it during normal use, so it must not be dressed as an error — that would read as a
 * broken product and train users to ignore real errors. Every other failure is an error state
 * carrying `request_id` so support can find the exact request (FRONTEND_SPEC §8).
 *
 * Nothing here decides *access*. The API already decided; this only decides how its answer reads.
 * A client-side role check would be a second authorization authority, and the one that drifts from
 * `core/authz.py` is always the one that grants too much.
 */

export type AuditFailurePresentation =
  | {
      /** ADR-0044 D5's explicit role state. Informational, never an error. */
      readonly kind: "requires-elevated-role";
      readonly message: string;
    }
  | {
      /** Anything else: transport, timeout, 5xx, unexpected. */
      readonly kind: "error";
      readonly title: string;
      readonly message: string;
      readonly requestId?: string;
    };

/** ADR-0044 D5's wording, kept as a constant so a test can assert the ratified phrasing. */
export const REQUIRES_ELEVATED_ROLE_MESSAGE =
  "Audit log requires the Owner or Admin role.";

export function presentAuditFailure(failure: ApiFailure): AuditFailurePresentation {
  if (failure.kind === "forbidden") {
    // Deliberately fixed text rather than the API's message. The backend's 403 body is uniform by
    // design, and echoing it verbatim would let a future wording change alter what this surface
    // discloses.
    return { kind: "requires-elevated-role", message: REQUIRES_ELEVATED_ROLE_MESSAGE };
  }

  return {
    kind: "error",
    title: "Could not load the Tool Call log",
    // `failure.message` is already normalised by the transport: a 5xx never carries the backend's
    // text, so no internal detail reaches the browser here.
    message: failure.message,
    ...(failure.requestId ? { requestId: failure.requestId } : {}),
  };
}
