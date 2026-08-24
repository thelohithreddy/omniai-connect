/**
 * Audit-record formatting (MC1.4).
 *
 * Pure functions, unit-tested, and **total**: every one accepts whatever the API actually sent —
 * including a malformed or unexpected value — and returns something safe to render. An audit
 * viewer that throws on one odd row hides the entire page, which in an audit trail is the worst
 * possible failure mode: the operator concludes nothing happened.
 *
 * Nothing here interprets provider content. `caller` is a free-form object from the runtime, so it
 * is read defensively and reduced to a short, inert description.
 */

/**
 * A UUID shortened for display.
 *
 * Full UUIDs make every column the same illegible width. The first segment is enough to correlate
 * rows by eye, and the untruncated value stays available via `request_id` and the detail endpoint.
 * Defensive about non-strings because the field is typed `string` by the contract but arrives as
 * JSON.
 */
export function shortId(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) return "—";
  return value.split("-")[0] ?? value.slice(0, 8);
}

/**
 * Render a duration.
 *
 * Sub-second values are the common case and read better as milliseconds; anything longer becomes
 * seconds so a slow call is obvious at a glance rather than being a wall of digits.
 */
export function formatDuration(durationMs: unknown): string {
  if (typeof durationMs !== "number" || !Number.isFinite(durationMs) || durationMs < 0) return "—";
  if (durationMs < 1000) return `${Math.round(durationMs)} ms`;
  return `${(durationMs / 1000).toFixed(durationMs < 10_000 ? 2 : 1)} s`;
}

/**
 * Render an ISO timestamp.
 *
 * Fixed `en-GB` + UTC rather than the server's locale: an audit trail is correlated against
 * backend logs, and a timestamp that silently shifts with the rendering machine's timezone is a
 * genuine incident-response hazard. The "UTC" suffix says so on screen.
 *
 * An unparseable value returns an em dash instead of "Invalid Date".
 */
export function formatTimestamp(value: unknown): string {
  if (typeof value !== "string") return "—";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "—";

  return `${new Intl.DateTimeFormat("en-GB", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZone: "UTC",
    hour12: false,
  }).format(parsed)} UTC`;
}

/**
 * Describe who made the call.
 *
 * `caller` is documented as `{interface, kind, api_token_id | member_id}` but typed as an open
 * object, so this reads the two fields it understands and ignores everything else. It deliberately
 * does **not** dump unknown keys: the object comes from the runtime, and rendering arbitrary keys
 * would turn a caller column into an uncontrolled data surface.
 *
 * Only the *kind* of identity and the interface are shown — never a token id. Which API token was
 * used is a credential-adjacent detail that does not belong in a list view.
 */
export function describeCaller(caller: unknown): string {
  if (typeof caller !== "object" || caller === null) return "—";

  const record = caller as Record<string, unknown>;
  const kind = typeof record.kind === "string" ? record.kind : null;
  const iface = typeof record.interface === "string" ? record.interface : null;

  // Capped and escaped by React on render; the cap stops a pathological value from stretching
  // the column.
  const parts = [kind, iface].filter((part): part is string => Boolean(part)).map((part) => part.slice(0, 24));
  return parts.length === 0 ? "—" : parts.join(" · ");
}
