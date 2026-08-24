import { cn } from "@/lib/utils";
import { presentToolCallStatus } from "@/lib/audit/status";

/**
 * Tool Call status badge (MC1.4).
 *
 * Carries meaning in **text**, not colour. The visible label already names the status, and
 * `srDescription` is exposed to assistive technology so an unrecognised value announces as
 * "Unrecognised status: …" rather than as a coloured dot with no name. WCAG 1.4.1 and
 * FRONTEND_SPEC §7 both require this; a status badge is where it is most often skipped.
 *
 * The status string comes from the API and is therefore untrusted. It is rendered as text — React
 * escapes it, nothing is interpolated into a class name, and `presentToolCallStatus` caps the
 * length, so a hostile or absurd value cannot inject markup or break the layout.
 */
const TONE_CLASS = {
  success: "border-success/40 bg-success/10 text-foreground",
  danger: "border-destructive/40 bg-destructive/10 text-foreground",
  warning: "border-border bg-muted text-foreground",
  neutral: "border-border bg-muted text-muted-foreground",
} as const;

export function StatusBadge({ status, className }: { readonly status: string; readonly className?: string }) {
  const presentation = presentToolCallStatus(status);

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium",
        TONE_CLASS[presentation.tone],
        className,
      )}
    >
      {/*
        The label is plain text, so it is both seen and announced — the badge is never
        colour-only. An unrecognised value gets one extra screen-reader-only clarifier so it is
        not mistaken for a status this build understands; a known value needs no duplicate,
        which would just make the badge read twice.
      */}
      {presentation.label}
      {presentation.isKnown ? null : <span className="sr-only"> (unrecognised status)</span>}
    </span>
  );
}
