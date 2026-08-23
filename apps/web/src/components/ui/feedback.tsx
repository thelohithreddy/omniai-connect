import type { ComponentProps, ReactNode } from "react";

import { cn } from "@/lib/utils";

/**
 * Loading, empty and error states (MC1.2 design system).
 *
 * Grouped in one module because they are the same decision — "there is nothing to show yet, and
 * here is why" — and keeping them together makes it obvious when a surface handles one case and
 * silently drops another.
 */

/**
 * Skeleton placeholder.
 *
 * `aria-hidden`, deliberately. A skeleton is a *visual* stand-in; announcing a grid of grey boxes
 * tells a screen-reader user nothing. Busy state belongs on the region that is loading — see
 * `LoadingState` — not on each decorative shape. FRONTEND_SPEC §8 asks for skeletons matching the
 * final layout rather than spinners, which is why this takes a className instead of a size prop.
 */
export function Skeleton({ className, ...props }: ComponentProps<"div">) {
  return (
    <div
      aria-hidden="true"
      className={cn("animate-pulse-subtle rounded-md bg-muted", className)}
      {...props}
    />
  );
}

export interface LoadingStateProps {
  /** Announced to assistive technology while the region is busy. */
  readonly label?: string;
  readonly children?: ReactNode;
  readonly className?: string;
}

/**
 * A busy region.
 *
 * `role="status"` with `aria-live="polite"` announces the label once, without interrupting. The
 * visible skeletons stay `aria-hidden`, so the user hears "Loading tool calls" rather than
 * silence — or worse, a stream of nothing while the page appears frozen.
 */
export function LoadingState({ label = "Loading", children, className }: LoadingStateProps) {
  return (
    <div role="status" aria-live="polite" aria-busy="true" className={cn("space-y-3", className)}>
      <span className="sr-only">{label}</span>
      {children ?? (
        <>
          <Skeleton className="h-4 w-2/3" />
          <Skeleton className="h-4 w-1/2" />
          <Skeleton className="h-4 w-5/6" />
        </>
      )}
    </div>
  );
}

export interface EmptyStateProps {
  readonly title: string;
  readonly description?: ReactNode;
  /** A primary action, e.g. "Connect an API". */
  readonly action?: ReactNode;
  readonly className?: string;
  /** Heading level for this position in the document outline. */
  readonly headingAs?: "h2" | "h3" | "h4";
}

/**
 * "There is nothing here yet."
 *
 * Renders a real heading rather than styled text so the region is reachable by heading
 * navigation, and so an empty list is distinguishable from a failed one.
 */
export function EmptyState({
  title,
  description,
  action,
  className,
  headingAs: Heading = "h3",
}: EmptyStateProps) {
  return (
    <div className={cn("flex flex-col items-center gap-2 rounded-lg border border-dashed border-border p-8 text-center", className)}>
      <Heading className="text-base font-semibold text-foreground">{title}</Heading>
      {description ? <p className="text-sm text-muted-foreground">{description}</p> : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

export interface ErrorStateProps {
  readonly title?: string;
  readonly message: string;
  /**
   * The API error envelope's `request_id`. FRONTEND_SPEC §8 requires it on error surfaces so a
   * user can quote one string to support and have the exact request found in the logs.
   */
  readonly requestId?: string;
  readonly action?: ReactNode;
  readonly className?: string;
}

export function ErrorState({
  title = "Something went wrong",
  message,
  requestId,
  action,
  className,
}: ErrorStateProps) {
  return (
    <div
      role="alert"
      className={cn("flex flex-col items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-4", className)}
    >
      <p className="font-medium text-foreground">{title}</p>
      <p className="text-sm text-foreground">{message}</p>
      {requestId ? (
        <p className="text-xs text-muted-foreground">
          Reference: <code className="font-mono">{requestId}</code>
        </p>
      ) : null}
      {action}
    </div>
  );
}
