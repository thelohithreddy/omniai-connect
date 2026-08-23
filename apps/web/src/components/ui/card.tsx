import type { ComponentProps } from "react";

import { cn } from "@/lib/utils";

/**
 * Card (MC1.2 design system).
 *
 * A surface, not a semantic element. `CardTitle` renders an `<h3>` by default but takes an `as`
 * override, because heading *level* is a property of the page outline rather than of the card:
 * hard-coding one guarantees a skipped level somewhere, which is a real navigation failure for
 * screen-reader users who move by heading.
 */

export function Card({ className, ...props }: ComponentProps<"div">) {
  return (
    <div
      className={cn("rounded-lg border border-border bg-card text-card-foreground", className)}
      {...props}
    />
  );
}

export function CardHeader({ className, ...props }: ComponentProps<"div">) {
  return <div className={cn("flex flex-col gap-1.5 p-6", className)} {...props} />;
}

export interface CardTitleProps extends ComponentProps<"h3"> {
  /** Heading level for this position in the document outline. */
  readonly as?: "h1" | "h2" | "h3" | "h4";
}

export function CardTitle({ className, as: Tag = "h3", ...props }: CardTitleProps) {
  return <Tag className={cn("text-lg font-semibold leading-none", className)} {...props} />;
}

export function CardDescription({ className, ...props }: ComponentProps<"p">) {
  return <p className={cn("text-sm text-muted-foreground", className)} {...props} />;
}

export function CardContent({ className, ...props }: ComponentProps<"div">) {
  return <div className={cn("p-6 pt-0", className)} {...props} />;
}

export function CardFooter({ className, ...props }: ComponentProps<"div">) {
  return <div className={cn("flex items-center gap-2 p-6 pt-0", className)} {...props} />;
}
