import { cva, type VariantProps } from "class-variance-authority";
import type { ComponentProps } from "react";

import { cn } from "@/lib/utils";

/**
 * Alert (MC1.2 design system).
 *
 * The ARIA role is derived from the variant rather than left to the caller, because the two must
 * agree and only one of them is visible in review. `role="alert"` interrupts the user
 * immediately; using it for an informational banner is noisy enough that people disable it, and
 * using `role="status"` for a failure means the failure is never announced at all.
 *
 * - `danger` → `role="alert"` (assertive): something failed and the user must know now.
 * - everything else → `role="status"` (polite): announced at the next pause.
 *
 * FRONTEND_SPEC §8 forbids silent failure; this is the primitive that makes an error audible.
 */
const alertVariants = cva("rounded-md border p-4 text-sm", {
  variants: {
    variant: {
      info: "border-border bg-muted text-foreground",
      success: "border-success/40 bg-success/10 text-foreground",
      danger: "border-destructive/40 bg-destructive/10 text-foreground",
    },
  },
  defaultVariants: { variant: "info" },
});

export interface AlertProps
  extends Omit<ComponentProps<"div">, "role">,
    VariantProps<typeof alertVariants> {}

export function Alert({ className, variant, ...props }: AlertProps) {
  return (
    <div
      role={variant === "danger" ? "alert" : "status"}
      className={cn(alertVariants({ variant }), className)}
      {...props}
    />
  );
}

export function AlertTitle({ className, ...props }: ComponentProps<"p">) {
  return <p className={cn("mb-1 font-medium", className)} {...props} />;
}

export function AlertDescription({ className, ...props }: ComponentProps<"div">) {
  return <div className={cn("text-muted-foreground", className)} {...props} />;
}
