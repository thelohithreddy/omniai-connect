import { cva, type VariantProps } from "class-variance-authority";
import type { ComponentProps } from "react";

import { cn } from "@/lib/utils";

/**
 * Button (MC1.2 design system).
 *
 * No `"use client"`. It is a styled `<button>` with no hooks, so it costs nothing in a server
 * component and is bundled into the client graph only when a client component imports it.
 *
 * Focus is not styled here — `globals.css` gives every `:focus-visible` element one consistent
 * ring. A per-component focus style is how a design system ends up with rings that differ, or
 * disappear entirely, on the one control someone forgot.
 */
const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        primary: "bg-primary text-primary-foreground hover:bg-primary/90",
        secondary: "bg-muted text-foreground hover:bg-muted/80",
        outline: "border border-input bg-background hover:bg-muted",
        ghost: "hover:bg-muted",
        destructive: "bg-destructive text-destructive-foreground hover:bg-destructive/90",
      },
      size: {
        sm: "h-8 px-3",
        md: "h-10 px-4",
        lg: "h-11 px-6",
      },
    },
    defaultVariants: { variant: "primary", size: "md" },
  },
);

export interface ButtonProps
  extends ComponentProps<"button">,
    VariantProps<typeof buttonVariants> {
  /**
   * Renders a busy state.
   *
   * Disables the control *and* sets `aria-busy`, because a visual spinner alone tells a screen
   * reader user nothing. Disabling matters just as much: the common failure here is a form that
   * stays clickable while submitting and fires the mutation twice.
   */
  readonly isLoading?: boolean;
}

export function Button({
  className,
  variant,
  size,
  isLoading = false,
  disabled,
  children,
  ...props
}: ButtonProps) {
  return (
    <button
      className={cn(buttonVariants({ variant, size }), className)}
      disabled={disabled || isLoading}
      aria-busy={isLoading || undefined}
      {...props}
    >
      {isLoading ? (
        <span
          // Decorative: the state is already conveyed by aria-busy, so announcing it twice
          // would make the control read as "busy busy".
          aria-hidden="true"
          className="size-4 animate-spin rounded-full border-2 border-current border-t-transparent"
        />
      ) : null}
      {children}
    </button>
  );
}

export { buttonVariants };
