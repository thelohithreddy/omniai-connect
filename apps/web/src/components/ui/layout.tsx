import type { ComponentProps } from "react";

import { cn } from "@/lib/utils";

/**
 * Layout primitives (MC1.2 design system).
 *
 * Two of them, on purpose. Consistent page width and consistent vertical rhythm are the only
 * layout decisions worth centralising before any real surface exists; anything more would be
 * guessing at screens that have not been designed, and ADR-0044 scopes MC1.2 to the *minimal*
 * coherent system.
 */

export interface ContainerProps extends ComponentProps<"div"> {
  readonly size?: "sm" | "md" | "lg";
}

const CONTAINER_WIDTH = {
  sm: "max-w-2xl",
  md: "max-w-4xl",
  lg: "max-w-7xl",
} as const;

export function Container({ className, size = "lg", ...props }: ContainerProps) {
  return (
    <div className={cn("mx-auto w-full px-4 sm:px-6", CONTAINER_WIDTH[size], className)} {...props} />
  );
}

export interface StackProps extends ComponentProps<"div"> {
  readonly gap?: "sm" | "md" | "lg";
}

const STACK_GAP = { sm: "gap-2", md: "gap-4", lg: "gap-8" } as const;

export function Stack({ className, gap = "md", ...props }: StackProps) {
  return <div className={cn("flex flex-col", STACK_GAP[gap], className)} {...props} />;
}
