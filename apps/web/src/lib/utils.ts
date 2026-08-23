import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * Compose Tailwind classes, resolving conflicts in favour of the caller (MC1.2).
 *
 * `clsx` handles conditionals; `tailwind-merge` resolves collisions so a caller's `className`
 * actually wins. Without the merge step, `<Button className="bg-destructive">` would emit both
 * `bg-primary` and `bg-destructive` and the outcome would depend on stylesheet order rather than
 * intent — a subtle, position-dependent bug that is hard to see in review.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
