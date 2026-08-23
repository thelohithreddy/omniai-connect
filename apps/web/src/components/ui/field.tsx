"use client";

import { useId } from "react";
import type { ComponentProps, ReactNode } from "react";

import { cn } from "@/lib/utils";

/**
 * Label, input and error, wired together (MC1.2 design system).
 *
 * A bare `<Label>` and `<Input>` shipped as separate primitives make correct wiring *optional*,
 * and optional wiring is the single most common accessibility defect in a form: an unbound label,
 * or an error message that is displayed but never announced. This component owns the
 * relationship, so a caller cannot forget it.
 *
 * FRONTEND_SPEC §7: "Form fields always have bound labels; errors are announced via `aria-live`."
 *
 * The id is generated with `useId` so the same field can appear more than once on a page (a
 * dialog over a form) without colliding — a hand-written `id="email"` breaks the label binding of
 * whichever copy renders second, silently.
 */

export interface FieldProps extends Omit<ComponentProps<"input">, "id"> {
  readonly label: string;
  /** Shown under the control and bound via `aria-describedby`. */
  readonly description?: ReactNode;
  /** Presence marks the field invalid and announces the message. */
  readonly error?: string;
}

export function Field({ label, description, error, className, required, ...props }: FieldProps) {
  const id = useId();
  const descriptionId = `${id}-description`;
  const errorId = `${id}-error`;

  // Both are referenced when both exist; a screen reader reads them in order.
  const describedBy = [description ? descriptionId : null, error ? errorId : null]
    .filter(Boolean)
    .join(" ");

  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-sm font-medium text-foreground">
        {label}
        {required ? (
          <>
            {" "}
            <span aria-hidden="true" className="text-destructive">
              *
            </span>
            <span className="sr-only">(required)</span>
          </>
        ) : null}
      </label>

      <input
        id={id}
        required={required}
        // aria-invalid drives both the assistive-technology state and the ring colour, so the
        // two can never disagree.
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy || undefined}
        className={cn(
          "h-10 w-full rounded-md border border-input bg-background px-3 text-sm",
          "placeholder:text-muted-foreground disabled:cursor-not-allowed disabled:opacity-50",
          "aria-[invalid=true]:border-destructive aria-[invalid=true]:ring-destructive",
          className,
        )}
        {...props}
      />

      {description ? (
        <p id={descriptionId} className="text-sm text-muted-foreground">
          {description}
        </p>
      ) : null}

      {/*
        `role="alert"` carries an implicit `aria-live="assertive"`, so a validation failure is
        announced when it appears rather than only when the field is next focused. The node is
        rendered only when there is an error; an always-present empty live region is announced
        inconsistently across screen readers.
      */}
      {error ? (
        <p id={errorId} role="alert" className="text-sm font-medium text-destructive">
          {error}
        </p>
      ) : null}
    </div>
  );
}
