"use client";

import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/ui/feedback";
import { Stack } from "@/components/ui/layout";

/**
 * Dashboard error boundary (MC1.3; FRONTEND_SPEC §8).
 *
 * **What is deliberately not rendered:** `error.message`. React replaces a server-side error's
 * message with a generic string in production, but a *client*-side throw keeps its real text —
 * and that text can carry an internal hostname, a filesystem path or a provider response. Showing
 * a fixed message costs nothing diagnostically and removes the whole class of disclosure.
 *
 * `error.digest` is safe and is the useful half: it is a hash Next also writes to the server log,
 * so a user can quote it and an operator can find the exact stack without it ever being sent to
 * the browser.
 */
export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <Stack>
      <ErrorState
        title="Something went wrong"
        message="This page could not be loaded. The problem has been recorded."
        requestId={error.digest}
        action={
          <Button type="button" variant="outline" size="sm" onClick={reset}>
            Try again
          </Button>
        }
      />
    </Stack>
  );
}
