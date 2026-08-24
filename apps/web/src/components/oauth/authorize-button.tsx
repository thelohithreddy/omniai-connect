"use client";

import { useState, useTransition } from "react";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Stack } from "@/components/ui/layout";
import { beginAuthorization, type AuthorizationStart } from "@/lib/oauth/actions";

/**
 * Start an OAuth authorization (MC1.5, ADR-0038).
 *
 * A form posting to a Server Action, not a client-side fetch. The browser's only job is to
 * navigate — the action resolves the workspace, calls the API and issues the redirect, so
 * `state`, the PKCE verifier and the workspace JWT never exist in this process.
 *
 * **Double submission is prevented, not merely discouraged.** `useTransition` disables the control
 * while the action is in flight, and every failure path re-enables it. That matters more here than
 * on an ordinary form: each activation mints a single-use `oauth_states` row, so a double click
 * would create a second in-flight authorization and leave an orphan row behind. On success the
 * action redirects and this component is torn down, so the pending state cannot be stranded.
 *
 * Outcomes come from a closed set the action defines. Nothing the API says is rendered verbatim
 * except an already-sanitised transient error message.
 */

const MESSAGE: Record<Exclude<AuthorizationStart["status"], "error">, string> = {
  unauthenticated: "Your session has expired. Sign in again to continue.",
  "no-workspace": "Select a workspace before authorizing a connection.",
  // The API's answer, rendered — not a permission this component decided (ADR-0044 D5).
  forbidden: "Authorizing a connection requires the Owner or Admin role.",
  // The API answers 404 uniformly for unknown and not-in-this-workspace alike; keeping one message
  // preserves that and stops connection ids being probed.
  "not-found": "This connection is no longer available.",
  unavailable: "This connection cannot be authorized right now.",
  "unsafe-url": "This connection's provider address is not valid. Contact support.",
};

export function AuthorizeButton({
  connectionId,
  label,
}: {
  readonly connectionId: string;
  readonly label: string;
}) {
  const [isPending, startTransition] = useTransition();
  const [outcome, setOutcome] = useState<AuthorizationStart | null>(null);

  return (
    <Stack gap="sm">
      {outcome ? (
        <Alert variant={outcome.status === "error" ? "danger" : "info"}>
          {outcome.status === "error" ? (
            <>
              {outcome.message}
              {outcome.requestId ? (
                <span className="mt-1 block text-xs text-muted-foreground">
                  Reference: <code className="font-mono">{outcome.requestId}</code>
                </span>
              ) : null}
            </>
          ) : (
            MESSAGE[outcome.status]
          )}
        </Alert>
      ) : null}

      <form
        action={(formData) =>
          startTransition(async () => {
            setOutcome(null);
            // A successful action redirects and never returns a value; only failures land here.
            const result = await beginAuthorization(formData);
            if (result) setOutcome(result);
          })
        }
      >
        <input type="hidden" name="connectionId" value={connectionId} />
        <Button type="submit" size="sm" isLoading={isPending}>
          {label}
        </Button>
      </form>
    </Stack>
  );
}
