"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Stack } from "@/components/ui/layout";
import {
  acceptPendingInvitation,
  discardPendingInvitation,
  type AcceptInvitationResult,
} from "@/lib/invitations/actions";

/**
 * The accept / decline control (MC1.3, ADR-0017).
 *
 * **This component never receives the token.** It calls a Server Action that reads the `httpOnly`
 * cookie itself, so the secret stays out of props, out of the RSC payload and out of anything a
 * browser extension or an XSS foothold could read. That is the whole reason acceptance is an
 * action rather than a fetch with the token in a body assembled here.
 *
 * Every outcome is a fixed message chosen from a closed set. Nothing the API returns is rendered
 * verbatim except a transient error's already-sanitised text — the uniform "cannot be used" state
 * is the same whether the invitation was unknown, expired or already consumed.
 */
export function AcceptInvitation() {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [result, setResult] = useState<AcceptInvitationResult | null>(null);

  function run(action: () => Promise<AcceptInvitationResult | void>): void {
    startTransition(() => {
      void (async () => {
        const outcome = await action();
        if (outcome) setResult(outcome);
        // Re-render from the server so the workspace binding set by the action takes effect.
        router.refresh();
      })();
    });
  }

  if (result?.status === "accepted") {
    return (
      <Stack>
        <Alert variant="success">
          You have joined the workspace as {result.role}.
        </Alert>
        <Button type="button" onClick={() => router.replace("/dashboard")}>
          Go to your dashboard
        </Button>
      </Stack>
    );
  }

  if (result && result.status !== "error") {
    const message =
      result.status === "already-member"
        ? "You are already a member of this workspace."
        : result.status === "unauthenticated"
          ? "Please sign in again to accept this invitation."
          : "This invitation link is no longer available. Ask a workspace owner to send a new one.";

    return (
      <Stack>
        <Alert variant="info">{message}</Alert>
        <Button type="button" variant="outline" onClick={() => router.replace("/dashboard")}>
          Go to your dashboard
        </Button>
      </Stack>
    );
  }

  return (
    <Stack>
      {result?.status === "error" ? (
        <Alert variant="danger">
          {result.message}
          {result.requestId ? (
            <span className="mt-1 block text-xs text-muted-foreground">
              Reference: <code className="font-mono">{result.requestId}</code>
            </span>
          ) : null}
        </Alert>
      ) : null}

      <div className="flex gap-2">
        <Button type="button" isLoading={isPending} onClick={() => run(acceptPendingInvitation)}>
          Accept invitation
        </Button>
        <Button
          type="button"
          variant="ghost"
          disabled={isPending}
          onClick={() =>
            run(async () => {
              await discardPendingInvitation();
              router.replace("/dashboard");
            })
          }
        >
          Not now
        </Button>
      </div>
    </Stack>
  );
}
