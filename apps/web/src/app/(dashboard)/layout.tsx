import type { ReactNode } from "react";

import { WorkspaceSwitcher } from "@/components/workspace-switcher";
import { SignOutButton } from "@/components/sign-out-button";
import { Alert } from "@/components/ui/alert";
import { Container, Stack } from "@/components/ui/layout";
import { requireSession } from "@/lib/session";
import { resolveWorkspace } from "@/lib/workspace/context";

/**
 * The authenticated control-plane boundary (MC1.3, ADR-0016, ADR-0044 §6).
 *
 * **This layout is the security boundary, not the navigation.** It runs on the server before any
 * child route produces markup, so an unauthenticated visitor is redirected before a single frame
 * of protected content exists — no flash of a dashboard, nothing to screenshot, nothing in the
 * HTML for a scraper. Direct URL entry, client-side navigation and a hard refresh all take this
 * same path, because a layout cannot be skipped.
 *
 * `force-dynamic` is load-bearing rather than defensive. ADR-0044 §6 forbids static rendering for
 * `(dashboard)`: a statically generated authenticated page would be built once, at deploy time,
 * with no session — and then served to everyone. Declaring it here means no future child page can
 * opt back into static rendering by accident.
 *
 * It also keeps this subtree out of F6's blast radius: dynamic rendering is exactly the condition
 * under which Next stamps the CSP nonce onto its scripts, so the dashboard already satisfies the
 * enforcement gate MC1.8 will apply.
 */
export const dynamic = "force-dynamic";

export default async function DashboardLayout({ children }: { children: ReactNode }) {
  // Order matters: authenticate first, then resolve tenancy. Resolving a workspace for an
  // unauthenticated caller would mean asking the API "who is this" with no identity to offer.
  await requireSession("/dashboard");

  const resolution = await resolveWorkspace();

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-border">
        <Container>
          <div className="flex h-14 items-center justify-between gap-4">
            <span className="font-semibold">OmniAI Connect</span>
            <div className="flex items-center gap-3">
              {/*
                Rendered for every authenticated member regardless of role (ADR-0044 §5): hiding
                navigation teaches nothing and makes the product feel broken, while the route
                itself is still gated server-side by the API's answer.
              */}
              <WorkspaceSwitcher
                memberships={resolution.ok ? resolution.context.memberships : resolution.memberships}
                activeWorkspaceId={resolution.ok ? resolution.context.workspaceId : null}
              />
              <SignOutButton />
            </div>
          </div>
        </Container>
      </header>

      <main className="py-8">
        <Container>
          {resolution.ok ? (
            children
          ) : (
            /*
              Fail closed, visibly. ADR-0016 requires a caller with several memberships and no
              valid selection to be refused rather than silently bound to one — so the children
              are not rendered at all, and no workspace-scoped request is ever made.
            */
            <Stack>
              <Alert variant="info">
                {resolution.reason === "no-memberships"
                  ? "You are not a member of any workspace yet. Ask an owner to invite you, or accept an invitation you have already received."
                  : "Select a workspace to continue."}
              </Alert>
            </Stack>
          )}
        </Container>
      </main>
    </div>
  );
}
