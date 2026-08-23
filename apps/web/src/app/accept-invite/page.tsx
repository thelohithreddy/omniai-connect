import { cookies } from "next/headers";
import Link from "next/link";
import { redirect } from "next/navigation";

import { AcceptInvitation } from "@/components/accept-invitation";
import { Alert } from "@/components/ui/alert";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Container, Stack } from "@/components/ui/layout";
import { getSessionOrNull } from "@/lib/auth/session";
import { INVITE_COOKIE } from "@/lib/invitations/token";

/**
 * Invitation acceptance (MC1.3, ADR-0017, ADR-0044).
 *
 * ADR-0044 recorded this route as a shipped backend flow whose frontend half was never built:
 * `InvitationService._deliver` has been emailing `{app_url}/accept-invite?token=…` since M1.3-F,
 * and this path returned a 404 the whole time.
 *
 * By the time this component renders, the token is **already out of the URL** — middleware moved
 * it into an `httpOnly` cookie and redirected to the bare path. This page therefore never sees a
 * token, never renders one, and cannot leak one into HTML, history or a `Referer`.
 *
 * Acceptance requires an explicit click, which posts a Server Action. It is not performed on GET:
 * email scanners and link prefetchers follow URLs, and a GET that consumed the invitation would
 * burn it before the human arrived.
 */
export const dynamic = "force-dynamic";

export default async function AcceptInvitePage() {
  const session = await getSessionOrNull();
  const hasInvitation = Boolean((await cookies()).get(INVITE_COOKIE)?.value);

  if (!session) {
    // The token stays in the cookie across the round trip, so the sign-in URL carries no secret —
    // putting it in `?next=` would move the token into a second URL and undo the relocation.
    redirect("/sign-in?next=%2Faccept-invite");
  }

  return (
    <div className="flex min-h-screen items-center justify-center py-12">
      <Container size="sm">
        <Card className="mx-auto max-w-md">
          <CardHeader>
            <CardTitle as="h1">Workspace invitation</CardTitle>
            <CardDescription>
              {hasInvitation
                ? "Accept to join this workspace."
                : "There is no invitation to accept."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Stack>
              {hasInvitation ? (
                <AcceptInvitation />
              ) : (
                <>
                  {/*
                    One message for "never had one", "expired in custody" and "already used".
                    Distinguishing them here would rebuild the oracle the API's uniform 404
                    deliberately removes.
                  */}
                  <Alert variant="info">
                    This invitation link is no longer available. Ask a workspace owner to send a
                    new one.
                  </Alert>
                  <Link href="/dashboard" className="text-sm font-medium underline">
                    Go to your dashboard
                  </Link>
                </>
              )}
            </Stack>
          </CardContent>
        </Card>
      </Container>
    </div>
  );
}
