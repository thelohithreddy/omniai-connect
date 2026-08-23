import { headers } from "next/headers";

import { Alert } from "@/components/ui/alert";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorState } from "@/components/ui/feedback";
import { Stack } from "@/components/ui/layout";
import { getCurrentWorkspace } from "@/lib/api/client";
import { ApiFailure } from "@/lib/api/errors";
import { resolveWorkspace } from "@/lib/workspace/context";

/**
 * Dashboard overview (MC1.3).
 *
 * Deliberately thin. MC1.3 is the route/session/workspace **foundation**; the connectors, tools,
 * logs and settings surfaces belong to later slices. What this page exists to prove is that the
 * whole chain works end to end — session → membership → bound workspace → server-only transport →
 * a real authenticated API response — because a foundation that has never carried a real request
 * is an untested foundation.
 *
 * Every call goes through the MC1.1 transport. Nothing here fetches from the browser, and the
 * backend JWT is minted inside the transport from the server-side session.
 */
export default async function DashboardPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const resolution = await resolveWorkspace();
  // The layout already refuses to render children unless a workspace is bound; this keeps the
  // page independently correct rather than relying on that ordering.
  if (!resolution.ok) return null;

  const error = (await searchParams).error;

  let workspace: Awaited<ReturnType<typeof getCurrentWorkspace>> | null = null;
  let failure: ApiFailure | null = null;
  try {
    workspace = await getCurrentWorkspace({
      headers: await headers(),
      workspaceId: resolution.context.workspaceId,
    });
  } catch (caught) {
    // Rendered as a normal state, not thrown to the error boundary: a 403 or a timeout on one
    // panel is an expected outcome of a distributed system, and the shell around it stays usable.
    // `ApiFailure.toClient()` has already stripped status, cause and stack.
    failure = caught instanceof ApiFailure ? caught : null;
    if (!failure) throw caught;
  }

  return (
    <Stack gap="lg">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
        <p className="text-sm text-muted-foreground">
          Your workspace is connected. Control-plane surfaces arrive in later releases.
        </p>
      </div>

      {error === "invalid-workspace" ? (
        <Alert variant="danger">That workspace is not available to you.</Alert>
      ) : null}

      {failure ? (
        <ErrorState
          title="Could not load this workspace"
          message={failure.message}
          requestId={failure.requestId}
        />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle as="h2">{workspace!.name}</CardTitle>
            <CardDescription>
              {/* Role is rendered from the caller's own membership — display only (ADR-0044 §5). */}
              Your role here is {resolution.context.role}.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 text-sm">
              <dt className="text-muted-foreground">Slug</dt>
              <dd className="font-mono">{workspace!.slug}</dd>
              <dt className="text-muted-foreground">Plan</dt>
              <dd>{workspace!.plan}</dd>
            </dl>
          </CardContent>
        </Card>
      )}
    </Stack>
  );
}
