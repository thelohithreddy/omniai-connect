import { headers } from "next/headers";

import { AuthorizeButton } from "@/components/oauth/authorize-button";
import { Alert } from "@/components/ui/alert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState, ErrorState } from "@/components/ui/feedback";
import { Stack } from "@/components/ui/layout";
import { listConnections } from "@/lib/api/client";
import { ApiFailure } from "@/lib/api/errors";
import { presentAuditFailure } from "@/lib/audit/authorization";
import { presentConnection } from "@/lib/oauth/connection-state";
import { resolveWorkspace } from "@/lib/workspace/context";

/**
 * Connections and their OAuth authorization state (MC1.5, ADR-0038).
 *
 * The dashboard half of the backend-owned flow. ADR-0038 keeps `state`, the PKCE verifier and the
 * token exchange entirely server-side, so this page has exactly two jobs: show where each
 * Connection stands, and hand the browser a button that asks the API where to navigate.
 *
 * `force-dynamic` for the same reason as every other workspace-scoped route (ADR-0044 §6): a
 * prerendered copy would be built once with no session and served to everyone. The transport
 * already sends `no-store`, so no authorization state enters a shared cache.
 */
export const dynamic = "force-dynamic";

/** Bounded: a workspace's Connection list is small, and pagination is a later concern. */
const PAGE_SIZE = 50;

export default async function ConnectionsPage() {
  const resolution = await resolveWorkspace();
  if (!resolution.ok) return null;

  let page: Awaited<ReturnType<typeof listConnections>> | null = null;
  let failure: ApiFailure | null = null;
  try {
    page = await listConnections(
      { headers: await headers(), workspaceId: resolution.context.workspaceId },
      { limit: PAGE_SIZE },
    );
  } catch (caught) {
    if (!(caught instanceof ApiFailure)) throw caught;
    failure = caught;
  }

  return (
    <Stack gap="lg">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Connections</h1>
        <p className="text-sm text-muted-foreground">
          Authorize a connection so its Tools can call the provider on your behalf.
        </p>
      </div>

      {failure ? <ConnectionsFailure failure={failure} /> : null}

      {page ? (
        page.data.length === 0 ? (
          <EmptyState
            title="No connections yet"
            headingAs="h2"
            description="Create a connection to a provider, then authorize it here."
          />
        ) : (
          <Stack>
            {page.data.map((connection) => {
              const presentation = presentConnection(connection);
              return (
                <Card key={connection.id}>
                  <CardHeader>
                    {/* The name is provider/operator data — rendered as text, never as markup. */}
                    <CardTitle as="h2">{connection.name}</CardTitle>
                    <p className="text-sm text-muted-foreground">
                      {presentation.label}
                      {/* State is never carried by colour alone (WCAG 1.4.1). */}
                      <span className="sr-only"> — {presentation.srDescription}</span>
                    </p>
                  </CardHeader>
                  <CardContent>
                    {presentation.state === "needs-reauth" ? (
                      <Alert variant="danger" className="mb-3">
                        This connection stopped working and must be authorized again.
                      </Alert>
                    ) : null}

                    {presentation.canAuthorize ? (
                      <AuthorizeButton
                        connectionId={connection.id}
                        label={
                          presentation.state === "needs-reauth" ? "Reauthorize" : "Authorize"
                        }
                      />
                    ) : (
                      <p className="text-sm text-muted-foreground">
                        No authorization action is available for this connection.
                      </p>
                    )}
                  </CardContent>
                </Card>
              );
            })}
          </Stack>
        )
      ) : null}
    </Stack>
  );
}

/**
 * Render the API's refusal.
 *
 * Reuses the audit surface's presenter: `connections:read` is role-gated the same way, so a 403 is
 * a correct answer for some roles rather than a fault, and duplicating the mapping would let the
 * two surfaces drift apart.
 */
function ConnectionsFailure({ failure }: { readonly failure: ApiFailure }) {
  const presentation = presentAuditFailure(failure);

  if (presentation.kind === "requires-elevated-role") {
    return (
      <Alert variant="info">
        <span className="font-medium">Connections require the Owner or Admin role.</span>{" "}
        Ask a workspace owner if you need access.
      </Alert>
    );
  }

  return (
    <ErrorState
      title="Could not load connections"
      message={presentation.message}
      requestId={presentation.requestId}
    />
  );
}
