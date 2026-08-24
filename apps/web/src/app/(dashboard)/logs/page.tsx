import { headers } from "next/headers";
import Link from "next/link";

import { ToolCallTable } from "@/components/audit/tool-call-table";
import { Alert } from "@/components/ui/alert";
import { EmptyState, ErrorState } from "@/components/ui/feedback";
import { Stack } from "@/components/ui/layout";
import { listToolCalls } from "@/lib/api/client";
import { ApiFailure } from "@/lib/api/errors";
import { presentAuditFailure } from "@/lib/audit/authorization";
import { resolveWorkspace } from "@/lib/workspace/context";

/**
 * Tool Call audit viewer (MC1.4, ADR-0044 D5).
 *
 * **The API is the authorization boundary, not this page.** `audit:read` is OWNER/ADMIN only, so
 * two of five roles cannot see this data. The frontend does not pre-check the role and refuse
 * locally: it *calls*, and renders whatever the API answers. A client-side role gate would be a
 * second authorization authority that could drift from `core/authz.py` — and the one that drifts
 * is always the one that grants too much.
 *
 * That is why a 403 is a rendered state rather than an error. ADR-0044 D5 spells out the
 * behaviour: navigation stays visible for every authenticated member, and a MEMBER or VIEWER who
 * reaches this route is told they need Owner or Admin — with **no data and no shape of data**.
 * Hiding the link would teach nothing (the feature is in public product material) while making the
 * nav reflow on every workspace switch.
 *
 * `force-dynamic` is inherited from the `(dashboard)` layout and restated here so this route
 * cannot become static independently. ADR-0044 §6 forbids static rendering for workspace-scoped
 * pages; a prerendered audit log would be built once, with no session, and served to everyone.
 * The transport already sends `no-store`, so no response enters a shared cache.
 */
export const dynamic = "force-dynamic";

/** Page size. Below the API's 100 maximum, and small enough to stay readable. */
const PAGE_SIZE = 25;

export default async function LogsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const resolution = await resolveWorkspace();
  // The layout refuses to render children without a bound workspace; this keeps the page correct
  // on its own rather than depending on that ordering.
  if (!resolution.ok) return null;

  const params = await searchParams;
  /*
    The cursor is opaque and is echoed back verbatim — never decoded, never constructed here
    (ADR-0044 D2). Only a single string is accepted: a repeated `?cursor=a&cursor=b` arrives as an
    array, which no legitimate link produces and parameter pollution often does.
  */
  const cursor = typeof params.cursor === "string" ? params.cursor : undefined;

  let page: Awaited<ReturnType<typeof listToolCalls>> | null = null;
  let failure: ApiFailure | null = null;
  try {
    page = await listToolCalls(
      { headers: await headers(), workspaceId: resolution.context.workspaceId },
      { limit: PAGE_SIZE, ...(cursor ? { cursor } : {}) },
    );
  } catch (caught) {
    // Only the transport's normalised failures are rendered. Anything else is a genuine defect and
    // is re-thrown to the error boundary, which shows a fixed message and a digest rather than
    // the thrown value.
    if (!(caught instanceof ApiFailure)) throw caught;
    failure = caught;
  }

  return (
    <Stack gap="lg">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Tool Call log</h1>
        <p className="text-sm text-muted-foreground">
          Every Tool Call made in this workspace, newest first.
        </p>
      </div>

      {failure ? <AuditFailure failure={failure} /> : null}

      {page ? (
        page.data.length === 0 ? (
          <EmptyState
            title="No Tool Calls yet"
            headingAs="h2"
            description="Once a Tool runs in this workspace, its calls appear here."
          />
        ) : (
          <>
            <ToolCallTable records={page.data} />
            <Pagination hasMore={page.has_more} nextCursor={page.next_cursor ?? null} isFirstPage={!cursor} />
          </>
        )
      ) : null}
    </Stack>
  );
}

/**
 * Render the API's refusal.
 *
 * `forbidden` is the ADR-0044 D5 state and is deliberately *not* styled as an error — it is a
 * correct, expected answer for three of five roles, and dressing it in red would read as a fault.
 * Every other failure is an error state carrying `request_id` so support can find the exact
 * request (FRONTEND_SPEC §8).
 *
 * No branch discloses anything about the data: a MEMBER learns their own permission, which the API
 * already tells them by returning 403, and nothing about how many records exist.
 */
function AuditFailure({ failure }: { readonly failure: ApiFailure }) {
  // The decision lives in `presentAuditFailure`, where it is unit-tested. Inline, the D5 rule was
  // untestable and a mutation removing it survived the MC1.4 mutation audit.
  const presentation = presentAuditFailure(failure);

  if (presentation.kind === "requires-elevated-role") {
    return (
      <Alert variant="info">
        <span className="font-medium">{presentation.message}</span>{" "}
        Ask a workspace owner if you need access.
      </Alert>
    );
  }

  return (
    <ErrorState
      title={presentation.title}
      message={presentation.message}
      requestId={presentation.requestId}
    />
  );
}

/**
 * Cursor pagination as plain links.
 *
 * Server-driven, as FRONTEND_SPEC §6 requires for `tool_calls` — the table is partitioned and
 * huge, so there is no client-side page model to drift from the server's. Links rather than
 * buttons means pagination works without JavaScript, is keyboard reachable for free, and each page
 * is a real URL a user can share with support.
 *
 * There is no "previous": the cursor is opaque and forward-only, so a back link would have to
 * invent state the API does not expose. The browser's own back button already works, because each
 * page is a distinct URL.
 */
function Pagination({
  hasMore,
  nextCursor,
  isFirstPage,
}: {
  readonly hasMore: boolean;
  readonly nextCursor: string | null;
  readonly isFirstPage: boolean;
}) {
  if (!hasMore && isFirstPage) return null;

  return (
    <nav aria-label="Tool Call log pages" className="flex items-center gap-3">
      {isFirstPage ? null : (
        <Link href="/logs" className="text-sm font-medium underline">
          First page
        </Link>
      )}
      {hasMore && nextCursor ? (
        <Link
          // `encodeURIComponent` because the cursor is opaque: it may contain characters that
          // would otherwise terminate the query string.
          href={`/logs?cursor=${encodeURIComponent(nextCursor)}`}
          className="text-sm font-medium underline"
        >
          Next page
        </Link>
      ) : (
        <span className="text-sm text-muted-foreground">End of log</span>
      )}
    </nav>
  );
}
