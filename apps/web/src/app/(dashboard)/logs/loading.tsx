import { LoadingState, Skeleton } from "@/components/ui/feedback";
import { Stack } from "@/components/ui/layout";

/**
 * Audit viewer loading state (MC1.4; FRONTEND_SPEC §8 asks for skeletons matching the final
 * layout rather than a spinner).
 *
 * `tool_calls` is a partitioned, high-volume table, so a slow page is a normal outcome rather than
 * an exceptional one. `LoadingState` marks the region `role="status"` / `aria-busy`, so a screen
 * reader user is told the log is loading instead of meeting silence.
 */
export default function LogsLoading() {
  return (
    <Stack gap="lg">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Tool Call log</h1>
        <p className="text-sm text-muted-foreground">
          Every Tool Call made in this workspace, newest first.
        </p>
      </div>

      <LoadingState label="Loading the Tool Call log">
        {/* Row-shaped, so the layout does not jump when the real table arrives. */}
        <div className="space-y-2 rounded-lg border border-border p-3">
          {Array.from({ length: 6 }, (_, index) => (
            <Skeleton key={index} className="h-6 w-full" />
          ))}
        </div>
      </LoadingState>
    </Stack>
  );
}
