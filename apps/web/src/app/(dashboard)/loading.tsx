import { LoadingState } from "@/components/ui/feedback";
import { Stack } from "@/components/ui/layout";

/**
 * Dashboard loading state (MC1.3; FRONTEND_SPEC §8 asks for skeletons matching the final layout
 * rather than a spinner).
 *
 * Present so a slow API response shows structure instead of a blank frame — and, because
 * `LoadingState` marks the region `role="status"` and `aria-busy`, so a screen-reader user is
 * told the page is working rather than left in silence.
 */
export default function DashboardLoading() {
  return (
    <Stack gap="lg">
      <LoadingState label="Loading your workspace" />
    </Stack>
  );
}
