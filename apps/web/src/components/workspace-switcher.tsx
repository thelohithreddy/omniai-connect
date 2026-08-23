"use client";

import { useTransition } from "react";

import type { MembershipRead } from "@omniai/types";

import { Button } from "@/components/ui/button";
import { selectWorkspace } from "@/lib/workspace/actions";

/**
 * Workspace switcher (MC1.3, ADR-0016).
 *
 * A form that posts to a Server Action, not client state that flips a variable. The distinction
 * is the point: switching workspace is a **server** operation that rebinds tenancy and re-renders
 * everything from the newly bound workspace. Nothing workspace-scoped is held client-side, so
 * there is no store to forget to clear and no stale view to survive the switch.
 *
 * The submitted id is re-authorized inside the action against the API's membership list; this
 * component is a convenience for choosing, never the thing that grants access.
 *
 * Deliberately a native `<form>` + `<select>` rather than a custom dropdown: it is keyboard
 * accessible, screen-reader navigable and submits without JavaScript, which also means the
 * switcher keeps working if hydration fails. A Radix popover would be more fashionable and
 * strictly worse here.
 */
export function WorkspaceSwitcher({
  memberships,
  activeWorkspaceId,
}: {
  readonly memberships: readonly MembershipRead[];
  readonly activeWorkspaceId: string | null;
}) {
  const [isPending, startTransition] = useTransition();

  if (memberships.length === 0) return null;

  return (
    <form
      action={(formData) => startTransition(() => void selectWorkspace(formData))}
      className="flex items-center gap-2"
    >
      <label htmlFor="workspace-switcher" className="sr-only">
        Active workspace
      </label>
      <select
        id="workspace-switcher"
        name="workspaceId"
        defaultValue={activeWorkspaceId ?? ""}
        className="h-9 rounded-md border border-input bg-background px-2 text-sm"
      >
        {/*
          Only present when nothing is bound — ADR-0016's fail-closed state, where the caller has
          several memberships and must actually choose. Once bound it disappears, so "no
          workspace" is not an option a user can select back into.
        */}
        {activeWorkspaceId === null ? (
          <option value="" disabled>
            Select a workspace…
          </option>
        ) : null}
        {memberships.map((membership) => (
          <option key={membership.id} value={membership.id}>
            {/*
              The id, because `GET /v1/workspaces` returns id and role only — ADR-0016 §7 keeps
              that response deliberately narrow. Names would need one bound call per workspace;
              recorded as a known limitation rather than papered over with a fake label.
            */}
            {membership.id.slice(0, 8)} · {membership.role}
          </option>
        ))}
      </select>
      <Button type="submit" size="sm" variant="outline" isLoading={isPending}>
        Switch
      </Button>
    </form>
  );
}
