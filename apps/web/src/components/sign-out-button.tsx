"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { signOut } from "@/lib/auth/client";
import { clearWorkspaceSelection } from "@/lib/workspace/actions";

/**
 * Sign out (MC1.3).
 *
 * Two steps, in this order, both of which matter:
 *
 * 1. **`signOut()` deletes the session server-side.** It is not a client-side "forget the token"
 *    — Better Auth removes the session row, so a copied cookie is dead afterwards too. This is
 *    what makes sign-out a real revocation for the *browser* session rather than a UI state
 *    change. (The backend JWT is separately bounded and deliberately not revocable — ADR-0018.)
 * 2. **The workspace selection cookie is cleared**, so the next person to use this browser does
 *    not inherit a previous human's selection.
 *
 * `router.refresh()` then discards the client router cache, which otherwise holds already-rendered
 * server output for visited routes. Without it, navigating "back" could redisplay a previously
 * rendered authenticated page from memory even though the session is gone.
 */
export function SignOutButton() {
  const router = useRouter();
  const [isPending, setPending] = useState(false);

  return (
    <Button
      type="button"
      variant="ghost"
      size="sm"
      isLoading={isPending}
      onClick={() => {
        setPending(true);
        void (async () => {
          try {
            await signOut();
            await clearWorkspaceSelection();
          } finally {
            // Navigate regardless. A failed sign-out must not strand the user on an
            // authenticated-looking page: the server gate re-runs on the next request and will
            // redirect if the session really is gone.
            router.replace("/sign-in");
            router.refresh();
          }
        })();
      }}
    >
      Sign out
    </Button>
  );
}
