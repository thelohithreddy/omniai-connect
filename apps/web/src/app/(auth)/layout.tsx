import type { ReactNode } from "react";

import { Container } from "@/components/ui/layout";

/**
 * Auth route group layout (MC1.3, FRONTEND_SPEC §1).
 *
 * `force-dynamic` because these pages read the session and the validated `next` parameter on the
 * server. Statically generating a sign-in page would freeze one request's search params into the
 * build output and, worse, would let an already-authenticated visitor be served a cached
 * "signed out" shell.
 */
export const dynamic = "force-dynamic";

export default function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background py-12">
      <Container size="sm">
        <div className="mx-auto w-full max-w-sm">{children}</div>
      </Container>
    </div>
  );
}
