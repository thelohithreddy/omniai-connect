import Link from "next/link";

import { Container, Stack } from "@/components/ui/layout";

/**
 * Root not-found boundary (MC1.3; FRONTEND_SPEC §8).
 *
 * Says nothing about what does exist. A 404 that distinguishes "no such route" from "no such
 * workspace" or "you may not see this" is an enumeration primitive — the same reason the API
 * answers an unknown and an unauthorised invitation with the identical 404.
 */
export default function NotFound() {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <Container size="sm">
        <Stack className="text-center">
          <h1 className="text-2xl font-semibold tracking-tight">Page not found</h1>
          <p className="text-sm text-muted-foreground">
            The page you are looking for does not exist.
          </p>
          <p>
            <Link href="/" className="text-sm font-medium underline">
              Return home
            </Link>
          </p>
        </Stack>
      </Container>
    </div>
  );
}
