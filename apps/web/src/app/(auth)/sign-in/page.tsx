import Link from "next/link";
import { redirect } from "next/navigation";

import { CredentialsForm } from "@/components/credentials-form";
import { Stack } from "@/components/ui/layout";
import { getSessionOrNull, safeNextPath } from "@/lib/session";

/**
 * Sign in (MC1.3, ADR-0002).
 *
 * The `next` parameter is reduced by `safeNextPath` **here, on the server**, before it is handed
 * to the form. An unvalidated `?next=` is the classic open redirect: `//evil.example` looks local
 * to a naive `startsWith("/")` check but is another origin to a browser, which turns a trusted
 * sign-in link into a phishing hop. Anything that does not survive validation is dropped
 * silently and the user lands on the dashboard.
 *
 * An already-authenticated visitor is redirected away rather than shown the form, so the back
 * button after signing in does not present a login page that appears to have failed.
 */
export default async function SignInPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const raw = (await searchParams).next;
  // Only a single string is considered. A repeated `?next=a&next=b` arrives as an array, which is
  // a shape no legitimate link produces and a parameter-pollution attempt often does.
  const nextPath = safeNextPath(typeof raw === "string" ? raw : null);

  if (await getSessionOrNull()) redirect(nextPath ?? "/dashboard");

  return (
    <Stack gap="lg">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Sign in</h1>
        <p className="text-sm text-muted-foreground">Continue to your control plane.</p>
      </div>

      <CredentialsForm mode="sign-in" nextPath={nextPath} />

      <p className="text-sm text-muted-foreground">
        No account?{" "}
        <Link href="/sign-up" className="font-medium text-foreground underline">
          Create one
        </Link>
      </p>
    </Stack>
  );
}
