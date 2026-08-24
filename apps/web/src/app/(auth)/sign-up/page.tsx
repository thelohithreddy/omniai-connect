import Link from "next/link";
import { redirect } from "next/navigation";

import { CredentialsForm } from "@/components/credentials-form";
import { Stack } from "@/components/ui/layout";
import { getSessionOrNull, safeNextPath } from "@/lib/session";

/**
 * Create an account (MC1.3, ADR-0002).
 *
 * Sign-up sends a verification email (`emailVerification.sendOnSignUp`), which matters beyond
 * hygiene: ADR-0017 §2 makes the API refuse a targeted invitation unless the JWT's `emailVerified`
 * is true, so an unverified account cannot accept an invitation. That is intentional, and it is
 * why the copy below tells the user to expect the email rather than leaving them to discover the
 * requirement at the invitation step.
 */
export default async function SignUpPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const raw = (await searchParams).next;
  const nextPath = safeNextPath(typeof raw === "string" ? raw : null);

  if (await getSessionOrNull()) redirect(nextPath ?? "/dashboard");

  return (
    <Stack gap="lg">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Create your account</h1>
        <p className="text-sm text-muted-foreground">
          We will email you a verification link. Verifying is required before you can accept a
          workspace invitation.
        </p>
      </div>

      <CredentialsForm mode="sign-up" nextPath={nextPath} />

      <p className="text-sm text-muted-foreground">
        Already have an account?{" "}
        <Link href="/sign-in" className="font-medium text-foreground underline">
          Sign in
        </Link>
      </p>
    </Stack>
  );
}
