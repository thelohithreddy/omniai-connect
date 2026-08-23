"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Stack } from "@/components/ui/layout";
import { signIn, signUp } from "@/lib/auth/client";

/**
 * Sign-in / sign-up form (MC1.3, ADR-0002).
 *
 * One component for both because they differ by a single call and a label; two near-identical
 * forms would drift, and the one that drifts is usually the one with the weaker error handling.
 *
 * **The redirect target is not chosen here.** `nextPath` has already been validated server-side by
 * `safeNextPath`, which rejects protocol-relative, absolute and control-character paths. Passing a
 * raw `?next=` from the URL into `router.replace` would be a textbook open redirect, and doing the
 * validation in the browser would put the check on the wrong side of the trust boundary.
 *
 * Credentials are never stored: no `localStorage`, no store, no URL state (FRONTEND_SPEC §5). The
 * password lives in a controlled input for the lifetime of the form and nowhere else.
 */
export function CredentialsForm({
  mode,
  nextPath,
}: {
  readonly mode: "sign-in" | "sign-up";
  /** Server-validated local path, or null. */
  readonly nextPath: string | null;
}) {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isPending, setPending] = useState(false);

  const isSignUp = mode === "sign-up";

  async function submit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setError(null);
    setPending(true);
    try {
      const result = isSignUp
        ? await signUp.email({ email, password, name: name || email })
        : await signIn.email({ email, password });

      if (result.error) {
        /*
          One message for every failure. Better Auth distinguishes "no such user" from "wrong
          password"; surfacing that difference turns the sign-in form into an account-existence
          oracle, which is a real enumeration primitive against a product whose customers are
          identifiable companies. Sign-up necessarily reveals collision, so it says so plainly
          there and nowhere else.
        */
        setError(
          isSignUp
            ? "That email address could not be registered. It may already have an account."
            : "Those credentials are not valid.",
        );
        return;
      }

      // Server navigation, so the dashboard layout's session gate runs for real rather than the
      // client assuming success.
      router.replace(nextPath ?? "/dashboard");
      router.refresh();
    } catch {
      // Never surface the thrown value: a network-layer error can carry the request URL and
      // headers.
      setError("Something went wrong. Please try again.");
    } finally {
      setPending(false);
    }
  }

  return (
    <form onSubmit={submit} noValidate>
      <Stack>
        {/*
          role="alert" announces the failure when it appears. A visually-obvious error that is
          never announced is the most common accessibility defect in an auth form.
        */}
        {error ? <Alert variant="danger">{error}</Alert> : null}

        {isSignUp ? (
          <Field
            label="Name"
            name="name"
            autoComplete="name"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        ) : null}

        <Field
          label="Email"
          name="email"
          type="email"
          required
          autoComplete="email"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
        />

        <Field
          label="Password"
          name="password"
          type="password"
          required
          // Tells a password manager which flow this is, so it offers to save on sign-up and
          // autofill on sign-in rather than guessing.
          autoComplete={isSignUp ? "new-password" : "current-password"}
          value={password}
          onChange={(event) => setPassword(event.target.value)}
        />

        <Button type="submit" isLoading={isPending}>
          {isSignUp ? "Create account" : "Sign in"}
        </Button>
      </Stack>
    </form>
  );
}
