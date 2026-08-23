/**
 * Environment configuration, validated at the boundary (FRONTEND_SPEC §9, ADR-0044).
 *
 * Two schemas, deliberately separate, because the split *is* the security control:
 *
 * - `publicEnv` may be read from anywhere. Every value in it is compiled into the browser
 *   bundle by Next, so a secret placed here is a published secret. It is `NEXT_PUBLIC_`-only by
 *   construction.
 * - `serverEnv()` may be read only on the server. It is a function rather than a constant so
 *   that merely importing this module does not evaluate server configuration — importing it
 *   from a client component would otherwise throw during the build for the wrong reason, and
 *   the *right* reason (`server-only`) lives one layer up in the transport.
 *
 * Reading `process.env` directly anywhere else in `apps/web` is a review reject: it bypasses
 * validation, and a typo in a variable name becomes `undefined` flowing into a fetch URL rather
 * than a startup failure.
 *
 * **Fail loudly, never fall back.** There are no production defaults here. A missing
 * `API_BASE_URL` in production must stop the process, not silently resolve to localhost and
 * make the control plane appear healthy while talking to nothing.
 */

import { z } from "zod";

/**
 * A URL that a server can actually dial. `z.url()` alone accepts values like `ftp://…`;
 * restricting the protocol keeps a misconfiguration from becoming an SSRF-shaped surprise in a
 * component that assumes http(s).
 */
const httpUrl = z
  .url()
  .refine(
    (value) => value.startsWith("http://") || value.startsWith("https://"),
    "must be an http(s) URL",
  );

const publicSchema = z.object({
  /** The control plane's own origin. Safe in the bundle; it is the address of this app. */
  NEXT_PUBLIC_APP_URL: httpUrl,
});

const serverSchema = z.object({
  /**
   * Where the Next server reaches FastAPI. **Server-only on purpose.**
   *
   * This is deliberately *not* `NEXT_PUBLIC_API_URL`. The browser never calls the API
   * (ADR-0044): there is no CORS middleware on FastAPI, so a direct call cannot succeed, and
   * the planned CSP pins `connect-src 'self'` so it will not even be attempted. Publishing the
   * API's address would advertise an origin the browser must never use, and in a container
   * deployment the server-side address (`http://api:8000`) is not the public one anyway.
   */
  API_BASE_URL: httpUrl,

  /**
   * How long a single backend request may take before it is aborted, in milliseconds.
   * Bounded by construction: an unbounded server fetch holds a Next render open until the
   * platform kills it, which turns one slow backend into a stalled control plane.
   */
  API_TIMEOUT_MS: z.coerce.number().int().positive().max(120_000).default(10_000),
});

export type PublicEnv = z.infer<typeof publicSchema>;
export type ServerEnv = z.infer<typeof serverSchema>;

/**
 * Formats a Zod failure into something an operator can act on **without printing values.**
 * A validation error that echoes the offending input would put a misconfigured secret into
 * logs, which is the one place a configuration mistake must not end up.
 */
function describe(issues: z.core.$ZodIssue[]): string {
  return issues
    .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
    .sort()
    .join("; ");
}

/**
 * Public configuration. Evaluated eagerly — it is safe everywhere and a missing app URL should
 * fail the build, not the first request that needs it.
 *
 * `process.env.NEXT_PUBLIC_*` is referenced by full literal name rather than by index, because
 * Next inlines these at build time only when it can see the literal.
 */
export const publicEnv: PublicEnv = (() => {
  const parsed = publicSchema.safeParse({
    NEXT_PUBLIC_APP_URL: process.env.NEXT_PUBLIC_APP_URL,
  });
  if (!parsed.success) {
    throw new Error(`Invalid public environment: ${describe(parsed.error.issues)}`);
  }
  return parsed.data;
})();

let cachedServerEnv: ServerEnv | undefined;

/**
 * Server configuration. Throws on the first call if the process is misconfigured.
 *
 * Memoised because it is read on every backend request and validation is pure; the cache holds
 * no secret beyond what `process.env` already holds in the same process.
 */
export function serverEnv(): ServerEnv {
  if (cachedServerEnv) return cachedServerEnv;

  const parsed = serverSchema.safeParse({
    API_BASE_URL: process.env.API_BASE_URL,
    API_TIMEOUT_MS: process.env.API_TIMEOUT_MS,
  });
  if (!parsed.success) {
    // The message names the variables, never their values.
    throw new Error(`Invalid server environment: ${describe(parsed.error.issues)}`);
  }
  cachedServerEnv = parsed.data;
  return cachedServerEnv;
}

/** Test seam: drop the memoised value so a test can re-validate a mutated `process.env`. */
export function resetServerEnvCache(): void {
  cachedServerEnv = undefined;
}

/**
 * The set of variable-name fragments that must never appear with a `NEXT_PUBLIC_` prefix.
 * Exported so a test — not a code review — enforces it.
 */
export const FORBIDDEN_PUBLIC_FRAGMENTS: readonly string[] = [
  "SECRET",
  "TOKEN",
  "PASSWORD",
  "PRIVATE",
  "CREDENTIAL",
  "API_KEY",
  "APIKEY",
  "DATABASE_URL",
  "MASTER_KEY",
  "SIGNING",
  "RESEND",
  "STRIPE",
];

/**
 * Returns the names of any `NEXT_PUBLIC_` variables that look secret-capable.
 *
 * Everything prefixed `NEXT_PUBLIC_` is inlined into the browser bundle, so this is not a
 * style rule — it is the difference between a published address and a published secret.
 */
export function findUnsafePublicVars(source: NodeJS.ProcessEnv = process.env): string[] {
  return Object.keys(source)
    .filter((name) => name.startsWith("NEXT_PUBLIC_"))
    .filter((name) => {
      const rest = name.slice("NEXT_PUBLIC_".length).toUpperCase();
      return FORBIDDEN_PUBLIC_FRAGMENTS.some((fragment) => rest.includes(fragment));
    })
    .sort();
}
