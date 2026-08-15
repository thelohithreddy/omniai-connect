import { Pool } from "pg";
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";

/**
 * Better Auth — the canonical human identity provider (ADR-0002).
 *
 * Identity lives in the Next.js layer and nowhere else. The FastAPI service never reads
 * these tables and never sees a session cookie; it will verify a signed JWT against the
 * JWKS this instance publishes (M1.3-B). That is why the connection below uses its own
 * role and its own schema rather than the application's.
 *
 * Construction is deferred behind `getAuth()` rather than exported as a ready instance.
 * `next build` evaluates every route module to collect page data, so a module-scope
 * `betterAuth(...)` call makes the build itself demand a real secret and a reachable
 * database — which would mean either a broken CI/Docker build or, worse, placeholder
 * credentials baked into an image to get past it. Nothing is lost by waiting: Next loads
 * route modules on first request anyway, so eager construction never actually failed at
 * server boot either. Validation still happens before any credential is issued.
 */

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    // Refuse to construct rather than fall back. An auth provider that starts with a
    // default nobody chose would silently sign tokens with it, and every one of those
    // tokens would have to be treated as compromised once discovered.
    throw new Error(`${name} is required for Better Auth and is not set`);
  }
  return value;
}

function createAuth() {
  /**
   * Better Auth derives the session cookie's `Secure` attribute from `baseURL`: an
   * `https://` URL produces `Secure` plus the `__Secure-` name prefix, anything else
   * produces neither (better-auth/dist/cookies/index.mjs, `createCookieGetter`). That is
   * the right default — a `Secure` cookie is simply not sent over plain http, so forcing it
   * on in local development would break login rather than harden it.
   *
   * The failure mode is the reverse one: an `http://` URL in production silently downgrades
   * every session cookie, and nothing in the response says so. Deriving the attribute is
   * not the same as checking it, so this asserts the precondition the derivation depends
   * on. `advanced.useSecureCookies` is deliberately NOT set — overriding the derivation
   * would pin one value across every environment and reintroduce exactly this bug.
   */
  const baseURL = required("BETTER_AUTH_URL");
  if (process.env.NODE_ENV === "production" && !baseURL.startsWith("https://")) {
    throw new Error(
      "BETTER_AUTH_URL must use https:// in production — session cookies would otherwise " +
        "be issued without the Secure attribute",
    );
  }

  /**
   * `search_path=identity` is the whole database boundary, applied at the connection.
   *
   * Better Auth creates and reads its tables unqualified, so the search path decides where
   * they live — and `scripts/migrate-identity.mts` migrates through this same config, so
   * migrations land in exactly the place the runtime looks. `identity` is a third schema on
   * purpose: `public` may not hold tables without `workspace_id` (DATABASE_DESIGN.md §1),
   * and `auth` belongs to Alembic, which drops it with `CASCADE` on downgrade — a path CI
   * runs on every push.
   */
  const pool = new Pool({
    connectionString: required("BETTER_AUTH_DATABASE_URL"),
    options: "-c search_path=identity",
  });

  return betterAuth({
    database: pool,
    secret: required("BETTER_AUTH_SECRET"),
    baseURL,

    /**
     * Email + password, per PRD FR-CP-1. Better Auth owns the hashing (scrypt by default);
     * ENGINEERING_PRINCIPLES P-15 forbids hand-rolling it, so nothing here touches a
     * password beyond handing it to the library.
     */
    emailAndPassword: {
      enabled: true,
    },

    /**
     * Email verification, enabled for invitation acceptance (ADR-0017 §2). The API refuses
     * to accept a targeted invitation unless the JWT's `emailVerified` is true, so verified
     * email is a real, achievable signal rather than one that is false forever.
     *
     * `requireEmailVerification` is deliberately NOT set: verification gates *invitation
     * acceptance* server-side, not sign-in, so existing flows are unchanged. The delivery
     * callback logs the verification URL rather than sending — control-plane email (Resend)
     * is wired in the API for invitations; the web-tier verification email is a dashboard
     * concern for when that UI lands. It must never throw (that would fail sign-up) and
     * never log anything but the URL Better Auth constructs.
     */
    emailVerification: {
      sendOnSignUp: true,
      sendVerificationEmail: async ({ url }: { url: string }): Promise<void> => {
        console.log(`[better-auth] email verification link generated: ${url}`);
      },
    },

    /**
     * Better Auth ships a telemetry package and is already off twice over — it returns a
     * no-op publisher unless `BETTER_AUTH_TELEMETRY_ENDPOINT` is set, and `enabled`
     * defaults to false. Stated anyway, because SYSTEM_ARCHITECTURE.md makes the Execution
     * Runtime the *only* egress: outbound calls from the control plane are a rule this
     * repository enforces, not a default it inherits, and a future version flipping that
     * default must not quietly start sending configuration off-box.
     */
    telemetry: { enabled: false },

    /**
     * The JWT plugin is what makes a separate Python service able to authenticate a human
     * without reaching into this database. It publishes JWKS at `/api/auth/jwks`; FastAPI
     * will verify against it in M1.3-B. Defaults are deliberately left alone — issuer and
     * audience derive from `baseURL`, so they are observable facts of the deployment rather
     * than values invented here, and the signing algorithm stays the library's EdDSA
     * default rather than something chosen without a decision.
     */
    plugins: [jwt()],
  });
}

let instance: ReturnType<typeof createAuth> | undefined;

/**
 * The single Better Auth instance for this process.
 *
 * Memoised because it owns a `pg.Pool`; constructing one per call would open a new
 * connection pool on every request and exhaust Postgres under any real load.
 */
export function getAuth(): ReturnType<typeof createAuth> {
  instance ??= createAuth();
  return instance;
}
