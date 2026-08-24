"use client";

import { createAuthClient } from "better-auth/client";

/**
 * Better Auth browser client (MC1.3, ADR-0002).
 *
 * The **only** thing the browser is allowed to talk to for identity, and it talks to this app's
 * own `/api/auth/*` routes — never to FastAPI. That is not a convention: the API has no CORS
 * middleware and the CSP pins `connect-src 'self'` (ADR-0044 D4), so a direct call fails twice
 * over.
 *
 * No `baseURL`. Better Auth then uses a same-origin relative path, which is exactly what
 * `connect-src 'self'` permits and what keeps deployment URLs out of the client bundle. Passing
 * `NEXT_PUBLIC_APP_URL` here would bake an absolute origin into browser JavaScript for no gain.
 *
 * This client handles sign-in, sign-up and sign-out only. It never sees the backend JWT: that is
 * minted server-side inside the MC1.1 transport, from the session cookie, and never crosses into
 * browser-reachable state.
 */
export const authClient = createAuthClient();

export const { signIn, signUp, signOut } = authClient;
