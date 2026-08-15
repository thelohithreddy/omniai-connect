import { toNextJsHandler } from "better-auth/next-js";

import { getAuth } from "@/lib/auth";

/**
 * Every Better Auth endpoint — sign-up, sign-in, sign-out, session, and the JWKS document
 * FastAPI will verify against in M1.3-B — served from this one catch-all route. Better Auth
 * owns its own routing table; adding routes per endpoint here would duplicate a mapping the
 * library already maintains and would silently omit endpoints a future plugin adds.
 *
 * The handler pair is built on first request rather than at module scope: `getAuth()`
 * demands real configuration, and `next build` evaluates route modules when collecting page
 * data, so constructing eagerly would make the production build require a secret and a
 * live database.
 */
let handlers: ReturnType<typeof toNextJsHandler> | undefined;

function getHandlers(): ReturnType<typeof toNextJsHandler> {
  handlers ??= toNextJsHandler(getAuth());
  return handlers;
}

export const GET = (request: Request): Promise<Response> => getHandlers().GET(request);
export const POST = (request: Request): Promise<Response> => getHandlers().POST(request);
