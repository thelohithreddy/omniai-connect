import "@testing-library/jest-dom/vitest";

import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

/**
 * Public environment for modules that transitively reach `lib/env.ts`.
 *
 * `publicEnv` is evaluated eagerly by design — a missing app URL should fail the build rather
 * than the first request that needs it — so any test importing the transport, the API client or
 * anything downstream of them needs it present.
 *
 * Only `NEXT_PUBLIC_*` values are set here, and only ones that are safe in a browser bundle by
 * definition. **No server variable is defaulted**: `API_BASE_URL` is deliberately absent so a
 * test that accidentally performs a real server request fails loudly instead of silently
 * resolving somewhere. `env.test.mts` in the Node lane owns validation behaviour itself and runs
 * in its own process, unaffected by this.
 */
process.env.NEXT_PUBLIC_APP_URL ??= "http://localhost:3000";

/**
 * Vitest setup (MC1.2, ADR-0044 D3).
 *
 * `cleanup` after every test unmounts the previous tree. Without it, `getByRole` searches a
 * document containing every component rendered so far in the file, so a query starts matching
 * multiple elements and the failure surfaces as a confusing "found multiple" error in an
 * unrelated test — or, worse, a test passes by finding the *previous* test's DOM.
 */
afterEach(() => {
  cleanup();
});
