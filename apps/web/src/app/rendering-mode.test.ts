import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

/**
 * Rendering mode per route (MC1.3; Phase 3, Phase 13).
 *
 * Two invariants that are invisible in source and only exist in build output:
 *
 * 1. **No authenticated or workspace-scoped route may be statically generated.** ADR-0044 §6
 *    forbids it, and the failure is severe rather than cosmetic: a prerendered authenticated page
 *    is built once at deploy time with no session, then served to everyone. Adding a page with no
 *    dynamic data dependency is enough to trigger it silently.
 *
 * 2. **The set of static routes is pinned**, because static rendering is exactly the condition
 *    under which F6 applies — Next cannot stamp a per-request CSP nonce onto markup generated at
 *    build time. Every static route is therefore a route that will break when MC1.8 enforces the
 *    policy, and the list must be a deliberate, reviewed one rather than whatever accumulated.
 *
 * Reads `.next/prerender-manifest.json`, which is the build's own record of what it prerendered.
 * Skips loudly rather than passing vacuously when the app has not been built.
 */

const WEB_ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const MANIFEST = join(WEB_ROOT, ".next", "prerender-manifest.json");

/**
 * Public routes that carry no user or workspace data and are allowed to be static.
 *
 * **Each entry is an accepted F6 exposure.** `/` is the placeholder landing page and
 * `/_not-found` the root 404; neither reads a session. Adding to this list is a security
 * decision, not a formality — and MC1.8 must resolve F6 for everything on it before enforcement.
 */
const STATIC_ALLOWLIST = ["/", "/_not-found"];

/** Routes that must never be prerendered, because they depend on a session or a workspace. */
const MUST_BE_DYNAMIC = ["/dashboard", "/sign-in", "/sign-up", "/accept-invite"];

describe("rendering mode", () => {
  if (!existsSync(MANIFEST)) {
    test.skip("requires a production build (`pnpm --filter web build`)", () => {});
    return;
  }

  const prerendered = Object.keys(
    (JSON.parse(readFileSync(MANIFEST, "utf8")) as { routes?: Record<string, unknown> }).routes ??
      {},
  );

  test("no authenticated or workspace-scoped route is prerendered", () => {
    const leaked = MUST_BE_DYNAMIC.filter((route) => prerendered.includes(route));

    expect(
      leaked,
      "a prerendered authenticated route is built once, with no session, and served to everyone",
    ).toEqual([]);
  });

  test("the set of static routes is exactly the reviewed allowlist", () => {
    // Fails in both directions on purpose. A new static route is a new F6 exposure that must be
    // acknowledged here; a removed one means this list has drifted from reality.
    expect(prerendered.sort()).toEqual([...STATIC_ALLOWLIST].sort());
  });

  test("every allowlisted static route is public by construction", () => {
    // A static route cannot read a session, so any entry naming an authenticated area is a
    // contradiction that should never have been added.
    for (const route of STATIC_ALLOWLIST) {
      expect(route).not.toMatch(/dashboard|settings|logs|workspace|invite/);
    }
  });
});
