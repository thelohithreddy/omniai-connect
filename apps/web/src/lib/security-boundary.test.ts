import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

/**
 * Server/client boundary, asserted from source (MC1.3; Phase 14).
 *
 * The Vitest lane aliases `server-only` away so guarded modules can be unit tested. That is safe
 * only if something still fails when a guard is deleted — otherwise the alias would quietly turn
 * the boundary into a comment. This file is that something.
 *
 * It reads the real source rather than importing it, so the alias cannot influence the result.
 */

/** This file lives at `src/lib/`, so two levels up is `src/`. */
const SRC = dirname(dirname(fileURLToPath(import.meta.url)));

function source(relativePath: string): string {
  return readFileSync(join(SRC, relativePath), "utf8");
}

/** Every module that handles credentials, session material or server configuration. */
const MUST_BE_SERVER_ONLY = [
  "lib/api/transport.ts",
  "lib/api/client.ts",
  "lib/session.ts",
  "lib/workspace/context.ts",
];

describe("server-only guards", () => {
  test.each(MUST_BE_SERVER_ONLY)("%s declares the guard", (relativePath) => {
    // Matched as a statement, not a substring: a docstring mentioning "server-only" must not
    // satisfy this, and several modules in this repository legitimately do mention it in prose.
    expect(source(relativePath)).toMatch(/^import "server-only";$/m);
  });

  test("the guard is the first statement, before any side-effecting import", () => {
    for (const relativePath of MUST_BE_SERVER_ONLY) {
      const firstStatement = source(relativePath)
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line !== "" && !line.startsWith("//") && !line.startsWith("*") && !line.startsWith("/*"))
        .at(0);

      // If another import ran first, its side effects would happen in a client bundle before the
      // guard could refuse — the refusal must come first to be worth anything.
      expect(firstStatement, relativePath).toBe('import "server-only";');
    }
  });
});

describe("no client path reaches server configuration (F7 regression)", () => {
  /**
   * F7 is the known, accepted gap: `lib/env.ts` carries no guard, so a client component that
   * called `serverEnv()` would render its value into prerendered HTML. It is latent because
   * nothing calls it that way. This test is what keeps it latent — MC1.3 must not introduce the
   * first such caller, and neither must any later slice.
   */
  test("serverEnv is referenced only by the server-only transport", () => {
    const callers = walk(SRC).filter((file) => {
      if (file.endsWith("lib/env.ts") || file.endsWith(".test.ts") || file.endsWith(".test.tsx")) {
        return false;
      }
      return /\bserverEnv\b/.test(readFileSync(file, "utf8"));
    });

    expect(callers.map((file) => file.slice(SRC.length + 1))).toEqual(["lib/api/transport.ts"]);
  });

  test("no client component imports the env module at all", () => {
    const offenders = walk(SRC).filter((file) => {
      const contents = readFileSync(file, "utf8");
      const isClient = /^\s*"use client";/m.test(contents);
      return isClient && /from "@\/lib\/env"/.test(contents);
    });

    expect(offenders).toEqual([]);
  });
});

/** Every `.ts`/`.tsx` file under a directory. */
function walk(directory: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(directory)) {
    const full = join(directory, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (/\.tsx?$/.test(entry)) out.push(full);
  }
  return out;
}
