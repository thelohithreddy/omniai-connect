/**
 * The import boundary, proven rather than documented (MC1.1, ADR-0044 §7).
 *
 * `apps/web/src/lib/api/transport.ts` opens with `import "server-only"`. That package ships a
 * module whose only statement throws; Next's bundler aliases it away for the server graph and
 * leaves it intact for the client graph, so a `"use client"` component that imports the
 * transport — at any depth — fails the build instead of shipping a JWT to the browser.
 *
 * This file is the **positive control** for that mechanism. A plain Node process resolves the
 * throwing module exactly as a client bundle would, so importing the transport here must throw.
 * If someone deletes the `server-only` import, these tests go green in the wrong direction —
 * which is why the structural assertion below is paired with the behavioural one.
 *
 * `api-transport.test.mts` neutralises the guard for its own process on purpose, and says so.
 * Neutralising it there is only safe because the guard is proven live here.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";

const webRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const TRANSPORT = join(webRoot, "src", "lib", "api", "transport.ts");
const CLIENT = join(webRoot, "src", "lib", "api", "client.ts");

describe("server-only guard is present", () => {
  test("the transport imports server-only before anything else", () => {
    const source = readFileSync(TRANSPORT, "utf8");
    const firstImport = source
      .split("\n")
      .map((line) => line.trim())
      .find((line) => line.startsWith("import "));
    assert.equal(
      firstImport,
      'import "server-only";',
      "the guard must be the first import so nothing can execute before it",
    );
  });

  test("the typed client carries the guard too", () => {
    // The client re-exports transport-backed functions. It carries its own guard so that a
    // future refactor which stops importing the transport directly cannot silently lose it.
    assert.match(readFileSync(CLIENT, "utf8"), /^import "server-only";$/m);
  });
});

describe("server-only guard is live", () => {
  test("importing the transport outside a server bundle throws", async () => {
    // This is what a client bundle would hit. If this ever resolves, the boundary is gone.
    await assert.rejects(
      import(`../src/lib/api/transport.ts?boundary=${Math.random()}`),
      (error: unknown) => {
        assert.match(
          (error as Error).message,
          /cannot be imported from a Client Component/i,
          "server-only did not refuse the import",
        );
        return true;
      },
    );
  });

  test("importing the typed client outside a server bundle throws", async () => {
    await assert.rejects(
      import(`../src/lib/api/client.ts?boundary=${Math.random()}`),
      /cannot be imported from a Client Component/i,
    );
  });

  test("the errors module is deliberately NOT server-only", async () => {
    // Negative control. `ApiFailure.toClient()` is meant to cross into client components, so
    // this module must remain importable — otherwise the previous assertions would pass simply
    // because every module in the directory throws.
    const mod = await import(`../src/lib/api/errors.ts?boundary=${Math.random()}`);
    assert.equal(typeof (mod as { ApiFailure?: unknown }).ApiFailure, "function");
  });
});
