/**
 * Environment boundary tests (MC1.1, FRONTEND_SPEC §9, ADR-0044).
 *
 * The split between public and server configuration is a security control, not a convention:
 * every `NEXT_PUBLIC_` value is compiled into the browser bundle. These assert the control
 * holds, including the failure modes — a missing production variable must stop the process
 * rather than resolve to a localhost default that makes a broken deployment look healthy.
 */

import assert from "node:assert/strict";
import { describe, test, beforeEach, afterEach } from "node:test";

const MODULE = "../src/lib/env.ts";

/** Re-import with a cache-busting query so each case validates a fresh `process.env`. */
async function loadEnv(): Promise<typeof import("../src/lib/env.ts")> {
  return (await import(`${MODULE}?v=${Math.random()}`)) as typeof import("../src/lib/env.ts");
}

const ORIGINAL = { ...process.env };

beforeEach(() => {
  process.env.NEXT_PUBLIC_APP_URL = "http://localhost:3000";
  process.env.API_BASE_URL = "http://localhost:8000";
  delete process.env.API_TIMEOUT_MS;
});

afterEach(() => {
  process.env = { ...ORIGINAL };
});

describe("public environment", () => {
  test("a valid app URL parses", async () => {
    const { publicEnv } = await loadEnv();
    assert.equal(publicEnv.NEXT_PUBLIC_APP_URL, "http://localhost:3000");
  });

  test("a missing app URL fails loudly rather than defaulting", async () => {
    delete process.env.NEXT_PUBLIC_APP_URL;
    await assert.rejects(loadEnv(), /Invalid public environment/);
  });

  test("a non-http scheme is refused", async () => {
    process.env.NEXT_PUBLIC_APP_URL = "ftp://example.com";
    await assert.rejects(loadEnv(), /Invalid public environment/);
  });
});

describe("server environment", () => {
  test("a valid API base URL parses and the timeout defaults", async () => {
    const { serverEnv } = await loadEnv();
    const env = serverEnv();
    assert.equal(env.API_BASE_URL, "http://localhost:8000");
    assert.equal(env.API_TIMEOUT_MS, 10_000);
  });

  test("a missing API base URL throws and names the variable, never a value", async () => {
    delete process.env.API_BASE_URL;
    const { serverEnv } = await loadEnv();
    assert.throws(serverEnv, (error: unknown) => {
      const message = (error as Error).message;
      assert.match(message, /Invalid server environment/);
      assert.match(message, /API_BASE_URL/);
      return true;
    });
  });

  test("the timeout is bounded — an absurd value is refused", async () => {
    process.env.API_TIMEOUT_MS = "999999999";
    const { serverEnv } = await loadEnv();
    assert.throws(serverEnv, /API_TIMEOUT_MS/);
  });

  test("a non-numeric timeout is refused rather than coerced to NaN", async () => {
    process.env.API_TIMEOUT_MS = "soon";
    const { serverEnv } = await loadEnv();
    assert.throws(serverEnv, /API_TIMEOUT_MS/);
  });

  test("validation failures never echo the offending value", async () => {
    process.env.API_BASE_URL = "postgresql://user:hunter2@db/omniai";
    const { serverEnv } = await loadEnv();
    assert.throws(serverEnv, (error: unknown) => {
      assert.doesNotMatch((error as Error).message, /hunter2/);
      return true;
    });
  });
});

describe("public/server separation", () => {
  test("the API base URL is NOT exposed as a public variable", async () => {
    const { publicEnv } = await loadEnv();
    assert.equal(
      Object.prototype.hasOwnProperty.call(publicEnv, "API_BASE_URL"),
      false,
      "API_BASE_URL must never reach the browser bundle",
    );
    assert.deepEqual(Object.keys(publicEnv), ["NEXT_PUBLIC_APP_URL"]);
  });

  test("secret-shaped NEXT_PUBLIC_ variables are detected", async () => {
    const { findUnsafePublicVars } = await loadEnv();
    // Positive control: the scanner must actually catch something before its clean result means
    // anything. Each of these is a shape that has leaked in real projects.
    const planted = {
      NEXT_PUBLIC_BETTER_AUTH_SECRET: "x",
      NEXT_PUBLIC_RESEND_API_KEY: "x",
      NEXT_PUBLIC_DATABASE_URL: "x",
      NEXT_PUBLIC_APP_URL: "http://localhost:3000",
    } as unknown as NodeJS.ProcessEnv;
    assert.deepEqual(findUnsafePublicVars(planted), [
      "NEXT_PUBLIC_BETTER_AUTH_SECRET",
      "NEXT_PUBLIC_DATABASE_URL",
      "NEXT_PUBLIC_RESEND_API_KEY",
    ]);
  });

  test("the repository's own environment declares no unsafe public variable", async () => {
    const { findUnsafePublicVars } = await loadEnv();
    assert.deepEqual(findUnsafePublicVars(), []);
  });
});
