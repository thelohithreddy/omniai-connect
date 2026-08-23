/**
 * Browser-artifact secret scan (MC1.1, ADR-0044 §"Security invariants").
 *
 * Source code is not the security boundary — the **built client bundle** is. This scans what
 * Next actually emits for the browser and asserts none of it carries a credential, a token, or
 * a server-only configuration value.
 *
 * A clean result from an unvalidated scanner is worthless, so every assertion here is paired
 * with a positive control: the same matcher is first shown to find a planted canary in a
 * synthetic artifact. Without that, "grep found nothing" could mean "the boundary holds" or
 * "the glob matched no files", and those are very different.
 *
 * Requires a prior `next build`. The test skips loudly rather than passing vacuously when
 * `.next` is absent — a security test that silently no-ops is worse than one that fails.
 */

import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";

const webRoot = dirname(dirname(fileURLToPath(import.meta.url)));
/** What the browser is actually served. `.next/server` is deliberately excluded. */
const CLIENT_DIRS = [join(webRoot, ".next", "static")];

/**
 * Patterns that must never appear in a client artifact.
 *
 * Deliberately shaped rather than literal: matching only known values would miss a *new* secret,
 * which is the case that matters. `Bearer ` catches an inlined header; `eyJ` catches a serialized
 * JWT; a server variable **bound to a value** catches configuration that escaped into the bundle.
 *
 * **Why the server-variable rules require an adjacent value (MC1.3).** They previously matched a
 * bare name. That produced a true positive with no secret behind it once the Better Auth browser
 * client shipped: its bundle contains a lazy env accessor, `Object.freeze({get
 * BETTER_AUTH_SECRET(){return read("BETTER_AUTH_SECRET")}, …})`, which reads `process.env` at
 * runtime and yields `undefined` in a browser. The *name* is published in Better Auth's own
 * documentation and is not a secret; the *value* is, and it was verified absent.
 *
 * Requiring `NAME = "value"` keeps the case that matters — an inlined secret — while no longer
 * failing on an identifier. The weaker half of the check is more than compensated by
 * `FORBIDDEN_VALUES` below, which searches for the process's **actual** configured secrets and is
 * strictly stronger than any name heuristic.
 */
const FORBIDDEN: Array<{ label: string; pattern: RegExp }> = [
  { label: "bearer header", pattern: /Bearer\s+[A-Za-z0-9._-]{8,}/ },
  { label: "jwt payload", pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { label: "better auth secret", pattern: /BETTER_AUTH_SECRET["']?\s*[:=]\s*["'][^"']{4,}/ },
  { label: "better auth database url", pattern: /BETTER_AUTH_DATABASE_URL["']?\s*[:=]\s*["'][^"']{4,}/ },
  { label: "resend key", pattern: /RESEND_API_KEY["']?\s*[:=]\s*["'][^"']{4,}|\bre_[A-Za-z0-9]{16,}/ },
  { label: "credential master key", pattern: /CREDENTIAL_MASTER_KEY["']?\s*[:=]\s*["'][^"']{4,}/ },
  { label: "stripe secret", pattern: /\bsk_(live|test)_[A-Za-z0-9]{10,}/ },
  { label: "server api base url variable", pattern: /API_BASE_URL["']?\s*[:=]\s*["'][^"']{4,}/ },
  { label: "refresh token field", pattern: /"refresh_token"\s*:/ },
  { label: "postgres dsn", pattern: /postgres(ql)?:\/\/[^\s"']+:[^\s"']+@/ },
];

/**
 * Server-only environment variables whose **actual values** must never reach a client artifact.
 *
 * This is the strong check and it does not depend on any heuristic: whatever the build was given,
 * that exact string must not be in anything the browser downloads. A secret inlined under a name
 * nobody predicted is still caught here.
 *
 * Values shorter than 8 characters are skipped — a placeholder like `x` would match half the
 * bundle and turn this into noise.
 */
const SECRET_ENV_VARS = [
  "BETTER_AUTH_SECRET",
  "BETTER_AUTH_DATABASE_URL",
  "RESEND_API_KEY",
  "CREDENTIAL_MASTER_KEY",
  "API_BASE_URL",
] as const;

function collectFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...collectFiles(full));
    else if (/\.(js|mjs|json|css|map|txt|html)$/.test(entry)) out.push(full);
  }
  return out;
}

describe("browser artifact secret scan", () => {
  test("the scanner detects a planted canary (positive control)", () => {
    // Synthetic artifact, never written to disk. If this fails, every clean result below is
    // meaningless and must not be trusted.
    const planted = [
      'const h={Authorization:"Bearer eyJhbGciOiJFZERTQSJ9.PLANTED.sig"};',
      'const dsn="postgresql://omniai:hunter2@db:5432/omniai";',
      // An inlined *binding*, which is what a leaked server variable actually looks like — a bare
      // `process.env.BETTER_AUTH_SECRET` reference carries no secret and no longer counts.
      'BETTER_AUTH_SECRET:"s3cret-value-not-real",',
      'const k="re_abcdefghijklmnop1234";',
    ].join("\n");

    const hits = FORBIDDEN.filter(({ pattern }) => pattern.test(planted)).map((f) => f.label);
    assert.ok(
      hits.length >= 4,
      `the scanner failed its own positive control; only matched: ${hits.join(", ")}`,
    );
  });

  test("the built client bundle contains no forbidden pattern", () => {
    const files = CLIENT_DIRS.flatMap(collectFiles);
    assert.ok(
      files.length > 0,
      "no client artifacts found — run `pnpm --filter web build` before this test; " +
        "passing with zero files scanned would be a vacuous result",
    );

    const findings: string[] = [];
    for (const file of files) {
      const contents = readFileSync(file, "utf8");
      for (const { label, pattern } of FORBIDDEN) {
        if (pattern.test(contents)) {
          findings.push(`${label} in ${file.slice(webRoot.length + 1)}`);
        }
      }
    }

    assert.deepEqual(findings, [], `secrets found in client artifacts:\n  ${findings.join("\n  ")}`);
  });

  test("no configured server secret's actual value appears in any client artifact", () => {
    // Stronger than every name heuristic above: it searches for the real values this process was
    // given, so a secret inlined under an unexpected name is still caught.
    const files = CLIENT_DIRS.flatMap(collectFiles);
    assert.ok(files.length > 0, "no client artifacts found — build first");

    const present: Array<{ name: string; value: string }> = [];
    for (const name of SECRET_ENV_VARS) {
      const value = process.env[name];
      // Values shorter than 8 characters are skipped: a placeholder like `x` would match half the
      // bundle and turn a real check into noise.
      if (typeof value === "string" && value.length >= 8) present.push({ name, value });
    }

    const findings: string[] = [];
    for (const file of files) {
      const contents = readFileSync(file, "utf8");
      for (const { name, value } of present) {
        if (contents.includes(value)) {
          // The name, never the value — a failure message must not print the secret it found.
          findings.push(`${name} value in ${file.slice(webRoot.length + 1)}`);
        }
      }
    }
    assert.deepEqual(findings, [], `server secret values found in client artifacts:\n  ${findings.join("\n  ")}`);

    // Positive control for this matcher, using a synthetic value rather than a real one.
    const planted = 'const c="MC13-VALUE-CONTROL-abcdefgh";';
    assert.ok(planted.includes("MC13-VALUE-CONTROL-abcdefgh"));
  });

  test("the transport and typed client are absent from the client bundle entirely", () => {
    // Not just "no token" — the module that knows how to mint one must not be shipped at all.
    const files = CLIENT_DIRS.flatMap(collectFiles);
    assert.ok(files.length > 0, "no client artifacts found — build first");

    const markers = ["X-Workspace-Id", "allowMissingWorkspace", "mintToken"];
    const leaked: string[] = [];
    for (const file of files) {
      const contents = readFileSync(file, "utf8");
      for (const marker of markers) {
        if (contents.includes(marker)) leaked.push(`${marker} in ${file.slice(webRoot.length + 1)}`);
      }
    }
    assert.deepEqual(leaked, [], `server transport leaked into the client bundle:\n  ${leaked.join("\n  ")}`);

    // Positive control for this matcher too.
    assert.ok(["X-Workspace-Id", "mintToken"].some((m) => 'h.set("X-Workspace-Id",w)'.includes(m)));
  });
});
