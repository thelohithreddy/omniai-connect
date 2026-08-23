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
 * which is the case that matters. `Bearer ` catches an inlined header; `BETTER_AUTH_SECRET`
 * catches a server variable that escaped into the bundle; `eyJ` catches a serialized JWT.
 */
const FORBIDDEN: Array<{ label: string; pattern: RegExp }> = [
  { label: "bearer header", pattern: /Bearer\s+[A-Za-z0-9._-]{8,}/ },
  { label: "jwt payload", pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { label: "better auth secret", pattern: /BETTER_AUTH_SECRET/ },
  { label: "better auth database url", pattern: /BETTER_AUTH_DATABASE_URL/ },
  { label: "resend key", pattern: /RESEND_API_KEY|\bre_[A-Za-z0-9]{16,}/ },
  { label: "credential master key", pattern: /CREDENTIAL_MASTER_KEY/ },
  { label: "stripe secret", pattern: /\bsk_(live|test)_[A-Za-z0-9]{10,}/ },
  { label: "server api base url variable", pattern: /\bAPI_BASE_URL\b/ },
  { label: "refresh token field", pattern: /"refresh_token"\s*:/ },
  { label: "postgres dsn", pattern: /postgres(ql)?:\/\/[^\s"']+:[^\s"']+@/ },
];

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
      'process.env.BETTER_AUTH_SECRET;',
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
