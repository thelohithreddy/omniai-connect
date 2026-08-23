/**
 * OpenAPI drift gate (MC1.1, ADR-0044 D2).
 *
 * Fails when the committed TypeScript contract no longer matches the committed OpenAPI
 * document — i.e. someone changed `openapi.json` without re-running the generator.
 *
 * **It never writes into the repository.** Generation happens in a temporary directory and the
 * result is compared byte-for-byte against the committed file. A gate that regenerates in place
 * and then diffs would leave a dirty tree behind on failure and, worse, could be "fixed" by a
 * careless `git checkout .` that also discards the developer's real work. CI checkouts are
 * ephemeral, but a gate should not depend on that to be safe to run locally.
 *
 * This checks one of the two drift directions. The other — backend moved without the schema
 * being re-exported — is `openapi:export` followed by `git diff --exit-code`, which CI runs
 * separately because it needs the Python application importable and this script does not.
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const schema = join(packageRoot, "openapi.json");
const committed = join(packageRoot, "src", "generated", "api.ts");

const scratch = mkdtempSync(join(tmpdir(), "omniai-openapi-drift-"));
const candidate = join(scratch, "api.ts");

try {
  execFileSync(
    "node",
    [join(packageRoot, "node_modules", "openapi-typescript", "bin", "cli.js"), schema, "-o", candidate],
    { stdio: ["ignore", "ignore", "inherit"] },
  );

  const expected = readFileSync(candidate, "utf8");
  const actual = readFileSync(committed, "utf8");

  if (expected !== actual) {
    console.error(
      [
        "",
        "OpenAPI drift detected.",
        "",
        "  packages/types/src/generated/api.ts does not match what the generator produces",
        "  from packages/types/openapi.json.",
        "",
        "  Fix:  pnpm --filter @omniai/types openapi:generate",
        "",
        "  Do not hand-edit the generated file — the OpenAPI document is the contract and the",
        "  backend owns it.",
        "",
      ].join("\n"),
    );
    process.exit(1);
  }

  console.log("OpenAPI contract and generated types agree.");
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
