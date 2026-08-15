/**
 * Apply Better Auth's schema to the `identity` schema.
 *
 * Uses the library's own `getMigrations` rather than `@better-auth/cli`. The CLI's latest
 * release is 1.4.21 while the installed library is 1.6.28, and a migrator a minor version
 * behind the runtime can generate a schema the runtime does not expect. `getMigrations`
 * ships inside the same package, so the schema and the code reading it cannot disagree.
 *
 * This is Better Auth's lifecycle, deliberately separate from Alembic's. Alembic owns
 * `public` and `auth`; nothing here touches either, and `alembic downgrade base` cannot
 * reach `identity`.
 *
 *   pnpm --filter web migrate:identity
 */
import { getMigrations } from "better-auth/db/migration";

import { getAuth } from "../src/lib/auth.ts";

// The runtime's own configuration, not a copy of it. Migrating through a second config
// object is how a schema ends up in a different place than the code that reads it.
const { toBeAdded, toBeCreated, runMigrations } = await getMigrations(getAuth().options);

const created = toBeCreated.map((table) => table.table);
const altered = toBeAdded.map((table) => table.table);

if (created.length === 0 && altered.length === 0) {
  console.log("identity schema is already up to date");
  process.exit(0);
}

console.log(`creating tables : ${created.join(", ") || "(none)"}`);
console.log(`altering tables : ${altered.join(", ") || "(none)"}`);

await runMigrations();
console.log("identity schema migrated");
process.exit(0);
