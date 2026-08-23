/**
 * Test-only stand-in for the `server-only` package (MC1.3).
 *
 * The real package throws on import outside a Server Component, which is exactly what makes the
 * MC1.1 boundary a build error rather than a convention. That also makes the modules it guards
 * un-unit-testable, so the Vitest lane aliases the package to this empty module.
 *
 * **This does not weaken the guard, and the guard's liveness is not assumed.** It is proven
 * independently, twice, outside this lane:
 *
 *   1. `tests/server-only-boundary.test.mts` (Node lane) imports the real package and asserts it
 *      throws, and asserts each guarded module still declares it;
 *   2. the production build fails — verified, exit 1 with an import trace — when a client
 *      component reaches the transport.
 *
 * `security-boundary.test.ts` additionally asserts, from source, that every module that must carry
 * the guard still does, so removing an `import "server-only"` fails this lane too.
 */
export {};
