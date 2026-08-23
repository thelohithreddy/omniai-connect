import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

/**
 * Vitest + React Testing Library lane (MC1.2, ADR-0044 D3).
 *
 * The existing `tsx --test` contract suite in `tests/*.test.mts` is **kept, not replaced** — it
 * drives real Better Auth against real Postgres and proves things a component test cannot. The
 * `include` below is therefore scoped to `src/**` so the two lanes cannot collide: Vitest would
 * otherwise try to run the Node contract suite in jsdom, where it does not belong, and the
 * duplicate run would look like coverage while proving nothing new.
 *
 * jsdom rather than happy-dom because Testing Library's accessibility queries and axe both lean
 * on layout and ARIA computation that jsdom implements more completely; a11y assertions that
 * silently pass on a thinner DOM would be worse than no assertions.
 *
 * `.mts` so the config is loaded as ESM natively, and `resolve.tsconfigPaths` rather than the
 * `vite-tsconfig-paths` plugin — Vite resolves `@/*` from `tsconfig.json` itself now, so the
 * plugin would be a dependency earning nothing.
 */
export default defineConfig({
  plugins: [react()],
  resolve: { tsconfigPaths: true },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    // `tests/` belongs to the Node lane; `e2e/` is reserved for Playwright in MC1.8.
    exclude: ["node_modules/**", ".next/**", "tests/**", "e2e/**"],
    restoreMocks: true,
  },
});
