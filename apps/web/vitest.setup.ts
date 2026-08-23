import "@testing-library/jest-dom/vitest";

import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

/**
 * Vitest setup (MC1.2, ADR-0044 D3).
 *
 * `cleanup` after every test unmounts the previous tree. Without it, `getByRole` searches a
 * document containing every component rendered so far in the file, so a query starts matching
 * multiple elements and the failure surfaces as a confusing "found multiple" error in an
 * unrelated test — or, worse, a test passes by finding the *previous* test's DOM.
 */
afterEach(() => {
  cleanup();
});
