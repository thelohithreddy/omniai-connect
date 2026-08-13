/**
 * ESLint flat config (ESLint 9).
 *
 * Replaces `next lint`, which is deprecated in Next.js 15 and removed in 16. More
 * immediately: `next lint` with no config file prompts interactively for a preset, so in
 * CI — where stdin is closed — it exits non-zero and fails the build. That was latent
 * from M0 and invisible because the repository had never been pushed.
 *
 * `FlatCompat` bridges `eslint-config-next`, which is still published in the legacy
 * eslintrc format, into flat config. It goes away once that package ships a native
 * flat export.
 */
import { dirname } from "path";
import { fileURLToPath } from "url";

import { FlatCompat } from "@eslint/eslintrc";

const compat = new FlatCompat({
  baseDirectory: dirname(fileURLToPath(import.meta.url)),
});

const config = [
  {
    // Flat config has no implicit ignores beyond node_modules; build output must be
    // listed explicitly or ESLint lints thousands of generated files.
    ignores: [".next/**", "out/**", "next-env.d.ts"],
  },
  ...compat.extends("next/core-web-vitals", "next/typescript"),
];

export default config;
