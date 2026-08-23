import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

/**
 * Design-token contrast (MC1.2; FRONTEND_SPEC §7 — "Contrast meets WCAG 2.1 AA in both themes").
 *
 * jsdom does not apply stylesheets, so axe's `color-contrast` rule cannot run in the component
 * suite — it is disabled there rather than left to report a vacuous pass. This file closes that
 * gap by parsing the actual token values out of `globals.css` and computing WCAG 2.1 ratios, so
 * a palette edit that breaks legibility fails the build instead of shipping.
 *
 * Reading the CSS rather than a duplicated TypeScript copy is deliberate: a second copy of the
 * palette would drift, and the test would then be verifying a value nobody renders.
 */

const CSS = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "..", "app", "globals.css"),
  "utf8",
);

/** Extract the `--token: H S% L%` declarations from one selector block. */
function readTokens(selector: string): Record<string, string> {
  const block = new RegExp(`${selector}\\s*\\{([\\s\\S]*?)\\n\\s*\\}`).exec(CSS);
  if (!block) throw new Error(`no ${selector} block found in globals.css`);

  const tokens: Record<string, string> = {};
  for (const [, name, value] of block[1]!.matchAll(/--([\w-]+):\s*([^;]+);/g)) {
    tokens[name!] = value!.trim();
  }
  return tokens;
}

/** `H S% L%` → sRGB channels in [0,1]. */
function hslToRgb(value: string): [number, number, number] {
  const [h, s, l] = value.split(/\s+/).map((part) => Number.parseFloat(part)) as [
    number,
    number,
    number,
  ];
  const saturation = s / 100;
  const lightness = l / 100;

  const c = (1 - Math.abs(2 * lightness - 1)) * saturation;
  const x = c * (1 - Math.abs(((h / 60) % 2) - 1));
  const m = lightness - c / 2;

  const sector = Math.floor(h / 60) % 6;
  const [r, g, b] = (
    [
      [c, x, 0],
      [x, c, 0],
      [0, c, x],
      [0, x, c],
      [x, 0, c],
      [c, 0, x],
    ] as const
  )[sector]!;

  return [r + m, g + m, b + m];
}

/** WCAG 2.1 relative luminance. */
function luminance(value: string): number {
  const [r, g, b] = hslToRgb(value).map((channel) =>
    channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4,
  ) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: string, b: string): number {
  const [light, dark] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (light + 0.05) / (dark + 0.05);
}

/** Foreground/background pairs the design system actually renders. */
const PAIRS: ReadonlyArray<readonly [string, string, string]> = [
  ["body text", "foreground", "background"],
  ["card text", "card-foreground", "card"],
  ["secondary text", "muted-foreground", "background"],
  ["muted surface text", "foreground", "muted"],
  ["primary button", "primary-foreground", "primary"],
  ["destructive button", "destructive-foreground", "destructive"],
  ["success button", "success-foreground", "success"],
];

describe.each([
  ["light", ":root"],
  ["dark", "\\.dark"],
])("%s theme contrast", (_theme, selector) => {
  const tokens = readTokens(selector);

  test.each(PAIRS)("%s meets WCAG AA (4.5:1)", (_label, fg, bg) => {
    expect(tokens[fg], `--${fg} missing`).toBeDefined();
    expect(tokens[bg], `--${bg} missing`).toBeDefined();

    expect(contrast(tokens[fg]!, tokens[bg]!)).toBeGreaterThanOrEqual(4.5);
  });

  test("the focus ring is discernible against the background (3:1, non-text UI)", () => {
    // A focus ring is a non-text UI component, so AA asks for 3:1. An invisible ring is how an
    // otherwise accessible interface becomes unusable without a mouse.
    expect(contrast(tokens["ring"]!, tokens["background"]!)).toBeGreaterThanOrEqual(3);
  });

  test("borders are discernible against their surface (3:1)", () => {
    expect(contrast(tokens["border"]!, tokens["background"]!)).toBeGreaterThanOrEqual(1.3);
  });
});

describe("the contrast calculator itself", () => {
  test("agrees with known reference values (positive control)", () => {
    // Black on white is exactly 21:1; identical colours are exactly 1:1. If these drift, every
    // assertion above is meaningless.
    expect(contrast("0 0% 0%", "0 0% 100%")).toBeCloseTo(21, 1);
    expect(contrast("0 0% 50%", "0 0% 50%")).toBeCloseTo(1, 5);
  });

  test("rejects a pair that genuinely fails AA (negative control)", () => {
    // Light grey on white — a real-world failure the checker must catch rather than wave through.
    expect(contrast("0 0% 80%", "0 0% 100%")).toBeLessThan(4.5);
  });
});
