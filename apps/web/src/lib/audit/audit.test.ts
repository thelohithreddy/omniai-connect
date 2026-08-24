import { describe, expect, test } from "vitest";

import { describeCaller, formatDuration, formatTimestamp, shortId } from "./format";
import {
  KNOWN_TOOL_CALL_STATUSES,
  isKnownToolCallStatus,
  presentToolCallStatus,
} from "./status";

/**
 * Audit status vocabulary and formatting (MC1.4, ADR-0044).
 *
 * The theme is **totality**. These functions receive whatever the API actually sent, and an audit
 * viewer that throws on one odd row hides the whole page — which in an audit trail is the worst
 * outcome, because the operator concludes nothing happened. So every case below feeds in something
 * the happy path did not expect.
 */

describe("the closed status vocabulary", () => {
  test("matches the backend's CHECK constraint exactly", () => {
    // `TOOL_CALL_STATUSES` in apps/api/app/domains/runtime/models.py. Drifting from it would make
    // a real status render as "unrecognised".
    expect([...KNOWN_TOOL_CALL_STATUSES]).toEqual(["succeeded", "failed", "denied", "timeout"]);
  });

  test.each([...KNOWN_TOOL_CALL_STATUSES])("%s is known and carries a label", (status) => {
    const presentation = presentToolCallStatus(status);

    expect(presentation.isKnown).toBe(true);
    expect(presentation.label.length).toBeGreaterThan(0);
    expect(presentation.srDescription.length).toBeGreaterThan(0);
  });

  test("denied is not conflated with failed", () => {
    // An authorization refusal and a provider fault are different things for an operator to act
    // on; giving them one tone would erase that distinction.
    expect(presentToolCallStatus("denied").tone).not.toBe(presentToolCallStatus("failed").tone);
  });

  test("succeeded and failed do not share a tone", () => {
    expect(presentToolCallStatus("succeeded").tone).toBe("success");
    expect(presentToolCallStatus("failed").tone).toBe("danger");
  });
});

describe("an unknown status is additive, never guessed", () => {
  test("a future value renders neutrally rather than as success or failure", () => {
    // ADR-0044 requires a future status to be additive. `pending` is the obvious M4 candidate.
    const presentation = presentToolCallStatus("pending");

    expect(presentation.isKnown).toBe(false);
    expect(presentation.tone).toBe("neutral");
    // The severity must not be invented — that would put a wrong signal in an audit trail.
    expect(presentation.tone).not.toBe("success");
    expect(presentation.tone).not.toBe("danger");
  });

  test("the raw value is preserved in the label", () => {
    expect(presentToolCallStatus("pending").label).toBe("pending");
  });

  test("an unknown value announces itself as unrecognised", () => {
    expect(presentToolCallStatus("pending").srDescription).toContain("Unrecognised");
  });

  test.each([
    ["empty", ""],
    ["whitespace", "   "],
  ])("a %s status still returns a label", (_label, status) => {
    const presentation = presentToolCallStatus(status);
    expect(presentation.label).toBe("Unknown");
    expect(presentation.isKnown).toBe(false);
  });

  test("a pathological value is capped so it cannot break the layout", () => {
    const presentation = presentToolCallStatus("x".repeat(5000));
    expect(presentation.label.length).toBeLessThanOrEqual(32);
  });

  test("markup in a status is not treated as known and stays a plain string", () => {
    // Escaping is React's job; this asserts the value is never promoted to a known status, which
    // is what would give attacker-controlled text a trusted tone.
    const presentation = presentToolCallStatus("<script>alert(1)</script>");
    expect(presentation.isKnown).toBe(false);
    expect(typeof presentation.label).toBe("string");
  });

  test("isKnownToolCallStatus rejects near-misses", () => {
    for (const status of ["Succeeded", "SUCCEEDED", "success", "ok", "fail", ""]) {
      expect(isKnownToolCallStatus(status), status).toBe(false);
    }
  });
});

describe("shortId", () => {
  test("shortens a UUID to its first segment", () => {
    expect(shortId("11111111-2222-3333-4444-555555555555")).toBe("11111111");
  });

  test.each([
    ["null", null],
    ["undefined", undefined],
    ["number", 42],
    ["object", {}],
    ["empty string", ""],
  ])("%s becomes an em dash rather than throwing", (_label, value) => {
    expect(shortId(value)).toBe("—");
  });
});

describe("formatDuration", () => {
  test.each([
    [0, "0 ms"],
    [1, "1 ms"],
    [999, "999 ms"],
    [1000, "1.00 s"],
    [12_345, "12.3 s"],
  ])("%d ms renders as %s", (input, expected) => {
    expect(formatDuration(input)).toBe(expected);
  });

  test.each([
    ["negative", -5],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["string", "500"],
    ["null", null],
  ])("%s becomes an em dash", (_label, value) => {
    expect(formatDuration(value)).toBe("—");
  });
});

describe("formatTimestamp", () => {
  test("renders in UTC regardless of the host timezone", () => {
    // Fixed UTC on purpose: an audit trail is correlated against backend logs, and a timestamp
    // that shifts with the rendering machine's timezone is an incident-response hazard.
    const rendered = formatTimestamp("2026-08-24T09:05:07Z");

    expect(rendered).toContain("UTC");
    expect(rendered).toContain("2026");
    expect(rendered).toContain("09:05:07");
  });

  test.each([
    ["not a date", "yesterday"],
    ["empty", ""],
    ["null", null],
    ["number", 1_700_000_000],
  ])("%s becomes an em dash, never 'Invalid Date'", (_label, value) => {
    expect(formatTimestamp(value)).toBe("—");
  });
});

describe("describeCaller", () => {
  test("shows the kind and interface", () => {
    expect(describeCaller({ kind: "member", interface: "rest" })).toBe("member · rest");
  });

  test("never leaks a token identifier", () => {
    // Which API token was used is credential-adjacent and does not belong in a list view.
    const described = describeCaller({
      kind: "api_token",
      interface: "mcp",
      api_token_id: "tok_secret_value",
      member_id: "mem_123",
    });

    expect(described).not.toContain("tok_secret_value");
    expect(described).not.toContain("mem_123");
    expect(described).toBe("api_token · mcp");
  });

  test("ignores unknown keys rather than dumping them", () => {
    // The object comes from the runtime; rendering arbitrary keys would make this an uncontrolled
    // data surface.
    expect(describeCaller({ kind: "member", injected: "<script>alert(1)</script>" })).toBe("member");
  });

  test.each([
    ["null", null],
    ["undefined", undefined],
    ["string", "member"],
    ["array", []],
    ["empty object", {}],
    ["non-string fields", { kind: 1, interface: false }],
  ])("%s becomes an em dash rather than throwing", (_label, value) => {
    expect(describeCaller(value)).toBe("—");
  });

  test("caps a pathological field length", () => {
    expect(describeCaller({ kind: "k".repeat(500) }).length).toBeLessThanOrEqual(24);
  });
});
