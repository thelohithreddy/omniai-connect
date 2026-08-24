import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { describe, expect, test } from "vitest";

import type { ToolCallLogRead } from "@omniai/types";

import { StatusBadge } from "./status-badge";
import { ToolCallTable } from "./tool-call-table";

/**
 * Audit viewer UI (MC1.4; Phase 10 UI security, Phase 11 accessibility).
 *
 * Audit records describe calls to third-party providers, so every field is untrusted input
 * (AI_RUNTIME §7). These tests feed hostile values through the real components and assert that
 * nothing becomes markup, a URL, or a trusted status.
 */

async function violations(container: HTMLElement): Promise<string[]> {
  const results = await axe.run(container, {
    // jsdom applies no stylesheet, so contrast cannot be computed here; the design tokens are
    // asserted directly in `design-tokens.test.ts` rather than reported as a vacuous pass.
    rules: { "color-contrast": { enabled: false } },
  });
  return results.violations.map((violation) => violation.id);
}

function record(overrides: Partial<ToolCallLogRead> = {}): ToolCallLogRead {
  return {
    id: "aaaaaaaa-1111-2222-3333-444444444444",
    connection_id: "bbbbbbbb-1111-2222-3333-444444444444",
    tool_id: "cccccccc-1111-2222-3333-444444444444",
    request_id: "req_01JABCDEF",
    caller: { kind: "member", interface: "rest" },
    status: "succeeded",
    error_code: null,
    input_summary: {},
    output_summary: null,
    duration_ms: 142,
    created_at: "2026-08-24T09:05:07Z",
    ...overrides,
  } as ToolCallLogRead;
}

describe("StatusBadge", () => {
  test("meaning is carried by text, not colour alone", () => {
    // WCAG 1.4.1. A badge that communicates only through colour is the classic violation, and it
    // is invisible to both a screen reader and a colour-blind user.
    render(<StatusBadge status="failed" />);
    expect(screen.getByText("Failed")).toBeInTheDocument();
  });

  test("an unrecognised status says so instead of borrowing a known meaning", () => {
    render(<StatusBadge status="pending" />);

    expect(screen.getByText("pending")).toBeInTheDocument();
    expect(screen.getByText(/unrecognised status/i)).toBeInTheDocument();
  });

  test("markup in a status is rendered as text, never as markup", () => {
    const hostile = '<img src=x onerror="alert(1)">';
    const { container } = render(<StatusBadge status={hostile} />);

    // Present as a string, absent as an element — the distinction that matters.
    expect(container.textContent).toContain("<img");
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
  });

  test("a status value cannot inject a class name", () => {
    const { container } = render(<StatusBadge status='" onmouseover="alert(1)' />);
    const badge = container.firstElementChild!;

    expect(badge.getAttribute("onmouseover")).toBeNull();
    expect(badge.className).not.toContain("alert(1)");
  });

  test.each(["succeeded", "failed", "denied", "timeout", "pending"])(
    "%s has no accessibility violations",
    async (status) => {
      const { container } = render(<StatusBadge status={status} />);
      expect(await violations(container)).toEqual([]);
    },
  );
});

describe("ToolCallTable", () => {
  test("renders a semantic, navigable table with scoped headers", () => {
    render(<ToolCallTable records={[record()]} />);

    const table = screen.getByRole("table");
    // Without `scope`, a multi-column table is an unlabelled grid of strings to a screen reader.
    for (const header of ["When", "Status", "Tool", "Connection", "Caller", "Duration", "Reference"]) {
      expect(within(table).getByRole("columnheader", { name: header })).toHaveAttribute("scope", "col");
    }
    // A caption names the table for anyone navigating by region.
    expect(within(table).getByText(/Tool Call audit log/i)).toBeInTheDocument();
  });

  test("shows the machine-readable instant alongside the rendered one", () => {
    render(<ToolCallTable records={[record()]} />);

    const time = screen.getByText(/2026/).closest("time")!;
    expect(time).toHaveAttribute("dateTime", "2026-08-24T09:05:07Z");
  });

  test("never renders the summary objects", () => {
    // `input_summary`/`output_summary` are open, provider-shaped metadata. Dumping arbitrary JSON
    // into the page is how an audit viewer becomes an exfiltration surface.
    const { container } = render(
      <ToolCallTable
        records={[
          record({
            input_summary: { secret_field: "SUMMARY-CANARY-input" },
            output_summary: { body: "SUMMARY-CANARY-output" },
          }),
        ]}
      />,
    );

    expect(container.textContent).not.toContain("SUMMARY-CANARY-input");
    expect(container.textContent).not.toContain("SUMMARY-CANARY-output");
  });

  test("hostile record fields cannot become markup or a link", () => {
    const { container } = render(
      <ToolCallTable
        records={[
          record({
            status: '<script>alert(1)</script>',
            error_code: 'javascript:alert(1)',
            request_id: '"><img src=x onerror=alert(1)>',
            caller: { kind: '<b>member</b>', interface: 'rest' },
          }),
        ]}
      />,
    );

    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    // No anchor is constructed from record data at all, so a javascript: URL has nowhere to land.
    expect(container.querySelectorAll("a")).toHaveLength(0);
  });

  test("a malformed record renders rather than crashing the page", () => {
    // One odd row must not blank the entire audit log — the failure mode where an operator
    // wrongly concludes nothing happened.
    const malformed = {
      id: "row-1",
      created_at: "not-a-date",
      duration_ms: "fast",
      caller: null,
      status: "",
      error_code: undefined,
      tool_id: null,
      connection_id: 12345,
      request_id: "",
    } as unknown as ToolCallLogRead;

    render(<ToolCallTable records={[malformed]} />);

    expect(screen.getByRole("table")).toBeInTheDocument();
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
  });

  test("is keyboard reachable and traps nothing", async () => {
    const user = userEvent.setup();
    render(
      <>
        <button type="button">before</button>
        <ToolCallTable records={[record(), record({ id: "second" })]} />
        <button type="button">after</button>
      </>,
    );

    // The table holds no interactive elements, so focus must pass straight through it.
    await user.tab();
    expect(screen.getByRole("button", { name: "before" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("button", { name: "after" })).toHaveFocus();
  });

  test("has no accessibility violations, with one row or many", async () => {
    const one = render(<ToolCallTable records={[record()]} />);
    expect(await violations(one.container)).toEqual([]);
    one.unmount();

    const many = render(
      <ToolCallTable
        records={["succeeded", "failed", "denied", "timeout", "pending"].map((status, index) =>
          record({ id: `row-${index}`, status, error_code: status === "failed" ? "provider_error" : null }),
        )}
      />,
    );
    expect(await violations(many.container)).toEqual([]);
  });

  test("an empty record list still renders a valid table", async () => {
    const { container } = render(<ToolCallTable records={[]} />);

    expect(screen.getByRole("table")).toBeInTheDocument();
    expect(await violations(container)).toEqual([]);
  });
});
