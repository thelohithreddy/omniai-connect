import type { ToolCallLogRead } from "@omniai/types";

import { StatusBadge } from "@/components/audit/status-badge";
import { describeCaller, formatDuration, formatTimestamp, shortId } from "@/lib/audit/format";

/**
 * Tool Call audit table (MC1.4, ADR-0044 D5).
 *
 * A server component rendering a semantic `<table>`. No `"use client"`, so it ships no JavaScript
 * and cannot hold workspace data in browser state.
 *
 * **Every field here is untrusted.** These records describe calls to third-party providers, so
 * `status`, `error_code` and the summary objects contain values this application did not author
 * (AI_RUNTIME §7 prompt-injection hygiene, FRONTEND_SPEC §8). They are rendered as text only:
 * nothing is passed to `dangerouslySetInnerHTML`, nothing becomes an `href` or `src`, and no value
 * is interpolated into a class name. React escapes the rest.
 *
 * `input_summary` and `output_summary` are deliberately **not** rendered. They are redacted
 * metadata objects rather than a fixed shape, and dumping arbitrary provider-shaped JSON into the
 * page is how an audit viewer becomes an exfiltration surface. Per-record detail is a later
 * slice; the API already exposes `GET /v1/tool-calls/{id}` for it.
 *
 * `scope` on every header is what makes the table navigable by screen reader — without it a
 * multi-column table is an unlabelled grid of strings.
 */
export function ToolCallTable({ records }: { readonly records: readonly ToolCallLogRead[] }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full border-collapse text-left text-sm">
        <caption className="sr-only">
          Tool Call audit log for this workspace, newest first.
        </caption>
        <thead>
          <tr className="border-b border-border bg-muted/50">
            <th scope="col" className="px-3 py-2 font-medium">
              When
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Status
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Tool
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Connection
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Caller
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Duration
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Reference
            </th>
          </tr>
        </thead>
        <tbody>
          {records.map((record) => (
            <tr key={record.id} className="border-b border-border last:border-0">
              <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                {/*
                  `<time>` carries the machine-readable instant while the cell shows a rendered
                  one, so the exact value survives copy-paste and assistive technology.
                */}
                <time dateTime={record.created_at}>{formatTimestamp(record.created_at)}</time>
              </td>
              <td className="px-3 py-2">
                <StatusBadge status={record.status} />
                {/*
                  The stable error code, not a provider message. API_GUIDELINES §6.1 codes are
                  ours and safe to show; a provider's error text is not, and is never in this
                  payload to begin with.
                */}
                {record.error_code ? (
                  <span className="ml-2 font-mono text-xs text-muted-foreground">
                    {record.error_code}
                  </span>
                ) : null}
              </td>
              <td className="px-3 py-2 font-mono text-xs">{shortId(record.tool_id)}</td>
              <td className="px-3 py-2 font-mono text-xs">{shortId(record.connection_id)}</td>
              <td className="px-3 py-2">{describeCaller(record.caller)}</td>
              <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                {formatDuration(record.duration_ms)}
              </td>
              <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                {record.request_id}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
