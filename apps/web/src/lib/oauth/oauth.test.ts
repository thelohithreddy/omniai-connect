import { describe, expect, test } from "vitest";

import type { ConnectionRead } from "@omniai/types";

import { checkAuthorizeUrl } from "./authorize-url";
import { presentConnection } from "./connection-state";

/**
 * OAuth URL validation and connection-state derivation (MC1.5, ADR-0038).
 *
 * Two pure invariants, both about refusing to guess:
 *
 *  - the only externally-sourced value that becomes a browser navigation is scheme-checked;
 *  - a Connection is never presented as working unless the API says it is.
 */

function connection(overrides: Partial<ConnectionRead> = {}): ConnectionRead {
  return {
    id: "11111111-1111-1111-1111-111111111111",
    connector_id: "22222222-2222-2222-2222-222222222222",
    name: "Acme",
    status: "active",
    config_overrides: {},
    credential_id: "33333333-3333-3333-3333-333333333333",
    last_health_check_at: null,
    health: "healthy",
    needs_reauth: false,
    created_at: "2026-08-24T09:00:00Z",
    ...overrides,
  } as ConnectionRead;
}

describe("authorization URL allowlist", () => {
  test("accepts a real provider URL and returns the normalised href", () => {
    const result = checkAuthorizeUrl(
      "https://provider.example/oauth/authorize?client_id=abc&code_challenge_method=S256",
    );

    expect(result.ok).toBe(true);
    expect(result.ok && result.url).toContain("https://provider.example/oauth/authorize");
  });

  test.each([
    ["javascript", "javascript:alert(1)"],
    ["uppercase javascript", "JavaScript:alert(1)"],
    ["data", "data:text/html,<script>alert(1)</script>"],
    ["vbscript", "vbscript:msgbox(1)"],
    ["file", "file:///etc/passwd"],
    ["plain http", "http://provider.example/oauth/authorize"],
  ])("refuses a %s URL", (_label, candidate) => {
    // This is the one place a value from outside the frontend becomes a navigation. A
    // `javascript:` URL here would be stored XSS delivered by our own redirect.
    const result = checkAuthorizeUrl(candidate);
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toBe("insecure-scheme");
  });

  test.each([
    ["relative", "/oauth/authorize"],
    ["protocol-relative", "//provider.example/authorize"],
    ["scheme-less host", "provider.example/authorize"],
    ["empty", ""],
    ["whitespace", "   "],
  ])("refuses a %s value as malformed", (_label, candidate) => {
    expect(checkAuthorizeUrl(candidate).ok).toBe(false);
  });

  test.each([
    ["null", null],
    ["undefined", undefined],
    ["number", 42],
    ["object", { href: "https://provider.example" }],
  ])("refuses a %s rather than throwing", (_label, candidate) => {
    expect(checkAuthorizeUrl(candidate).ok).toBe(false);
  });

  test.each([
    ["https-lookalike scheme", "httpsevil://provider.example/authorize"],
    ["hyphenated lookalike", "https-evil://provider.example/authorize"],
    ["https prefix on another scheme", "httpsx://provider.example"],
  ])("refuses a %s", (_label, candidate) => {
    // These all begin with the literal "https", so a `startsWith("https")` check would wave them
    // through while `new URL().protocol` correctly reports `httpsevil:` / `https-evil:`. A
    // mutation replacing the parsed-protocol comparison with a prefix test survived until this
    // case existed — the parsed form is the control, not the string shape.
    const result = checkAuthorizeUrl(candidate);
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toBe("insecure-scheme");
  });

  test("http is refused even for localhost", () => {
    // RFC 6749 §3.1 requires TLS on the authorization endpoint; permitting http would buy nothing
    // except a downgrade path for the one navigation carrying `state`.
    expect(checkAuthorizeUrl("http://localhost:9000/authorize").ok).toBe(false);
  });
});

describe("connection state is the API's answer, not a recomputation", () => {
  test("needs_reauth wins over everything else", () => {
    // ADR-0038 D5 makes this derived by the backend. Nothing below may mask it — a connection the
    // API says is broken must never read as working.
    const presentation = presentConnection(
      connection({ needs_reauth: true, status: "active", credential_id: "cred" }),
    );

    expect(presentation.state).toBe("needs-reauth");
    expect(presentation.canAuthorize).toBe(true);
  });

  test("an active connection with a credential is connected", () => {
    expect(presentConnection(connection()).state).toBe("connected");
  });

  test("an active connection with no credential has never been authorized", () => {
    const presentation = presentConnection(connection({ credential_id: null }));

    expect(presentation.state).toBe("not-connected");
    expect(presentation.canAuthorize).toBe(true);
  });

  test.each(["revoked", "error", "disabled"])("a %s connection is inactive and offers no action", (status) => {
    const presentation = presentConnection(connection({ status }));

    expect(presentation.state).toBe("inactive");
    // Authorizing a revoked Connection fails at the API with 409; offering the button would invite
    // a pointless round trip and a confusing error.
    expect(presentation.canAuthorize).toBe(false);
  });

  test("an unrecognised status is never presented as working", () => {
    // A future status must be additive. Claiming a broken integration is fine is the worst failure
    // this surface has.
    const presentation = presentConnection(connection({ status: "quiescing" }));

    expect(presentation.state).toBe("unknown");
    expect(presentation.label).not.toMatch(/connected/i);
    expect(presentation.canAuthorize).toBe(false);
  });

  test.each([
    ["null status", null],
    ["numeric status", 7],
    ["missing status", undefined],
  ])("%s degrades to unknown rather than throwing", (_label, status) => {
    const presentation = presentConnection(connection({ status } as never));
    expect(presentation.state).toBe("unknown");
  });

  test("every state carries a screen-reader description distinct from colour", () => {
    for (const status of ["active", "revoked", "quiescing"]) {
      for (const needsReauth of [true, false]) {
        const presentation = presentConnection(connection({ status, needs_reauth: needsReauth }));
        expect(presentation.srDescription.length, `${status}/${needsReauth}`).toBeGreaterThan(0);
        expect(presentation.label.length).toBeGreaterThan(0);
      }
    }
  });
});
