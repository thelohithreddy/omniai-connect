/**
 * Contract tests for the human authentication surface (M1.3-D).
 *
 * Better Auth's handler is a plain fetch handler, so the whole surface is exercised
 * in-process: no dev server, no browser, no port. Real Postgres though — sessions,
 * password hashes and signing keys are rows, and a suite that mocked the database would
 * assert nothing about the thing being protected.
 *
 * These are contract tests, not tests of the library's internals. Everything asserted here
 * is a property this application depends on and would be harmed by losing: that passwords
 * never appear in a response, that the session cookie stays HttpOnly, that sign-out really
 * deletes the row, that JWKS publishes public material only. A Better Auth upgrade or a
 * config change that quietly flipped any of them would break these.
 *
 *   pnpm --filter web test
 */
import assert from "node:assert/strict";
import { createPublicKey, randomUUID, verify as verifySignature } from "node:crypto";
import { after, before, describe, test } from "node:test";

import { getAuth } from "../src/lib/auth.ts";

const ORIGIN = "http://localhost:3000";
const BASE = `${ORIGIN}/api/auth`;

/**
 * Generated per run rather than written down. A password literal in the repository is
 * indistinguishable from a leaked credential to a secret scanner — gitleaks flagged the
 * previous fixed string — and a password that differs every run is a stronger fixture
 * anyway: the leakage assertions below search output for *this* run's value, so they
 * cannot accidentally pass by matching nothing.
 */
const PASSWORD = `pw-${randomUUID()}`;

const auth = getAuth();

type Json = Record<string, unknown>;

function uniqueEmail(label: string): string {
  return `m13d-${label}-${Math.random().toString(36).slice(2, 10)}@example.test`;
}

async function call(
  path: string,
  init: { method?: string; body?: Json; cookie?: string; origin?: string | null } = {},
): Promise<{ status: number; text: string; json: Json | null; setCookie: string[]; res: Response }> {
  const headers = new Headers({ "content-type": "application/json" });
  // Better Auth rejects state-changing requests without a trusted Origin. Sent by default
  // so that tests exercising other behaviour are not silently answered with a 403.
  if (init.origin !== null) headers.set("origin", init.origin ?? ORIGIN);
  if (init.cookie) headers.set("cookie", init.cookie);

  const res = await auth.handler(
    new Request(`${BASE}${path}`, {
      method: init.method ?? "GET",
      headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    }),
  );
  const text = await res.text();
  let json: Json | null = null;
  try {
    json = JSON.parse(text) as Json;
  } catch {
    json = null;
  }
  return { status: res.status, text, json, setCookie: res.headers.getSetCookie(), res };
}

/** The `name=value` pair only, which is what a browser would send back. */
function cookiePair(setCookie: string[], name = "better-auth.session_token"): string {
  const header = setCookie.find((c) => c.startsWith(`${name}=`));
  assert.ok(header, `no ${name} cookie was set`);
  return header.split(";")[0];
}

async function signUp(label: string): Promise<{ email: string; cookie: string; userId: string }> {
  const email = uniqueEmail(label);
  const { status, json, setCookie } = await call("/sign-up/email", {
    method: "POST",
    body: { email, password: PASSWORD, name: "Contract Test" },
  });
  assert.equal(status, 200, "sign-up should succeed");
  const user = (json?.user ?? {}) as Json;
  return { email, cookie: cookiePair(setCookie), userId: String(user.id) };
}

/** Every identity row this file creates, removed in `after` so runs stay repeatable. */
const createdEmails: string[] = [];

before(() => {
  // A misconfigured DSN would otherwise surface as dozens of confusing assertion failures.
  assert.ok(process.env.BETTER_AUTH_DATABASE_URL, "BETTER_AUTH_DATABASE_URL must be set");
});

after(async () => {
  if (createdEmails.length === 0) return;
  const ctx = await auth.$context;
  for (const email of createdEmails) {
    const user = await ctx.internalAdapter.findUserByEmail(email);
    if (user?.user?.id) await ctx.internalAdapter.deleteUser(user.user.id);
  }
});

describe("route wiring", () => {
  test("the catch-all route serves Better Auth over GET and POST", async () => {
    /**
     * The rest of this file drives `auth.handler` directly, which is fast and precise but
     * would keep passing if the Next route were deleted, renamed, or wired to the wrong
     * instance — leaving the application with no authentication endpoints at all and a
     * fully green suite. This is the test that actually asserts the app exposes them.
     */
    const route = await import("../src/app/api/auth/[...all]/route.ts");

    assert.equal(typeof route.GET, "function", "the route must export a GET handler");
    assert.equal(typeof route.POST, "function", "the route must export a POST handler");

    const jwks = await route.GET(new Request(`${BASE}/jwks`));
    assert.equal(jwks.status, 200, "GET /api/auth/jwks must be served by the route");
    const keys = ((await jwks.json()) as Json).keys as Json[];
    assert.ok(Array.isArray(keys) && keys.length > 0, "the route must serve real JWKS");

    const signUp = await route.POST(
      new Request(`${BASE}/sign-up/email`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: ORIGIN },
        body: JSON.stringify({
          email: uniqueEmail("route"),
          password: PASSWORD,
          name: "Route",
        }),
      }),
    );
    assert.equal(signUp.status, 200, "POST must reach Better Auth through the route");
    createdEmails.push(((await signUp.json()) as Json & { user: Json }).user.email as string);
  });
});

describe("sign-up and sign-in", () => {
  test("a new account can be created and signed into", async () => {
    const { email } = await signUp("happy");
    createdEmails.push(email);

    const { status, setCookie } = await call("/sign-in/email", {
      method: "POST",
      body: { email, password: PASSWORD },
    });
    assert.equal(status, 200);
    assert.ok(cookiePair(setCookie), "sign-in must issue a session cookie");
  });

  test("the wrong password is rejected", async () => {
    const { email } = await signUp("wrongpw");
    createdEmails.push(email);

    const { status } = await call("/sign-in/email", {
      method: "POST",
      body: { email, password: "not-the-right-password" },
    });
    assert.equal(status, 401, "a wrong password must not authenticate");
  });

  test("an account that does not exist is rejected", async () => {
    const { status } = await call("/sign-in/email", {
      method: "POST",
      body: { email: uniqueEmail("ghost"), password: PASSWORD },
    });
    assert.equal(status, 401);
  });

  test("a wrong password and an unknown account are indistinguishable", async () => {
    // Otherwise the endpoint is a membership oracle: an attacker learns which addresses
    // hold accounts without ever guessing a password.
    const { email } = await signUp("enumeration");
    createdEmails.push(email);

    const wrongPassword = await call("/sign-in/email", {
      method: "POST",
      body: { email, password: "not-the-right-password" },
    });
    const noSuchUser = await call("/sign-in/email", {
      method: "POST",
      body: { email: uniqueEmail("absent"), password: PASSWORD },
    });

    assert.equal(wrongPassword.status, noSuchUser.status);
    assert.equal(wrongPassword.json?.message, noSuchUser.json?.message);
  });
});

describe("secret handling", () => {
  test("no response in the sign-up or session flow contains a password", async () => {
    const { email, cookie } = await signUp("nopassword");
    createdEmails.push(email);

    const session = await call("/get-session", { cookie });
    assert.equal(session.status, 200);

    for (const [label, body] of [
      ["sign-up", (await call("/sign-in/email", { method: "POST", body: { email, password: PASSWORD } })).text],
      ["get-session", session.text],
    ] as const) {
      assert.ok(!body.includes(PASSWORD), `${label} echoed the plaintext password`);
      assert.match(body, /\S/, `${label} returned an empty body — the check would be vacuous`);
      assert.ok(!/"password"\s*:/.test(body), `${label} exposed a password field`);
    }
  });

  test("neither the signing secret nor the database DSN appears in a response body", async () => {
    const secret = process.env.BETTER_AUTH_SECRET;
    const dsn = process.env.BETTER_AUTH_DATABASE_URL;
    assert.ok(secret && secret.length > 0, "BETTER_AUTH_SECRET must be set for this test");
    assert.ok(dsn && dsn.length > 0, "BETTER_AUTH_DATABASE_URL must be set for this test");
    // The DSN embeds the identity role's password, so leaking it hands over the schema.
    const dbPassword = new URL(dsn).password;

    const { email, cookie } = await signUp("nosecret");
    createdEmails.push(email);

    for (const path of ["/get-session", "/token", "/jwks"] as const) {
      const { text } = await call(path, { cookie });
      assert.match(text, /\S/, `${path} returned an empty body — the check would be vacuous`);
      assert.ok(!text.includes(secret), `${path} leaked BETTER_AUTH_SECRET`);
      assert.ok(!text.includes(dsn), `${path} leaked BETTER_AUTH_DATABASE_URL`);
      if (dbPassword) {
        assert.ok(!text.includes(dbPassword), `${path} leaked the database password`);
      }
    }
  });

  test("telemetry is disabled, so the control plane makes no outbound call", async () => {
    // SYSTEM_ARCHITECTURE.md makes the Execution Runtime the only egress. Better Auth's
    // telemetry would send configuration off-box, so the setting is pinned rather than
    // inherited — and pinned settings deserve a test, or they drift back on an upgrade.
    assert.equal(auth.options.telemetry?.enabled, false);
    assert.equal(process.env.BETTER_AUTH_TELEMETRY_ENDPOINT, undefined);
  });

  test("no credential is written to stdout or stderr during a full auth flow", async () => {
    /**
     * Logs travel: to a shipper, a third-party aggregator, a support ticket screenshot. A
     * password or session cookie written to stdout is a credential in all of those places,
     * and no response-body assertion would ever notice.
     *
     * Captured by replacing the stream writers rather than by reading a logger's buffer,
     * so anything reaching the process output is seen — Better Auth's own logger, an
     * accidental `console.log`, or a library printing a query.
     */
    const chunks: string[] = [];
    const streams = [process.stdout, process.stderr] as const;
    const originals = streams.map((s) => s.write.bind(s));

    let email: string;
    let cookie: string;
    try {
      // Copies rather than intercepts. The test runner's own reporter writes to these same
      // streams, so swallowing them loses reporter events — an earlier version of this test
      // silently ate another test's completion line and the suite reported 18 of 19 tests
      // as if nothing were wrong. A probe that can hide tests is worse than no probe.
      streams.forEach((stream, i) => {
        stream.write = ((chunk: string | Uint8Array, ...rest: unknown[]): boolean => {
          chunks.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString());
          return (originals[i] as (...args: unknown[]) => boolean)(chunk, ...rest);
        }) as typeof stream.write;
      });

      ({ email, cookie } = await signUp("nolog"));
      await call("/sign-in/email", { method: "POST", body: { email, password: PASSWORD } });
      await call("/sign-in/email", { method: "POST", body: { email, password: "wrong-one" } });
      await call("/get-session", { cookie });
      await call("/token", { cookie });
      await call("/sign-out", { method: "POST", body: {}, cookie });
    } finally {
      streams.forEach((stream, i) => {
        stream.write = originals[i];
      });
    }
    createdEmails.push(email);

    const output = chunks.join("");
    const encoded = cookie.split("=").slice(1).join("=");
    const decoded = decodeURIComponent(encoded);
    // The unsigned half is base64url and therefore identical whether the cookie was
    // percent-encoded or not. Checking only the decoded form let a real leak through
    // undetected: the logged header was percent-encoded, so `includes` never matched.
    const opaqueToken = decoded.split(".")[0];
    const secret = String(process.env.BETTER_AUTH_SECRET);

    for (const [label, needle] of [
      ["the plaintext password", PASSWORD],
      ["a rejected password attempt", "wrong-one"],
      ["the session cookie (as sent)", encoded],
      ["the session cookie (decoded)", decoded],
      ["the session identifier", opaqueToken],
      ["BETTER_AUTH_SECRET", secret],
    ] as const) {
      assert.ok(needle.length > 0, `${label}: empty needle would make this vacuous`);
      assert.ok(!output.includes(needle), `${label} was written to the process output`);
    }
  });
});

describe("session cookie", () => {
  test("is HttpOnly, SameSite=Lax and scoped to the whole site", async () => {
    const email = uniqueEmail("cookieattrs");
    createdEmails.push(email);
    const { setCookie } = await call("/sign-up/email", {
      method: "POST",
      body: { email, password: PASSWORD, name: "Cookie" },
    });
    const header = setCookie.find((c) => c.startsWith("better-auth.session_token="));
    assert.ok(header, "no session cookie was issued");

    // HttpOnly is what keeps a successful XSS from reading the session outright.
    assert.match(header, /HttpOnly/i);
    // Lax still sends the cookie on top-level navigation while blocking cross-site POSTs.
    assert.match(header, /SameSite=Lax/i);
    assert.match(header, /Path=\//i);
  });

  test("carries Secure and the __Secure- prefix when the deployment is https", async () => {
    /**
     * Runs against **this application's** options with only `baseURL` swapped, not against
     * a bare config. That distinction is the test: an `advanced.useSecureCookies: false`
     * added to auth.ts would override the protocol derivation and ship insecure cookies to
     * production, and a test built from a fresh config object would never see it.
     *
     * The dev case is asserted too, because the derivation must keep working downwards —
     * a Secure cookie is never sent over http, so forcing it on would break local login.
     */
    const { getCookies } = await import("better-auth/cookies");
    const options = auth.options;

    const dev = getCookies({ ...options, baseURL: "http://localhost:3000" }).sessionToken;
    assert.equal(dev.attributes.secure, false);
    assert.equal(dev.name, "better-auth.session_token");

    const prod = getCookies({ ...options, baseURL: "https://app.omniai.example" }).sessionToken;
    assert.equal(prod.attributes.secure, true);
    assert.equal(prod.name, "__Secure-better-auth.session_token");
    assert.equal(prod.attributes.httpOnly, true);
    assert.equal(prod.attributes.sameSite, "lax");
  });

  test("an expired session no longer authenticates", async () => {
    // Expiry is enforced when the session is read, not by a sweeper, so the only way to
    // prove it is to age a real row and present the same cookie again.
    const { email, cookie } = await signUp("expired");
    createdEmails.push(email);

    const live = await call("/get-session", { cookie });
    assert.ok((live.json?.session as Json | undefined)?.userId, "session should start valid");

    const ctx = await auth.$context;
    await ctx.adapter.update({
      model: "session",
      where: [{ field: "userId", value: String((live.json?.session as Json).userId) }],
      update: { expiresAt: new Date(Date.now() - 60_000) },
    });

    const expired = await call("/get-session", { cookie });
    assert.equal(expired.json, null, "an expired session must not authenticate");
  });

  test("the session identifier in the response body cannot be replayed", async () => {
    /**
     * `/get-session` does return `session.token`, so client-side JavaScript can read it
     * even though the cookie is HttpOnly. That is only safe because the cookie is
     * `<token>.<HMAC>`: the value in the body is the unsigned half, and Better Auth
     * rejects a cookie whose signature is missing or wrong.
     *
     * So the property worth pinning is not "the token is hidden" — it is not — but "the
     * exposed half is useless on its own". If cookie signing were ever disabled, the body
     * would be handing out working session credentials to any successful XSS, and this is
     * the test that would notice.
     */
    const { email, cookie } = await signUp("notokenleak");
    createdEmails.push(email);

    const { json } = await call("/get-session", { cookie });
    const session = (json?.session ?? {}) as Json;
    assert.ok(session.userId, "session body should describe a session");

    const exposed = String(session.token ?? "");
    assert.ok(exposed.length > 0, "expected a session token in the body — otherwise vacuous");
    assert.ok(
      decodeURIComponent(cookie.split("=").slice(1).join("=")).startsWith(`${exposed}.`),
      "the cookie should be the exposed token plus a signature",
    );

    const replayed = await call("/get-session", {
      cookie: `better-auth.session_token=${exposed}`,
    });
    assert.equal(replayed.json, null, "the unsigned token must not authenticate");

    // Control: the properly signed cookie still resolves, proving the replay above failed
    // because the signature was missing rather than because the request was malformed.
    const control = await call("/get-session", { cookie });
    assert.ok((control.json?.session as Json | undefined)?.userId);
  });
});

describe("sign-out", () => {
  test("deletes the session server-side, not just the cookie", async () => {
    const { email, cookie } = await signUp("signout");
    createdEmails.push(email);

    const before = await call("/get-session", { cookie });
    assert.ok((before.json?.session as Json | undefined)?.userId, "session should exist first");

    const out = await call("/sign-out", { method: "POST", body: {}, cookie });
    assert.equal(out.status, 200);

    // Replaying the *same* cookie: if sign-out only cleared it client-side, a stolen cookie
    // would still authenticate and this would still return a session.
    const after = await call("/get-session", { cookie });
    assert.equal(after.json, null, "the revoked session must no longer resolve");
  });
});

describe("cross-site request forgery", () => {
  test("a state-changing request from another origin is refused", async () => {
    const { email, cookie } = await signUp("csrf");
    createdEmails.push(email);

    const { status } = await call("/sign-out", {
      method: "POST",
      body: {},
      cookie,
      origin: "https://evil.test",
    });
    assert.equal(status, 403, "a foreign origin must not be able to act on a session");

    const still = await call("/get-session", { cookie });
    assert.ok(
      (still.json?.session as Json | undefined)?.userId,
      "the refused request must not have signed the user out",
    );
  });

  test("no response invites a credentialed cross-origin read", async () => {
    /**
     * `Access-Control-Allow-Origin: *` together with credentials is rejected by browsers,
     * but reflecting an arbitrary Origin alongside `Allow-Credentials: true` is not — and
     * that combination lets any site read a signed-in user's session and JWT. Nothing here
     * configures CORS, so the correct result is no CORS headers at all; this asserts that
     * absence rather than trusting it.
     */
    const { email, cookie } = await signUp("cors");
    createdEmails.push(email);

    for (const path of ["/get-session", "/token", "/jwks"] as const) {
      const { res } = await call(path, { cookie, origin: "https://evil.test" });
      const allowOrigin = res.headers.get("access-control-allow-origin");
      const allowCredentials = res.headers.get("access-control-allow-credentials");

      assert.notEqual(allowOrigin, "https://evil.test", `${path} reflected a foreign origin`);
      if (allowCredentials === "true") {
        assert.equal(allowOrigin, null, `${path} allows credentialed cross-origin reads`);
      }
    }
  });
});

describe("JWKS and JWT", () => {
  test("JWKS publishes public material only", async () => {
    const { status, json } = await call("/jwks");
    assert.equal(status, 200);
    const keys = (json?.keys ?? []) as Json[];
    assert.ok(keys.length > 0, "JWKS must publish at least one key");

    for (const key of keys) {
      assert.equal(key.kty, "OKP");
      assert.equal(key.crv, "Ed25519");
      assert.ok(key.kid, "every key needs a kid so a verifier can select one");
      // `d` is the Ed25519 private scalar. Publishing it would let anyone mint tokens.
      for (const priv of ["d", "p", "q", "dp", "dq", "qi"]) {
        assert.equal(key[priv], undefined, `JWKS exposed private parameter '${priv}'`);
      }
    }
  });

  test("the signing private key is encrypted at rest", async () => {
    /**
     * The row in `identity.jwks` holds the Ed25519 private key. Better Auth encrypts it
     * with BETTER_AUTH_SECRET unless told not to, and stored plaintext would mean anyone
     * with read access to one table — a replica, a backup, a leaked dump — could mint
     * tokens for any user indefinitely.
     *
     * Asserted by shape. Encrypted, the column holds opaque ciphertext; unencrypted, it
     * holds a JWK — and a JWK is recognisable by its structural members (`kty`, `crv`, and
     * the private scalar `d`), which is what this looks for. The public half is stored as
     * a plain JWK in the neighbouring column, so those markers genuinely distinguish the
     * two states rather than being absent from both.
     */
    await call("/jwks"); // ensure a key pair exists before reading the table
    const ctx = await auth.$context;
    const keys = (await ctx.adapter.findMany({ model: "jwks" })) as Json[];
    assert.ok(keys.length > 0, "no signing key was stored — the check would be vacuous");

    for (const key of keys) {
      const stored = String(key.privateKey ?? "");
      assert.ok(stored.length > 0, "the stored private key is empty");
      for (const marker of ['"d"', '"kty"', '"crv"', "Ed25519", "OKP"]) {
        assert.ok(
          !stored.includes(marker),
          `the private key is stored unencrypted (found ${marker})`,
        );
      }
      // Control: the same markers are present in the public key, proving their absence
      // above is a property of encryption and not of how this column is serialised.
      assert.match(String(key.publicKey ?? ""), /"kty"/);
    }
  });

  test("an issued JWT verifies against the published JWKS", async () => {
    const { email, cookie } = await signUp("jwt");
    createdEmails.push(email);

    const { status, json } = await call("/token", { cookie });
    assert.equal(status, 200);
    const token = String(json?.token ?? "");
    assert.match(token, /^[\w-]+\.[\w-]+\.[\w-]+$/, "expected a compact JWS");

    const [rawHeader, rawPayload, rawSignature] = token.split(".");
    const decode = (part: string): Json =>
      JSON.parse(Buffer.from(part, "base64url").toString()) as Json;
    const header = decode(rawHeader);
    const payload = decode(rawPayload);

    assert.equal(header.alg, "EdDSA", "the signing algorithm must not drift");
    assert.ok(header.kid, "without a kid a verifier cannot pick the right key");

    const jwks = (await call("/jwks")).json;
    const key = ((jwks?.keys ?? []) as Json[]).find((k) => k.kid === header.kid);
    assert.ok(key, "the token was signed with a key that is not published");

    const publicKey = createPublicKey({ key: key as never, format: "jwk" });
    const signed = Buffer.from(`${rawHeader}.${rawPayload}`);
    assert.ok(
      verifySignature(null, signed, publicKey, Buffer.from(rawSignature, "base64url")),
      "the JWT signature does not verify against the published key",
    );

    // A verifier (M1.3-B) pins these, so they are part of the contract.
    assert.equal(payload.iss, ORIGIN);
    assert.equal(payload.aud, ORIGIN);
    assert.ok(payload.sub, "sub identifies the human and must be present");
    assert.ok(Number(payload.exp) > Number(payload.iat), "the token must expire");
    assert.ok(!token.includes(PASSWORD));
  });

  test("a tampered JWT does not verify", async () => {
    // Guards the assertion above: proves it is checking the signature rather than merely
    // parsing a well-formed token.
    const { email, cookie } = await signUp("tamper");
    createdEmails.push(email);

    const token = String((await call("/token", { cookie })).json?.token ?? "");
    const [rawHeader, rawPayload, rawSignature] = token.split(".");
    const payload = JSON.parse(Buffer.from(rawPayload, "base64url").toString()) as Json;
    payload.sub = "attacker-controlled";
    const forged = Buffer.from(JSON.stringify(payload)).toString("base64url");

    const header = JSON.parse(Buffer.from(rawHeader, "base64url").toString()) as Json;
    const jwks = (await call("/jwks")).json;
    const key = ((jwks?.keys ?? []) as Json[]).find((k) => k.kid === header.kid);
    const publicKey = createPublicKey({ key: key as never, format: "jwk" });

    assert.equal(
      verifySignature(
        null,
        Buffer.from(`${rawHeader}.${forged}`),
        publicKey,
        Buffer.from(rawSignature, "base64url"),
      ),
      false,
      "a rewritten subject must invalidate the signature",
    );
  });

  test("a JWT is only issued to an authenticated caller", async () => {
    const { status } = await call("/token");
    assert.notEqual(status, 200, "an anonymous caller must not receive a signed token");
  });
});
