/*
 * Copyright 2026 2351485 ALBERTA INC.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Self-test for the doors pattern. No network, no dependencies:
 *   node test/self-test.mjs
 * Exits non-zero on the first failing suite count > 0.
 */

import assert from "node:assert/strict";
import { configuredProviders } from "../src/providers.js";
import { handleCallback, handleStart } from "../src/oauth-door.js";
import { consumeMagicLink, requestMagicLink } from "../src/magic-link.js";
import { endSession, resolveSession, resolveSignIn } from "../src/accounts.js";
import { MemoryStore } from "../src/store.js";
import { s256Challenge } from "../src/util.js";
import worker from "../src/index.js";

let passed = 0;
const failures = [];
async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`PASS ${name}`);
  } catch (err) {
    failures.push(name);
    console.log(`FAIL ${name}\n  ${err.message}`);
  }
}

const ENV = {
  GITHUB_OAUTH_CLIENT_ID: "gh-client-id",
  GITHUB_OAUTH_CLIENT_SECRET: "gh-secret",
  GOOGLE_OAUTH_CLIENT_ID: "gg-client-id",
  GOOGLE_OAUTH_CLIENT_SECRET: "gg-secret",
  MAILER_API_URL: "https://mailer.example/send",
  MAILER_API_KEY: "mailer-key",
  MAILER_FROM: "signin@example.com",
};

// --- 1. PKCE S256 against the RFC 7636 test vector -------------------------
await test("pkce: RFC 7636 vector", async () => {
  const challenge = await s256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
  assert.equal(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
});

// --- 2. Doors light only when BOTH bindings exist ---------------------------
await test("providers: dark until both bindings land, then lit", async () => {
  assert.deepEqual(configuredProviders({}).map((p) => p.def.id), []);
  assert.deepEqual(
    configuredProviders({ GITHUB_OAUTH_CLIENT_ID: "x" }).map((p) => p.def.id),
    [],
    "ID alone must stay dark",
  );
  assert.deepEqual(
    configuredProviders({ GITHUB_OAUTH_CLIENT_ID: "x", GITHUB_OAUTH_CLIENT_SECRET: "y" }).map(
      (p) => p.def.id,
    ),
    ["github"],
  );
  assert.deepEqual(configuredProviders(ENV).map((p) => p.def.id), ["github", "google"]);
});

// --- Fake provider backends --------------------------------------------------
function fakeFetch(kind) {
  return async (url) => {
    const u = String(url);
    if (u.includes("github.com/login/oauth/access_token") || u.includes("oauth2.googleapis.com/token")) {
      return { ok: true, status: 200, json: async () => ({ access_token: "fake-access-token" }) };
    }
    if (u.includes("api.github.com/user/emails")) {
      return {
        ok: true,
        status: 200,
        json: async () => [{ email: "person@example.com", primary: true, verified: true }],
      };
    }
    if (u.includes("api.github.com/user")) {
      return {
        ok: true,
        status: 200,
        json: async () => ({ id: 4242, login: "octo", name: "Octo", email: null }),
      };
    }
    if (u.includes("openidconnect.googleapis.com")) {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          sub: "g-123",
          email: "person@example.com",
          email_verified: true,
          name: "Person",
        }),
      };
    }
    throw new Error(`unexpected fetch: ${u} (${kind})`);
  };
}

/** Run start → extract (state, verifier) from the state cookie → callback. */
async function oauthRoundTrip(store, provider, fetchImpl) {
  const startRes = await handleStart(
    new Request(`https://auth.example.com/v1/auth/${provider}/start`),
    ENV,
  );
  assert.equal(startRes.status, 302);
  const location = startRes.headers.get("location");
  const state = new URL(location).searchParams.get("state");
  const cookie = startRes.headers.get("set-cookie");
  const stateCookie = cookie.split(";")[0]; // auth_state=<state>.<verifier>
  const callbackRes = await handleCallback(
    new Request(
      `https://auth.example.com/v1/auth/${provider}/callback?code=abc&state=${state}`,
      { headers: { cookie: stateCookie } },
    ),
    ENV,
    store,
    { fetchImpl },
  );
  return { startRes, location, callbackRes };
}

function sessionTokenFrom(res) {
  const cookie = res.headers.get("set-cookie") || "";
  const m = cookie.match(/session=([^;]+)/);
  return m ? m[1] : null;
}

// --- 3–6. OAuth doors + the identity-resolution law --------------------------
const store = new MemoryStore();
let githubAccountId = null;

await test("oauth: github round trip creates account + hardened session cookie", async () => {
  const { location, callbackRes } = await oauthRoundTrip(store, "github", fakeFetch());
  assert.ok(location.startsWith("https://github.com/login/oauth/authorize"));
  assert.ok(new URL(location).searchParams.get("code_challenge"));
  assert.equal(callbackRes.status, 302);
  assert.equal(callbackRes.headers.get("x-auth-resolution"), "created");
  const cookie = callbackRes.headers.get("set-cookie");
  assert.ok(cookie.includes("HttpOnly") && cookie.includes("Secure") && cookie.includes("SameSite=Lax"));
  const token = sessionTokenFrom(callbackRes);
  const account = await resolveSession(store, token);
  assert.ok(account && account.email === "person@example.com");
  githubAccountId = account.id;
});

await test("oauth: returning github sign-in lands on the same account", async () => {
  const { callbackRes } = await oauthRoundTrip(store, "github", fakeFetch());
  assert.equal(callbackRes.headers.get("x-auth-resolution"), "returning");
  const account = await resolveSession(store, sessionTokenFrom(callbackRes));
  assert.equal(account.id, githubAccountId);
});

await test("identity law: google door, same verified email -> SAME account (attach)", async () => {
  const { callbackRes } = await oauthRoundTrip(store, "google", fakeFetch());
  assert.equal(callbackRes.headers.get("x-auth-resolution"), "attached");
  const account = await resolveSession(store, sessionTokenFrom(callbackRes));
  assert.equal(account.id, githubAccountId, "cross-door sign-in must not mint a second account");
  assert.equal(await store.countIdentities(githubAccountId), 2);
});

await test("identity law: an UNVERIFIED email never merges accounts", async () => {
  const { account, created } = await resolveSignIn(store, {
    provider: "github",
    subject: "someone-else",
    email: "person@example.com",
    emailVerified: false,
    name: null,
  });
  assert.equal(created, true);
  assert.notEqual(account.id, githubAccountId);
});

await test("oauth: state mismatch is refused, no session issued", async () => {
  const res = await handleCallback(
    new Request("https://auth.example.com/v1/auth/github/callback?code=abc&state=wrong", {
      headers: { cookie: "auth_state=right.verifier" },
    }),
    ENV,
    store,
    { fetchImpl: fakeFetch() },
  );
  assert.equal(res.status, 400);
  assert.equal(sessionTokenFrom(res), null);
});

// --- 7–9. The email door ------------------------------------------------------
const sent = [];
const mailer = { send: async (msg) => sent.push(msg) };
const mailStore = new MemoryStore();
const T0 = 1_700_000_000_000;

await test("magic link: hash-only storage, single use, session issued", async () => {
  const r = await requestMagicLink(mailStore, {
    email: "Person@Example.com",
    origin: "https://auth.example.com",
    mailer,
    now: T0,
  });
  assert.equal(r.sent, true);
  const token = new URL(sent[0].text.match(/https:\/\/\S+/)[0]).searchParams.get("token");
  assert.ok(token);
  assert.ok(!mailStore.dump().includes(token), "raw token must never touch the store");
  const first = await consumeMagicLink(mailStore, token, T0 + 1000);
  assert.ok(first && first.sessionToken);
  assert.equal(first.account.email, "person@example.com");
  const second = await consumeMagicLink(mailStore, token, T0 + 2000);
  assert.equal(second, null, "second use must fail");
});

await test("magic link: expired link is refused", async () => {
  await requestMagicLink(mailStore, {
    email: "late@example.com",
    origin: "https://auth.example.com",
    mailer,
    now: T0,
  });
  const token = new URL(sent[sent.length - 1].text.match(/https:\/\/\S+/)[0]).searchParams.get("token");
  const late = await consumeMagicLink(mailStore, token, T0 + 61 * 60 * 1000);
  assert.equal(late, null);
});

await test("magic link: rate-limited request is silently dropped, same outward answer", async () => {
  const before = sent.length;
  const r = await requestMagicLink(mailStore, {
    email: "flood@example.com",
    origin: "https://auth.example.com",
    mailer,
    now: T0,
    rateLimitOk: () => false,
  });
  assert.deepEqual(r.ok, true);
  assert.equal(sent.length, before, "no email may be sent when rate-limited");
});

await test("magic link: email door attaches to the OAuth account by verified email", async () => {
  const r = await requestMagicLink(store, {
    email: "person@example.com",
    origin: "https://auth.example.com",
    mailer,
    now: T0,
  });
  assert.equal(r.sent, true);
  const token = new URL(sent[sent.length - 1].text.match(/https:\/\/\S+/)[0]).searchParams.get("token");
  const result = await consumeMagicLink(store, token, T0 + 1000);
  assert.equal(result.account.id, githubAccountId);
  assert.equal(result.attached, true);
  assert.equal(await store.countIdentities(githubAccountId), 3);
});

// --- 10. Sessions --------------------------------------------------------------
await test("session: expiry and sign-out both end it", async () => {
  const { callbackRes } = await oauthRoundTrip(store, "github", fakeFetch());
  const token = sessionTokenFrom(callbackRes);
  assert.ok(await resolveSession(store, token));
  assert.equal(await resolveSession(store, token, Date.now() + 31 * 24 * 3600 * 1000), null);
  const { callbackRes: res2 } = await oauthRoundTrip(store, "github", fakeFetch());
  const token2 = sessionTokenFrom(res2);
  await endSession(store, token2);
  assert.equal(await resolveSession(store, token2), null);
});

// --- 11. Providers endpoint (worker entry) -------------------------------------
await test("worker: /v1/auth/providers lists exactly the lit doors", async () => {
  const env = { ...ENV, AUTH_STORE: new MemoryStore() };
  const res = await worker.fetch(new Request("https://auth.example.com/v1/auth/providers"), env);
  assert.deepEqual(await res.json(), { providers: ["github", "google", "email"] });
  const dark = await worker.fetch(
    new Request("https://auth.example.com/v1/auth/providers"),
    { AUTH_STORE: new MemoryStore() },
  );
  assert.deepEqual(await dark.json(), { providers: [] });
});

console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length) process.exit(1);
