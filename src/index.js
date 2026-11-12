/*
 * Copyright 2026 2351485 ALBERTA INC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Reference Worker entry — wires the doors into routes of the shape
 * proven in production (the Conduit Router gateway):
 *
 *   GET  /v1/auth/providers           → the doors that are LIT
 *   GET  /v1/auth/<provider>/start    → OAuth door: begin
 *   GET  /v1/auth/<provider>/callback → OAuth door: complete
 *   POST /v1/auth/email/request       → email door: send a magic link
 *   GET  /v1/auth/email/callback      → email door: complete
 *   GET  /v1/auth/me                  → the signed-in account, or 401
 *   POST /v1/auth/signout             → end the session
 *
 * A door appears in /v1/auth/providers only when it is configured:
 * OAuth doors need both bindings; the email door needs its mailer
 * bindings. Configuration is the whole integration — see
 * docs/ADD-A-DOOR.md.
 *
 * STORAGE: by default this entry uses the in-memory MemoryStore,
 * which is correct for tests and demos only (state dies with the
 * isolate). Production: pass a store implementing the same interface
 * over D1/KV/Postgres (schema.sql) as `env.AUTH_STORE`, or replace
 * createStore() with your adapter.
 */

import { configuredProviders } from "./providers.js";
import { handleCallback, handleStart } from "./oauth-door.js";
import { consumeMagicLink, requestMagicLink } from "./magic-link.js";
import {
  clearSessionCookieHeader,
  endSession,
  resolveSession,
  sessionCookieHeader,
  SESSION_COOKIE_NAME,
} from "./accounts.js";
import { MemoryStore } from "./store.js";
import { getCookie, json } from "./util.js";

function createStore(env) {
  return env.AUTH_STORE || new MemoryStore();
}

/** The email door is lit when all three mailer bindings exist. */
function mailerFrom(env) {
  if (!env.MAILER_API_URL || !env.MAILER_API_KEY || !env.MAILER_FROM) return null;
  return {
    async send({ to, subject, text }) {
      const res = await fetch(env.MAILER_API_URL, {
        method: "POST",
        headers: {
          authorization: `Bearer ${env.MAILER_API_KEY}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ from: env.MAILER_FROM, to, subject, text }),
      });
      if (!res.ok) throw new Error(`mailer responded ${res.status}`);
    },
  };
}

// Demo-grade rate limiting for the email door (per address 5/hour,
// per IP 20/hour). Production: back this with KV or a Durable Object —
// an in-isolate Map undercounts across isolates, never overcounts
// safety: it can only let MORE through under load, so treat the real
// control as the store-backed implementation in your deployment.
const mailHits = new Map();
function rateLimitOk({ email, ip }) {
  const now = Date.now();
  const check = (key, limit) => {
    const hits = (mailHits.get(key) || []).filter((t) => now - t < 3600_000);
    hits.push(now);
    mailHits.set(key, hits);
    return hits.length <= limit;
  };
  return check(`email:${email}`, 5) && check(`ip:${ip || "?"}`, 20);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean); // ["v1","auth",...]
    if (parts[0] !== "v1" || parts[1] !== "auth") return json({ error: "not_found" }, 404);
    const store = createStore(env);

    // The lit doors — read this back after every configuration change.
    if (parts[2] === "providers" && request.method === "GET") {
      const doors = configuredProviders(env).map((p) => p.def.id);
      if (mailerFrom(env)) doors.push("email");
      return json({ providers: doors });
    }

    if (parts[2] === "email" && parts[3] === "request" && request.method === "POST") {
      const mailer = mailerFrom(env);
      if (!mailer) return json({ error: "email_door_not_configured" }, 404);
      const body = await request.json().catch(() => ({}));
      await requestMagicLink(store, {
        email: body.email,
        origin: url.origin,
        mailer,
        rateLimitOk,
        ip: request.headers.get("cf-connecting-ip"),
      });
      // Enumeration resistance: identical answer for every address.
      return json({ ok: true });
    }

    if (parts[2] === "email" && parts[3] === "callback" && request.method === "GET") {
      const result = await consumeMagicLink(store, url.searchParams.get("token"));
      if (!result) return json({ error: "invalid_or_expired_link" }, 400);
      return new Response(null, {
        status: 302,
        headers: {
          location: "/app",
          "set-cookie": sessionCookieHeader(result.sessionToken),
          "x-auth-resolution": result.created ? "created" : result.attached ? "attached" : "returning",
        },
      });
    }

    if (parts[2] === "me" && request.method === "GET") {
      const token = getCookie(request.headers.get("Cookie"), SESSION_COOKIE_NAME);
      const account = await resolveSession(store, token);
      if (!account) return json({ error: "not_signed_in" }, 401);
      return json({ id: account.id, email: account.email });
    }

    if (parts[2] === "signout" && request.method === "POST") {
      const token = getCookie(request.headers.get("Cookie"), SESSION_COOKIE_NAME);
      await endSession(store, token);
      return json({ ok: true }, 200, { "set-cookie": clearSessionCookieHeader() });
    }

    if (parts[3] === "start" && request.method === "GET") return handleStart(request, env);
    if (parts[3] === "callback" && request.method === "GET") return handleCallback(request, env, store);

    return json({ error: "not_found" }, 404);
  },
};
