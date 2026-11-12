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

import { getProvider } from "./providers.js";
import { createSession, resolveSignIn, sessionCookieHeader } from "./accounts.js";
import { getCookie, json, randomToken, s256Challenge, safeEqual } from "./util.js";

/**
 * The OAuth door: start + callback, generic over every registered
 * provider. The callback URL shape is fixed by the pattern:
 *
 *   GET /v1/auth/<provider>/start     → 302 to the provider, with a
 *                                       state + PKCE cookie (10 min)
 *   GET /v1/auth/<provider>/callback  → code exchange, identity fetch,
 *                                       resolveSignIn, session, 302
 *                                       to the app with the session
 *                                       cookie set
 *
 * Register the callback as `<origin>/v1/auth/<provider>/callback` in
 * the provider's developer console — exact match, no wildcards.
 */

const STATE_COOKIE_NAME = "auth_state";
const STATE_TTL_SEC = 600; // 10 minutes

export function callbackUrl(origin, providerId) {
  return `${origin}/v1/auth/${providerId}/callback`;
}

export async function handleStart(request, env, providers) {
  const url = new URL(request.url);
  const providerId = url.pathname.split("/")[3];
  const lit = getProvider(env, providerId, providers);
  if (!lit) return json({ error: "provider_not_configured" }, 404);

  const state = randomToken(16);
  const verifier = randomToken(32);
  const challenge = await s256Challenge(verifier);

  const authorize = new URL(lit.def.authorizeUrl);
  authorize.searchParams.set("client_id", lit.clientId);
  authorize.searchParams.set("redirect_uri", callbackUrl(url.origin, providerId));
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("code_challenge", challenge);
  authorize.searchParams.set("code_challenge_method", "S256");
  if (lit.def.scopes.length) authorize.searchParams.set("scope", lit.def.scopes.join(" "));
  for (const [k, v] of Object.entries(lit.def.extraAuthorizeParams || {})) {
    authorize.searchParams.set(k, v);
  }

  const stateCookie =
    `${STATE_COOKIE_NAME}=${encodeURIComponent(`${state}.${verifier}`)}; HttpOnly; Secure; ` +
    `SameSite=Lax; Path=/v1/auth; Max-Age=${STATE_TTL_SEC}`;

  return new Response(null, {
    status: 302,
    headers: { location: authorize.toString(), "set-cookie": stateCookie },
  });
}

export async function handleCallback(request, env, store, { fetchImpl = fetch, now = Date.now() } = {}) {
  const url = new URL(request.url);
  const providerId = url.pathname.split("/")[3];
  const lit = getProvider(env, providerId);
  if (!lit) return json({ error: "provider_not_configured" }, 404);

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const cookieValue = getCookie(request.headers.get("Cookie"), STATE_COOKIE_NAME);
  const [cookieState, verifier] = cookieValue ? cookieValue.split(".") : [null, null];
  if (!code || !state || !cookieState || !verifier || !safeEqual(state, cookieState)) {
    return json({ error: "invalid_state" }, 400);
  }

  // Exchange the code for an access token (PKCE verifier included).
  const tokenRes = await fetchImpl(lit.def.tokenUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({
      client_id: lit.clientId,
      client_secret: lit.clientSecret,
      code,
      redirect_uri: callbackUrl(url.origin, providerId),
      grant_type: "authorization_code",
      code_verifier: verifier,
    }),
  });
  const tokenData = await tokenRes.json().catch(() => null);
  if (!tokenRes.ok || !tokenData || !tokenData.access_token) {
    return json({ error: "token_exchange_failed" }, 502);
  }
  const authHeaders = { authorization: `Bearer ${tokenData.access_token}`, accept: "application/json" };

  const userRes = await fetchImpl(lit.def.userinfoUrl, { headers: authHeaders });
  if (!userRes.ok) return json({ error: "identity_fetch_failed" }, 502);
  const user = await userRes.json();

  let emails = null;
  if (lit.def.emailsUrl) {
    const emailsRes = await fetchImpl(lit.def.emailsUrl, { headers: authHeaders });
    if (emailsRes.ok) emails = await emailsRes.json();
  }

  const identity = lit.def.parseIdentity(user, emails);
  const { account, created, attached } = await resolveSignIn(store, identity, now);
  const sessionToken = await createSession(store, account.id, now);

  return new Response(null, {
    status: 302,
    headers: {
      location: "/app",
      "set-cookie": sessionCookieHeader(sessionToken),
      // Observable resolution branch — proves the identity law fired.
      "x-auth-resolution": created ? "created" : attached ? "attached" : "returning",
    },
  });
}
