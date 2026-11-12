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

import { createSession, resolveSignIn } from "./accounts.js";
import { randomToken, sha256Hex } from "./util.js";

/**
 * The email door — a magic link, NOT OAuth. No password exists; the
 * mailbox itself is the credential. Distilled from two production
 * doors (Linktary's email auth and the Conduit Router's email door).
 *
 * Non-negotiable properties, all proven in production:
 *
 *   - The token is 256-bit random; the store keeps ONLY its SHA-256.
 *   - Single use, atomically consumed; short TTL (default 60 minutes).
 *   - Enumeration resistance: the request endpoint answers identically
 *     whether or not the address has an account — it never branches
 *     on account existence. Send failures are swallowed for the same
 *     reason.
 *   - Rate limits per address and per client IP (hooks below) — an
 *     open mail door is an abuse magnet.
 *   - Never log tokens. Never log the mailer payload.
 *
 * The mailer is an interface, not a vendor: anything that can send one
 * email works (Resend, MailChannels, SES, an SMTP relay). The door
 * lights when its mailer binding exists — same rule as OAuth doors.
 */

export const MAGIC_LINK_TTL_MINUTES = 60;

/**
 * Request a sign-in link. Always resolves to the same outward result;
 * `sent` is returned for the caller's logs/tests only — the HTTP layer
 * must answer identically either way.
 *
 * rateLimitOk: optional ({email, ip}) => boolean. When it returns
 * false the request is silently dropped (no store row, no email) while
 * the outward answer stays the same.
 */
export async function requestMagicLink(
  store,
  { email, origin, mailer, now = Date.now(), ttlMinutes = MAGIC_LINK_TTL_MINUTES, rateLimitOk = null, ip = null },
) {
  const normalized = String(email || "").trim().toLowerCase();
  if (!normalized || !normalized.includes("@")) return { ok: true, sent: false };
  if (rateLimitOk && !(await rateLimitOk({ email: normalized, ip }))) {
    return { ok: true, sent: false };
  }
  const token = randomToken(32);
  const tokenHash = await sha256Hex(token);
  await store.putMagicLink(tokenHash, {
    email: normalized,
    expiresAt: now + ttlMinutes * 60 * 1000,
  });
  const url = `${origin}/v1/auth/email/callback?token=${token}`;
  try {
    await mailer.send({
      to: normalized,
      subject: "Your sign-in link",
      text: `Sign in with this link (valid ${ttlMinutes} minutes, single use):\n\n${url}\n`,
    });
    return { ok: true, sent: true };
  } catch {
    // Swallowed deliberately — enumeration resistance. The stored link
    // simply expires unused.
    return { ok: true, sent: false };
  }
}

/**
 * Consume a magic link: verifies hash, expiry, and single use, then
 * resolves through the SAME identity law as every OAuth door — the
 * email door's identity (provider "email", subject = the address) is
 * verified by construction, since following the link proves mailbox
 * control. Returns { account, sessionToken, created, attached } or
 * null for any failure (expired, used, unknown — indistinguishable).
 */
export async function consumeMagicLink(store, token, now = Date.now()) {
  if (!token) return null;
  const tokenHash = await sha256Hex(token);
  const row = await store.consumeMagicLink(tokenHash, now);
  if (!row || row.expiresAt <= now) return null;
  const { account, created, attached } = await resolveSignIn(
    store,
    { provider: "email", subject: row.email, email: row.email, emailVerified: true, name: null },
    now,
  );
  const sessionToken = await createSession(store, account.id, now);
  return { account, sessionToken, created, attached };
}
