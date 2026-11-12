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

import { randomToken, sha256Hex } from "./util.js";

/**
 * THE IDENTITY-RESOLUTION LAW — the one part of the doors pattern that
 * is not configuration, and the part that bites when it is missing.
 *
 * When a sign-in arrives through any door, resolve in this order:
 *
 *   1. The identity (provider + subject) is known → its account.
 *   2. Else, the identity carries a VERIFIED email that an existing
 *      account holds → attach the new identity to THAT account.
 *   3. Else → create a new account and attach the identity.
 *
 * An UNVERIFIED email never merges accounts (rule 2 requires verified):
 * a provider profile field is a claim, not proof of mailbox control.
 *
 * Why this is law: in production, a second door opened for the same
 * person minted a second account — the owner found and deleted the
 * duplicate by hand. Every door added without this law multiplies
 * that defect. Built once, in this shared layer, every future door
 * inherits correct behaviour for free.
 *
 * Returns { account, created, attached } so callers can observe which
 * branch fired (created = rule 3, attached = rule 2).
 */
export async function resolveSignIn(store, identity, now = Date.now()) {
  const known = await store.getIdentity(identity.provider, identity.subject);
  if (known) {
    const account = await store.getAccount(known.accountId);
    // Refresh the account's verified email if this door proves a new one.
    if (identity.emailVerified && identity.email && account && account.email !== identity.email) {
      await store.setAccountEmail(account.id, identity.email);
    }
    return { account, created: false, attached: false };
  }

  if (identity.emailVerified && identity.email) {
    const existing = await store.getAccountByVerifiedEmail(identity.email);
    if (existing) {
      await store.putIdentity({
        provider: identity.provider,
        subject: identity.subject,
        accountId: existing.id,
        email: identity.email,
        emailVerified: true,
      });
      return { account: existing, created: false, attached: true };
    }
  }

  const account = await store.createAccount({
    email: identity.emailVerified ? identity.email : null,
    now,
  });
  await store.putIdentity({
    provider: identity.provider,
    subject: identity.subject,
    accountId: account.id,
    email: identity.email || null,
    emailVerified: !!identity.emailVerified,
  });
  return { account, created: true, attached: false };
}

// ---------------------------------------------------------------------------
// Sessions. The cookie carries a random token; the store keeps only its
// SHA-256 hash. Cookie flags follow the production pattern: HttpOnly +
// Secure + SameSite=Lax, path-scoped to the whole app.

export const SESSION_COOKIE_NAME = "session";
export const SESSION_TTL_SEC = 30 * 24 * 60 * 60; // 30 days

export async function createSession(store, accountId, now = Date.now()) {
  const token = randomToken(32);
  const tokenHash = await sha256Hex(token);
  await store.putSession(tokenHash, {
    accountId,
    expiresAt: now + SESSION_TTL_SEC * 1000,
  });
  return token;
}

export async function resolveSession(store, token, now = Date.now()) {
  if (!token) return null;
  const tokenHash = await sha256Hex(token);
  const row = await store.getSession(tokenHash);
  if (!row) return null;
  if (row.expiresAt <= now) {
    await store.deleteSession(tokenHash);
    return null;
  }
  return store.getAccount(row.accountId);
}

export async function endSession(store, token) {
  if (!token) return;
  await store.deleteSession(await sha256Hex(token));
}

export function sessionCookieHeader(token) {
  return (
    `${SESSION_COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Lax; ` +
    `Path=/; Max-Age=${SESSION_TTL_SEC}`
  );
}

export function clearSessionCookieHeader() {
  return `${SESSION_COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}
