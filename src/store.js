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
 * Storage contract for the account layer.
 *
 * Every door resolves into these four tables (schema.sql carries the
 * SQL form for D1/SQLite):
 *
 *   accounts     id, email (the account's verified email, if any), created_at
 *   identities   (provider, subject) -> account_id, email, email_verified
 *   sessions     token_hash -> account_id, expires_at      (hash only)
 *   magic_links  token_hash -> email, expires_at, consumed_at (hash only)
 *
 * RAW TOKENS ARE NEVER STORED — only their SHA-256 hashes. A database
 * leak then yields no usable credential.
 *
 * MemoryStore below is the reference implementation used by the
 * self-test and for local demos. Production deployments implement the
 * same async interface over D1, KV, or Postgres. `consumeMagicLink`
 * must be atomic in a real store (single UPDATE ... WHERE consumed_at
 * IS NULL): single-use is a security property, not a nicety.
 */
export class MemoryStore {
  constructor() {
    this.accounts = new Map(); // id -> {id, email, createdAt}
    this.identities = new Map(); // "provider:subject" -> {provider, subject, accountId, email, emailVerified}
    this.emailIndex = new Map(); // lowercase verified email -> accountId
    this.sessions = new Map(); // tokenHash -> {accountId, expiresAt}
    this.magicLinks = new Map(); // tokenHash -> {email, expiresAt, consumedAt}
    this.seq = 0;
  }

  async createAccount({ email, now }) {
    const id = `acct_${++this.seq}_${now.toString(36)}`;
    const account = { id, email: email || null, createdAt: now };
    this.accounts.set(id, account);
    if (email) this.emailIndex.set(email.toLowerCase(), id);
    return account;
  }

  async getAccount(id) {
    return this.accounts.get(id) || null;
  }

  async getAccountByVerifiedEmail(email) {
    if (!email) return null;
    const id = this.emailIndex.get(email.toLowerCase());
    return id ? this.accounts.get(id) || null : null;
  }

  async setAccountEmail(accountId, email) {
    const account = this.accounts.get(accountId);
    if (!account) return;
    if (account.email) this.emailIndex.delete(account.email.toLowerCase());
    account.email = email;
    if (email) this.emailIndex.set(email.toLowerCase(), accountId);
  }

  async getIdentity(provider, subject) {
    return this.identities.get(`${provider}:${subject}`) || null;
  }

  async putIdentity({ provider, subject, accountId, email, emailVerified }) {
    const row = { provider, subject, accountId, email, emailVerified: !!emailVerified };
    this.identities.set(`${provider}:${subject}`, row);
    return row;
  }

  async countIdentities(accountId) {
    let n = 0;
    for (const row of this.identities.values()) if (row.accountId === accountId) n++;
    return n;
  }

  async putSession(tokenHash, { accountId, expiresAt }) {
    this.sessions.set(tokenHash, { accountId, expiresAt });
  }

  async getSession(tokenHash) {
    return this.sessions.get(tokenHash) || null;
  }

  async deleteSession(tokenHash) {
    this.sessions.delete(tokenHash);
  }

  async putMagicLink(tokenHash, { email, expiresAt }) {
    this.magicLinks.set(tokenHash, { email, expiresAt, consumedAt: null });
  }

  /** Atomic single-use consume: returns the link row once, then never again. */
  async consumeMagicLink(tokenHash, now) {
    const row = this.magicLinks.get(tokenHash);
    if (!row || row.consumedAt !== null) return null;
    row.consumedAt = now;
    return row;
  }

  /** Serialize all state — the self-test scans this for raw tokens. */
  dump() {
    return JSON.stringify({
      accounts: [...this.accounts.values()],
      identities: [...this.identities.values()],
      sessions: [...this.sessions.entries()],
      magicLinks: [...this.magicLinks.entries()],
    });
  }
}
