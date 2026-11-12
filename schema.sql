-- Copyright 2026 2351485 ALBERTA INC.
-- SPDX-License-Identifier: Apache-2.0
--
-- Account-layer schema for the doors pattern (D1 / SQLite dialect;
-- adapts mechanically to Postgres). Four tables, one law: raw tokens
-- are never stored — sessions and magic links keep SHA-256 hashes only.

CREATE TABLE IF NOT EXISTS accounts (
  id         TEXT PRIMARY KEY,
  email      TEXT,               -- the account's VERIFIED email, or NULL
  created_at INTEGER NOT NULL    -- unix milliseconds
);

-- At most one account per verified email: the storage-level backstop
-- for the identity-resolution law (see src/accounts.js).
CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_email
  ON accounts (lower(email)) WHERE email IS NOT NULL;

CREATE TABLE IF NOT EXISTS identities (
  provider       TEXT NOT NULL,  -- 'github' | 'google' | 'email' | ...
  subject        TEXT NOT NULL,  -- the provider's stable user id
  account_id     TEXT NOT NULL REFERENCES accounts(id),
  email          TEXT,           -- the email this identity presented
  email_verified INTEGER NOT NULL DEFAULT 0,
  created_at     INTEGER NOT NULL,
  PRIMARY KEY (provider, subject)
);

CREATE INDEX IF NOT EXISTS idx_identities_account ON identities (account_id);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,   -- SHA-256 of the cookie token, never the token
  account_id TEXT NOT NULL REFERENCES accounts(id),
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS magic_links (
  token_hash  TEXT PRIMARY KEY,  -- SHA-256 of the link token, never the token
  email       TEXT NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER            -- NULL until the single allowed use
);
