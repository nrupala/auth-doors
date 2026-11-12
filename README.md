# auth-doors — many sign-in doors, one account layer

Reusable scaffolding for product authentication: **sign-in providers
("doors") that plug into a single account layer by configuration, not
by new code.**

Distilled from two production systems at AIMLDS — the Conduit Router
gateway (GitHub door proven end-to-end in production; the Google door
lit later by configuration alone) and Linktary's email magic-link
auth — and generalized so the next product gets its doors by assembly.

## The pattern

- **One account layer.** Accounts, identities, and sessions live in
  four tables (`schema.sql`). Every door resolves into them through
  one function, `resolveSignIn`.
- **A door is configuration.** Each OAuth provider is one definition
  (endpoints + identity parser) plus two environment bindings:
  `<PROVIDER>_OAUTH_CLIENT_ID` and `<PROVIDER>_OAUTH_CLIENT_SECRET`.
  A door is **dark until both bindings exist** and lights the moment
  they land. Adding Google after GitHub took zero new code in
  production; adding Microsoft, Apple, or GitLab is the same move.
  Step-by-step: [docs/ADD-A-DOOR.md](docs/ADD-A-DOOR.md).
- **The email door is a magic link, not OAuth.** The mailbox is the
  credential — 256-bit single-use token, hash-only storage, short
  TTL, enumeration-resistant responses, per-address and per-IP rate
  limits. The mailer is an interface; any HTTP mail API fits.

## The one law that is code, not configuration

**Identity resolution happens by verified email, in one shared
place.** When a sign-in arrives through any door:

1. Known identity (provider + subject) → its account.
2. Else, a **verified** email matching an existing account → attach
   the new identity to that account.
3. Else → create the account.

An unverified email never merges accounts. Skip this law and every
new door mints duplicate accounts for the same person — in
production, the owner found and deleted such a duplicate by hand.
Here it is implemented once (`src/accounts.js`), tested
(`test/self-test.mjs`), and backstopped in SQL (unique index on the
account email).

## Security properties (all enforced, all tested)

- Tokens — session, magic-link — are stored **only as SHA-256
  hashes**. A database leak yields no usable credential.
- OAuth flow uses **state + PKCE (S256)**; state mismatches are
  refused with no session issued.
- Session cookies: `HttpOnly; Secure; SameSite=Lax`, 30-day cap,
  server-side invalidation on sign-out.
- The email door answers identically for every address
  (enumeration resistance) and swallows send failures for the same
  reason.
- **Secrets travel into the host's secret store only** — page to
  page in a browser, or `wrangler secret put` — never through chat,
  files, or this repo. This kit contains placeholders only.
- Full life cycle: an account surface is not complete without
  sign-out and account deletion in the product that adopts the kit
  (the production account layer carries both).

## Layout

```
src/providers.js   the registry: definitions + the lights-when-bound rule
src/oauth-door.js  start/callback handlers, generic over providers
src/magic-link.js  the email door (request + consume)
src/accounts.js    THE identity-resolution law + sessions + cookies
src/store.js       storage contract + in-memory reference store
src/index.js       reference Worker entry: /v1/auth/* routes
schema.sql         accounts / identities / sessions / magic_links (D1/SQLite)
test/self-test.mjs 13 checks, no network, no dependencies
docs/ADD-A-DOOR.md adding a provider, step by step
SKILL.md           the same pattern as an agent skill (house copy)
```

## Run the proof

```sh
node test/self-test.mjs   # Node >= 18, nothing to install
```

Covers the RFC 7636 PKCE vector, the dark/lit door matrix, full
GitHub and Google round trips against fake provider backends, the
identity law in all three branches, state-mismatch refusal,
magic-link hash-only storage / single use / expiry / rate-limit
silence, cross-door account attachment, session expiry and sign-out,
and the `/v1/auth/providers` read-back.

## Adopt it

1. Copy `src/` into your Worker (or port the five small modules —
   they are dependency-free Web-platform JavaScript).
2. Apply `schema.sql` and implement the store interface over your
   database, or keep `MemoryStore` for a demo.
3. Register one provider, place its two bindings, read back
   `/v1/auth/providers`, run a sign-in round trip.
4. Repeat per door. Each additional door is an afternoon of
   configuration, most of it waiting on the provider's console.

## Licence

Apache-2.0. © 2351485 ALBERTA INC.
