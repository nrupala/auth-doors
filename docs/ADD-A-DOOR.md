<!-- SPDX-License-Identifier: Apache-2.0 -->

# Add a door — step by step

Adding a sign-in provider to a product that uses the doors pattern.
Proven sequence: GitHub (first door, Conduit Router, Nov 2026),
Google (second door — configuration only, no code change).

## A. An OAuth provider (GitHub, Google, Microsoft, Apple, GitLab…)

1. **Define the provider** (skip if it's a built-in). One entry in
   `src/providers.js`: the authorize/token/userinfo endpoints, the
   scopes, and a `parseIdentity` that returns
   `{ provider, subject, email, emailVerified, name }`.
   `emailVerified` must mean the PROVIDER verified mailbox control —
   a public profile email is not verification (GitHub: use the
   `/user/emails` entry marked verified; Google: `email_verified`).
2. **Register the app in the provider's console.**
   - Callback / redirect URI, exact:
     `https://<your-origin>/v1/auth/<provider>/callback`
   - Scopes: the minimum that yields a stable subject id and a
     verified email. Nothing more.
   - The provider hands you a client ID (public) and a client
     secret (a real secret).
3. **Place the two bindings.**
   - `<PROVIDER>_OAUTH_CLIENT_ID` — plain configuration value.
   - `<PROVIDER>_OAUTH_CLIENT_SECRET` — into the host's **secret
     store only** (dashboard secret field, or
     `wrangler secret put`). Carry it page to page in the browser;
     never paste it into chat, a file, an issue, or a commit. If a
     secret ever transits anywhere else, rotate it once captured.
4. **Read back the door.** `GET /v1/auth/providers` must now list the
   provider. If it doesn't, a binding is missing or misnamed — fix
   configuration, not code.
5. **Round-trip test, as a user.** Sign in through the new door →
   land in the app → confirm the account surface shows the account →
   sign out. Then the **cross-door test**: sign in through a
   *different* existing door with the same verified email → you must
   land on the SAME account (`x-auth-resolution: attached`), never a
   fresh one. A duplicate account means the identity-resolution law
   is not wired — stop and fix that before opening the door to users.

## B. The email door (magic link)

1. Choose any HTTP mail API that accepts `{from, to, subject, text}`
   with a bearer key (the reference mailer in `src/index.js` is
   Resend-shaped; adapt those few lines for another provider). The
   sending domain must be yours, with its SPF/DKIM in place — a
   sign-in email that lands in spam is a locked door.
2. Place the bindings: `MAILER_API_URL`, `MAILER_FROM` (plain), and
   `MAILER_API_KEY` (secret store only).
3. Read back `/v1/auth/providers` — `email` appears.
4. Round-trip: request a link → receive it → follow it → land in the
   app on the right account → follow the same link again → refused
   (single use). Request a link for an address with no account and
   for one with an account: the outward answers must be identical.

## C. Rules that hold for every door

- A door ships with its **full life cycle**: sign-in, sign-out, and
  account deletion all work before the door is announced.
- **Half-configured doors stay dark.** Never link users to a door
  whose secret binding is missing — the providers list is the single
  source of truth for what is offered.
- One well-aimed test per door beats a broad claim: providers
  read-back + one real round trip + the cross-door attach test.
  That is the whole acceptance battery, and it is cheap.
