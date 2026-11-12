---
name: auth-doors
description: Add sign-in providers ("doors") to a product by configuration instead of new code — OAuth providers and an email magic-link door resolving into one account layer under the verified-email identity law. Use when a product needs sign-in, a new OAuth provider, or an email door.
---

# auth-doors — many sign-in doors, one account layer

Reference implementation and full documentation:
`nrupala/auth-doors` (public, Apache-2.0) — `src/` is dependency-free
Web-platform JavaScript, `test/self-test.mjs` is the proof
(13 checks, no network).

## When to use

- A product needs user sign-in for the first time.
- A product with one OAuth door needs another provider.
- A product needs an email (magic-link) door.
- An account-duplication bug appears after a second door opens —
  the identity law below is missing.

## The pattern, in one paragraph

Providers are definitions (endpoints + an identity parser) plus two
environment bindings each: `<PROVIDER>_OAUTH_CLIENT_ID` (plain) and
`<PROVIDER>_OAUTH_CLIENT_SECRET` (secret store only). A door is dark
until both bindings exist and lights when they land — no code
change. The email door is a magic link (hash-only, single-use,
60-minute TTL, enumeration-resistant, rate-limited) lit by its
mailer bindings. All doors resolve into one account layer: accounts,
identities, sessions, magic links (see the repo's `schema.sql`).

## The law (never skip)

Identity resolution by **verified email**, in exactly one shared
place (`resolveSignIn`):

1. Known (provider, subject) → its account.
2. Verified email matching an existing account → attach the new
   identity to that account.
3. Otherwise → create the account.

An unverified email NEVER merges accounts. Production evidence: a
second door without this law minted a duplicate account the owner
had to delete by hand.

## Procedure (per door)

1. Built-in provider (github, google) or write one definition.
2. Register the provider app; callback exactly
   `https://<origin>/v1/auth/<provider>/callback`; minimum scopes.
3. Place the bindings — the secret goes page-to-page into the
   host's secret store, never through chat or files; a secret that
   transited elsewhere gets rotated once captured.
4. Read back `GET /v1/auth/providers` — the door must be listed.
5. Round-trip as a user: sign in → account surface → sign out.
6. Cross-door test: sign in via another door with the same verified
   email → SAME account (`x-auth-resolution: attached`). A duplicate
   means stop and wire the law before opening the door.

Email door: mailer bindings → providers read-back → link round
trip → second use of the same link refused → unknown vs known
address answers indistinguishable.

## Acceptance battery (all three, every door)

- Providers-list read-back names the door.
- One real sign-in round trip per door.
- The cross-door attach test.

## Full life cycle

A door is not done at sign-in: sign-out and account deletion ship
in the same build, with removal semantics stated in the UI.
