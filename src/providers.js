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
 * The provider registry — the heart of the doors pattern.
 *
 * A "door" is one sign-in provider plugged into ONE account layer.
 * A door is DARK until BOTH of its configuration bindings exist in the
 * environment, and it lights the moment they land — no code change, no
 * rebuild of the door logic. This is not theory: in the Conduit Router
 * gateway (production), the Google door lit the day its two bindings
 * were placed, because the shipped code was already generic over
 * providers. GitHub had been door #1; Google was a configuration copy.
 *
 * Binding names follow one convention:
 *   <PROVIDER>_OAUTH_CLIENT_ID       (plain configuration value)
 *   <PROVIDER>_OAUTH_CLIENT_SECRET   (secret — placed in the host's
 *                                     secret store only, never in code,
 *                                     files, or chat)
 *
 * To add a provider: write one definition (endpoints + identity
 * parser), register it, place its two bindings. See docs/ADD-A-DOOR.md.
 */

export function defineProvider(def) {
  if (!def || !def.id || !def.authorizeUrl || !def.tokenUrl || !def.userinfoUrl) {
    throw new Error("provider definition requires id, authorizeUrl, tokenUrl, userinfoUrl");
  }
  if (typeof def.parseIdentity !== "function") {
    throw new Error(`provider ${def.id}: parseIdentity is required`);
  }
  const upper = def.id.toUpperCase().replace(/[^A-Z0-9]/g, "_");
  return {
    scopes: [],
    clientIdEnv: `${upper}_OAUTH_CLIENT_ID`,
    clientSecretEnv: `${upper}_OAUTH_CLIENT_SECRET`,
    ...def,
  };
}

/** GitHub — identity from /user; verified email from /user/emails. */
export const githubProvider = defineProvider({
  id: "github",
  authorizeUrl: "https://github.com/login/oauth/authorize",
  tokenUrl: "https://github.com/login/oauth/access_token",
  userinfoUrl: "https://api.github.com/user",
  emailsUrl: "https://api.github.com/user/emails",
  scopes: ["read:user", "user:email"],
  parseIdentity(user, emails) {
    let email = null;
    let emailVerified = false;
    if (Array.isArray(emails)) {
      const primary = emails.find((e) => e.primary && e.verified) || emails.find((e) => e.verified);
      if (primary) {
        email = primary.email;
        emailVerified = true;
      }
    }
    if (!email && user.email) {
      // A public profile email is NOT proof of mailbox control.
      email = user.email;
      emailVerified = false;
    }
    return {
      provider: "github",
      subject: String(user.id),
      email,
      emailVerified,
      name: user.name || user.login || null,
    };
  },
});

/** Google — OpenID Connect userinfo; email_verified comes from Google. */
export const googleProvider = defineProvider({
  id: "google",
  authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
  tokenUrl: "https://oauth2.googleapis.com/token",
  userinfoUrl: "https://openidconnect.googleapis.com/v1/userinfo",
  scopes: ["openid", "email", "profile"],
  extraAuthorizeParams: { access_type: "online", prompt: "select_account" },
  parseIdentity(user) {
    return {
      provider: "google",
      subject: String(user.sub),
      email: user.email || null,
      emailVerified: user.email_verified === true,
      name: user.name || null,
    };
  },
});

export const builtinProviders = [githubProvider, googleProvider];

/**
 * The doors that are LIT for this environment: a provider appears only
 * when BOTH its bindings are present and non-empty. Half-configured
 * doors stay dark — a door with an ID but no secret must never be
 * offered to a user.
 */
export function configuredProviders(env, providers = builtinProviders) {
  const lit = [];
  for (const def of providers) {
    const clientId = env[def.clientIdEnv];
    const clientSecret = env[def.clientSecretEnv];
    if (clientId && clientSecret) {
      lit.push({ def, clientId, clientSecret });
    }
  }
  return lit;
}

/** Find one lit provider by id, or null when its door is dark. */
export function getProvider(env, id, providers = builtinProviders) {
  return configuredProviders(env, providers).find((p) => p.def.id === id) || null;
}
