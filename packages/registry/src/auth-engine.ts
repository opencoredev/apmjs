// Better Auth and the libraries only sign-in, second factors and legacy passwords use. auth.ts, passwords.ts and
// server.ts load this module on first use (loadAuthEngine, a dynamic import the build splits into its own chunk), so
// a cold isolate that serves installs never parses or runs it: it is about half the Worker's code, and an isolate
// started for a burst of npm's requests waited for all of it before its first answer.
import { Effect } from "effect";
import { betterAuth } from "better-auth";
import { genericOAuth, twoFactor, deviceAuthorization } from "better-auth/plugins";
import { passkey } from "@better-auth/passkey";
import { Pool } from "pg";
import { z } from "zod";
import { optedOut, signInMethod, type AccountEvents } from "./account-events.ts";
import type { AuthOptions, GitHubEndpoints } from "./auth.ts";
import type { Store } from "./db.ts";
import type { StoreError } from "./errors.ts";

export { hashPassword, symmetricDecrypt, symmetricEncrypt, verifyPassword } from "better-auth/crypto";

export { generateAuthenticationOptions, verifyAuthenticationResponse } from "@simplewebauthn/server";

export { getAuthenticatorName } from "@better-auth/passkey";

export { Pool };

const GITHUB: GitHubEndpoints = {
  authorize: "https://github.com/login/oauth/authorize",
  token: "https://github.com/login/oauth/access_token",
  user: "https://api.github.com/user",
  emails: "https://api.github.com/user/emails",
};

const GitHubUser = z.object({ id: z.number(), login: z.string(), name: z.string().nullish(), email: z.string().nullish(), avatar_url: z.string().nullish() });
const GitHubEmails = z.array(z.object({ email: z.string(), primary: z.boolean(), verified: z.boolean() }));

/** The part of a passkey sign-in's body that names the passkey that answered. */
const PasskeySignIn = z.object({ response: z.object({ id: z.string().min(1).max(1024) }) });

export function buildBetterAuth(input: {
  pool: Pool;
  options: AuthOptions;
  baseURL: string;
  store: Store["Service"];
  now: () => number;
  cliClientId: string;
  accountEvents: AccountEvents | null;
}) {
  const { pool, options, store, now, cliClientId, accountEvents } = input;
  const baseURL = input.baseURL.replace(/\/$/, "");
  const web = new URL(baseURL);
  const gh = options.github ? { ...options.github, endpoints: options.github.endpoints ?? GITHUB } : null;
  const record = (effect: Effect.Effect<void, StoreError>): Promise<void> => Effect.runPromise(effect);
  // the accounts this instance (one request) made: their first session is the sign-up, not a returning sign-in
  const created = new Set<string>();

  return betterAuth({
    appName: "apm",
    database: pool,
    baseURL,
    basePath: "/api/auth",
    secret: options.secret,
    trustedOrigins: [web.origin],
    telemetry: { enabled: false },
    // Sign-up and sign-in counts (account-events.ts): queued for after the answer, and never able to fail a sign-in.
    databaseHooks: {
      user: {
        create: {
          after: async (user, ctx) => {
            created.add(user.id);

            try {
              accountEvents?.send({ name: "account_created", method: signInMethod(ctx) ?? "other", authUserId: user.id, optedOut: optedOut(ctx?.request?.headers) });
            } catch {
              // counting never fails a sign-up
            }
          },
        },
      },
      session: {
        create: {
          after: async (session, ctx) => {
            try {
              // the account page's "last used" for the passkey that signed in; never able to fail the sign-in
              const signIn = signInMethod(ctx) === "passkey" ? PasskeySignIn.safeParse(ctx?.body) : null;

              if (signIn?.success) await record(store.notePasskeyUse({ authUserId: session.userId, credentialID: signIn.data.response.id, at: now() }));
            } catch {
              // a lost "last used" never reaches the person signing in
            }

            try {
              const method = signInMethod(ctx);

              if (method === null || created.has(session.userId)) return;
              accountEvents?.send({ name: "sign_in", method, authUserId: session.userId, optedOut: optedOut(ctx?.request?.headers) });
            } catch {
              // counting never fails a sign-in
            }
          },
        },
      },
    },
    account: { accountLinking: { enabled: true, trustedProviders: ["github", "vercel"], allowDifferentEmails: true } },
    ...(options.vercel ? { socialProviders: { vercel: { clientId: options.vercel.clientId, clientSecret: options.vercel.clientSecret } } } : {}),
    plugins: [
      ...(gh
        ? [
            genericOAuth({
              config: [
                {
                  providerId: "github",
                  clientId: gh.clientId,
                  clientSecret: gh.clientSecret,
                  authorizationUrl: gh.endpoints.authorize,
                  tokenUrl: gh.endpoints.token,
                  scopes: ["read:user", "user:email"],
                  getUserInfo: async (tokens) => {
                    const headers = { authorization: `Bearer ${tokens.accessToken}`, accept: "application/vnd.github+json", "user-agent": "apm-registry" };
                    const res = await fetch(gh.endpoints.user, { headers, signal: AbortSignal.timeout(10_000) });

                    if (!res.ok) return null;
                    const profile = GitHubUser.safeParse(await res.json());

                    if (!profile.success) return null;
                    const p = profile.data;
                    await record(store.setGitHubProfile(String(p.id), p.login, now()));
                    let email = p.email ?? null;
                    let verified = false;
                    const er = await fetch(gh.endpoints.emails, { headers, signal: AbortSignal.timeout(10_000) }).catch(() => null);
                    const emails = er?.ok ? GitHubEmails.safeParse(await er.json()) : null;

                    if (emails?.success) {
                      const primary = emails.data.find((e) => e.primary && e.verified) ?? emails.data.find((e) => e.verified);

                      if (primary) {
                        email = primary.email;
                        verified = true;
                      }
                    }

                    return {
                      id: String(p.id),
                      name: p.name || p.login,
                      // GitHub accounts can hide every address; the noreply form keeps one per account.
                      email: email ?? `${p.id}+${p.login}@users.noreply.github.com`,
                      emailVerified: verified,
                      ...(p.avatar_url ? { image: p.avatar_url } : {}),
                    };
                  },
                },
              ],
            }),
          ]
        : []),
      // Accounts come from GitHub or Vercel and have no password. The route gates ask for the existing factor
      // instead, and apm checks TOTP codes itself (one budget, each step once).
      twoFactor({ issuer: "apm", allowPasswordless: true }),
      passkey({ rpID: web.hostname, rpName: "apm", origin: web.origin }),
      deviceAuthorization({ expiresIn: "15m", interval: "1s", validateClient: (id) => id === cliClientId }),
    ],
    // A passkey sign-in makes a session and nothing else: a second factor for an action answers a challenge the
    // registry made for that action (Auth.passkeyChallenge), never this route's.
  });
}

export type BetterAuthInstance = ReturnType<typeof buildBetterAuth>;
