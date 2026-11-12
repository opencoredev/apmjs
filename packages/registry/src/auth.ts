// Sign-in for people: Better Auth with GitHub and Vercel, TOTP 2FA, passkeys and the device flow that
// `apm login` uses. Better Auth's tables live in the registry's Postgres next to apm's own.
// An apm name (and scope) is the lowercased GitHub login of the signed-in account; Vercel-only accounts
// have no name until they link GitHub. apm checks second factors itself (factors.ts, the ledger in db.ts):
// one attempt budget, each TOTP step once, passkey checks spent on one action.
import { timingSafeEqual } from "node:crypto";
import { Context, Effect, Layer, Result, Scope } from "effect";
import { betterAuth } from "better-auth";
import { genericOAuth, twoFactor, deviceAuthorization } from "better-auth/plugins";
import { createAuthMiddleware } from "better-auth/api";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { passkey } from "@better-auth/passkey";
import { Pool } from "pg";
import { z } from "zod";
import { Clock } from "./clock.ts";
import { Store, type Linked, type User } from "./db.ts";
import { AuthError, type StoreError } from "./errors.ts";
import { matchingStep, parseProofHeader, parseSixDigits, PROOF_HEADER, type FactorProof, type ProofCheck, type SixDigits } from "./factors.ts";

export { parseProofHeader, PROOF_HEADER, type FactorProof, type ProofCheck } from "./factors.ts";

export type GitHubEndpoints = { authorize: string; token: string; user: string; emails: string };

export type AuthOptions = {
  /** Signs session cookies and encrypts TOTP secrets. Keep it stable across deploys. */
  secret: string;
  github?: { clientId: string; clientSecret: string; endpoints?: GitHubEndpoints };
  vercel?: { clientId: string; clientSecret: string };
};

const GITHUB: GitHubEndpoints = {
  authorize: "https://github.com/login/oauth/authorize",
  token: "https://github.com/login/oauth/access_token",
  user: "https://api.github.com/user",
  emails: "https://api.github.com/user/emails",
};

const CLI_CLIENT_ID = "apm-cli";

const GitHubUser = z.object({ id: z.number(), login: z.string(), name: z.string().nullish(), email: z.string().nullish(), avatar_url: z.string().nullish() });
const GitHubEmails = z.array(z.object({ email: z.string(), primary: z.boolean(), verified: z.boolean() }));
const SessionShape = z.object({ session: z.object({ token: z.string(), userId: z.string(), createdAt: z.coerce.date() }), user: z.object({ id: z.string() }).loose() });
const DeviceStartShape = z.object({ device_code: z.string(), user_code: z.string(), expires_in: z.number(), interval: z.number() });
const DeviceTokenShape = z.object({ access_token: z.string() });
const ApiErrorShape = z.object({ body: z.object({ error: z.string() }).loose() });
const RecoveryCodes = z.array(z.string());
const EnrollBody = z.object({ code: z.string() });

export type SignedIn = { authUserId: string; sessionToken: string; signedInAt: number };

export type DevicePoll = { kind: "pending" } | { kind: "slow_down" } | { kind: "denied" } | { kind: "expired" } | { kind: "approved"; authUserId: string };

export type DeviceStart = { deviceCode: string; userCode: string; expiresIn: number; interval: number };

type Fx<A> = Effect.Effect<A, StoreError | AuthError>;

export type AuthApi = {
  readonly handler: (req: Request) => Fx<Response>;
  readonly providers: { github: boolean; vercel: boolean };
  readonly sessionOf: (req: Request) => Effect.Effect<SignedIn | null, AuthError>;
  /** The apm user bound to this account, binding it from the GitHub login the first time. Null for accounts without GitHub. */
  readonly apmUserOf: (authUserId: string) => Fx<User | null>;
  /** The lowercased GitHub login linked to this account, whether or not it became the apm name. */
  readonly gitHubNameOf: (authUserId: string) => Fx<string | null>;
  readonly profileOf: (authUserId: string) => Fx<{ name: string; email: string; image: string | null } | null>;
  readonly linked: (authUserId: string) => Fx<Linked[]>;
  readonly factors: (authUserId: string) => Fx<{ totp: boolean; passkeys: number }>;
  /**
   * Checks a proof and spends it on `purpose`. Every TOTP and recovery-code check takes from one budget;
   * a TOTP step is accepted once; a passkey check is bound to the session it made (`sessionToken`).
   */
  readonly checkProof: (input: { authUserId: string; sessionToken: string | null; proof: FactorProof; purpose: string }) => Fx<ProofCheck>;
  readonly startDevice: Fx<DeviceStart>;
  readonly pollDevice: (deviceCode: string) => Fx<DevicePoll>;
};

function decodeBase32(text: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";

  for (const ch of text.replace(/=+$/, "").toUpperCase()) {
    const i = alphabet.indexOf(ch);

    if (i >= 0) bits += i.toString(2).padStart(5, "0");
  }

  const out: number[] = [];

  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));

  return new Uint8Array(out);
}

function sameText(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);

  return x.length === y.length && timingSafeEqual(x, y);
}

type Gate = "open" | "factor-if-enrolled";

/**
 * The Better Auth routes the website and the device page use, and nothing else. Account changes that add or
 * remove a way in need the existing factor when the account has one. Everything else answers 404.
 */
const ROUTES: ReadonlyMap<string, { methods: readonly string[]; gate: Gate }> = new Map([
  ["get-session", { methods: ["GET"], gate: "open" }],
  ["sign-in/social", { methods: ["POST"], gate: "open" }],
  ["sign-out", { methods: ["POST"], gate: "open" }],
  ["error", { methods: ["GET"], gate: "open" }],
  ["ok", { methods: ["GET"], gate: "open" }],
  ["link-social", { methods: ["POST"], gate: "factor-if-enrolled" }],
  ["two-factor/enable", { methods: ["POST"], gate: "factor-if-enrolled" }],
  ["two-factor/disable", { methods: ["POST"], gate: "factor-if-enrolled" }],
  // Registration options are harmless on their own; the step that adds the passkey needs the existing factor.
  ["passkey/generate-register-options", { methods: ["GET"], gate: "open" }],
  ["passkey/verify-registration", { methods: ["POST"], gate: "factor-if-enrolled" }],
  ["passkey/generate-authenticate-options", { methods: ["GET"], gate: "open" }],
  ["passkey/verify-authentication", { methods: ["POST"], gate: "open" }],
  ["device", { methods: ["GET"], gate: "open" }],
  ["device/approve", { methods: ["POST"], gate: "open" }],
  ["device/deny", { methods: ["POST"], gate: "open" }],
]);

/** OAuth providers redirect back here. */
const CALLBACK_PREFIXES = ["callback/", "oauth2/callback/"];

/** What apm's own answers on the auth routes carry. */
type AuthReply = { error: string; code?: string } | { status: true };

function jsonResponse(body: AuthReply, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function refusal(check: Exclude<ProofCheck, { kind: "ok" }>): Response {
  switch (check.kind) {
    case "locked":
      return jsonResponse({ error: "Too many wrong codes. Wait 15 minutes and try again.", code: "LOCKED" }, 429);
    case "reused":
      return jsonResponse({ error: "That code was already used. Wait for the next code from your authenticator app.", code: "CODE_REUSED" }, 401);
    case "bad":
      return jsonResponse({ error: "That code is not valid.", code: "INVALID_CODE" }, 401);
    case "none":
      return jsonResponse({ error: "Confirm with your passkey first, or use your authenticator app.", code: "NO_FACTOR" }, 401);
    default: {
      const _exhaustive: never = check;

      return _exhaustive;
    }
  }
}

function buildBetterAuth(input: { pool: Pool; options: AuthOptions; baseURL: string; store: Store["Service"]; now: () => number }) {
  const { pool, options, store, now } = input;
  const baseURL = input.baseURL.replace(/\/$/, "");
  const web = new URL(baseURL);
  const gh = options.github ? { ...options.github, endpoints: options.github.endpoints ?? GITHUB } : null;
  const record = (effect: Effect.Effect<void, StoreError>): Promise<void> => Effect.runPromise(effect);

  return betterAuth({
    appName: "apm",
    database: pool,
    baseURL,
    basePath: "/api/auth",
    secret: options.secret,
    trustedOrigins: [web.origin],
    telemetry: { enabled: false },
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
      deviceAuthorization({ expiresIn: "15m", interval: "1s", validateClient: (id) => id === CLI_CLIENT_ID }),
    ],
    hooks: {
      after: createAuthMiddleware(async (ctx) => {
        // A passkey sign-in is a fresh second factor for one action, from the session it just made.
        if (ctx.path === "/passkey/verify-authentication") {
          const s = ctx.context.newSession;

          if (s) await record(store.recordPasskeyProof({ sessionToken: s.session.token, authUserId: s.user.id, at: now() }));
        }
      }),
    },
  });
}

export class Auth extends Context.Service<Auth, AuthApi>()("@apm/registry/Auth") {
  /**
   * Better Auth over the same Postgres. The instance (and its connection) is made on first use in a request,
   * so routes that never touch sign-in pay nothing for it, and the connection closes when the request ends.
   */
  static layer(input: { databaseUrl: string; options: AuthOptions; baseURL: string }): Layer.Layer<Auth, never, Store | Clock> {
    return Layer.effect(
      Auth,
      Effect.gen(function* () {
        const store = yield* Store;
        const clock = yield* Clock;
        const nowMs = yield* clock.now;
        const gh = input.options.github ?? null;
        const requestScope = yield* Effect.scope;

        const instance = yield* Effect.cached(
          Effect.acquireRelease(
            Effect.sync(() => {
              const pool = new Pool({ connectionString: input.databaseUrl, max: 1 });

              return { pool, auth: buildBetterAuth({ pool, options: input.options, baseURL: input.baseURL, store, now: () => nowMs }) };
            }),
            ({ pool }) => Effect.promise(() => pool.end()).pipe(Effect.ignore),
          ).pipe(
            Effect.map(({ auth }) => auth),
            Scope.provide(requestScope),
          ),
        );

        const call = <A>(operation: string, run: (auth: ReturnType<typeof buildBetterAuth>) => Promise<A>): Effect.Effect<A, AuthError> =>
          Effect.flatMap(instance, (auth) => Effect.tryPromise({ try: () => run(auth), catch: (cause) => new AuthError({ operation, cause }) }));

        const secretKey = Effect.flatMap(instance, (auth) =>
          Effect.tryPromise({ try: async () => (await auth.$context).secretConfig, catch: (cause) => new AuthError({ operation: "context", cause }) }),
        );

        const decrypt = (data: string) =>
          Effect.flatMap(secretKey, (key) => Effect.tryPromise({ try: () => symmetricDecrypt({ key, data }), catch: (cause) => new AuthError({ operation: "decrypt", cause }) }));

        const encrypt = (data: string) =>
          Effect.flatMap(secretKey, (key) => Effect.tryPromise({ try: () => symmetricEncrypt({ key, data }), catch: (cause) => new AuthError({ operation: "encrypt", cause }) }));

        const gitHubLoginOf = (authUserId: string) =>
          Effect.gen(function* () {
            const github = (yield* store.accountsOf(authUserId)).find((a) => a.provider === "github");
            const login = github ? yield* store.gitHubLogin(github.accountId) : null;

            return github && login ? { githubId: github.accountId, login } : null;
          });

        const apmUserOf = (authUserId: string): Fx<User | null> =>
          Effect.gen(function* () {
            const bound = yield* store.getUserByAuthId(authUserId);

            if (bound) {
              // The scope stays bound to GitHub's numeric id. A rename only changes the login shown.
              const gh = yield* gitHubLoginOf(authUserId);

              if (gh && bound.github_id === gh.githubId && bound.github_login !== gh.login) {
                yield* store.setGitHubLogin(bound.name, gh.login);

                return yield* store.getUserByAuthId(authUserId);
              }

              return bound;
            }

            const gh = yield* gitHubLoginOf(authUserId);

            if (!gh) return null;
            const name = gh.login.toLowerCase();
            const existing = yield* store.getUser(name);
            const link = { authUserId, githubId: gh.githubId, githubLogin: gh.login };

            if (!existing) {
              const profile = yield* store.authProfile(authUserId);
              yield* store.createUser({
                name,
                password_hash: "",
                email: profile?.email ?? "",
                created_at: yield* clock.now,
                auth_user_id: authUserId,
                github_id: gh.githubId,
                github_login: gh.login,
              });
            } else if (existing.auth_user_id === null && existing.password_hash === "" && (existing.github_id === null || existing.github_id === gh.githubId)) {
              // A passwordless name made outside sign-in (an operator's minted token): the GitHub account with that login claims it.
              yield* store.bindUser(name, link);
            } else {
              // The name belongs to someone else: an older password account, or a scope a renamed GitHub account keeps.
              return null;
            }

            return yield* store.getUserByAuthId(authUserId);
          });

        /** Runs one budgeted check: reserves an attempt first, settles it with the outcome. */
        const budgeted = (authUserId: string, check: Fx<ProofCheck>): Fx<ProofCheck> =>
          Effect.gen(function* () {
            const r = yield* store.reserveAttempt({ authUserId, at: yield* clock.wallNow });

            if (r.kind === "locked") return { kind: "locked" } satisfies ProofCheck;
            const result = yield* check.pipe(Effect.onError(() => store.settleAttempt({ id: r.id, authUserId, ok: false }).pipe(Effect.ignore)));
            yield* store.settleAttempt({ id: r.id, authUserId, ok: result.kind === "ok" });

            return result;
          });

        const checkTotp = (authUserId: string, code: SixDigits, phase: "enrolled" | "enrolling"): Fx<ProofCheck> =>
          Effect.gen(function* () {
            const row = yield* store.twoFactor(authUserId);

            if (!row || row.verified !== (phase === "enrolled")) return { kind: "none" } satisfies ProofCheck;

            return yield* budgeted(
              authUserId,
              Effect.gen(function* () {
                const raw = yield* decrypt(row.secret);
                const key = raw.startsWith("base32:") ? decodeBase32(raw.slice(7)) : new TextEncoder().encode(raw);
                // TOTP is anchored to wall-clock time, not the registry's clock.
                const step = matchingStep({ key, code, at: yield* clock.wallNow });

                if (step === null) return { kind: "bad" } satisfies ProofCheck;

                return (yield* store.acceptStep({ authUserId, step })) ? ({ kind: "ok" } satisfies ProofCheck) : ({ kind: "reused" } satisfies ProofCheck);
              }),
            );
          });

        const checkRecovery = (authUserId: string, code: string): Fx<ProofCheck> =>
          Effect.gen(function* () {
            const row = yield* store.twoFactor(authUserId);

            if (!row || !row.verified) return { kind: "none" } satisfies ProofCheck;

            return yield* budgeted(
              authUserId,
              Effect.gen(function* () {
                const decoded = RecoveryCodes.safeParse(JSON.parse(yield* decrypt(row.backupCodes)));

                if (!decoded.success) return { kind: "bad" } satisfies ProofCheck;
                const codes = decoded.data;
                const match = codes.find((c) => sameText(c, code));

                if (match === undefined) return { kind: "bad" } satisfies ProofCheck;
                const rest = yield* encrypt(JSON.stringify(codes.filter((c) => c !== match)));
                // Compare-and-swap: of two requests spending the same code, one wins.
                const swapped = yield* store.swapBackupCodes({ authUserId, expected: row.backupCodes, next: rest });

                return swapped ? ({ kind: "ok" } satisfies ProofCheck) : ({ kind: "reused" } satisfies ProofCheck);
              }),
            );
          });

        const checkProof = (input: { authUserId: string; sessionToken: string | null; proof: FactorProof; purpose: string }): Fx<ProofCheck> => {
          const { authUserId, proof } = input;

          switch (proof.kind) {
            case "totp":
              return checkTotp(authUserId, proof.code, "enrolled");
            case "recovery":
              return checkRecovery(authUserId, proof.code);
            case "passkey": {
              const sessionToken = input.sessionToken;

              if (sessionToken === null) return Effect.succeed({ kind: "none" });

              return Effect.gen(function* () {
                const spent = yield* store.consumePasskeyProof({ sessionToken, authUserId, purpose: input.purpose, at: yield* clock.now });

                return spent ? ({ kind: "ok" } satisfies ProofCheck) : ({ kind: "none" } satisfies ProofCheck);
              });
            }

            default: {
              const _exhaustive: never = proof;

              return _exhaustive;
            }
          }
        };

        const sessionOf = (req: Request): Effect.Effect<SignedIn | null, AuthError> =>
          call("getSession", (auth) => auth.api.getSession({ headers: req.headers })).pipe(
            // an unreadable or stale session cookie means "not signed in", as before the port
            Effect.orElseSucceed(() => null),
            Effect.map((raw) => {
              const s = SessionShape.safeParse(raw);

              if (!s.success) return null;

              return { authUserId: s.data.user.id, sessionToken: s.data.session.token, signedInAt: s.data.session.createdAt.getTime() };
            }),
          );

        /** Finishes authenticator setup: the first code from the app turns 2FA on. apm checks it, so the step is spent. */
        const enroll = (req: Request): Fx<Response> =>
          Effect.gen(function* () {
            const who = yield* sessionOf(req);

            if (!who) return jsonResponse({ error: "Sign in first." }, 401);
            const body = EnrollBody.safeParse(yield* Effect.promise(() => req.json().catch(() => null)));
            const code = body.success ? parseSixDigits(body.data.code) : null;

            if (!code) return jsonResponse({ error: "Send the 6-digit code your authenticator app shows.", code: "INVALID_CODE" }, 400);
            const row = yield* store.twoFactor(who.authUserId);

            if (!row) return jsonResponse({ error: "Start authenticator setup first." }, 400);

            if (row.verified) return jsonResponse({ error: "Your authenticator app is already set up." }, 400);
            const check = yield* checkTotp(who.authUserId, code, "enrolling");

            if (check.kind !== "ok") return refusal(check);
            yield* store.enableTwoFactor(who.authUserId);

            return jsonResponse({ status: true }, 200);
          });

        const handler = (req: Request): Fx<Response> =>
          Effect.gen(function* () {
            const path = new URL(req.url).pathname.replace(/^\/api\/auth\//, "");

            if (path === "two-factor/verify-totp" && req.method === "POST") return yield* enroll(req);

            if (CALLBACK_PREFIXES.some((p) => path.startsWith(p)) && (req.method === "GET" || req.method === "POST")) return yield* call("handler", (auth) => auth.handler(req));
            const route = ROUTES.get(path);

            if (!route || !route.methods.includes(req.method)) return jsonResponse({ error: "Not found" }, 404);

            if (route.gate === "factor-if-enrolled") {
              const who = yield* sessionOf(req);

              if (who) {
                const f = yield* store.authFactors(who.authUserId);

                if (f.totp || f.passkeys > 0) {
                  const proof = parseProofHeader(req.headers.get(PROOF_HEADER));

                  if (!proof) {
                    return jsonResponse(
                      { error: "This changes how you sign in, so it needs your current authenticator code, a recovery code, or your passkey.", code: "SECOND_FACTOR_REQUIRED" },
                      403,
                    );
                  }

                  const check = yield* checkProof({ authUserId: who.authUserId, sessionToken: who.sessionToken, proof, purpose: `account:${path}` });

                  if (check.kind !== "ok") return refusal(check);
                }
              }
            }

            return yield* call("handler", (auth) => auth.handler(req));
          });

        const api: AuthApi = {
          handler,
          providers: { github: gh !== null, vercel: input.options.vercel !== undefined },
          sessionOf,
          apmUserOf,
          gitHubNameOf: (authUserId) => Effect.map(gitHubLoginOf(authUserId), (gh) => (gh ? gh.login.toLowerCase() : null)),
          profileOf: (authUserId) => store.authProfile(authUserId),
          linked: (authUserId) => store.accountsOf(authUserId),
          factors: (authUserId) => store.authFactors(authUserId),
          checkProof,
          startDevice: call("deviceCode", (auth) => auth.api.deviceCode({ body: { client_id: CLI_CLIENT_ID } })).pipe(
            Effect.flatMap((raw) =>
              Effect.try({ try: () => DeviceStartShape.parse(raw), catch: (cause) => new AuthError({ operation: "deviceCode: parse", cause }) }),
            ),
            Effect.map((d) => ({ deviceCode: d.device_code, userCode: d.user_code, expiresIn: d.expires_in, interval: d.interval })),
          ),
          pollDevice: (deviceCode) =>
            Effect.gen(function* () {
              const auth = yield* instance;

              // Better Auth answers a pending or refused grant by throwing its API error; the code says which.
              const result = yield* Effect.tryPromise({
                try: () => auth.api.deviceToken({ body: { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: deviceCode, client_id: CLI_CLIENT_ID } }),
                catch: (e) => {
                  const err = ApiErrorShape.safeParse(e);

                  return err.success ? err.data.body.error : "expired_token";
                },
              }).pipe(Effect.result);

              if (Result.isFailure(result)) {
                const code = result.failure;

                if (code === "authorization_pending") return { kind: "pending" } as const;

                if (code === "slow_down") return { kind: "slow_down" } as const;

                if (code === "access_denied") return { kind: "denied" } as const;

                return { kind: "expired" } as const;
              }

              const tok = DeviceTokenShape.safeParse(result.success);

              if (!tok.success) return { kind: "expired" } as const;
              // The CLI gets an apm token, not a website session: drop the session the grant made.
              const userId = yield* store.takeSession(tok.data.access_token);

              if (userId === null) return { kind: "expired" } as const;

              return { kind: "approved", authUserId: userId } as const;
            }),
        };

        return Auth.of(api);
      }),
    );
  }
}
