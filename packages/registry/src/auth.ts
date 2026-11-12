// Sign-in for people: Better Auth with GitHub and Vercel, TOTP 2FA, passkeys and the device flow that
// `apm login` uses. Better Auth's tables live in the registry's SQLite file next to apm's own.
// An apm name (and scope) is the lowercased GitHub login of the signed-in account; Vercel-only accounts
// have no name until they link GitHub.
import { betterAuth } from "better-auth";
import { genericOAuth, twoFactor, deviceAuthorization } from "better-auth/plugins";
import { createAuthMiddleware } from "better-auth/api";
import { getMigrations } from "better-auth/db/migration";
import { symmetricDecrypt } from "better-auth/crypto";
import { passkey } from "@better-auth/passkey";
import { createOTP } from "@better-auth/utils/otp";
import { z } from "zod";
import type { Store, User } from "./db.ts";

export type GitHubEndpoints = { authorize: string; token: string; user: string; emails: string };
export type AuthOptions = {
  /** Signs session cookies and encrypts TOTP secrets. Keep it stable across restarts. */
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

/** How long a passkey or TOTP check on the website counts for actions that need a fresh second factor. */
export const STEPUP_MS = 10 * 60_000;
const CLI_CLIENT_ID = "apm-cli";
const MAX_FAILURES = 5;
const FAILURE_WINDOW_MS = 15 * 60_000;

const GitHubUser = z.object({ id: z.number(), login: z.string(), name: z.string().nullish(), email: z.string().nullish(), avatar_url: z.string().nullish() });
const GitHubEmails = z.array(z.object({ email: z.string(), primary: z.boolean(), verified: z.boolean() }));
const SessionShape = z.object({ session: z.object({ token: z.string(), userId: z.string(), createdAt: z.coerce.date() }), user: z.object({ id: z.string() }).loose() });
const DeviceStartShape = z.object({ device_code: z.string(), user_code: z.string(), expires_in: z.number(), interval: z.number() });
const DeviceTokenShape = z.object({ access_token: z.string() });
const ApiErrorShape = z.object({ body: z.object({ error: z.string() }).loose() });

export type SignedIn = { authUserId: string; sessionToken: string; signedInAt: number };
export type SecondFactorCheck = { kind: "ok" } | { kind: "bad" } | { kind: "none" } | { kind: "locked" };
export type DevicePoll =
  | { kind: "pending" }
  | { kind: "slow_down" }
  | { kind: "denied" }
  | { kind: "expired" }
  | { kind: "approved"; authUserId: string };
export type DeviceStart = { deviceCode: string; userCode: string; expiresIn: number; interval: number };
export type Linked = { provider: string; accountId: string };

export type ApmAuth = {
  handler: (req: Request) => Promise<Response>;
  providers: { github: boolean; vercel: boolean };
  sessionOf: (req: Request) => Promise<SignedIn | null>;
  /** The apm user bound to this account, binding it from the GitHub login the first time. Null for accounts without GitHub. */
  apmUserOf: (authUserId: string) => User | null;
  /** The lowercased GitHub login linked to this account, whether or not it became the apm name. */
  gitHubNameOf: (authUserId: string) => string | null;
  profileOf: (authUserId: string) => { name: string; email: string; image: string | null } | null;
  linked: (authUserId: string) => Linked[];
  factors: (authUserId: string) => { totp: boolean; passkeys: number };
  verifyTotp: (authUserId: string, code: string) => Promise<SecondFactorCheck>;
  startDevice: () => Promise<DeviceStart>;
  pollDevice: (deviceCode: string) => Promise<DevicePoll>;
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

export async function createAuth(input: { store: Store; options: AuthOptions; baseURL: string; now: () => number }): Promise<ApmAuth> {
  const { store, options, now } = input;
  const db = store.db;
  const baseURL = input.baseURL.replace(/\/$/, "");
  const web = new URL(baseURL);
  const gh = options.github ? { ...options.github, endpoints: options.github.endpoints ?? GITHUB } : null;

  const auth = betterAuth({
    appName: "apm",
    database: db,
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
                    store.setGitHubProfile(String(p.id), p.login, now());
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
      twoFactor({ issuer: "apm", allowPasswordless: true }),
      passkey({ rpID: web.hostname, rpName: "apm", origin: web.origin }),
      deviceAuthorization({ expiresIn: "15m", interval: "1s", validateClient: (id) => id === CLI_CLIENT_ID }),
    ],
    hooks: {
      after: createAuthMiddleware(async (ctx) => {
        // Signing in with a passkey is a fresh second factor.
        if (ctx.path === "/passkey/verify-authentication") {
          const s = ctx.context.newSession;
          if (s) store.setStepup(s.user.id, now(), "passkey");
        }
      }),
    },
  });

  const migrations = await getMigrations(auth.options);
  await migrations.runMigrations();
  const context = await auth.$context;

  const failures = new Map<string, { count: number; since: number }>();

  function accountsOf(authUserId: string): Linked[] {
    return db
      .query("SELECT providerId, accountId FROM account WHERE userId = ? ORDER BY createdAt")
      .all(authUserId)
      .map((r) => z.object({ providerId: z.string(), accountId: z.string() }).parse(r))
      .map((r) => ({ provider: r.providerId, accountId: r.accountId }));
  }

  function apmUserOf(authUserId: string): User | null {
    const bound = store.getUserByAuthId(authUserId);
    if (bound) return bound;
    const github = accountsOf(authUserId).find((a) => a.provider === "github");
    if (!github) return null;
    const login = store.gitHubLogin(github.accountId);
    if (!login) return null;
    const name = login.toLowerCase();
    const existing = store.getUser(name);
    const link = { authUserId, githubId: github.accountId, githubLogin: login };
    if (!existing) {
      const profile = db.query("SELECT email FROM user WHERE id = ?").get(authUserId);
      const email = profile ? z.object({ email: z.string() }).parse(profile).email : "";
      store.createUser({ name, password_hash: "", email, created_at: now(), auth_user_id: authUserId, github_id: github.accountId, github_login: login });
    } else if (existing.auth_user_id === null && existing.password_hash === "" && (existing.github_id === null || existing.github_id === github.accountId)) {
      // A passwordless name made outside sign-in (an operator's minted token): the GitHub account with that login claims it.
      store.bindUser(name, link);
    } else {
      // The name belongs to someone else: an older password account, or a renamed GitHub login another account took.
      return null;
    }
    return store.getUserByAuthId(authUserId);
  }

  async function verifyTotp(authUserId: string, code: string): Promise<SecondFactorCheck> {
    const f = failures.get(authUserId);
    const t = Date.now();
    if (f && t - f.since < FAILURE_WINDOW_MS && f.count >= MAX_FAILURES) return { kind: "locked" };
    const row = db.query("SELECT secret, verified FROM twoFactor WHERE userId = ?").get(authUserId);
    if (!row) return { kind: "none" };
    const tf = z.object({ secret: z.string(), verified: z.union([z.number(), z.boolean(), z.null()]) }).parse(row);
    if (tf.verified === 0 || tf.verified === false) return { kind: "none" };
    const raw = await symmetricDecrypt({ key: context.secretConfig, data: tf.secret });
    const secret = raw.startsWith("base32:") ? decodeBase32(raw.slice(7)) : raw;
    // TOTP is anchored to wall-clock time, not the registry's clock.
    const ok = /^\d{6}$/.test(code) && (await createOTP(secret, { digits: 6, period: 30 }).verify(code));
    if (ok) {
      failures.delete(authUserId);
      return { kind: "ok" };
    }
    const fresh = !f || t - f.since >= FAILURE_WINDOW_MS;
    failures.set(authUserId, fresh ? { count: 1, since: t } : { count: (f?.count ?? 0) + 1, since: f?.since ?? t });
    return { kind: "bad" };
  }

  return {
    handler: (req) => auth.handler(req),
    providers: { github: gh !== null, vercel: options.vercel !== undefined },
    async sessionOf(req) {
      const raw: unknown = await auth.api.getSession({ headers: req.headers }).catch(() => null);
      const s = SessionShape.safeParse(raw);
      if (!s.success) return null;
      return { authUserId: s.data.user.id, sessionToken: s.data.session.token, signedInAt: s.data.session.createdAt.getTime() };
    },
    apmUserOf,
    gitHubNameOf(authUserId) {
      const github = accountsOf(authUserId).find((a) => a.provider === "github");
      const login = github ? store.gitHubLogin(github.accountId) : null;
      return login ? login.toLowerCase() : null;
    },
    profileOf(authUserId) {
      const row = db.query("SELECT name, email, image FROM user WHERE id = ?").get(authUserId);
      return row ? z.object({ name: z.string(), email: z.string(), image: z.string().nullable() }).parse(row) : null;
    },
    linked: accountsOf,
    factors(authUserId) {
      const u = db.query("SELECT twoFactorEnabled FROM user WHERE id = ?").get(authUserId);
      const totp = u ? Boolean(z.object({ twoFactorEnabled: z.union([z.number(), z.boolean(), z.null()]) }).parse(u).twoFactorEnabled) : false;
      const pk = db.query("SELECT count(*) AS n FROM passkey WHERE userId = ?").get(authUserId);
      return { totp, passkeys: pk ? z.object({ n: z.number() }).parse(pk).n : 0 };
    },
    verifyTotp,
    async startDevice() {
      const raw: unknown = await auth.api.deviceCode({ body: { client_id: CLI_CLIENT_ID } });
      const d = DeviceStartShape.parse(raw);
      return { deviceCode: d.device_code, userCode: d.user_code, expiresIn: d.expires_in, interval: d.interval };
    },
    async pollDevice(deviceCode) {
      let raw: unknown;
      try {
        raw = await auth.api.deviceToken({ body: { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: deviceCode, client_id: CLI_CLIENT_ID } });
      } catch (e) {
        const err = ApiErrorShape.safeParse(e);
        const code = err.success ? err.data.body.error : "expired_token";
        if (code === "authorization_pending") return { kind: "pending" };
        if (code === "slow_down") return { kind: "slow_down" };
        if (code === "access_denied") return { kind: "denied" };
        return { kind: "expired" };
      }
      const tok = DeviceTokenShape.parse(raw);
      // The CLI gets an apm token, not a website session: drop the session the grant made.
      const row = db.query("SELECT userId FROM session WHERE token = ?").get(tok.access_token);
      db.query("DELETE FROM session WHERE token = ?").run(tok.access_token);
      if (!row) return { kind: "expired" };
      return { kind: "approved", authUserId: z.object({ userId: z.string() }).parse(row).userId };
    },
  };
}
