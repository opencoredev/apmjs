// Sign-in for people: Better Auth with GitHub and Vercel, TOTP 2FA, passkeys and the device flow that
// `apm login` uses. Better Auth's tables live in the registry's SQLite file next to apm's own.
// An apm name (and scope) is the lowercased GitHub login of the signed-in account; Vercel-only accounts
// have no name until they link GitHub.
import { betterAuth } from "better-auth";
import { genericOAuth, twoFactor, deviceAuthorization } from "better-auth/plugins";
import { createAuthMiddleware } from "better-auth/api";
import { getMigrations } from "better-auth/db/migration";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { passkey } from "@better-auth/passkey";
import { timingSafeEqual } from "node:crypto";
import { z } from "zod";
import type { Store, User } from "./db.ts";
import { FactorLedger, matchingStep, parseSixDigits, type SixDigits } from "./factors.ts";

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

const CLI_CLIENT_ID = "apm-cli";

/** The header the website sends the existing factor in, for account changes that need it. */
export const PROOF_HEADER = "x-apm-second-factor";

const GitHubUser = z.object({ id: z.number(), login: z.string(), name: z.string().nullish(), email: z.string().nullish(), avatar_url: z.string().nullish() });
const GitHubEmails = z.array(z.object({ email: z.string(), primary: z.boolean(), verified: z.boolean() }));
const SessionShape = z.object({ session: z.object({ token: z.string(), userId: z.string(), createdAt: z.coerce.date() }), user: z.object({ id: z.string() }).loose() });
const DeviceStartShape = z.object({ device_code: z.string(), user_code: z.string(), expires_in: z.number(), interval: z.number() });
const DeviceTokenShape = z.object({ access_token: z.string() });
const ApiErrorShape = z.object({ body: z.object({ error: z.string() }).loose() });

export type SignedIn = { authUserId: string; sessionToken: string; signedInAt: number };

/** A second factor offered for one action: a TOTP code, a recovery code, or this session's passkey check. */
export type FactorProof = { kind: "totp"; code: SixDigits } | { kind: "recovery"; code: string } | { kind: "passkey" };

export type ProofCheck = { kind: "ok" } | { kind: "bad" } | { kind: "reused" } | { kind: "none" } | { kind: "locked" };
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
  /**
   * Checks a proof and spends it on `purpose`. Every TOTP and recovery-code check takes from one budget;
   * a TOTP step is accepted once; a passkey check is bound to the session it made (`sessionToken`).
   */
  checkProof: (input: { authUserId: string; sessionToken: string | null; proof: FactorProof; purpose: string }) => Promise<ProofCheck>;
  ledger: FactorLedger;
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

/** Parses the proof header: `totp:123456`, `recovery:abcde-12345` or `passkey`. */
export function parseProofHeader(value: string | null): FactorProof | null {
  if (value === null) return null;
  const v = value.trim();

  if (v === "passkey") return { kind: "passkey" };

  if (v.startsWith("totp:")) {
    const code = parseSixDigits(v.slice(5));

    return code ? { kind: "totp", code } : null;
  }

  if (v.startsWith("recovery:")) {
    const code = v.slice(9).trim();

    return /^[A-Za-z0-9-]{6,64}$/.test(code) ? { kind: "recovery", code } : null;
  }

  return null;
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

function sameText(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);

  return x.length === y.length && timingSafeEqual(x, y);
}

export async function createAuth(input: {
  store: Store;
  options: AuthOptions;
  baseURL: string;
  now: () => number;
  /** The clock authenticator codes are checked against. Wall-clock time; tests pass their own. */
  totpNow?: () => number;
}): Promise<ApmAuth> {
  const { store, options, now } = input;
  const totpNow = input.totpNow ?? Date.now;
  const ledger = new FactorLedger(store.db);
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
      // Accounts come from GitHub or Vercel and have no password. The route gates below ask for the existing
      // factor instead, and apm checks TOTP codes itself (one budget, each step once).
      twoFactor({ issuer: "apm", allowPasswordless: true }),
      passkey({ rpID: web.hostname, rpName: "apm", origin: web.origin }),
      deviceAuthorization({ expiresIn: "15m", interval: "1s", validateClient: (id) => id === CLI_CLIENT_ID }),
    ],
    hooks: {
      after: createAuthMiddleware(async (ctx) => {
        // A passkey sign-in is a fresh second factor for one action, from the session it just made.
        if (ctx.path === "/passkey/verify-authentication") {
          const s = ctx.context.newSession;

          if (s) ledger.recordPasskeyProof({ sessionToken: s.session.token, authUserId: s.user.id, at: now() });
        }
      }),
    },
  });

  const migrations = await getMigrations(auth.options);
  await migrations.runMigrations();
  const context = await auth.$context;

  function accountsOf(authUserId: string): Linked[] {
    return db
      .query("SELECT providerId, accountId FROM account WHERE userId = ? ORDER BY createdAt")
      .all(authUserId)
      .map((r) => z.object({ providerId: z.string(), accountId: z.string() }).parse(r))
      .map((r) => ({ provider: r.providerId, accountId: r.accountId }));
  }

  function gitHubLoginOf(authUserId: string): { githubId: string; login: string } | null {
    const github = accountsOf(authUserId).find((a) => a.provider === "github");
    const login = github ? store.gitHubLogin(github.accountId) : null;

    return github && login ? { githubId: github.accountId, login } : null;
  }

  function apmUserOf(authUserId: string): User | null {
    const bound = store.getUserByAuthId(authUserId);

    if (bound) {
      // The scope stays bound to GitHub's numeric id. A rename only changes the login shown.
      const gh = gitHubLoginOf(authUserId);

      if (gh && bound.github_id === gh.githubId && bound.github_login !== gh.login) {
        store.setGitHubLogin(bound.name, gh.login);

        return store.getUserByAuthId(authUserId);
      }

      return bound;
    }

    const gh = gitHubLoginOf(authUserId);

    if (!gh) return null;
    const { login } = gh;
    const name = login.toLowerCase();
    const existing = store.getUser(name);
    const link = { authUserId, githubId: gh.githubId, githubLogin: login };
    if (!existing) {
      const profile = db.query("SELECT email FROM user WHERE id = ?").get(authUserId);
      const email = profile ? z.object({ email: z.string() }).parse(profile).email : "";
      store.createUser({ name, password_hash: "", email, created_at: now(), auth_user_id: authUserId, github_id: gh.githubId, github_login: login });
    } else if (existing.auth_user_id === null && existing.password_hash === "" && (existing.github_id === null || existing.github_id === gh.githubId)) {
      // A passwordless name made outside sign-in (an operator's minted token): the GitHub account with that login claims it.
      store.bindUser(name, link);
    } else {
      // The name belongs to someone else: an older password account, or a scope a renamed GitHub account keeps.
      return null;
    }
    return store.getUserByAuthId(authUserId);
  }

  const TwoFactorRow = z.object({ secret: z.string(), backupCodes: z.string(), verified: z.union([z.number(), z.boolean(), z.null()]) });

  function twoFactorRow(authUserId: string): z.infer<typeof TwoFactorRow> | null {
    const row = db.query("SELECT secret, backupCodes, verified FROM twoFactor WHERE userId = ?").get(authUserId);

    return row ? TwoFactorRow.parse(row) : null;
  }

  const isVerified = (v: number | boolean | null): boolean => v !== 0 && v !== false;

  /** Runs one budgeted check: reserves an attempt first, settles it with the outcome. */
  async function budgeted(authUserId: string, check: () => Promise<ProofCheck>): Promise<ProofCheck> {
    const r = ledger.reserve({ authUserId, at: totpNow() });

    if (r.kind === "locked") return { kind: "locked" };
    let result: ProofCheck = { kind: "bad" };

    try {
      result = await check();
    } finally {
      ledger.settle({ id: r.id, authUserId, ok: result.kind === "ok" });
    }

    return result;
  }

  async function checkTotp(authUserId: string, code: SixDigits, phase: "enrolled" | "enrolling"): Promise<ProofCheck> {
    const row = twoFactorRow(authUserId);

    if (!row || isVerified(row.verified) !== (phase === "enrolled")) return { kind: "none" };

    return budgeted(authUserId, async () => {
      const raw = await symmetricDecrypt({ key: context.secretConfig, data: row.secret });
      const key = raw.startsWith("base32:") ? decodeBase32(raw.slice(7)) : new TextEncoder().encode(raw);
      // TOTP is anchored to wall-clock time, not the registry's clock.
      const step = matchingStep({ key, code, at: totpNow() });

      if (step === null) return { kind: "bad" };

      return ledger.acceptStep({ authUserId, step }) ? { kind: "ok" } : { kind: "reused" };
    });
  }

  async function checkRecovery(authUserId: string, code: string): Promise<ProofCheck> {
    const row = twoFactorRow(authUserId);

    if (!row || !isVerified(row.verified)) return { kind: "none" };

    return budgeted(authUserId, async () => {
      const codes = z.array(z.string()).parse(JSON.parse(await symmetricDecrypt({ key: context.secretConfig, data: row.backupCodes })));
      const match = codes.find((c) => sameText(c, code));

      if (match === undefined) return { kind: "bad" };
      const rest = await symmetricEncrypt({ key: context.secretConfig, data: JSON.stringify(codes.filter((c) => c !== match)) });
      // Compare-and-swap: of two requests spending the same code, one wins.
      const swapped = db.query("UPDATE twoFactor SET backupCodes = ? WHERE userId = ? AND backupCodes = ?").run(rest, authUserId, row.backupCodes);

      return swapped.changes === 1 ? { kind: "ok" } : { kind: "reused" };
    });
  }

  async function checkProof(input: { authUserId: string; sessionToken: string | null; proof: FactorProof; purpose: string }): Promise<ProofCheck> {
    const { authUserId, proof } = input;

    switch (proof.kind) {
      case "totp":
        return checkTotp(authUserId, proof.code, "enrolled");
      case "recovery":
        return checkRecovery(authUserId, proof.code);
      case "passkey":
        if (input.sessionToken === null) return { kind: "none" };

        return ledger.consumePasskeyProof({ sessionToken: input.sessionToken, authUserId, purpose: input.purpose, at: now() }) ? { kind: "ok" } : { kind: "none" };
      default: {
        const _exhaustive: never = proof;

        return _exhaustive;
      }
    }
  }

  function factors(authUserId: string) {
    const u = db.query("SELECT twoFactorEnabled FROM user WHERE id = ?").get(authUserId);
    const totp = u ? Boolean(z.object({ twoFactorEnabled: z.union([z.number(), z.boolean(), z.null()]) }).parse(u).twoFactorEnabled) : false;
    const pk = db.query("SELECT count(*) AS n FROM passkey WHERE userId = ?").get(authUserId);

    return { totp, passkeys: pk ? z.object({ n: z.number() }).parse(pk).n : 0 };
  }

  async function sessionOf(req: Request): Promise<SignedIn | null> {
    const raw: unknown = await auth.api.getSession({ headers: req.headers }).catch(() => null);
    const s = SessionShape.safeParse(raw);

    if (!s.success) return null;

    return { authUserId: s.data.user.id, sessionToken: s.data.session.token, signedInAt: s.data.session.createdAt.getTime() };
  }

  function refusal(check: ProofCheck): Response {
    switch (check.kind) {
      case "ok":
        return jsonResponse({ error: "ok" }, 500);
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

  /** Finishes authenticator setup: the first code from the app turns 2FA on. apm checks it, so the step is spent. */
  async function enroll(req: Request): Promise<Response> {
    const who = await sessionOf(req);

    if (!who) return jsonResponse({ error: "Sign in first." }, 401);
    const body = z.object({ code: z.string() }).safeParse(await req.json().catch(() => null));
    const code = body.success ? parseSixDigits(body.data.code) : null;

    if (!code) return jsonResponse({ error: "Send the 6-digit code your authenticator app shows.", code: "INVALID_CODE" }, 400);
    const row = twoFactorRow(who.authUserId);

    if (!row) return jsonResponse({ error: "Start authenticator setup first." }, 400);

    if (isVerified(row.verified)) return jsonResponse({ error: "Your authenticator app is already set up." }, 400);
    const check = await checkTotp(who.authUserId, code, "enrolling");

    if (check.kind !== "ok") return refusal(check);
    db.transaction(() => {
      db.query("UPDATE twoFactor SET verified = 1 WHERE userId = ?").run(who.authUserId);
      db.query("UPDATE user SET twoFactorEnabled = 1 WHERE id = ?").run(who.authUserId);
    })();

    return jsonResponse({ status: true }, 200);
  }

  async function handler(req: Request): Promise<Response> {
    const path = new URL(req.url).pathname.replace(/^\/api\/auth\//, "");

    if (path === "two-factor/verify-totp" && req.method === "POST") return enroll(req);

    if (CALLBACK_PREFIXES.some((p) => path.startsWith(p)) && (req.method === "GET" || req.method === "POST")) return auth.handler(req);
    const route = ROUTES.get(path);

    if (!route || !route.methods.includes(req.method)) return jsonResponse({ error: "Not found" }, 404);

    if (route.gate === "factor-if-enrolled") {
      const who = await sessionOf(req);

      if (who) {
        const f = factors(who.authUserId);

        if (f.totp || f.passkeys > 0) {
          const proof = parseProofHeader(req.headers.get(PROOF_HEADER));

          if (!proof) {
            return jsonResponse(
              { error: "This changes how you sign in, so it needs your current authenticator code, a recovery code, or your passkey.", code: "SECOND_FACTOR_REQUIRED" },
              403,
            );
          }

          const check = await checkProof({ authUserId: who.authUserId, sessionToken: who.sessionToken, proof, purpose: `account:${path}` });

          if (check.kind !== "ok") return refusal(check);
        }
      }
    }

    return auth.handler(req);
  }

  return {
    handler,
    providers: { github: gh !== null, vercel: options.vercel !== undefined },
    sessionOf,
    apmUserOf,
    gitHubNameOf(authUserId) {
      const gh = gitHubLoginOf(authUserId);

      return gh ? gh.login.toLowerCase() : null;
    },
    profileOf(authUserId) {
      const row = db.query("SELECT name, email, image FROM user WHERE id = ?").get(authUserId);
      return row ? z.object({ name: z.string(), email: z.string(), image: z.string().nullable() }).parse(row) : null;
    },
    linked: accountsOf,
    factors,
    checkProof,
    ledger,
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
