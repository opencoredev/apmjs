// Routes for people and the CLI login: the signed-in account, device login for `apm login`,
// website step-up checks, and staged versions waiting for a person to approve them.
import { existsSync, readFileSync, rmSync } from "node:fs";
import { z } from "zod";
import { finalize, parseAnalysis, readTarball } from "@apm/core";
import type { ApmAuth, SignedIn } from "./auth.ts";
import type { StagedRecord, User } from "./db.ts";
import { commitVersion, fail, issueToken, json, publishRefusal, stagedTarballPath, type Ctx } from "./server.ts";

const CodeBody = z.object({ code: z.string().optional() });
const DeviceTokenBody = z.object({ deviceCode: z.string().min(1) });
const RevokeTokenBody = z.object({ id: z.string().min(8) });

/** Marks staged versions past 24h as expired and deletes their tarballs. */
export function sweepStaged(ctx: Ctx): void {
  for (const id of ctx.store.expireStaged(ctx.now())) {
    try {
      rmSync(stagedTarballPath(ctx, id), { force: true });
    } catch {
      // a malformed id never names a file
    }
  }
}

async function readBody<T>(req: Request, schema: z.ZodType<T>): Promise<{ ok: true; value: T } | { ok: false; res: Response }> {
  let raw: unknown = {};
  const text = await req.text();
  if (text.trim() !== "") {
    try {
      raw = JSON.parse(text);
    } catch {
      return { ok: false, res: fail(400, "Body must be JSON.") };
    }
  }
  const parsed = schema.safeParse(raw);
  return parsed.success ? { ok: true, value: parsed.data } : { ok: false, res: fail(400, `Invalid request body: ${parsed.error.message}`) };
}

export function accountRoutes(input: { ctx: Ctx; auth: ApmAuth }): (req: Request, url: URL) => Promise<Response | null> {
  const { ctx, auth } = input;
  const web = (): string => ctx.access.webUrl();

  /** Cookie-authenticated writes must come from the website (or the registry itself, for tests). */
  function badOrigin(req: Request): Response | null {
    const origin = req.headers.get("origin");
    if (origin === null) return null;
    const allowed = new Set([new URL(web()).origin, new URL(ctx.baseUrl()).origin]);
    return allowed.has(origin) ? null : fail(403, "Cross-site request refused.");
  }

  async function signedIn(req: Request): Promise<{ s: SignedIn; user: User | null } | Response> {
    const s = await auth.sessionOf(req);
    if (!s) return fail(401, `Sign in at ${web()} first.`);
    return { s, user: auth.apmUserOf(s.authUserId) };
  }

  function mayApprove(row: StagedRecord, user: string): boolean {
    return row.staged_by === user || ctx.store.owners(row.package).includes(user);
  }

  function stagedSummary(row: StagedRecord): Record<string, unknown> {
    return {
      id: row.id,
      package: row.package,
      version: row.version,
      publisher: row.staged_by,
      tag: row.tag,
      stagedAt: new Date(row.staged_at).toISOString(),
      expiresAt: new Date(row.expires_at).toISOString(),
      status: row.status,
      url: `${web()}approve/${row.id}`,
    };
  }

  function stagedDetail(row: StagedRecord): Record<string, unknown> {
    const path = stagedTarballPath(ctx, row.id);
    let files: { path: string; size: number }[] = [];
    if (existsSync(path)) {
      try {
        files = readTarball(new Uint8Array(readFileSync(path)))
          .map((f) => ({ path: f.path, size: f.size }))
          .sort((a, b) => a.path.localeCompare(b.path));
      } catch {
        files = [];
      }
    }
    const analysis = parseAnalysis(row.score);
    const report = analysis
      ? finalize(analysis, { publishedAt: Number.NEGATIVE_INFINITY, now: ctx.now(), deprecated: null, status: "active", statusReason: null })
      : null;
    const pkg = ctx.store.getPackage(row.package);
    const latest = pkg?.distTags.latest ?? null;
    return {
      ...stagedSummary(row),
      newPackage: pkg === null,
      currentLatest: latest,
      description: typeof row.manifest.description === "string" ? row.manifest.description : "",
      size: row.size,
      files,
      score: report,
    };
  }

  /** Approval needs a TOTP code now, or a passkey/TOTP check on the website within the last 10 minutes. */
  async function secondFactor(s: SignedIn, code: string | undefined): Promise<Response | null> {
    if (code !== undefined && code.trim() !== "") {
      const check = await auth.verifyTotp(s.authUserId, code.trim());
      switch (check.kind) {
        case "ok":
          return null;
        case "bad":
          return fail(401, "That code is not valid. Use the current 6-digit code from your authenticator app.");
        case "locked":
          return fail(429, "Too many wrong codes. Wait 15 minutes and try again.");
        case "none":
          return fail(401, "No authenticator app is set up on this account. Confirm with your passkey instead.");
        default: {
          const _exhaustive: never = check;
          return _exhaustive;
        }
      }
    }
    const at = ctx.store.stepupAt(s.authUserId);
    const t = ctx.now();
    if (at !== null && at <= t && t - at <= 10 * 60_000) return null;
    return fail(401, "Confirm it's you: enter the code from your authenticator app, or use your passkey.");
  }

  return async (req, url) => {
    const p = url.pathname;
    if (!p.startsWith("/-/apm/v1/")) return null;
    const rest = p.slice("/-/apm/v1/".length);

    if (rest === "auth/config" && req.method === "GET") {
      const u = new URL(web());
      return json({ providers: auth.providers, passkeys: u.protocol === "https:" || u.hostname === "localhost", legacyAuth: ctx.access.legacyAuth, namePolicy: ctx.access.namePolicy });
    }

    // ---------- apm login: device flow ----------
    if (rest === "login/device" && req.method === "POST") {
      const d = await auth.startDevice();
      return json({
        deviceCode: d.deviceCode,
        userCode: d.userCode,
        verificationUrl: `${web()}device`,
        verificationUrlComplete: `${web()}device?code=${encodeURIComponent(d.userCode)}`,
        interval: d.interval,
        expiresIn: d.expiresIn,
      });
    }
    if (rest === "login/device/token" && req.method === "POST") {
      const body = await readBody(req, DeviceTokenBody);
      if (!body.ok) return body.res;
      const r = await auth.pollDevice(body.value.deviceCode);
      switch (r.kind) {
        case "pending":
          return json({ error: "authorization_pending" }, 400);
        case "slow_down":
          return json({ error: "slow_down" }, 400);
        case "denied":
          return json({ error: "access_denied", message: "The login was denied in the browser." }, 403);
        case "expired":
          return json({ error: "expired_token", message: "The code expired. Run apm login again." }, 410);
        case "approved": {
          const user = auth.apmUserOf(r.authUserId);
          if (!user) return json({ error: "no_scope", message: `Link your GitHub account at ${web()}account first: your apm scope is your GitHub login.` }, 403);
          const token = issueToken(ctx, { user: user.name, label: "apm login", scope: "stage" });
          return json({ token, username: user.name });
        }
        default: {
          const _exhaustive: never = r;
          return _exhaustive;
        }
      }
    }

    // ---------- the signed-in account ----------
    if (rest === "account" && req.method === "GET") {
      const who = await signedIn(req);
      if (who instanceof Response) return who;
      const { s, user } = who;
      const profile = auth.profileOf(s.authUserId);
      const factors = auth.factors(s.authUserId);
      const tokens = user
        ? ctx.store.listTokens(user.name).map((t) => ({
            id: t.token_hash.slice(0, 16),
            label: t.label,
            scope: t.scope,
            createdAt: new Date(t.created_at).toISOString(),
            expiresAt: t.expires_at === null ? null : new Date(t.expires_at).toISOString(),
            revokedAt: t.revoked_at === null ? null : new Date(t.revoked_at).toISOString(),
          }))
        : [];
      const stepup = ctx.store.stepupAt(s.authUserId);
      const githubName = auth.gitHubNameOf(s.authUserId);
      return json({
        scope: user?.name ?? null,
        // GitHub is linked but its login is already an older apm account's name: needs a name dispute.
        scopeTaken: user === null && githubName !== null ? githubName : null,
        github: user?.github_login ?? null,
        name: profile?.name ?? "",
        email: profile?.email ?? "",
        image: profile?.image ?? null,
        linked: auth.linked(s.authUserId),
        security: { totp: factors.totp, passkeys: factors.passkeys, verifiedAt: stepup === null ? null : new Date(stepup).toISOString() },
        canPublish: user !== null && (factors.totp || factors.passkeys > 0),
        tokens,
        pending: user ? ctx.store.pendingFor(user.name).length : 0,
      });
    }
    if (rest === "account/tokens/revoke" && req.method === "POST") {
      const bad = badOrigin(req);
      if (bad) return bad;
      const who = await signedIn(req);
      if (who instanceof Response) return who;
      if (!who.user) return fail(404, "No tokens on this account.");
      const body = await readBody(req, RevokeTokenBody);
      if (!body.ok) return body.res;
      const match = ctx.store.listTokens(who.user.name).filter((t) => t.token_hash.startsWith(body.value.id));
      const [one, ...more] = match;
      if (!one || more.length > 0) return fail(404, "No such token.");
      ctx.store.revokeToken(one.token_hash, ctx.now());
      return json({ ok: true });
    }
    if (rest === "verify" && req.method === "POST") {
      const bad = badOrigin(req);
      if (bad) return bad;
      const who = await signedIn(req);
      if (who instanceof Response) return who;
      const body = await readBody(req, CodeBody);
      if (!body.ok) return body.res;
      if (!body.value.code) return fail(400, "Send the 6-digit code from your authenticator app.");
      const denied = await secondFactor(who.s, body.value.code);
      if (denied) return denied;
      const at = ctx.now();
      ctx.store.setStepup(who.s.authUserId, at, "totp");
      return json({ ok: true, until: new Date(at + 10 * 60_000).toISOString() });
    }

    // ---------- staged versions ----------
    if (rest === "staged" && req.method === "GET") {
      const who = await signedIn(req);
      if (who instanceof Response) return who;
      if (!who.user) return json({ staged: [] });
      return json({ staged: ctx.store.pendingFor(who.user.name).map(stagedSummary) });
    }
    const m = /^staged\/([A-Za-z0-9_-]+)(?:\/(approve|reject))?$/.exec(rest);
    if (m?.[1]) {
      const id = m[1];
      const action = m[2] ?? null;
      if (action === null && req.method !== "GET") return fail(405, "Method not allowed");
      if (action !== null && req.method !== "POST") return fail(405, "Method not allowed");
      if (action !== null) {
        const bad = badOrigin(req);
        if (bad) return bad;
      }
      const who = await signedIn(req);
      if (who instanceof Response) return who;
      const row = ctx.store.getStaged(id);
      if (!row) return fail(404, "No staged version with that id.");
      if (!who.user || !mayApprove(row, who.user.name)) return fail(403, `Only ${row.staged_by} or an owner of ${row.package} can approve this.`);
      if (action === null) return json(stagedDetail(row));
      if (row.status === "expired" || (row.status === "pending" && row.expires_at <= ctx.now())) {
        sweepStaged(ctx);
        return fail(410, `${row.package}@${row.version} waited more than 24h and expired. Publish it again to get a new link.`);
      }
      if (row.status !== "pending") return fail(409, `${row.package}@${row.version} was already ${row.status}.`);
      const user = who.user.name;
      if (action === "reject") {
        ctx.store.decideStaged(id, { status: "rejected", at: ctx.now(), by: user });
        rmSync(stagedTarballPath(ctx, id), { force: true });
        return json({ ok: true, status: "rejected" });
      }
      const body = await readBody(req, CodeBody);
      if (!body.ok) return body.res;
      const denied = await secondFactor(who.s, body.value.code);
      if (denied) return denied;
      if (ctx.store.getVersion(row.package, row.version)) return fail(409, `${row.package}@${row.version} already exists. Versions are immutable; bump the version.`);
      const perm = await publishRefusal(ctx, row.package, row.staged_by);
      if (perm) return fail(perm.status, perm.error);
      const path = stagedTarballPath(ctx, id);
      if (!existsSync(path)) return fail(410, "The staged tarball is gone. Publish it again.");
      const done = commitVersion(ctx, {
        name: row.package,
        version: row.version,
        manifest: row.manifest,
        tarball: { stagedPath: path },
        shasum: row.shasum,
        integrity: row.integrity,
        tag: row.tag,
        readme: row.readme,
        score: row.score,
        publisher: row.staged_by,
        detail: { approvedBy: user, stagedAt: new Date(row.staged_at).toISOString() },
      });
      if (done.kind === "refused") return fail(done.status, done.error);
      ctx.store.decideStaged(id, { status: "approved", at: ctx.now(), by: user });
      return json({ ok: true, status: "approved", package: row.package, version: row.version });
    }
    return null;
  };
}
