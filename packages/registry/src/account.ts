// Routes for people and the CLI login: the signed-in account, device login for `apm login`,
// website step-up checks, and staged versions waiting for a person to approve them.
import { existsSync, readFileSync, rmSync } from "node:fs";
import { z } from "zod";
import { finalize, parseAnalysis, readTarball, SCORE_FLOOR, type ScoreReport, type TarEntry } from "@apm/core";
import { actionKey, commandLine, LiveAction } from "./actions.ts";
import type { ApmAuth, SignedIn } from "./auth.ts";
import type { StagedRecord, User } from "./db.ts";
import { GRANT_MS } from "./factors.ts";
import { commitVersion, fail, issueToken, json, publishRefusal, stagedTarballPath, type Ctx } from "./server.ts";
import { ProofFields, secondFactor } from "./step-up.ts";

const ApproveBody = z.object({ ...ProofFields, confirmName: z.string().optional() });
const VerifyBody = z.object({ ...ProofFields, command: LiveAction });
const DeviceTokenBody = z.object({ deviceCode: z.string().min(1) });
const RevokeTokenBody = z.object({ id: z.string().min(8) });

/** File contents the approval page shows, at most. */
const MAX_FILE_TEXT = 512 * 1024;

/**
 * Why a person must type the package name to approve this version, or null. The analysis did not finish
 * (no report, or the tarball could not be listed), or the score is under the floor.
 */
export function typedConfirmationReason(input: { report: Pick<ScoreReport, "score"> | null; filesListed: boolean }): string | null {
  if (input.report === null || !input.filesListed) return "The analysis did not finish, so nothing below was checked.";

  if (input.report.score < SCORE_FLOOR) return `The score is ${input.report.score}, under the floor of ${SCORE_FLOOR}.`;

  return null;
}

function looksBinary(data: Uint8Array): boolean {
  const head = data.subarray(0, 8000);

  if (head.includes(0)) return true;

  try {
    new TextDecoder("utf-8", { fatal: true }).decode(head.length === data.length ? data : head.subarray(0, Math.max(0, head.length - 4)));

    return false;
  } catch {
    return true;
  }
}

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

  function stagedEntries(row: StagedRecord): TarEntry[] | null {
    const path = stagedTarballPath(ctx, row.id);

    if (!existsSync(path)) return null;

    try {
      return readTarball(new Uint8Array(readFileSync(path)));
    } catch {
      return null;
    }
  }

  /** What a person reviews before approving: the files, the score report, and whether they must type the name. */
  function reviewOf(row: StagedRecord) {
    const entries = stagedEntries(row);
    const analysis = parseAnalysis(row.score);
    const report = analysis
      ? finalize(analysis, { publishedAt: Number.NEGATIVE_INFINITY, now: ctx.now(), deprecated: null, status: "active", statusReason: null })
      : null;

    return { entries, report, typed: typedConfirmationReason({ report, filesListed: entries !== null }) };
  }

  function stagedDetail(row: StagedRecord): Record<string, unknown> {
    const { entries, report, typed } = reviewOf(row);
    const files = (entries ?? []).map((f) => ({ path: f.path, size: f.size })).sort((a, b) => a.path.localeCompare(b.path));
    const pkg = ctx.store.getPackage(row.package);
    const latest = pkg?.distTags.latest ?? null;
    return {
      ...stagedSummary(row),
      newPackage: pkg === null,
      currentLatest: latest,
      description: typeof row.manifest.description === "string" ? row.manifest.description : "",
      size: row.size,
      integrity: row.integrity,
      shasum: row.shasum,
      files,
      score: report,
      floor: SCORE_FLOOR,
      analysis: report === null || entries === null ? "incomplete" : "complete",
      confirmation: typed === null ? { kind: "plain" } : { kind: "typed", reason: typed },
    };
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
      const githubName = auth.gitHubNameOf(s.authUserId);
      return json({
        scope: user?.name ?? null,
        // GitHub is linked but its login is already an older apm account's name: needs a name dispute.
        scopeTaken: user === null && githubName !== null ? githubName : null,
        github: user?.github_login ?? null,
        // The GitHub login changed after the scope was claimed. The scope stays; a name dispute can move packages.
        githubRenamed: user !== null && user.github_login !== null && user.github_login.toLowerCase() !== user.name,
        name: profile?.name ?? "",
        email: profile?.email ?? "",
        image: profile?.image ?? null,
        linked: auth.linked(s.authUserId),
        security: { totp: factors.totp, passkeys: factors.passkeys },
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

    // A person confirms one named CLI command; the CLI may then run that command once, within 10 minutes.
    if (rest === "verify" && req.method === "POST") {
      const bad = badOrigin(req);
      if (bad) return bad;
      const who = await signedIn(req);
      if (who instanceof Response) return who;
      const body = await readBody(req, VerifyBody);
      if (!body.ok) return body.res;
      const command = body.value.command;
      const denied = await secondFactor({ auth, session: who.s, body: body.value, purpose: `confirm:${actionKey(command)}` });
      if (denied) return denied;
      const { expiresAt } = auth.ledger.grant({ authUserId: who.s.authUserId, action: actionKey(command), at: ctx.now() });

      return json({ ok: true, command: commandLine(command), until: new Date(expiresAt).toISOString(), validForMs: GRANT_MS });
    }

    // ---------- staged versions ----------
    if (rest === "staged" && req.method === "GET") {
      const who = await signedIn(req);
      if (who instanceof Response) return who;
      if (!who.user) return json({ staged: [] });
      return json({ staged: ctx.store.pendingFor(who.user.name).map(stagedSummary) });
    }

    const m = /^staged\/([A-Za-z0-9_-]+)(?:\/(approve|reject|file))?$/.exec(rest);
    if (m?.[1]) {
      const id = m[1];
      const action = m[2] ?? null;
      const read = action === null || action === "file";

      if (read && req.method !== "GET") return fail(405, "Method not allowed");

      if (!read && req.method !== "POST") return fail(405, "Method not allowed");

      if (!read) {
        const bad = badOrigin(req);
        if (bad) return bad;
      }
      const who = await signedIn(req);
      if (who instanceof Response) return who;
      const row = ctx.store.getStaged(id);
      if (!row) return fail(404, "No staged version with that id.");
      if (!who.user || !mayApprove(row, who.user.name)) return fail(403, `Only ${row.staged_by} or an owner of ${row.package} can approve this.`);
      if (action === null) return json(stagedDetail(row));

      if (action === "file") {
        // Read-only: one file's contents, looked up by its exact path in the staged tarball.
        const want = url.searchParams.get("path") ?? "";
        const entry = (stagedEntries(row) ?? []).find((e) => e.path === want);

        if (!entry) return fail(404, "No such file in this upload.");
        const binary = looksBinary(entry.data);
        const truncated = !binary && entry.data.length > MAX_FILE_TEXT;
        const text = binary ? null : new TextDecoder().decode(entry.data.subarray(0, MAX_FILE_TEXT));

        return json({ path: entry.path, size: entry.size, binary, truncated, text });
      }
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

      const body = await readBody(req, ApproveBody);
      if (!body.ok) return body.res;
      const { typed } = reviewOf(row);

      if (typed !== null && body.value.confirmName !== row.package) {
        return fail(400, `${typed} Type the package name, ${row.package}, to approve it anyway.`);
      }

      const denied = await secondFactor({ auth, session: who.s, body: body.value, purpose: `approve:${id}` });
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
