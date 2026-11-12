// Routes for people and the CLI login: the signed-in account, device login for `apm login`,
// website confirmations of one CLI command, and staged versions waiting for a person to approve them.
import { Effect, Option } from "effect";
import { z } from "zod";
import { finalize, parseAnalysis, readTarball, SCORE_FLOOR } from "@apm/core";
import { publishRefusal } from "./access.ts";
import { actionKey, commandLine, LiveAction } from "./actions.ts";
import { Auth, type SignedIn } from "./auth.ts";
import { Blobs } from "./blobs.ts";
import { Clock } from "./clock.ts";
import { RegistryConfig } from "./config.ts";
import { Store, type StagedRecord, type User } from "./db.ts";
import { refuse } from "./errors.ts";
import { fail, json, parseOptionalBody } from "./http.ts";
import { WORKER_MAX_UNPACKED_BYTES } from "./analysis.ts";
import { sha512, tarballKey } from "./hash.ts";
import { GRANT_MS, parseSixDigits, type FactorProof, type ProofCheck } from "./factors.ts";
import { typedConfirmationReason } from "./approval.ts";
import { commitVersion, dropBlobIfUnused, issueToken } from "./server.ts";

export { typedConfirmationReason } from "./approval.ts";

/** A second factor sent by the website: a TOTP code typed now, or the passkey check this session just made. */
const ProofFields = { code: z.string().optional(), passkey: z.literal(true).optional() };
const ApproveBody = z.object({ ...ProofFields, confirmName: z.string().optional() });
const VerifyBody = z.object({ ...ProofFields, command: LiveAction });
const DeviceTokenBody = z.object({ deviceCode: z.string().min(1) });
const RevokeTokenBody = z.object({ id: z.string().min(8) });

const now = Effect.flatMap(Clock, (c) => c.now);

/** File contents the approval page shows, at most. */
const MAX_FILE_TEXT = 512 * 1024;

type ProofFieldValues = { code?: string | undefined; passkey?: true | undefined };

/** The website's proof fields as a proof: a malformed code is an error, not "no code". */
function proofOf(body: ProofFieldValues): { kind: "ok"; proof: FactorProof } | { kind: "missing" } | { kind: "malformed" } {
  if (body.code !== undefined) {
    const code = parseSixDigits(body.code);

    return code ? { kind: "ok", proof: { kind: "totp", code } } : { kind: "malformed" };
  }

  if (body.passkey) return { kind: "ok", proof: { kind: "passkey" } };

  return { kind: "missing" };
}

function looksBinary(data: Uint8Array): boolean {
  const head = data.subarray(0, 8000);

  if (head.includes(0)) return true;

  try {
    new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(head.length === data.length ? data : head.subarray(0, Math.max(0, head.length - 4)));

    return false;
  } catch {
    return true;
  }
}

/** Marks staged versions past 24h as expired and deletes their tarballs. Runs from the cron. */
export const sweepStaged = Effect.gen(function* () {
  const expired = yield* (yield* Store).expireStaged(yield* now);

  for (const row of expired) yield* dropBlobIfUnused(row.tarball_key);
});

/** Cookie-authenticated writes must come from the website (or the registry itself, for tests). */
const checkOrigin = (req: Request) =>
  Effect.gen(function* () {
    const origin = req.headers.get("origin");

    if (origin === null) return;
    const { webUrl, baseUrl } = yield* RegistryConfig;
    const allowed = new Set([new URL(webUrl).origin, new URL(baseUrl).origin]);

    if (!allowed.has(origin)) return yield* Effect.fail(refuse(403, "Cross-site request refused."));
  });

const signedIn = (req: Request) =>
  Effect.gen(function* () {
    const auth = yield* Auth;
    const s = yield* auth.sessionOf(req);

    if (!s) return yield* Effect.fail(refuse(401, `Sign in at ${(yield* RegistryConfig).webUrl} first.`));
    const user: User | null = yield* auth.apmUserOf(s.authUserId);

    return { s, user };
  });

const mayApprove = (row: StagedRecord, user: string) =>
  Effect.map(
    Store.use((store) => store.owners(row.package)),
    (owners) => row.staged_by === user || owners.includes(user),
  );

const stagedSummary = (row: StagedRecord, webUrl: string): Record<string, unknown> => ({
  id: row.id,
  package: row.package,
  version: row.version,
  publisher: row.staged_by,
  tag: row.tag,
  stagedAt: new Date(row.staged_at).toISOString(),
  expiresAt: new Date(row.expires_at).toISOString(),
  status: row.status,
  url: `${webUrl}approve/${row.id}`,
});

/** The staged tarball's entries, or null when it is gone or cannot be read. */
const stagedEntries = (row: StagedRecord) =>
  Effect.gen(function* () {
    const blob = yield* (yield* Blobs).bytes(row.tarball_key);

    if (Option.isNone(blob)) return null;

    try {
      return readTarball(blob.value, WORKER_MAX_UNPACKED_BYTES);
    } catch {
      return null;
    }
  });

/** What a person reviews before approving: the files, the score report, and whether they must type the name. */
const reviewOf = (row: StagedRecord) =>
  Effect.gen(function* () {
    const entries = yield* stagedEntries(row);
    const analysis = parseAnalysis(row.score);
    const report = analysis ? finalize(analysis, { publishedAt: Number.NEGATIVE_INFINITY, now: yield* now, deprecated: null, status: "active", statusReason: null }) : null;

    return { entries, report, typed: typedConfirmationReason({ report, filesListed: entries !== null }) };
  });

const stagedDetail = (row: StagedRecord) =>
  Effect.gen(function* () {
    const { webUrl } = yield* RegistryConfig;
    const { entries, report, typed } = yield* reviewOf(row);
    const files = (entries ?? []).map((f) => ({ path: f.path, size: f.size })).sort((a, b) => a.path.localeCompare(b.path));
    const pkg = yield* (yield* Store).getPackage(row.package);
    const latest = pkg?.distTags.latest ?? null;

    return {
      ...stagedSummary(row, webUrl),
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
  });

function refused(check: Exclude<ProofCheck, { kind: "ok" }>) {
  switch (check.kind) {
    case "bad":
      return refuse(401, "That code is not valid. Use the current 6-digit code from your authenticator app.");
    case "reused":
      return refuse(401, "That code was already used. Wait for the next code from your authenticator app.");
    case "locked":
      return refuse(429, "Too many wrong codes. Wait 15 minutes and try again.");
    case "none":
      return refuse(401, "Confirm it's you: enter the code from your authenticator app, or use your passkey.");
    default: {
      const _exhaustive: never = check;

      return _exhaustive;
    }
  }
}

/** A second factor for one action, from this session: a code typed now, or this session's own passkey check. */
const secondFactor = (s: SignedIn, body: ProofFieldValues, purpose: string) =>
  Effect.gen(function* () {
    const p = proofOf(body);

    if (p.kind === "malformed") return yield* Effect.fail(refuse(400, "Send the 6-digit code from your authenticator app."));

    if (p.kind === "missing") return yield* Effect.fail(refuse(401, "Confirm it's you: enter the code from your authenticator app, or use your passkey."));
    const check = yield* (yield* Auth).checkProof({ authUserId: s.authUserId, sessionToken: s.sessionToken, proof: p.proof, purpose });

    if (check.kind !== "ok") return yield* Effect.fail(refused(check));
  });

/** The account and login routes under /-/apm/v1/; null when the path is not one of them. */
export const accountRoute = (req: Request, url: URL) =>
  Effect.gen(function* () {
    const p = url.pathname;

    if (!p.startsWith("/-/apm/v1/")) return null;
    const rest = p.slice("/-/apm/v1/".length);
    const config = yield* RegistryConfig;
    const web = config.webUrl;
    const store = yield* Store;

    if (rest === "auth/config" && req.method === "GET") {
      const auth = yield* Auth;
      const u = new URL(web);

      return json({ providers: auth.providers, passkeys: u.protocol === "https:" || u.hostname === "localhost", legacyAuth: config.legacyAuth, namePolicy: config.namePolicy });
    }

    // ---------- apm login: device flow ----------
    if (rest === "login/device" && req.method === "POST") {
      const d = yield* (yield* Auth).startDevice;

      return json({
        deviceCode: d.deviceCode,
        userCode: d.userCode,
        verificationUrl: `${web}device`,
        verificationUrlComplete: `${web}device?code=${encodeURIComponent(d.userCode)}`,
        interval: d.interval,
        expiresIn: d.expiresIn,
      });
    }

    if (rest === "login/device/token" && req.method === "POST") {
      const auth = yield* Auth;
      const body = yield* parseOptionalBody(req, DeviceTokenBody);
      const r = yield* auth.pollDevice(body.deviceCode);

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
          const user = yield* auth.apmUserOf(r.authUserId);

          if (!user) return json({ error: "no_scope", message: `Link your GitHub account at ${web}account first: your apm scope is your GitHub login.` }, 403);
          const token = yield* issueToken({ user: user.name, label: "apm login", scope: "stage" });

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
      const auth = yield* Auth;
      const { s, user } = yield* signedIn(req);
      const profile = yield* auth.profileOf(s.authUserId);
      const factors = yield* auth.factors(s.authUserId);

      const tokens = user
        ? (yield* store.listTokens(user.name)).map((t) => ({
            id: t.token_hash.slice(0, 16),
            label: t.label,
            scope: t.scope,
            createdAt: new Date(t.created_at).toISOString(),
            expiresAt: t.expires_at === null ? null : new Date(t.expires_at).toISOString(),
            revokedAt: t.revoked_at === null ? null : new Date(t.revoked_at).toISOString(),
          }))
        : [];

      const githubName = yield* auth.gitHubNameOf(s.authUserId);
      const pending = user ? (yield* store.pendingFor(user.name, yield* now)).length : 0;

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
        linked: yield* auth.linked(s.authUserId),
        security: { totp: factors.totp, passkeys: factors.passkeys },
        canPublish: user !== null && (factors.totp || factors.passkeys > 0),
        tokens,
        pending,
      });
    }

    if (rest === "account/tokens/revoke" && req.method === "POST") {
      yield* checkOrigin(req);
      const who = yield* signedIn(req);

      if (!who.user) return fail(404, "No tokens on this account.");
      const body = yield* parseOptionalBody(req, RevokeTokenBody);
      const match = (yield* store.listTokens(who.user.name)).filter((t) => t.token_hash.startsWith(body.id));
      const [one, ...more] = match;

      if (!one || more.length > 0) return fail(404, "No such token.");
      yield* store.revokeToken(one.token_hash, yield* now);

      return json({ ok: true });
    }

    // A person confirms one named CLI command; the CLI may then run that command once, within 10 minutes.
    if (rest === "verify" && req.method === "POST") {
      yield* checkOrigin(req);
      const who = yield* signedIn(req);
      const body = yield* parseOptionalBody(req, VerifyBody);
      const command = body.command;
      yield* secondFactor(who.s, body, `confirm:${actionKey(command)}`);
      const { expiresAt } = yield* store.grant({ authUserId: who.s.authUserId, action: actionKey(command), at: yield* now });

      return json({ ok: true, command: commandLine(command), until: new Date(expiresAt).toISOString(), validForMs: GRANT_MS });
    }

    // ---------- staged versions ----------
    if (rest === "staged" && req.method === "GET") {
      const who = yield* signedIn(req);

      if (!who.user) return json({ staged: [] });
      const rows = yield* store.pendingFor(who.user.name, yield* now);

      return json({ staged: rows.map((r) => stagedSummary(r, web)) });
    }

    const m = /^staged\/([A-Za-z0-9_-]+)(?:\/(approve|reject|file))?$/.exec(rest);

    if (m?.[1]) {
      const id = m[1];
      const action = m[2] ?? null;
      const read = action === null || action === "file";

      if (read && req.method !== "GET") return fail(405, "Method not allowed");

      if (!read && req.method !== "POST") return fail(405, "Method not allowed");

      if (!read) yield* checkOrigin(req);
      const who = yield* signedIn(req);
      const row = yield* store.getStaged(id);

      if (!row) return fail(404, "No staged version with that id.");

      if (!who.user || !(yield* mayApprove(row, who.user.name))) return fail(403, `Only ${row.staged_by} or an owner of ${row.package} can approve this.`);

      if (action === null) return json(yield* stagedDetail(row));

      if (action === "file") {
        // Read-only: one file's contents, looked up by its exact path in the staged tarball.
        const want = url.searchParams.get("path") ?? "";
        const entry = ((yield* stagedEntries(row)) ?? []).find((e) => e.path === want);

        if (!entry) return fail(404, "No such file in this upload.");
        const binary = looksBinary(entry.data);
        const truncated = !binary && entry.data.length > MAX_FILE_TEXT;
        const text = binary ? null : new TextDecoder().decode(entry.data.subarray(0, MAX_FILE_TEXT));

        return json({ path: entry.path, size: entry.size, binary, truncated, text });
      }

      const at = yield* now;

      if (row.status === "expired" || (row.status === "pending" && row.expires_at <= at)) {
        yield* sweepStaged;

        return fail(410, `${row.package}@${row.version} waited more than 24h and expired. Publish it again to get a new link.`);
      }

      if (row.status !== "pending") return fail(409, `${row.package}@${row.version} was already ${row.status}.`);
      const user = who.user.name;

      if (action === "reject") {
        yield* store.decideStaged(id, { status: "rejected", at, by: user });
        yield* dropBlobIfUnused(row.tarball_key);

        return json({ ok: true, status: "rejected" });
      }

      const body = yield* parseOptionalBody(req, ApproveBody);
      const { typed } = yield* reviewOf(row);

      if (typed !== null && body.confirmName !== row.package) {
        return fail(400, `${typed} Type the package name, ${row.package}, to approve it anyway.`);
      }

      yield* secondFactor(who.s, body, `approve:${id}`);

      if (yield* store.getVersion(row.package, row.version)) return fail(409, `${row.package}@${row.version} already exists. Versions are immutable; bump the version.`);
      const perm = yield* publishRefusal(row.package, row.staged_by);

      if (perm) return fail(perm.status, perm.error);
      const staged = yield* (yield* Blobs).bytes(row.tarball_key);

      if (Option.isNone(staged)) return fail(410, "The staged tarball is gone. Publish it again.");
      // the blob is content-addressed: bytes that no longer hash to their key were changed after upload
      const digest = sha512(staged.value);

      if (tarballKey(digest.hex) !== row.tarball_key || digest.integrity !== row.integrity) {
        return fail(409, `${row.package}@${row.version}: the staged tarball no longer matches what was uploaded. Publish it again.`);
      }

      // The decision and the version land together: of two approvals racing, one commits and the other gets a 409.
      yield* store.tx(
        Effect.gen(function* () {
          if (!(yield* store.decideStaged(id, { status: "approved", at, by: user }))) {
            return yield* Effect.fail(refuse(409, `${row.package}@${row.version} was already decided.`));
          }

          yield* commitVersion({
            name: row.package,
            version: row.version,
            manifest: row.manifest,
            tarballKey: row.tarball_key,
            size: row.size,
            shasum: row.shasum,
            integrity: row.integrity,
            tag: row.tag,
            readme: row.readme,
            score: row.score,
            publisher: row.staged_by,
            detail: { approvedBy: user, stagedAt: new Date(row.staged_at).toISOString() },
          });
        }),
      );

      return json({ ok: true, status: "approved", package: row.package, version: row.version });
    }

    return null;
  });
