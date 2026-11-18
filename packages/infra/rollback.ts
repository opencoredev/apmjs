// Rolls apm's Workers back to an earlier deployment, through Cloudflare's Workers deployments API (the same calls
// `wrangler rollback` makes). Alchemy uploads each Worker as a new version and deploys it at 100%, so every deploy is a
// deployment Cloudflare keeps, and going back is one more deployment that routes all traffic to an older version. No
// code is rebuilt and no database is touched.
//
//   bun packages/infra/rollback.ts list     --stage production [--limit 5]
//   bun packages/infra/rollback.ts previous --stage production [--worker registry --worker web] [--yes]
//   bun packages/infra/rollback.ts to       --stage production --worker registry --deployment <id> [--yes]
//   bun packages/infra/rollback.ts to       --stage production --worker registry --version <version-id> [--yes]
//
// Without --yes it prints what it would do and changes nothing. `previous` takes each Worker to the newest deployment
// before its live one that runs different versions; after a rollback that is the deployment rolled back from, so use
// `list` and `to` then. Workers go back website first, then docs, then the registry: an older website runs against a
// newer registry, never the other way round (deploy.ts, "Order").
//
// This is the only rollback there is: deploy.ts never rolls back on its own. What it trusts is the release record
// (releases.ts): one canonical line per deploy run, written by deploy.ts under the release lock once that run's smoke
// check passed, naming each Worker's live version then. Every version a rollback would route traffic to, on every
// Worker and every share of a split deployment, must be one a line names as that Worker; the registry and website left
// live must be named by one line, a pair one deploy left live together; and that line's migration manifest must fit the
// stage's migration ledger (apm_migrations, read only, through ~/.config/apmjs/neon-url, within 15 s): every migration
// in it applied, and every applied migration not in it marked `-- apm:rollback-safe`, wherever it sorts. Just before
// each change, the Worker's live deployment is read again and must still be the one planned from, running versions the
// record names. Variables on a version are never trusted. --skip-migration-check skips only the ledger comparison, for
// someone who has looked at the schema by hand. Every deploy and rollback runs on evo-1 (docs/DEPLOY.md, "Scope").
//
// A rollback (--yes) takes the release lock (release-lock.ts) before it reads anything and holds it until it exits:
// the same exclusive flock deploy.ts and the incident agent's helper take, /home/leo/.config/apmjs/release.lock or the
// path in APM_RELEASE_LOCK. A held lock refuses at once with exit code 6.
//
// It reads the Cloudflare token from ~/.config/apmjs/cloudflare-token (APM_SECRETS_DIR overrides the folder) and never
// prints it; the account comes from cloudflare.env there, or from the token's only account.
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { migrationFiles } from "../registry/scripts/migrate.ts";
import { queryOnce } from "../registry/src/db-health.ts";
import { BUSY_CODE, takeReleaseLock } from "./release-lock.ts";
import { conflictingBuilds, ledgerPath, names, readReleases, releaseNamingAll, releaseOf, type Release } from "./releases.ts";

export const STAGES = ["staging", "production"] as const;

export type Stage = (typeof STAGES)[number];

/** apm's Workers, in the order a rollback takes them: the website before the registry it binds. */
export const WORKERS = ["web", "docs", "registry"] as const;

export type WorkerKind = (typeof WORKERS)[number];

export function scriptName(kind: WorkerKind, stage: Stage): string {
  return `apmjs-${kind}-${stage}`;
}

/** The marker a migration carries in its leading comment when code from before it still runs on the schema after it. */
export const ROLLBACK_SAFE = "-- apm:rollback-safe";

/** Whether `sql` declares itself safe to run older code against, in the comment lines it starts with. */
export function isRollbackSafe(sql: string): boolean {
  for (const line of sql.split("\n")) {
    const t = line.trim();

    if (t === "") continue;

    if (!t.startsWith("--")) return false;

    // the marker alone, or followed by why: "-- apm:rollback-safe: adds a table nothing older reads"
    if (t === ROLLBACK_SAFE || t.startsWith(`${ROLLBACK_SAFE} `) || t.startsWith(`${ROLLBACK_SAFE}:`)) return true;
  }

  return false;
}

/** The migrations among `ids` that are not marked rollback-safe (an id with no file counts as not safe). */
export function unsafeMigrations(ids: readonly string[]): string[] {
  const files = new Map(migrationFiles().map((m) => [m.id, m.sql]));

  return ids.filter((id) => {
    const sql = files.get(id);

    return sql === undefined || !isRollbackSafe(sql);
  });
}

// ---------- Cloudflare's Workers deployments API ----------
export const DEFAULT_API = "https://api.cloudflare.com/client/v4";

export type Cloudflare = { readonly apiBase: string; readonly token: string; readonly accountId: string };

const VersionShare = z.object({ version_id: z.string(), percentage: z.number() });

export type VersionShare = z.infer<typeof VersionShare>;

export const Deployment = z.object({
  id: z.string(),
  created_on: z.string(),
  source: z.string().optional(),
  author_email: z.string().optional(),
  versions: z.array(VersionShare),
  annotations: z.object({ "workers/message": z.string().optional(), "workers/triggered_by": z.string().optional() }).loose().optional(),
});

export type Deployment = z.infer<typeof Deployment>;

const ApiErrors = z.object({ success: z.boolean().optional(), errors: z.array(z.object({ code: z.number().optional(), message: z.string() })).optional() }).loose();

/** Thrown for an API answer that is not a success: its status and Cloudflare's messages, never the request's headers. */
export class CloudflareError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/** How long one Cloudflare API request may take, unless its caller has less time left. */
const REQUEST_TIMEOUT_MS = 30_000;

async function call<S extends z.ZodType>(cf: Cloudflare, path: string, schema: S, init: { method?: string; body?: unknown; timeoutMs?: number } = {}): Promise<z.output<S>> {
  const headers = new Headers({ authorization: `Bearer ${cf.token}` });

  if (init.body !== undefined) headers.set("content-type", "application/json");

  const res = await fetch(`${cf.apiBase}/accounts/${cf.accountId}${path}`, {
    method: init.method ?? "GET",
    headers,
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
    signal: AbortSignal.timeout(Math.max(1, Math.min(REQUEST_TIMEOUT_MS, init.timeoutMs ?? REQUEST_TIMEOUT_MS))),
  });

  // a body that is not JSON is reported below, by its status
  const raw = await res.json().catch(() => null);

  const errors = ApiErrors.safeParse(raw);
  const messages = errors.success ? (errors.data.errors ?? []).map((e) => `${e.code ?? "?"}: ${e.message}`).join("; ") : "";

  if (!res.ok || (errors.success && errors.data.success === false)) throw new CloudflareError(res.status, `Cloudflare answered ${res.status} for ${init.method ?? "GET"} ${path}${messages === "" ? "" : ` (${messages})`}`);
  const envelope = z.object({ result: z.unknown() }).safeParse(raw);
  const parsed = schema.safeParse(envelope.success ? envelope.data.result : undefined);

  if (!parsed.success) throw new CloudflareError(res.status, `Cloudflare's answer to ${path} is not in the expected shape: ${parsed.error.message}`);

  return parsed.data;
}

/** The script's deployments, newest first; null when the account has no such Worker. `timeoutMs` bounds the request. */
export async function listDeployments(cf: Cloudflare, script: string, timeoutMs?: number): Promise<Deployment[] | null> {
  try {
    const result = await call(cf, `/workers/scripts/${encodeURIComponent(script)}/deployments`, z.object({ deployments: z.array(Deployment) }), { timeoutMs });

    return [...result.deployments].sort((a, b) => b.created_on.localeCompare(a.created_on));
  } catch (e) {
    if (e instanceof CloudflareError && e.status === 404) return null;
    throw e;
  }
}

const VersionSettings = z.object({ resources: z.object({ bindings: z.array(z.object({ type: z.string(), name: z.string(), text: z.string().optional() }).loose()) }).loose() }).loose();

/** A version's plain-text variables, from its settings (secrets carry no text and are left out). `timeoutMs` bounds the request. */
export async function versionVariables(cf: Cloudflare, script: string, versionId: string, timeoutMs?: number): Promise<Record<string, string>> {
  const settings = await call(cf, `/workers/scripts/${encodeURIComponent(script)}/versions/${encodeURIComponent(versionId)}`, VersionSettings, { timeoutMs });

  return Object.fromEntries(settings.resources.bindings.flatMap((b) => (b.type === "plain_text" && b.text !== undefined ? [[b.name, b.text]] : [])));
}

/** Routes the script's traffic to `versions` as a new deployment (what wrangler rollback does, force included). */
export function deploy(cf: Cloudflare, script: string, versions: readonly VersionShare[], message: string): Promise<Deployment> {
  return call(cf, `/workers/scripts/${encodeURIComponent(script)}/deployments?force=true`, Deployment, {
    method: "POST",
    body: { strategy: "percentage", versions, annotations: { "workers/message": message.slice(0, 100) } },
  });
}

/** Whether two deployments route traffic to the same versions in the same shares. */
export function sameVersions(a: readonly VersionShare[], b: readonly VersionShare[]): boolean {
  const key = (v: readonly VersionShare[]): string =>
    [...v]
      .map((x) => `${x.version_id}:${x.percentage}`)
      .sort()
      .join(",");

  return key(a) === key(b);
}

/** The newest deployment before the live one (`deployments[0]`) that runs other versions; null when there is none. */
export function previousOf(deployments: readonly Deployment[]): Deployment | null {
  const [live, ...older] = deployments;

  if (live === undefined) return null;

  return older.find((d) => !sameVersions(d.versions, live.versions)) ?? null;
}

// ---------- the stage's secrets ----------
export const SECRETS = process.env.APM_SECRETS_DIR ?? join(homedir(), ".config", "apmjs");

function secretFile(name: string): string {
  const path = join(SECRETS, name);

  if (!existsSync(path)) throw new Error(`Missing ${path}. See docs/DEPLOY.md for the files the deploy reads.`);

  return readFileSync(path, "utf8").trim();
}

/** The account: CLOUDFLARE_ACCOUNT_ID in cloudflare.env, else the one account the token can see. */
async function accountOf(apiBase: string, token: string): Promise<string> {
  const env = join(SECRETS, "cloudflare.env");

  if (existsSync(env)) {
    const m = /^\s*CLOUDFLARE_ACCOUNT_ID\s*=\s*["']?([0-9a-f]{32})["']?\s*$/m.exec(readFileSync(env, "utf8"));

    if (m?.[1]) return m[1];
  }

  const res = await fetch(`${apiBase}/accounts`, { headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(30_000) });
  const body = z.object({ result: z.array(z.object({ id: z.string() })) }).safeParse(await res.json());

  if (!body.success || body.data.result.length !== 1) throw new Error(`Could not tell which Cloudflare account to use (HTTP ${res.status}); put CLOUDFLARE_ACCOUNT_ID in ${env}.`);

  return body.data.result[0]?.id ?? "";
}

export async function cloudflareFromSecrets(): Promise<Cloudflare> {
  const apiBase = process.env.APM_CLOUDFLARE_API ?? DEFAULT_API;
  const token = secretFile("cloudflare-token");

  return { apiBase, token, accountId: await accountOf(apiBase, token) };
}

// ---------- rolling back ----------
/** One Worker's step of a rollback: where it is and where it goes. */
export type Step = { kind: WorkerKind; script: string; from: Deployment; to: readonly VersionShare[]; toLabel: string };

export type Log = (line: string) => void;

/**
 * Runs `steps` in WORKERS order; stops at the first that fails or that `verify` refuses (it runs just before each
 * change, so what it checks is what is live at that moment), and says which went back and which did not.
 */
export async function rollBack(cf: Cloudflare, steps: readonly Step[], message: string, log: Log, verify: (step: Step) => Promise<string | null> = async () => null): Promise<boolean> {
  const ordered = [...steps].sort((a, b) => WORKERS.indexOf(a.kind) - WORKERS.indexOf(b.kind));

  for (const [i, s] of ordered.entries()) {
    const why = await verify(s);

    if (why !== null) {
      log(`NOT rolling back ${s.script}: ${why}`);

      for (const left of ordered.slice(i + 1)) log(`not rolled back: ${left.script} (stopped above)`);

      return false;
    }

    try {
      const d = await deploy(cf, s.script, s.to, message);
      log(`rolled back ${s.script}: deployment ${s.from.id} → ${s.toLabel} (new deployment ${d.id})`);
    } catch (e) {
      log(`FAILED to roll back ${s.script}: ${e instanceof Error ? e.message : String(e)}`);

      for (const left of ordered.slice(i + 1)) log(`not rolled back: ${left.script} (stopped at the failure above)`);

      return false;
    }
  }

  return true;
}

/** The stage's database, as deploy.ts reaches it; null without neon-url. */
function stageDatabaseUrl(stage: Stage): string | null {
  const path = join(SECRETS, "neon-url");

  if (!existsSync(path)) return null;
  const url = new URL(readFileSync(path, "utf8").trim());
  url.pathname = stage === "production" ? "/neondb" : "/apmjs_staging";
  url.searchParams.set("sslmode", "verify-full");

  return url.toString();
}

/** How long reading the ledger may take, connecting and closing included. */
export const LEDGER_DEADLINE_MS = 15_000;

const LedgerRows = z.array(z.object({ id: z.string() }));

/**
 * Every migration the database at `url` has applied, from its ledger (read only); null when it cannot be read within
 * `deadlineMs`. The whole read is bounded, and at the deadline its connection is destroyed (db-health.ts, queryOnce), so
 * a server that authenticates and then stops answering costs nothing past it.
 */
export async function ledgerOf(url: string | null, deadlineMs: number = LEDGER_DEADLINE_MS): Promise<string[] | null> {
  if (url === null) return null;
  const rows = LedgerRows.safeParse(await queryOnce(url, "SELECT id FROM apm_migrations ORDER BY id", deadlineMs));

  return rows.success ? rows.data.map((r) => r.id) : null;
}

/**
 * The variables deploy.ts stamps on every registry version it uploads (alchemy.run.ts): the commit it was built from,
 * and its full migration manifest, every migration id in that commit, split into parts that each fit a Worker variable
 * and sealed with the sha256 of the whole list.
 */
export const REVISION_VAR = "APM_REVISION";

/** One id per deploy run, on every Worker that run uploads: a registry and a website with the same build were deployed together. */
export const BUILD_VAR = "APM_BUILD";

const BUILD_ID = /^[0-9a-f][0-9a-f-]{7,63}$/;

export const MIGRATIONS_PARTS_VAR = "APM_MIGRATIONS_PARTS";

export const MIGRATIONS_SHA_VAR = "APM_MIGRATIONS_SHA256";

const MIGRATIONS_PART_PREFIX = "APM_MIGRATIONS_";

/** A Worker variable holds 5 KB; each part stays well under it. */
const PART_CHARS = 4_000;

const MAX_PARTS = 64;

function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

/** A version's provenance as Worker variables: the revision, the manifest's parts, their count and its seal. */
export type ProvenanceVariables = Readonly<Record<`APM_${string}`, string>>;

/** The variables that stamp `revision`, the deploy run's `build` and `ids` (a commit's migrations, in order) on a version. */
export function provenanceVars(revision: string, build: string, ids: readonly string[]): ProvenanceVariables {
  if (!BUILD_ID.test(build)) throw new Error(`not a build id: ${build}`);
  const joined = ids.join(",");
  const parts: string[] = [];

  for (let at = 0; at < joined.length || parts.length === 0; at += PART_CHARS) parts.push(joined.slice(at, at + PART_CHARS));

  if (parts.length > MAX_PARTS) throw new Error(`the migration manifest needs ${parts.length} parts, past the ${MAX_PARTS} rollback.ts reads`);

  return { [REVISION_VAR]: revision, [BUILD_VAR]: build, [MIGRATIONS_PARTS_VAR]: String(parts.length), [MIGRATIONS_SHA_VAR]: sha256(joined), ...Object.fromEntries(parts.map((part, i) => [`${MIGRATIONS_PART_PREFIX}${i}`, part])) };
}

export type MigrationCheck = { kind: "unreadable" } | { kind: "not-applied"; version: string; ids: string[] } | { kind: "unsafe"; ids: string[] } | { kind: "ok"; extra: string[] };

/** The versions of a deployment that receive traffic. */
export function receiving(versions: readonly VersionShare[]): VersionShare[] {
  return versions.filter((v) => v.percentage > 0);
}

/**
 * Whether code built with `manifests` (each target version's migration manifest, from the release record) can run on
 * today's schema: every migration in a manifest must be in the migration ledger (its code expects them), and every
 * migration the ledger holds beyond a manifest, wherever it sorts, must be marked rollback-safe. A ledger that cannot
 * be read is never "ok".
 */
export async function migrationCheck(input: { manifests: readonly { version: string; migrations: readonly string[] }[]; ledger: () => Promise<readonly string[] | null> }): Promise<MigrationCheck> {
  const ledger = await input.ledger();

  if (ledger === null) return { kind: "unreadable" };
  const applied = new Set(ledger);
  const extra = new Set<string>();

  for (const m of input.manifests) {
    const mine = new Set(m.migrations);
    const notApplied = m.migrations.filter((id) => !applied.has(id));

    if (notApplied.length > 0) return { kind: "not-applied", version: m.version, ids: notApplied };

    for (const id of ledger) if (!mine.has(id)) extra.add(id);
  }

  const unsafe = unsafeMigrations([...extra]);

  return unsafe.length > 0 ? { kind: "unsafe", ids: unsafe } : { kind: "ok", extra: [...extra] };
}

/** Why a check refuses, in a sentence; null when it allows the rollback. */
export function refusal(check: MigrationCheck): string | null {
  switch (check.kind) {
    case "unreadable":
      return "the stage's migration ledger could not be read (no neon-url, or the database did not answer in time)";
    case "not-applied":
      return `the target version ${check.version} was built with ${check.ids.join(", ")}, which the database has not applied`;
    case "unsafe":
      return `${check.ids.join(", ")} ${check.ids.length === 1 ? "is" : "are"} applied but not in the target's migration manifest, and not marked ${ROLLBACK_SAFE}, so its code may not run on today's schema`;
    case "ok":
      return null;
    default: {
      const _exhaustive: never = check;

      return _exhaustive;
    }
  }
}

/**
 * Whether `steps` may run: the reason it may not, or null. Trust comes from the release record (releases.ts): one
 * canonical line per deploy run, written by deploy.ts under the release lock after that run's smoke check passed. A
 * version's variables are never trusted.
 *
 * - Afterwards, every registry and website version receiving traffic, rolled back or left as it is, must be named by
 *   one canonical line: a pair one deploy left live together. No other pairing counts, however close in time.
 * - Every version that would receive traffic on a Worker being rolled back, on every share of a split deployment, must
 *   be named by a canonical line as that Worker (the pair's line, for the registry and website), and that line's
 *   migration manifest must fit the migration ledger (migrationCheck; `skipMigrationCheck` skips only this part).
 */
export async function checkRollback(input: { cf: Cloudflare; stage: Stage; steps: readonly Step[]; releases: readonly Release[]; ledger: () => Promise<readonly string[] | null>; skipMigrationCheck?: boolean }): Promise<string | null> {
  let ledger: Promise<readonly string[] | null> | null = null;
  const once = (): Promise<readonly string[] | null> => (ledger ??= input.ledger());
  let pairLine: Release | null = null;

  if (input.steps.some((s) => s.kind === "registry" || s.kind === "web")) {
    const pairs: { script: string; versionId: string }[] = [];

    for (const kind of ["registry", "web"] as const) {
      const script = scriptName(kind, input.stage);
      const step = input.steps.find((s) => s.kind === kind);
      const versions = step?.to ?? (await listDeployments(input.cf, script))?.[0]?.versions ?? [];

      if (receiving(versions).length === 0) return `${script} has no version receiving traffic, so no pair can be checked`;

      for (const v of receiving(versions)) pairs.push({ script, versionId: v.version_id });
    }

    pairLine = releaseNamingAll(input.releases, pairs);

    if (pairLine === null) {
      return `the registry and the website would run ${pairs.map((p) => `${p.script} ${p.versionId}`).join(", ")}, which no one line of the release record (${ledgerPath()}) names together: not a pair one deploy left live. Roll both back to one build: rollback.ts to --build <id> (see list)`;
    }
  }

  for (const step of input.steps) {
    const versions = receiving(step.to);

    if (versions.length === 0) return `${step.script}: the target routes no traffic`;
    const manifests: { version: string; migrations: readonly string[] }[] = [];

    for (const v of versions) {
      const line = step.kind === "docs" ? releaseOf(input.releases, step.script, v.version_id) : pairLine;

      if (line === null || !names(line, step.script, v.version_id)) return `${step.script}: the target version ${v.version_id} is not in the release record (${ledgerPath()}): no recorded deploy left it live, so what it is cannot be trusted`;
      manifests.push({ version: v.version_id, migrations: line.manifest });
    }

    if (input.skipMigrationCheck === true) continue;
    const why = refusal(await migrationCheck({ manifests, ledger: once }));

    if (why !== null) return `${step.script}: ${why}`;
  }

  return null;
}

/**
 * Just before a step's change: what is live must still be what the plan read (the same deployment), and every version
 * it routes traffic to must be one the release record names as that Worker. Anything else (someone deployed, or rolled
 * back, since) refuses the rest.
 */
export async function liveStillAsPlanned(cf: Cloudflare, step: Step, releases: readonly Release[]): Promise<string | null> {
  const live = (await listDeployments(cf, step.script))?.[0];

  if (live === undefined) return "it has no deployment now";

  if (live.id !== step.from.id) return `its live deployment is now ${live.id}, not ${step.from.id} as planned: someone changed it meanwhile`;

  return unrecordedLive(step.script, live, releases);
}

/** The placeholder unrecordedVersions gives for a live deployment that routes traffic to no version. */
export function noVersionLive(live: Deployment): string {
  return `deployment ${live.id}, which routes traffic to no version`;
}

/**
 * The versions `live` routes traffic to that no line of the release record names as `script`. A deployment that routes
 * traffic to no version at all (an empty or all-0% list, which Cloudflare should never answer) names nothing the record
 * could vouch for, so it is one unrecorded entry (noVersionLive), never an empty, vacuously recorded list.
 */
export function unrecordedVersions(script: string, live: Deployment, releases: readonly Release[]): string[] {
  const shares = receiving(live.versions);

  if (shares.length === 0) return [noVersionLive(live)];

  return shares.filter((v) => releaseOf(releases, script, v.version_id) === null).map((v) => v.version_id);
}

/** What to run instead when a live version is one the record does not name. */
export function fixForward(stage: Stage): string {
  return `fix forward: deploy a fixed commit with bun packages/infra/deploy.ts deploy --stage ${stage}`;
}

/**
 * Why `script`'s live deployment may not be replaced, or null: a version no line of the release record names is one
 * rollback.ts cannot identify (a deploy that failed or was stopped after its upload and before its record, or a change
 * made outside deploy.ts), so it never replaces it. The way out is a new deploy.
 */
export function unrecordedLive(script: string, live: Deployment, releases: readonly Release[]): string | null {
  const unknown = unrecordedVersions(script, live, releases);

  if (unknown.length === 0) return null;
  const stage = STAGES.find((s) => script.endsWith(`-${s}`)) ?? "production";

  if (receiving(live.versions).length === 0) return `${script}'s live ${noVersionLive(live)}, so what runs there cannot be identified. rollback.ts does not replace what it cannot identify; ${fixForward(stage)}`;

  return `${script} runs ${unknown.join(", ")}, which no line of the release record names (an upload from a deploy that failed or was stopped before it recorded, or a change outside deploy.ts). rollback.ts does not replace a version it cannot identify; ${fixForward(stage)}`;
}

function describe(d: Deployment): string {
  const versions = d.versions.map((v) => `${v.version_id}${v.percentage === 100 ? "" : ` (${v.percentage}%)`}`).join(", ");
  const message = d.annotations?.["workers/message"];

  return `${d.id}  ${d.created_on}  ${d.source ?? "?"}  versions ${versions}${message ? `  "${message}"` : ""}`;
}

const Args = z.object({
  action: z.enum(["list", "previous", "to"]),
  build: z.string().nullable(),
  stage: z.enum(STAGES),
  workers: z.array(z.enum(WORKERS)),
  deployment: z.string().nullable(),
  version: z.string().nullable(),
  limit: z.coerce.number().int().min(1).max(50),
  yes: z.boolean(),
  skipMigrationCheck: z.boolean(),
});

function flagValues(argv: readonly string[], flag: string): string[] {
  return argv.flatMap((a, i) => (a === flag && argv[i + 1] !== undefined ? [argv[i + 1] ?? ""] : []));
}

export function parseArgs(argv: readonly string[]) {
  return Args.parse({
    action: argv[0],
    build: flagValues(argv, "--build")[0] ?? null,
    stage: flagValues(argv, "--stage")[0] ?? "staging",
    workers: flagValues(argv, "--worker"),
    deployment: flagValues(argv, "--deployment")[0] ?? null,
    version: flagValues(argv, "--version")[0] ?? null,
    limit: flagValues(argv, "--limit")[0] ?? "5",
    yes: argv.includes("--yes"),
    skipMigrationCheck: argv.includes("--skip-migration-check"),
  });
}

/** Where one Worker goes: its versions and how to name them. */
type Target = { versions: readonly VersionShare[]; label: string };

/** The CLI: returns its exit code. */
export async function main(argv: readonly string[], log: Log = (l) => process.stdout.write(`${l}\n`)): Promise<number> {
  const args = parseArgs(argv);

  // a change holds the release lock (APM_RELEASE_LOCK) before it reads anything, so no deploy or other rollback moves
  // these Workers while this one decides; it is held until this process exits
  if (args.yes && args.action !== "list") {
    const taken = takeReleaseLock({ script: import.meta.path, argv, stage: args.stage });

    if (taken.kind === "busy") {
      log(`Not rolling back: ${taken.text}`);

      return BUSY_CODE;
    }
  }

  const cf = await cloudflareFromSecrets();
  const releases = readReleases(args.stage);

  for (const build of conflictingBuilds(args.stage)) log(`release record: build ${build} has lines that disagree; none of them is trusted`);

  if (args.action === "list") {
    for (const kind of WORKERS) {
      const script = scriptName(kind, args.stage);
      const all = await listDeployments(cf, script);

      log(`${script}:`);

      if (all === null) {
        log("  no such Worker");
        continue;
      }

      for (const [i, d] of all.slice(0, args.limit).entries()) {
        const recorded = receiving(d.versions).map((v) => releaseOf(releases, script, v.version_id));
        const first = recorded[0];

        const build =
          first === undefined || first === null || recorded.some((r) => r?.build !== first.build)
            ? "not in the release record"
            : `build ${first.build} (${first.sha.slice(0, 12)})${kind === "registry" ? `, install checks ${first.installChecks ?? "database"}` : ""}`;

        log(`  ${i === 0 ? "live" : "    "}  ${describe(d)}  ${build}`);
      }
    }

    return 0;
  }

  const byBuild = args.action === "to" && args.build !== null;
  // a build names a pair: the website and the registry go back to it together (and docs too, when asked for)
  const kinds = byBuild ? (args.workers.includes("docs") ? (["web", "docs", "registry"] as const) : (["web", "registry"] as const)) : args.workers.length > 0 ? args.workers : args.action === "previous" ? (["web", "registry"] as const) : [];

  if (kinds.length === 0) {
    log("Name the Worker to roll back with --worker registry|web|docs, or a build with --build <id>.");

    return 2;
  }

  if (args.action === "to" && !byBuild && (kinds.length !== 1 || (args.deployment === null) === (args.version === null))) {
    log("`to` takes --build <id>, or one --worker and either --deployment <id> or --version <version-id>.");

    return 2;
  }

  const steps: Step[] = [];

  for (const kind of kinds) {
    const script = scriptName(kind, args.stage);
    const all = await listDeployments(cf, script);
    const live = all?.[0];

    if (all === null || live === undefined) {
      log(`${script}: no deployments; nothing to roll back`);

      return 1;
    }

    let target: Target;

    if (byBuild) {
      const uploaded = releases.findLast((r) => r.build === args.build)?.workers[kind];

      if (uploaded === undefined || uploaded.script !== script) {
        log(`${script}: the release record has no ${kind} version of build ${args.build} (see \`list\`)`);

        return 1;
      }

      target = { versions: [{ version_id: uploaded.versionId, percentage: 100 }], label: `version ${uploaded.versionId} (build ${args.build})` };
    } else if (args.action === "previous") {
      const prev = previousOf(all);

      if (prev === null) {
        log(`${script}: no earlier deployment runs other versions`);

        return 1;
      }

      target = { versions: prev.versions, label: `deployment ${prev.id} of ${prev.created_on}` };
    } else if (args.deployment !== null) {
      const named = all.find((d) => d.id === args.deployment);

      if (named === undefined) {
        log(`${script}: no deployment ${args.deployment} among its recent ones (see \`list\`)`);

        return 1;
      }

      target = { versions: named.versions, label: `deployment ${named.id} of ${named.created_on}` };
    } else {
      const versionId = args.version ?? "";
      target = { versions: [{ version_id: versionId, percentage: 100 }], label: `version ${versionId}` };
    }

    if (sameVersions(target.versions, live.versions)) {
      log(`${script}: already runs ${target.label}`);
      continue;
    }

    steps.push({ kind, script, from: live, to: target.versions, toLabel: target.label });
  }

  if (steps.length === 0) return 0;

  // a live version the record does not name is never replaced: say so now, not after a plan that cannot run
  for (const s of steps) {
    const unknown = unrecordedLive(s.script, s.from, releases);

    if (unknown !== null) {
      log(`Not rolling back: ${unknown}. Nothing changed.`);

      return 1;
    }
  }

  const why = await checkRollback({ cf, stage: args.stage, steps, releases, ledger: () => ledgerOf(stageDatabaseUrl(args.stage)), skipMigrationCheck: args.skipMigrationCheck });

  if (why !== null) {
    log(`Not rolling back: ${why}. Migrations never roll back; fix forward, or roll back to a build that fits (after checking the schema by hand, --skip-migration-check skips the ledger check; nothing skips the release record and pair checks).`);

    return 1;
  }

  log(args.skipMigrationCheck ? "release record and pairing checked; the migration ledger was not (--skip-migration-check)" : "release record, migrations and pairing checked");

  for (const s of steps) log(`${args.yes ? "rolling back" : "would roll back"} ${s.script}: live ${s.from.id} → ${s.toLabel}`);

  if (!args.yes) {
    log("Nothing changed. Run again with --yes to roll back.");

    return 0;
  }

  return (await rollBack(cf, steps, `rollback.ts ${args.action} by ${process.env.USER ?? "an operator"}`, log, (step) => liveStillAsPlanned(cf, step, releases))) ? 0 : 1;
}

if (import.meta.main) process.exit(await main(process.argv.slice(2)));
