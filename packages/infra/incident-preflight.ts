// The incident preflight: what an incident agent's deploy (deploy.ts deploy --incident) must pass before it touches the
// database or builds anything, and what the agent runs on its candidate commit first. It reads Cloudflare, the release
// record and the stage's migration ledger, and changes nothing.
//
//   bun packages/infra/incident-preflight.ts --stage production
//   bun packages/infra/incident-preflight.ts --stage staging
//
// It refuses, with every reason it found, unless:
//   1. the checkout is HEAD exactly: a full commit id and no tracked changes;
//   2. the registry and the website each route all their traffic to one version, and one canonical line of the release
//      record (releases.ts) names both; that line's SHA is a full commit id this repository has (the deployed commit);
//   3. nothing in packages/infra (its tests aside), the registry's migrate/compat/build scripts or the root package.json
//      changed between the deployed commit and HEAD;
//   4. bun.lock pins the same Alchemy packages (alchemy, @alchemy.run/*) at both commits, entry for entry;
//   5. against the stage's own migration ledger (apm_migrations, read only, rollback.ts ledgerOf): no applied migration
//      was removed or edited since the deployed commit, and every pending migration, the full pending set, carries
//      `-- apm:incident-safe` in its leading comment and is byte for byte what it was at the deployed commit. A person's
//      review adds that marker; an incident fix never adds or edits a migration.
//
// It prints `incident preflight: PASS` or `incident preflight: REFUSED: <reasons>`, then one JSON evidence line, and
// exits 0 on a pass and 1 on a refusal. deploy.ts --incident runs the same checks under the release lock and prints the
// same two lines (APM_INCIDENT_PREFLIGHT_V1 is the marker the incident helper looks for there).
//
// Secrets come from ~/.config/apmjs (APM_SECRETS_DIR overrides it): the Cloudflare token and neon-url; nothing prints them.
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { InstallChecks } from "./install-checks.ts";
import { readReleases, releaseNamingAll, type Release } from "./releases.ts";
import { cloudflareFromSecrets, ledgerOf, listDeployments, receiving, scriptName, stageDatabaseUrl, STAGES, type Cloudflare, type Deployment, type Stage } from "./rollback.ts";

/** The marker deploy.ts carries when it runs this preflight; the incident helper (apmjs-ops.py) checks for it. */
export const INCIDENT_PREFLIGHT_MARKER = "APM_INCIDENT_PREFLIGHT_V1";

/** The marker a migration carries in its leading comment when a person reviewed it as safe to apply in an incident deploy. */
export const INCIDENT_SAFE = "-- apm:incident-safe";

/** The repository root this file lives in. */
export const REPO_ROOT = join(import.meta.dirname, "..", "..");

const MIGRATIONS_DIR = "packages/registry/migrations";

/** What migrate.ts applies: packages/registry/migrations/NNNN_*.sql (migrate.ts, migrationFiles). */
const MIGRATION_FILE = /^\d{4}_.+\.sql$/;

const FULL_SHA = /^[0-9a-f]{40}$/;

/** Whether `sql` declares itself safe for an incident deploy, in the comment lines it starts with (as rollback.ts isRollbackSafe). */
export function isIncidentSafe(sql: string): boolean {
  for (const line of sql.split("\n")) {
    const t = line.trim();

    if (t === "") continue;

    if (!t.startsWith("--")) return false;

    // the marker alone, or followed by why: "-- apm:incident-safe: adds a column nothing reads yet"
    if (t === INCIDENT_SAFE || t.startsWith(`${INCIDENT_SAFE} `) || t.startsWith(`${INCIDENT_SAFE}:`)) return true;
  }

  return false;
}

/** The registry scripts that build and migrate what a deploy ships. */
const BUILD_SCRIPT = /^packages\/registry\/scripts\/(?:migrate|compat|build)[^/]*\.ts$/;

/** The paths among `paths` an incident fix must not change: the deploy machinery, the registry's build and migrate scripts, the root package.json. */
export function forbiddenInfraChanges(paths: readonly string[]): string[] {
  return paths.filter((p) => (p.startsWith("packages/infra/") && !p.startsWith("packages/infra/test/")) || BUILD_SCRIPT.test(p) || p === "package.json");
}

// ---------- bun.lock ----------
const DepMap = z.record(z.string(), z.string());

const LockWorkspace = z
  .object({ dependencies: DepMap.optional(), devDependencies: DepMap.optional(), optionalDependencies: DepMap.optional(), peerDependencies: DepMap.optional() })
  .loose();

const BunLock = z
  .object({
    lockfileVersion: z.number(),
    workspaces: z.record(z.string(), LockWorkspace),
    packages: z.record(z.string(), z.tuple([z.string()]).rest(z.unknown())),
    overrides: DepMap.optional(),
    patchedDependencies: DepMap.optional(),
  })
  .loose();

const DEP_FIELDS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const;

/** Whether `name` (a package name, or an override's or patch's "name@version" key) is an Alchemy package. */
function isAlchemy(name: string): boolean {
  return name === "alchemy" || name.startsWith("alchemy@") || name.startsWith("@alchemy.run/");
}

/** The package a bun.lock resolution names: "alchemy@2.0.0" → "alchemy", "@alchemy.run/sql@2.0.0" → "@alchemy.run/sql". */
function resolvedName(resolution: string): string {
  const at = resolution.indexOf("@", 1);

  return at < 0 ? resolution : resolution.slice(0, at);
}

/** The package a bun.lock packages key installs, its last name: "alchemy", "@alchemy.run/cloudflare/rolldown" → "rolldown". */
function keyName(key: string): string {
  const parts = key.split("/");
  const last = parts.at(-1) ?? key;
  const scope = parts.at(-2);

  return scope?.startsWith("@") === true ? `${scope}/${last}` : last;
}

export type AlchemyPins = { ok: true; pins: Record<string, string> } | { ok: false; error: string };

/**
 * Every Alchemy pin in a bun.lock: each workspace's dependency spec, override and patch on alchemy or @alchemy.run/*,
 * and each package entry (resolution, metadata and integrity, whole) that resolves to one. Two locks pin the same
 * Alchemy exactly when their maps are equal, so any version, resolution or spec change shows.
 */
export function alchemyLockPins(lockText: string): AlchemyPins {
  let raw: unknown;

  try {
    raw = Bun.JSONC.parse(lockText);
  } catch (e) {
    return { ok: false, error: `bun.lock is not JSONC (${e instanceof Error ? e.message : String(e)})` };
  }

  const lock = BunLock.safeParse(raw);

  if (!lock.success) return { ok: false, error: `bun.lock is not in the expected form: ${lock.error.message.slice(0, 300)}` };
  const pins: Record<string, string> = {};

  for (const [path, workspace] of Object.entries(lock.data.workspaces)) {
    for (const field of DEP_FIELDS) {
      for (const [name, spec] of Object.entries(workspace[field] ?? {})) if (isAlchemy(name)) pins[`workspace ${path || "(root)"} ${field} ${name}`] = spec;
    }
  }

  for (const [name, spec] of Object.entries(lock.data.overrides ?? {})) if (isAlchemy(name)) pins[`override ${name}`] = spec;

  for (const [name, patch] of Object.entries(lock.data.patchedDependencies ?? {})) if (isAlchemy(name)) pins[`patch ${name}`] = patch;

  for (const [key, entry] of Object.entries(lock.data.packages)) {
    if (isAlchemy(resolvedName(entry[0])) || isAlchemy(keyName(key))) pins[`package ${key}`] = JSON.stringify(entry);
  }

  return { ok: true, pins: Object.fromEntries(Object.entries(pins).sort(([a], [b]) => a.localeCompare(b))) };
}

/** The pin keys whose value differs between `a` and `b`, or that only one has, sorted. */
export function pinDifferences(a: Readonly<Record<string, string>>, b: Readonly<Record<string, string>>): string[] {
  return [...new Set([...Object.keys(a), ...Object.keys(b)])].filter((k) => a[k] !== b[k]).sort();
}

// ---------- git ----------
type GitOut = { ok: true; out: Buffer } | { ok: false; error: string };

function git(cwd: string, args: readonly string[]): GitOut {
  const run = Bun.spawnSync(["git", ...args], { cwd, stdout: "pipe", stderr: "pipe", env: { ...process.env, GIT_OPTIONAL_LOCKS: "0" } });

  if (run.exitCode !== 0) return { ok: false, error: `git ${args.join(" ")}: ${run.stderr.toString().trim().slice(0, 200) || `exit ${run.exitCode}`}` };

  return { ok: true, out: run.stdout };
}

/** A file's bytes at `rev`, or null when that commit has no such file. */
function fileAt(cwd: string, rev: string, path: string): Buffer | null {
  const run = git(cwd, ["show", `${rev}:${path}`]);

  return run.ok ? run.out : null;
}

/** Deterministic sha256 over the sorted migration files on disk so untracked or edited SQL files count as drift. */
function hashMigrations(sources: readonly MigrationSource[]): string {
  const h = createHash("sha256");

  for (const m of sources) {
    h.update(m.id);
    h.update("\0");
    h.update(String(m.bytes.byteLength));
    h.update("\0");
    h.update(m.bytes);
    h.update("\0");
  }

  return h.digest("hex");
}

/**
 * What the checkout is: HEAD, the tracked changes `git status` lists, the sha256 of `git diff HEAD`, and the sha256 of
 * migration files on disk. Any git or disk read failure fails closed (`ok: false`).
 */
export type CheckoutSnapshot =
  | { readonly ok: true; readonly head: string; readonly trackedStatus: string; readonly trackedDiffHash: string; readonly migrationsHash: string }
  | { readonly ok: false; readonly error: string };

export function checkoutSnapshot(cwd: string): CheckoutSnapshot {
  const head = git(cwd, ["rev-parse", "HEAD"]);

  if (!head.ok) return { ok: false, error: head.error };
  const status = git(cwd, ["status", "--porcelain", "--untracked-files=no"]);

  if (!status.ok) return { ok: false, error: status.error };
  const diff = git(cwd, ["diff", "--binary", "--no-ext-diff", "HEAD"]);

  if (!diff.ok) return { ok: false, error: diff.error };

  let migrationsHash: string;

  try {
    migrationsHash = hashMigrations(candidateMigrations(cwd));
  } catch (e) {
    return { ok: false, error: `migrations unreadable: ${e instanceof Error ? e.message : String(e)}` };
  }

  return {
    ok: true,
    head: head.out.toString("utf8").trim(),
    trackedStatus: status.out.toString("utf8").replace(/\n+$/, ""),
    trackedDiffHash: createHash("sha256").update(diff.out).digest("hex"),
    migrationsHash,
  };
}

/** Why the checkout is no longer what `before` recorded (or could not be read), or null when unchanged. */
export function checkoutDrift(cwd: string, before: CheckoutSnapshot): string | null {
  if (!before.ok) return `the initial checkout could not be read: ${before.error}`;
  const now = checkoutSnapshot(cwd);

  if (!now.ok) return `the checkout could not be read: ${now.error}`;
  const why: string[] = [];

  if (now.head !== before.head) why.push(`HEAD moved from ${before.head || "(none)"} to ${now.head || "(none)"}`);

  if (now.trackedStatus !== before.trackedStatus) why.push(`the tracked files' status changed (now: ${now.trackedStatus.split("\n").join(", ") || "clean"})`);

  if (now.trackedDiffHash !== before.trackedDiffHash) why.push("the tracked files' contents changed");

  if (now.migrationsHash !== before.migrationsHash) why.push("the migration files on disk changed");

  return why.length === 0 ? null : `the checkout changed since this deploy started: ${why.join("; ")}`;
}

// ---------- migrations ----------
/** One migration file: its id (the file name without .sql) and its bytes. */
export type MigrationSource = { readonly id: string; readonly bytes: Buffer };

/** A migration the stage's ledger has not applied: whether it is marked and whether the deployed commit had it, unchanged. */
export type PendingMigration = { id: string; incidentSafe: boolean; unchangedSinceDeployed: boolean };

export type MigrationVerdict = { pending: PendingMigration[]; appliedIssues: string[]; reasons: string[] };

/**
 * Rule 5, from what was read: `applied` (the ledger), `candidate` (the migration files a deploy would apply, at HEAD),
 * `atHead` and `atDeployed` (a migration's bytes at HEAD and at the deployed commit, null when absent).
 */
export function evaluateMigrations(input: {
  applied: readonly string[];
  candidate: readonly MigrationSource[];
  atHead: (id: string) => Buffer | null;
  atDeployed: (id: string) => Buffer | null;
}): MigrationVerdict {
  const appliedIssues: string[] = [];

  for (const id of input.applied) {
    const head = input.atHead(id);
    const deployed = input.atDeployed(id);

    // only migrations present at the deployed commit can be edited or removed by the candidate; historical
    // ledger rows already absent on the deployed commit (e.g. a renamed staging migration) are unchanged
    if (deployed !== null && head === null) appliedIssues.push(`${id} is applied and was removed since the deployed commit`);
    else if (deployed !== null && head !== null && !head.equals(deployed)) appliedIssues.push(`${id} is applied and was edited since the deployed commit`);
    else if (deployed === null && head !== null) appliedIssues.push(`${id} is applied and was re-added since the deployed commit`);
  }

  const applied = new Set(input.applied);

  const pending = input.candidate
    .filter((m) => !applied.has(m.id))
    .map((m) => {
      const deployed = input.atDeployed(m.id);

      return { id: m.id, incidentSafe: isIncidentSafe(m.bytes.toString("utf8")), unchangedSinceDeployed: deployed !== null && deployed.equals(m.bytes) };
    });

  const reasons = appliedIssues.length === 0 ? [] : [`applied migrations changed: ${appliedIssues.join("; ")}`];
  const unmarked = pending.filter((m) => !m.incidentSafe).map((m) => m.id);
  const changed = pending.filter((m) => !m.unchangedSinceDeployed).map((m) => m.id);

  if (unmarked.length > 0) reasons.push(`pending migrations not marked ${INCIDENT_SAFE}: ${unmarked.join(", ")}`);

  if (changed.length > 0) reasons.push(`pending migrations added or edited since the deployed commit: ${changed.join(", ")}`);

  return { pending, appliedIssues, reasons };
}

/** The migration files in the checkout at `repo`, as migrate.ts finds them: what a deploy from it would apply. */
export function candidateMigrations(repo: string): MigrationSource[] {
  const dir = join(repo, MIGRATIONS_DIR);

  if (!existsSync(dir)) return [];

  return readdirSync(dir)
    .filter((f) => MIGRATION_FILE.test(f))
    .sort()
    .map((f) => ({ id: f.replace(/\.sql$/, ""), bytes: readFileSync(join(dir, f)) }));
}

// ---------- the live pair ----------
/** The deployed commit: the release-record line naming the live registry and website. */
export type Deployed = { build: string; sha: string; installChecks: InstallChecks };

export type LiveVersion = { script: string; versionId: string };

/** What one Worker's live deployment routes all its traffic to, or why it is not one version. */
export async function liveVersion(cf: Cloudflare, script: string): Promise<{ ok: true; live: LiveVersion } | { ok: false; why: string }> {
  let deployments: Deployment[] | null;

  try {
    deployments = await listDeployments(cf, script);
  } catch (e) {
    return { ok: false, why: `${script}: its deployments could not be read (${e instanceof Error ? e.message : String(e)})` };
  }

  if (deployments === null) return { ok: false, why: `${script}: no such Worker` };
  const versions = receiving(deployments[0]?.versions ?? []);
  const only = versions[0];

  if (only === undefined || versions.length !== 1 || only.percentage !== 100) {
    return { ok: false, why: `${script} does not route all its traffic to one version (${versions.map((v) => `${v.version_id}@${v.percentage}%`).join(", ") || "no deployment"})` };
  }

  return { ok: true, live: { script, versionId: only.version_id } };
}

// ---------- the preflight ----------
export type AlchemyLockEvidence = { kind: "same" } | { kind: "changed"; keys: string[] } | { kind: "unreadable"; error: string } | { kind: "not-checked" };

export type PreflightEvidence = {
  stage: Stage;
  ok: boolean;
  reasons: string[];
  deployed: Deployed | null;
  checkout: { head: string; clean: boolean; trackedStatus: string };
  live: LiveVersion[];
  changedInfraFiles: string[] | null;
  alchemyLock: AlchemyLockEvidence;
  pendingMigrations: PendingMigration[] | null;
  appliedMigrationIssues: string[] | null;
};

export type IncidentPreflight =
  | { ok: true; deployed: Deployed; migrations: readonly MigrationSource[]; evidence: PreflightEvidence }
  | { ok: false; deployed: Deployed | null; evidence: PreflightEvidence };

/**
 * Runs every rule against `repo` and `stage`, collecting each refusal. A rule that needs the deployed commit (3, 4, 5's
 * comparisons) is not checked without one; its evidence says so (null, "not-checked").
 */
export async function runIncidentPreflight(input: {
  cf: Cloudflare;
  stage: Stage;
  repo: string;
  releases: readonly Release[];
  /** The stage's applied migration ids (rollback.ts ledgerOf); null when the ledger cannot be read. */
  readAppliedMigrations: () => Promise<readonly string[] | null>;
}): Promise<IncidentPreflight> {
  const reasons: string[] = [];

  // 1. the clean exact checkout (any git/index error fails closed)
  const snapshot = checkoutSnapshot(input.repo);
  const head = snapshot.ok ? snapshot.head : "";
  const trackedStatus = snapshot.ok ? snapshot.trackedStatus : "";
  const clean = snapshot.ok && FULL_SHA.test(head) && trackedStatus === "";

  if (!snapshot.ok) reasons.push(`the checkout could not be read (${snapshot.error})`);
  else {
    if (!FULL_SHA.test(head)) reasons.push(`HEAD is not a commit (${head || "unreadable"})`);

    if (trackedStatus !== "") reasons.push(`the checkout has tracked changes: ${trackedStatus.split("\n").join(", ")}`);
  }

  // 2. the recorded live pair
  const reads = await Promise.all([liveVersion(input.cf, scriptName("registry", input.stage)), liveVersion(input.cf, scriptName("web", input.stage))]);
  const live: LiveVersion[] = [];

  for (const r of reads) {
    if (r.ok) live.push(r.live);
    else reasons.push(r.why);
  }

  let deployed: Deployed | null = null;

  if (live.length === reads.length) {
    const line = releaseNamingAll(input.releases, live);

    if (line === null) reasons.push(`no release-record line names the live pair (${live.map((l) => `${l.script} ${l.versionId}`).join(", ")})`);
    else if (!FULL_SHA.test(line.sha)) reasons.push(`the live pair's release line (build ${line.build}) has no clean commit: ${line.sha}`);
    else if (!git(input.repo, ["cat-file", "-e", `${line.sha}^{commit}`]).ok) reasons.push(`the deployed commit ${line.sha} (build ${line.build}) is not in this repository`);
    else deployed = { build: line.build, sha: line.sha, installChecks: line.installChecks ?? "database" };
  }

  let changedInfraFiles: string[] | null = null;
  let alchemyLock: AlchemyLockEvidence = { kind: "not-checked" };
  let pendingMigrations: PendingMigration[] | null = null;
  let appliedMigrationIssues: string[] | null = null;
  let validatedMigrations: MigrationSource[] | null = null;

  if (deployed !== null && FULL_SHA.test(head)) {
    const sha = deployed.sha;

    // 3. no deploy machinery changed since the deployed commit
    const diff = git(input.repo, ["diff", "--name-only", "--no-renames", "-z", `${sha}..HEAD`]);

    if (diff.ok) {
      changedInfraFiles = forbiddenInfraChanges(diff.out.toString("utf8").split("\0").filter((p) => p !== ""));

      if (changedInfraFiles.length > 0) reasons.push(`infrastructure changed since the deployed commit: ${changedInfraFiles.join(", ")}`);
    } else reasons.push(`the changes since the deployed commit could not be listed (${diff.error})`);

    // 4. the same Alchemy in bun.lock
    const before = alchemyLockPins(fileAt(input.repo, sha, "bun.lock")?.toString("utf8") ?? "");
    const after = alchemyLockPins(fileAt(input.repo, "HEAD", "bun.lock")?.toString("utf8") ?? "");

    if (!before.ok || !after.ok) {
      const error = [before.ok ? null : `at ${sha}: ${before.error}`, after.ok ? null : `at HEAD: ${after.error}`].filter((e) => e !== null).join("; ");

      alchemyLock = { kind: "unreadable", error };
      reasons.push(`bun.lock's Alchemy pins could not be read (${error})`);
    } else {
      const keys = pinDifferences(before.pins, after.pins);

      alchemyLock = keys.length === 0 ? { kind: "same" } : { kind: "changed", keys };

      if (keys.length > 0) reasons.push(`bun.lock pins different Alchemy packages than the deployed commit: ${keys.join(", ")}`);
    }

    // 5. migrations against the stage's own ledger
    const applied = await input.readAppliedMigrations();

    if (applied === null) reasons.push("the stage's migration ledger could not be read (no neon-url, or the database did not answer in time)");
    else {
      const candidate = candidateMigrations(input.repo);

      const verdict = evaluateMigrations({
        applied,
        candidate,
        atHead: (id) => fileAt(input.repo, "HEAD", `${MIGRATIONS_DIR}/${id}.sql`),
        atDeployed: (id) => fileAt(input.repo, sha, `${MIGRATIONS_DIR}/${id}.sql`),
      });

      validatedMigrations = candidate;
      pendingMigrations = verdict.pending;
      appliedMigrationIssues = verdict.appliedIssues;
      reasons.push(...verdict.reasons);
    }
  }

  const evidence: PreflightEvidence = {
    stage: input.stage,
    ok: reasons.length === 0,
    reasons,
    deployed,
    checkout: { head, clean, trackedStatus },
    live,
    changedInfraFiles,
    alchemyLock,
    pendingMigrations,
    appliedMigrationIssues,
  };

  return reasons.length === 0 && deployed !== null && validatedMigrations !== null
    ? { ok: true, deployed, migrations: validatedMigrations, evidence }
    : { ok: false, deployed, evidence };
}

/** The preflight's two lines: PASS or REFUSED with its reasons, then the JSON evidence. */
export function preflightLines(result: IncidentPreflight): [string, string] {
  const verdict = result.ok ? "incident preflight: PASS" : `incident preflight: REFUSED: ${result.evidence.reasons.join(" | ") || "the deployed commit could not be found"}`;

  return [verdict, JSON.stringify(result.evidence)];
}

export type IncidentInstallChecks = { kind: "ok"; installChecks: InstallChecks; inherited: boolean } | { kind: "refused"; why: string };

/**
 * The install-check mode an incident deploy runs with: the deployed release's, unless --install-checks or
 * APM_INSTALL_CHECKS asks for one, which must then be the same (an incident deploy never flips the mode).
 */
export function resolveIncidentInstallChecks(input: { argv: readonly string[]; env: Readonly<Record<string, string | undefined>>; deployed: InstallChecks; requested: InstallChecks }): IncidentInstallChecks {
  const explicit = input.argv.includes("--install-checks") || input.env.APM_INSTALL_CHECKS !== undefined;

  if (!explicit) return { kind: "ok", installChecks: input.deployed, inherited: true };

  if (input.requested !== input.deployed) {
    return { kind: "refused", why: `install checks ${input.requested} was asked for, but the live release runs ${input.deployed}; an incident deploy keeps the live mode (leave --install-checks out)` };
  }

  return { kind: "ok", installChecks: input.requested, inherited: false };
}

const Args = z.object({ stage: z.enum(STAGES) });

if (import.meta.main) {
  const at = process.argv.indexOf("--stage");
  const args = Args.safeParse({ stage: at > 0 ? process.argv[at + 1] : undefined });

  if (!args.success) {
    process.stdout.write("incident preflight: REFUSED: give --stage staging or --stage production\n");
    process.exit(1);
  }

  const stage = args.data.stage;
  const cf = await cloudflareFromSecrets();
  const result = await runIncidentPreflight({ cf, stage, repo: REPO_ROOT, releases: readReleases(stage), readAppliedMigrations: () => ledgerOf(stageDatabaseUrl(stage)) });

  for (const line of preflightLines(result)) process.stdout.write(`${line}\n`);
  process.exit(result.ok ? 0 : 1);
}
