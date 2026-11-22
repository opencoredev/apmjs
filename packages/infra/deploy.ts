// Deploys apm to Cloudflare: builds the registry Worker, migrates the stage's Neon database, then runs the
// Alchemy stack. Secrets are read from ~/.config/apmjs and handed to the child process only; nothing prints them.
// `plan` changes nothing: it reports a missing database, pending migrations and a missing auth secret, and
// runs Alchemy's own plan.
//
//   bun packages/infra/deploy.ts plan    --stage staging
//   bun packages/infra/deploy.ts deploy  --stage staging
//   bun packages/infra/deploy.ts deploy  --stage production
//   bun packages/infra/deploy.ts deploy  --stage staging --adopt   (state lost: adopt what exists)
//   bun packages/infra/deploy.ts deploy  --stage staging --install-checks database   (phase 1: the publish fence, database reads)
//   bun packages/infra/deploy.ts deploy  --stage staging --install-checks edge       (phase 2: edge views; docs/DEPLOY.md)
//   bun packages/infra/deploy.ts deploy  --stage production --incident               (the incident agent's deploy)
//
// --incident (marker APM_INCIDENT_PREFLIGHT_V1, which the incident helper apmjs-ops.py looks for here) runs the incident
// preflight (incident-preflight.ts) under the release lock, before the database, a build or Alchemy, and prints
// `incident preflight: PASS|REFUSED` with its JSON evidence line; a refusal exits 1 having changed nothing. An incident
// deploy keeps the live release's install-check mode: it inherits it when --install-checks and APM_INSTALL_CHECKS are
// absent, and refuses when either asks for another.
//
// Every deploy records HEAD and the tracked files right after it takes the lock, before it reads any source, and exits 1
// when either changed before Alchemy starts, or before the release record is written (then nothing is recorded).
//
// The install-check mode is printed on the first line and kept on the release record's line, after the registry's
// live version is confirmed to carry it.
//
// After Alchemy, a deploy runs the stage's smoke check (smoke.ts) once, with this run's build: the registry and the
// website must answer with it before and after the behavioural checks. When it passes, still under the lock, it reads
// each Worker's live deployment, confirms the registry's and the website's live versions carry this run's stamp, and
// appends one line to the release record (deploy-record.ts, releases.ts): build id, git SHA, stage, migration manifest
// and the live version ids. That record is all rollback.ts trusts. When Alchemy, the smoke check or the record fails,
// nothing is recorded, nothing is rolled back, and the deploy exits 1 with what to do next (deploy-finish.ts): the
// rollback.ts command to the last recorded build, or fix forward when this run left a version live it did not record.
//
// The registry and website versions this script uploads carry APM_REVISION, APM_BUILD (a new id each run) and the
// sealed migration manifest as plain-text variables (rollback.ts, provenanceVars); because the build id changes every
// run, every deploy uploads both. The docs Worker is assets-only: Alchemy uploads it only when its pages change, and
// Cloudflare keeps no variables on it.
//
// Lock: a deploy holds the release lock (release-lock.ts) for its whole run: an exclusive flock on
// /home/leo/.config/apmjs/release.lock, or on the path in APM_RELEASE_LOCK, shared with rollback.ts and the incident
// agent's helper. It is taken before anything else (secrets, migrations, builds) and held until this process and the
// children it starts to change anything (Alchemy, the smoke check, which get the lock's descriptor) have exited. The
// holder is recorded in release.lock.json beside it. A held lock stops the deploy at once with exit code 6.
//
// Order: migrations, then the registry Worker, then the website. The website binds the registry (REGISTRY in
// alchemy.run.ts), and Alchemy starts a resource only after every resource it depends on has finished, and not at all
// when one failed (Apply.ts, waitForDeps on readyStable). Keep that binding: the registry is the only gate for a
// version's source, so it must redact before a website that expects redaction goes live. A website deployed on its own
// (wrangler, a dashboard rollback) against an older registry fails closed: it requires the `redacted` and
// `readmeVersion` fields that registry does not send, and shows "registry unavailable" instead of the answer
// (apps/web/lib/registry.ts). packages/infra/test/deploy-order.test.ts checks the binding.
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { z } from "zod";
import { buildWorker } from "../registry/scripts/build.ts";
import { databuddyBuildEnv } from "./analytics.ts";
import { authSecret, prepareDatabase, type DatabaseReport } from "./stage.ts";
import { migrationFiles, migrationFromBytes, type Migration } from "../registry/scripts/migrate.ts";
import { BUSY_CODE, lockedSpawn, takeReleaseLock, type ReleaseLock } from "./release-lock.ts";
import { recordLiveRelease } from "./deploy-record.ts";
import { finishDeploy, recoveryAdvice, smokeCommand } from "./deploy-finish.ts";
import { readReleases } from "./releases.ts";
import { ledgerOf, provenanceVars, stageDatabaseUrl, type Cloudflare } from "./rollback.ts";
import { installChecksOf } from "./install-checks.ts";
import { checkoutDrift, checkoutSnapshot, INCIDENT_PREFLIGHT_MARKER, preflightLines, resolveIncidentInstallChecks, runIncidentPreflight, type CheckoutSnapshot } from "./incident-preflight.ts";

const SECRETS = process.env.APM_SECRETS_DIR ?? join(homedir(), ".config", "apmjs");
const INFRA = import.meta.dirname;
const REPO_ROOT = join(INFRA, "..", "..");

const Args = z.object({ action: z.enum(["plan", "deploy"]), stage: z.enum(["staging", "production"]) });
const stageAt = process.argv.indexOf("--stage");

const args = {
  ...Args.parse({ action: process.argv[2], stage: stageAt > 0 ? process.argv[stageAt + 1] : "staging" }),
  // the incident agent's deploy: the incident preflight (APM_INCIDENT_PREFLIGHT_V1) runs first and must pass
  incident: process.argv.includes("--incident"),
};

// what install reads of npm's packages check on this deploy: "database" unless --install-checks edge asks; an incident
// deploy inherits the live release's mode instead (below)
let installChecks = installChecksOf({ argv: process.argv, env: process.env });

// one change to apm at a time, on this machine: the release lock (APM_RELEASE_LOCK), held from here until this process
// and the children it starts to change anything (Alchemy, the smoke check) have exited. A plan changes nothing and
// takes no lock.
let lock: ReleaseLock | null = null;

/** The checkout as this deploy found it, right after taking the lock: the upload and the record refuse once it moved. */
let beforeCheckout: CheckoutSnapshot | null = null;

if (args.action === "deploy") {
  const taken = takeReleaseLock({ script: import.meta.path, argv: process.argv.slice(2), stage: args.stage });

  if (taken.kind === "busy") {
    process.stdout.write(`deploy ${taken.text}\n`);
    process.exit(BUSY_CODE);
  }

  lock = taken.lock;
  process.stdout.write(`release lock: held (${lock.path})\n`);
  beforeCheckout = checkoutSnapshot(REPO_ROOT);

  if (!beforeCheckout.ok) {
    process.stdout.write(`deploy refused: the checkout could not be read (${beforeCheckout.error}); nothing changed\n`);
    process.exit(1);
  }
}

/** Why the checkout moved since this deploy took the lock, or null (always null for a plan, which records nothing). */
function drift(): string | null {
  return beforeCheckout === null ? null : checkoutDrift(REPO_ROOT, beforeCheckout);
}

/** The Neon database each stage owns. Production keeps Neon's default database. */
const DATABASES = { staging: "apmjs_staging", production: "neondb" } as const;

function secretFile(name: string): string {
  const path = join(SECRETS, name);

  if (!existsSync(path)) throw new Error(`Missing ${path}. See docs/DEPLOY.md for the files deploy.ts reads.`);

  return readFileSync(path, "utf8").trim();
}

/** KEY=value lines; values never leave this process except into the deploy's own environment. */
function envFile(name: string): Map<string, string> {
  const out = new Map<string, string>();

  for (const line of secretFile(name).split("\n")) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);

    if (m?.[1] && m[2] !== undefined) out.set(m[1], m[2].replace(/^["']|["']$/g, ""));
  }

  return out;
}

function required(map: Map<string, string>, key: string, file: string): string {
  const value = map.get(key);

  if (!value) throw new Error(`${file} has no ${key}.`);

  return value;
}

/**
 * The AI review is on for a stage when review-token-<stage> exists; the reviewer process holds the same token.
 * Only the token's sha256 reaches Cloudflare. review.env may name the admins (APM_ADMINS=login,login).
 */
function reviewSettings(stage: string) {
  if (!existsSync(join(SECRETS, `review-token-${stage}`))) return { hash: "", admins: "" };
  const admins = existsSync(join(SECRETS, "review.env")) ? (envFile("review.env").get("APM_ADMINS") ?? "") : "";

  return { hash: createHash("sha256").update(secretFile(`review-token-${stage}`)).digest("hex"), admins };
}

/**
 * The sha256 of debug-token-<stage>, or "" when the file is absent. A request whose x-apm-debug header is that token
 * gets the registry's full Server-Timing; only the hash reaches Cloudflare.
 */
function debugTokenHash(stage: string): string {
  return existsSync(join(SECRETS, `debug-token-${stage}`)) ? createHash("sha256").update(secretFile(`debug-token-${stage}`)).digest("hex") : "";
}

/** The stage's database on the Neon endpoint, with TLS verified (Neon serves a public certificate). */
function databaseUrl(neonUrl: string, database: string): string {
  const u = new URL(neonUrl);
  u.pathname = `/${database}`;
  u.searchParams.set("sslmode", "verify-full");

  return u.toString();
}

function describeDatabase(report: DatabaseReport, database: string): string {
  switch (report.kind) {
    case "missing":
      return `database ${database}: missing; deploy creates it and applies ${report.pending.length} migration(s)\n`;
    case "planned":
      return report.pending.length === 0 ? "migrations: up to date\n" : `migrations: deploy would apply ${report.pending.join(", ")}\n`;
    case "migrated":
      return `${report.created ? `database ${database}: created\n` : ""}${report.applied.length === 0 ? "migrations: up to date\n" : `migrations: applied ${report.applied.join(", ")}\n`}`;
    default: {
      const _exhaustive: never = report;

      return _exhaustive;
    }
  }
}

const WorkersSubdomain = z.object({ result: z.object({ subdomain: z.string() }) });

async function workersSubdomain(token: string, accountId: string): Promise<string> {
  const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/subdomain`, { headers: { authorization: `Bearer ${token}` } });
  const body = WorkersSubdomain.safeParse(await res.json());

  if (!body.success) throw new Error(`Could not read the account's workers.dev subdomain (HTTP ${res.status}).`);

  return body.data.result.subdomain;
}

const cloudflare = envFile("cloudflare.env");
const github = envFile("github-oauth.env");
const token = secretFile("cloudflare-token");
const accountId = required(cloudflare, "CLOUDFLARE_ACCOUNT_ID", "cloudflare.env");
const neonUrl = secretFile("neon-url");
const review = reviewSettings(args.stage);
const debugHash = debugTokenHash(args.stage);
const database = DATABASES[args.stage];
const cf: Cloudflare = { apiBase: process.env.APM_CLOUDFLARE_API ?? "https://api.cloudflare.com/client/v4", token, accountId };

// the migrations this run will apply and record: for --incident, the exact bytes preflight validated (never re-read from disk)
let runMigrations: readonly Migration[] = migrationFiles();

// the incident preflight, under the lock and before the database, a build or Alchemy (incident-preflight.ts)
if (args.action === "deploy" && args.incident) {
  const preflight = await runIncidentPreflight({ cf, stage: args.stage, repo: REPO_ROOT, releases: readReleases(args.stage), readAppliedMigrations: () => ledgerOf(stageDatabaseUrl(args.stage)) });

  for (const line of preflightLines(preflight)) process.stdout.write(`${line}\n`);

  if (!preflight.ok) {
    process.stdout.write(`deploy refused by the incident preflight (${INCIDENT_PREFLIGHT_MARKER}): nothing changed\n`);
    process.exit(1);
  }

  const resolved = resolveIncidentInstallChecks({ argv: process.argv, env: process.env, deployed: preflight.deployed.installChecks, requested: installChecks });

  if (resolved.kind === "refused") {
    process.stdout.write(`deploy refused: ${resolved.why}; nothing changed\n`);
    process.exit(1);
  }

  installChecks = resolved.installChecks;
  runMigrations = preflight.migrations.map((m) => migrationFromBytes(m.id, m.bytes));
}

process.stdout.write(`apm ${args.action} → ${args.stage} (database ${database}; AI review ${review.hash === "" ? "off" : "on"}; install checks ${installChecks})\n`);

if (installChecks === "edge") {
  process.stdout.write("install checks edge: only once a build with the publish fence is the only registry version serving (docs/DEPLOY.md, \"Install checks\")\n");
}

// no database writes if the checkout already moved since the lock was taken (including untracked migration files)
const movedBeforeDb = drift();

if (movedBeforeDb !== null) {
  process.stdout.write(`deploy refused before migrations: ${movedBeforeDb}; nothing changed\n`);
  process.exit(1);
}

const report = await prepareDatabase({
  action: args.action,
  adminUrl: databaseUrl(neonUrl, new URL(neonUrl).pathname.slice(1)),
  databaseUrl: databaseUrl(neonUrl, database),
  database,
  migrations: runMigrations,
});

process.stdout.write(describeDatabase(report, database));

const secret = authSecret({ action: args.action, dir: SECRETS, stage: args.stage });

// a plan of a stage that has never been deployed has no secret yet; Alchemy plans with a stand-in
if (secret.kind === "missing") process.stdout.write(`auth secret: missing; deploy creates ${join(SECRETS, `auth-secret-${args.stage}`)}\n`);

// plan must not change the working tree: it bundles into a throwaway folder that is removed afterwards
const planDir = args.action === "plan" ? mkdtempSync(join(tmpdir(), "apm-plan-bundle-")) : null;
const bundle = planDir === null ? await buildWorker("worker") : await buildWorker("worker", planDir);

process.stdout.write(`registry bundle: ${bundle}\n`);

const subdomain = await workersSubdomain(token, accountId);
const head = beforeCheckout !== null && beforeCheckout.ok ? beforeCheckout.head : Bun.spawnSync(["git", "rev-parse", "HEAD"], { cwd: INFRA }).stdout.toString().trim() || "unknown";

// a tree with uncommitted changes is not the commit it names
const dirty = beforeCheckout !== null && beforeCheckout.ok ? beforeCheckout.trackedStatus !== "" : Bun.spawnSync(["git", "status", "--porcelain", "--untracked-files=no"], { cwd: INFRA }).stdout.toString().trim() !== "";
const revision = dirty ? `${head}-dirty` : head;
const build = randomUUID();
const alchemyFlags: string[] = [];

if (args.action === "deploy") alchemyFlags.push("--yes");

// adopts existing resources when the local Alchemy state was lost (docs/DEPLOY.md, "State")
if (process.argv.includes("--adopt")) alchemyFlags.push("--adopt");

const alchemyCommand = ["bun", join(INFRA, "node_modules", ".bin", "alchemy"), args.action, "--stage", args.stage, "--no-input", ...alchemyFlags];

const alchemyOptions = {
    cwd: INFRA,
    env: {
      PATH: process.env.PATH ?? "",
      HOME: homedir(),
      // build and install temp files follow the caller's TMPDIR (the /tmp RAM disk on the build box has filled)
      TMPDIR: tmpdir(),
      CI: "1",
      CLOUDFLARE_API_TOKEN: token,
      CLOUDFLARE_ACCOUNT_ID: accountId,
      WORKERS_SUBDOMAIN: subdomain,
      NEON_URL: neonUrl,
      APM_DATABASE: database,
      APM_REGISTRY_BUNDLE: bundle,
      AUTH_SECRET: secret.kind === "missing" ? "plan-only-stand-in-for-the-auth-secret-deploy-creates" : secret.value,
      GITHUB_CLIENT_ID: required(github, "APM_GITHUB_CLIENT_ID", "github-oauth.env"),
      GITHUB_CLIENT_SECRET: required(github, "APM_GITHUB_CLIENT_SECRET", "github-oauth.env"),
      REVIEW_TOKEN_HASH: review.hash,
      APM_ADMINS: review.admins,
      DEBUG_TOKEN_HASH: debugHash,
      // what install reads of npm's packages check before their answer (registry edge-checks.ts): --install-checks
      INSTALL_CHECKS: installChecks,
      // what built the registry and the website: this run's commit, build id and migration manifest. The record waits
      // for the live versions to carry it (deploy-record.ts), and the smoke check for them to answer with the build
      APM_PROVENANCE: JSON.stringify(provenanceVars(revision, build, runMigrations.map((m) => m.id))),
      // the website's registry URL for anything it renders at build time
      APM_REGISTRY: args.stage === "production" ? "https://registry.apmjs.dev/" : `https://apmjs-registry-${args.stage}.${subdomain}.workers.dev/`,
      // the website's and the docs' Databuddy tracker: production's client id, "" (no tracker) on any other stage
      ...databuddyBuildEnv(args.stage),
      ALCHEMY_TELEMETRY_DISABLED: "1",
      DO_NOT_TRACK: "1",
    },
  };

// nothing uploads from a checkout that moved since this deploy read it
const moved = drift();

if (moved !== null) {
  if (planDir !== null) rmSync(planDir, { recursive: true, force: true });
  process.stdout.write(`deploy refused before Alchemy: ${moved}; nothing was uploaded\n`);
  process.exit(1);
}

// a deploy's Alchemy holds the release lock with this process: killing this one mid-upload leaves it held
const child = lock === null ? Bun.spawn(alchemyCommand, { ...alchemyOptions, stdout: "inherit", stderr: "inherit" }) : lockedSpawn(lock, alchemyCommand, alchemyOptions);

const exitCode = await child.exited;

if (planDir !== null) rmSync(planDir, { recursive: true, force: true });

if (args.action !== "deploy") process.exit(exitCode);

// the smoke check (with this run's build and the subdomain resolved above) and the record, under the lock
const smoke = async (): Promise<number> => {
  const command = smokeCommand(INFRA, args.stage, build, subdomain);
  const run = lock === null ? Bun.spawn(command, { cwd: INFRA, stdout: "inherit", stderr: "inherit", env: { ...process.env } }) : lockedSpawn(lock, command, { cwd: INFRA, env: { ...process.env } });

  return run.exited;
};

process.exit(
  await finishDeploy({
    alchemyExit: exitCode,
    smoke,
    // what is live now, confirmed to be this run's versions: the line every later rollback trusts
    // and only from the checkout this run started from: a moved one is never recorded
    record: async () => {
      const movedBeforeRecord = drift();

      if (movedBeforeRecord !== null) return { kind: "not-recorded", why: movedBeforeRecord };

      return recordLiveRelease({ cf, stage: args.stage, build, sha: revision, manifest: runMigrations.map((m) => m.id), installChecks, beforeAppend: drift });
    },
    advice: async () => recoveryAdvice({ cf, stage: args.stage, releases: readReleases(args.stage) }),
    log: (line) => process.stdout.write(`${line}\n`),
  }),
);
