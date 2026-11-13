// Deploys apm to Cloudflare: builds the registry Worker, migrates the stage's Neon database, then runs the
// Alchemy stack. Secrets are read from ~/.config/apmjs and handed to the child process only; nothing prints them.
// `plan` changes nothing: it reports a missing database, pending migrations and a missing auth secret, and
// runs Alchemy's own plan.
//
//   bun packages/infra/deploy.ts plan    --stage staging
//   bun packages/infra/deploy.ts deploy  --stage staging
//   bun packages/infra/deploy.ts deploy  --stage production
//   bun packages/infra/deploy.ts deploy  --stage staging --adopt   (state lost: adopt what exists)
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
import { createHash } from "node:crypto";
import { z } from "zod";
import { buildWorker, TAIL_DIR } from "../registry/scripts/build.ts";
import { authSecret, prepareDatabase, type DatabaseReport } from "./stage.ts";

const SECRETS = process.env.APM_SECRETS_DIR ?? join(homedir(), ".config", "apmjs");
const INFRA = import.meta.dirname;

const Args = z.object({ action: z.enum(["plan", "deploy"]), stage: z.enum(["staging", "production"]) });
const stageAt = process.argv.indexOf("--stage");
const args = Args.parse({ action: process.argv[2], stage: stageAt > 0 ? process.argv[stageAt + 1] : "staging" });

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

process.stdout.write(`apm ${args.action} → ${args.stage} (database ${database}; AI review ${review.hash === "" ? "off" : "on"})\n`);

const report = await prepareDatabase({
  action: args.action,
  adminUrl: databaseUrl(neonUrl, new URL(neonUrl).pathname.slice(1)),
  databaseUrl: databaseUrl(neonUrl, database),
  database,
});

process.stdout.write(describeDatabase(report, database));

const secret = authSecret({ action: args.action, dir: SECRETS, stage: args.stage });

// a plan of a stage that has never been deployed has no secret yet; Alchemy plans with a stand-in
if (secret.kind === "missing") process.stdout.write(`auth secret: missing; deploy creates ${join(SECRETS, `auth-secret-${args.stage}`)}\n`);

// plan must not change the working tree: it bundles into a throwaway folder that is removed afterwards
const planDir = args.action === "plan" ? mkdtempSync(join(tmpdir(), "apm-plan-bundle-")) : null;
const planTailDir = args.action === "plan" ? mkdtempSync(join(tmpdir(), "apm-plan-tail-")) : null;
const bundle = planDir === null ? await buildWorker("worker") : await buildWorker("worker", planDir);

// in a folder of its own: a bundle: false upload takes every module in its entry's folder and below
const tailBundle = await buildWorker("tail", planTailDir ?? TAIL_DIR);

process.stdout.write(`registry bundle: ${bundle}\ntail bundle: ${tailBundle}\n`);

const subdomain = await workersSubdomain(token, accountId);
const alchemyFlags: string[] = [];

if (args.action === "deploy") alchemyFlags.push("--yes");

// adopts existing resources when the local Alchemy state was lost (docs/DEPLOY.md, "State")
if (process.argv.includes("--adopt")) alchemyFlags.push("--adopt");

const child = Bun.spawn(
  ["bun", join(INFRA, "node_modules", ".bin", "alchemy"), args.action, "--stage", args.stage, "--no-input", ...alchemyFlags],
  {
    cwd: INFRA,
    stdout: "inherit",
    stderr: "inherit",
    env: {
      PATH: process.env.PATH ?? "",
      HOME: homedir(),
      CI: "1",
      CLOUDFLARE_API_TOKEN: token,
      CLOUDFLARE_ACCOUNT_ID: accountId,
      WORKERS_SUBDOMAIN: subdomain,
      NEON_URL: neonUrl,
      APM_DATABASE: database,
      APM_REGISTRY_BUNDLE: bundle,
      APM_TAIL_BUNDLE: tailBundle,
      AUTH_SECRET: secret.kind === "missing" ? "plan-only-stand-in-for-the-auth-secret-deploy-creates" : secret.value,
      GITHUB_CLIENT_ID: required(github, "APM_GITHUB_CLIENT_ID", "github-oauth.env"),
      GITHUB_CLIENT_SECRET: required(github, "APM_GITHUB_CLIENT_SECRET", "github-oauth.env"),
      REVIEW_TOKEN_HASH: review.hash,
      APM_ADMINS: review.admins,
      DEBUG_TOKEN_HASH: debugHash,
      // the website's registry URL for anything it renders at build time
      APM_REGISTRY: args.stage === "production" ? "https://registry.apmjs.dev/" : `https://apmjs-registry-${args.stage}.${subdomain}.workers.dev/`,
      ALCHEMY_TELEMETRY_DISABLED: "1",
      DO_NOT_TRACK: "1",
    },
  },
);

const exitCode = await child.exited;

for (const dir of [planDir, planTailDir]) if (dir !== null) rmSync(dir, { recursive: true, force: true });

process.exit(exitCode);
