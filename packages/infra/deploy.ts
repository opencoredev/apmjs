// Deploys apm to Cloudflare: builds the registry Worker, migrates the stage's Neon database, then runs the
// Alchemy stack. Secrets are read from ~/.config/apmjs and handed to the child process only; nothing prints them.
//
//   bun packages/infra/deploy.ts plan    --stage staging
//   bun packages/infra/deploy.ts deploy  --stage staging
//   bun packages/infra/deploy.ts deploy  --stage production
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { Client } from "pg";
import { z } from "zod";
import { buildWorker } from "../registry/scripts/build.ts";
import { migrate } from "../registry/scripts/migrate.ts";

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

/** The auth secret signs sessions and encrypts TOTP secrets, so it is made once per stage and kept. */
function authSecret(stage: string): string {
  const name = `auth-secret-${stage}`;

  if (!existsSync(join(SECRETS, name))) {
    mkdirSync(SECRETS, { recursive: true, mode: 0o700 });
    writeFileSync(join(SECRETS, name), `${randomBytes(48).toString("base64url")}\n`, { mode: 0o600 });
  }

  return secretFile(name);
}

/** The stage's database on the Neon endpoint, with TLS verified (Neon serves a public certificate). */
function databaseUrl(neonUrl: string, database: string): string {
  const u = new URL(neonUrl);
  u.pathname = `/${database}`;
  u.searchParams.set("sslmode", "verify-full");

  return u.toString();
}

async function ensureDatabase(neonUrl: string, database: string): Promise<void> {
  const c = new Client({ connectionString: databaseUrl(neonUrl, new URL(neonUrl).pathname.slice(1)) });
  await c.connect();

  try {
    const exists = await c.query("SELECT 1 FROM pg_database WHERE datname = $1", [database]);

    if (exists.rowCount === 0) await c.query(`CREATE DATABASE "${database.replace(/"/g, "")}"`);
  } finally {
    await c.end();
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
const database = DATABASES[args.stage];

process.stdout.write(`apm ${args.action} → ${args.stage} (database ${database})\n`);

await ensureDatabase(neonUrl, database);

const applied = await migrate(databaseUrl(neonUrl, database));

process.stdout.write(applied.length === 0 ? "migrations: up to date\n" : `migrations: applied ${applied.join(", ")}\n`);

const bundle = await buildWorker("worker");

process.stdout.write(`registry bundle: ${bundle}\n`);

const subdomain = await workersSubdomain(token, accountId);

const child = Bun.spawn(
  ["bun", join(INFRA, "node_modules", ".bin", "alchemy"), args.action, "--stage", args.stage, "--no-input", ...(args.action === "deploy" ? ["--yes"] : [])],
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
      AUTH_SECRET: authSecret(args.stage),
      GITHUB_CLIENT_ID: required(github, "APM_GITHUB_CLIENT_ID", "github-oauth.env"),
      GITHUB_CLIENT_SECRET: required(github, "APM_GITHUB_CLIENT_SECRET", "github-oauth.env"),
      // the website's registry URL for anything it renders at build time
      APM_REGISTRY: args.stage === "production" ? "https://registry.apmjs.dev/" : `https://apmjs-registry-${args.stage}.${subdomain}.workers.dev/`,
      ALCHEMY_TELEMETRY_DISABLED: "1",
      DO_NOT_TRACK: "1",
    },
  },
);

process.exit(await child.exited);
