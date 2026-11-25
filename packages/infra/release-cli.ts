// Releases the apm CLI on a stage: standalone binaries (bun build --compile, no Bun or git needed to run them) at
// <site>/cli/<version>/apm-<target>, and the install script at <site>/install with every released binary's SHA-256
// written into it. The version is packages/cli/src/version.ts. The website serves both from the stage's CLI bucket
// (alchemy.run.ts creates it; apps/web/lib/cli-download.ts serves it), so a release uploads files and deploys nothing.
//
//   bun packages/infra/release-cli.ts --stage staging
//   bun packages/infra/release-cli.ts --stage production
//   bun packages/infra/release-cli.ts --stage local [--host 127.0.0.1] [--port 8790] [--dir ~/.cache/apm-cli-local] [--serve]
//
// A released version never changes. A version is released once cli/<version>/SHA256SUMS exists in the bucket: a run
// that finds it builds nothing and uploads no binary; it only rebuilds the index and the script from what is there and
// republishes them if they differ. Before that file exists (a run cut short) the version's binaries are uploaded again,
// and the site serves none of them (apps/web/lib/cli-download.ts answers an uncached 404 until SHA256SUMS exists).
// So a rerun is always safe. Order: binaries, SHA256SUMS, cli/releases.txt, install.sh; then every binary is downloaded
// back through the site and hashed, the script the site serves is compared with the one written, and the documented
// install command runs in a fresh HOME (cli-check.ts). Only then is the run recorded, one line in
// ~/.config/apmjs/cli-releases.jsonl (cli-ledger.ts).
//
// staging and production hold the release lock (release-lock.ts) for the whole run, as deploy.ts does, and need the
// website deployed with the CLI bucket first (deploy.ts). production also refuses a tree with uncommitted changes.
// local keeps the bucket in a folder and serves it with the website's own handler in workerd, for trying the install
// on this machine or, with --host set to its Tailscale address, from another; --serve keeps serving until Ctrl-C.
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { z } from "zod";
import { CLI_VERSION } from "../cli/src/version.ts";
import { installCheck, hostTarget, sha256File, sha256Stream } from "./cli-check.ts";
import { appendCliRelease, readCliReleases } from "./cli-ledger.ts";
import { binaryName, CliVersion, formatIndex, formatSums, installScript, KEYS, mergeIndex, parseIndex, parseSums, SiteUrl, TARGETS, type CliSum } from "./cli-install.ts";
import { cloudflareStore, localStore, type CliStore } from "./cli-store.ts";
import { BUSY_CODE, takeReleaseLock } from "./release-lock.ts";

const ROOT = join(import.meta.dirname, "..", "..");
const CLI_MAIN = join(ROOT, "packages", "cli", "src", "main.ts");
const SECRETS = process.env.APM_SECRETS_DIR ?? join(homedir(), ".config", "apmjs");

const Args = z.object({
  stage: z.enum(["staging", "production", "local"]),
  host: z.string().default("127.0.0.1"),
  port: z.coerce.number().int().min(1).max(65535).default(8790),
  dir: z.string().default(join(homedir(), ".cache", "apm-cli-local")),
  serve: z.boolean(),
});

function option(name: string): string | undefined {
  const at = process.argv.indexOf(`--${name}`);

  return at > 0 ? process.argv[at + 1] : undefined;
}

const args = Args.parse({ stage: option("stage"), host: option("host"), port: option("port"), dir: option("dir"), serve: process.argv.includes("--serve") });
const version = CliVersion.parse(CLI_VERSION);
const log = (line: string) => process.stdout.write(`${line}\n`);

// ---------- where it goes ----------
function secret(name: string): string {
  const path = join(SECRETS, name);

  if (!existsSync(path)) throw new Error(`Missing ${path}. See docs/DEPLOY.md for the files deploy.ts reads.`);

  return readFileSync(path, "utf8").trim();
}

function accountId(): string {
  const id = /^\s*CLOUDFLARE_ACCOUNT_ID\s*=\s*["']?([^"'\s]+)/m.exec(secret("cloudflare.env"))?.[1];

  if (id === undefined) throw new Error("cloudflare.env has no CLOUDFLARE_ACCOUNT_ID.");

  return id;
}

const WorkersSubdomain = z.object({ result: z.object({ subdomain: z.string() }) });

type Destination = { store: CliStore; site: SiteUrl; close: () => Promise<void> };

async function destination(): Promise<Destination> {
  if (args.stage === "local") {
    mkdirSync(args.dir, { recursive: true });
    const local = await localStore({ dir: args.dir, host: args.host, port: args.port, bundleDir: mkdtempSync(join(tmpdir(), "apm-cli-local-")) });

    return { store: local.store, site: SiteUrl.parse(local.url), close: local.close };
  }

  const apiBase = process.env.APM_CLOUDFLARE_API ?? "https://api.cloudflare.com/client/v4";
  const token = secret("cloudflare-token");
  const account = accountId();
  let site: string;

  if (args.stage === "production") site = "https://apmjs.dev";
  else {
    const res = await fetch(`${apiBase}/accounts/${account}/workers/subdomain`, { headers: { authorization: `Bearer ${token}` } });
    const body = WorkersSubdomain.safeParse(await res.json().catch(() => null));

    if (!body.success) throw new Error(`Could not read the account's workers.dev subdomain (HTTP ${res.status}).`);
    site = `https://apmjs-web-${args.stage}.${body.data.result.subdomain}.workers.dev`;
  }

  return { store: cloudflareStore({ apiBase, token, accountId: account, bucket: `apmjs-cli-${args.stage}` }), site: SiteUrl.parse(site), close: async () => {} };
}

// ---------- build ----------
function git(...argv: string[]): string {
  return Bun.spawnSync(["git", ...argv], { cwd: ROOT }).stdout.toString().trim();
}

/** Builds every target into `dir` and checks this machine's own binary runs and reports the version. */
async function build(dir: string): Promise<CliSum[]> {
  const sums: CliSum[] = [];

  for (const t of TARGETS) {
    const out = join(dir, binaryName(t.target));
    const proc = Bun.spawnSync([process.execPath, "build", "--compile", "--minify", `--target=${t.bun}`, CLI_MAIN, "--outfile", out], { cwd: ROOT, stdout: "pipe", stderr: "pipe" });

    if (proc.exitCode !== 0) throw new Error(`bun build --compile for ${t.target} exited ${proc.exitCode}: ${proc.stderr.toString().trim()}`);
    sums.push({ version, target: t.target, sha256: await sha256File(out) });
    log(`built ${binaryName(t.target)} (${(Bun.file(out).size / 1024 / 1024).toFixed(1)} MiB)`);
  }

  const own = hostTarget();

  if (own !== null) {
    const ran = Bun.spawnSync([join(dir, binaryName(own)), "--version"], { env: { PATH: "/usr/bin:/bin", HOME: dir } });
    const said = ran.stdout.toString().trim();

    if (ran.exitCode !== 0 || said !== version) throw new Error(`the ${own} build, run here without Bun on PATH, exited ${ran.exitCode} and printed "${said}", not ${version}`);
    log(`${binaryName(own)} --version: ${said} (run without Bun on PATH)`);
  }

  return sums;
}

// ---------- check what the site serves ----------
async function hashUrl(url: string): Promise<{ status: number; sha256: string | null }> {
  const res = await fetch(url);

  if (!res.ok || res.body === null) return { status: res.status, sha256: null };

  return { status: res.status, sha256: await sha256Stream(res.body) };
}

/** Every binary of `version` downloaded back through the site and hashed, and the script the site serves. */
async function verify(site: SiteUrl, sums: readonly CliSum[], script: string): Promise<string[]> {
  const problems: string[] = [];

  for (const s of sums) {
    const url = `${site}/cli/${s.version}/${binaryName(s.target)}`;
    const got = await hashUrl(url);

    if (got.sha256 !== s.sha256) problems.push(`${url}: ${got.sha256 === null ? `HTTP ${got.status}` : `SHA-256 ${got.sha256}, not ${s.sha256}`}`);
  }

  const served = await fetch(`${site}/install`);
  const text = await served.text();

  if (!served.ok || text !== script) problems.push(`${site}/install: ${served.ok ? "serves another script than the one just written (an old version still answering?)" : `HTTP ${served.status}`}`);

  return problems;
}

// ---------- Homebrew ----------
const BREW_TAP = "opencoredev/homebrew-tap";

/** Starts the tap's Update apm workflow for this version through gh, which tests the new formula on every platform and commits it. Never fails the release; gh gets 30 s so a hung call cannot hold the release lock. */
function startBrewUpdate(released: CliVersion): string {
  const manual = `gh workflow run update-apm.yml --repo ${BREW_TAP} -f version=${released}`;

  try {
    const run = Bun.spawnSync(["gh", "workflow", "run", "update-apm.yml", "--repo", BREW_TAP, "-f", `version=${released}`], { stdout: "pipe", stderr: "pipe", timeout: 30_000, killSignal: "SIGKILL" });

    if (run.exitCode === 0) return `Homebrew: started the ${BREW_TAP} update for ${released} (https://github.com/${BREW_TAP}/actions)`;

    const why = run.exitCode === null ? "gh did not finish within 30 s and was stopped" : run.stderr.toString().trim() || `gh exited ${run.exitCode}`;

    return `Homebrew: could not start the tap update (${why}); run: ${manual}`;
  } catch (error) {
    return `Homebrew: could not run gh (${error instanceof Error ? error.message : String(error)}), so the tap was not updated; run: ${manual}`;
  }
}

// ---------- the run ----------
if (args.stage !== "local") {
  const taken = takeReleaseLock({ script: import.meta.path, argv: process.argv.slice(2), stage: args.stage });

  if (taken.kind === "busy") {
    log(`release-cli ${taken.text}`);
    process.exit(BUSY_CODE);
  }

  log(`release lock: held (${taken.lock.path})`);
}

const head = git("rev-parse", "HEAD") || "unknown";
const dirty = git("status", "--porcelain", "--untracked-files=no") !== "";
const revision = dirty ? `${head}-dirty` : head;

if (args.stage === "production" && dirty) {
  log(`refused: the tree has uncommitted changes; a production release is built from a commit. Nothing was changed.`);
  process.exit(1);
}

const { store, site, close } = await destination();
const work = mkdtempSync(join(tmpdir(), "apm-cli-release-"));
const decoder = new TextDecoder();
let code = 1;

try {
  log(`apm CLI ${version} → ${args.stage} (${site}), from ${revision.slice(0, 12)}, Bun ${Bun.version}`);
  const existing = await store.get(KEYS.sums(version));
  let sums: CliSum[];
  let binaries: "built" | "republished";

  if (existing !== null) {
    sums = parseSums(version, decoder.decode(existing));
    binaries = "republished";
    log(`apm ${version} is already released on ${args.stage} (${KEYS.sums(version)}); building nothing, uploading no binary`);
  } else {
    sums = await build(work);
    binaries = "built";

    for (const s of sums) {
      await store.put(KEYS.binary(version, s.target), Bun.file(join(work, binaryName(s.target))), "application/octet-stream");
      log(`uploaded ${KEYS.binary(version, s.target)}`);
    }

    // the release lock keeps any other run out, so nothing can have released this version since the read above
    await store.put(KEYS.sums(version), formatSums(sums), "text/plain; charset=utf-8");
    log(`released ${KEYS.sums(version)}`);
  }

  const before = await store.get(KEYS.index);
  const index = mergeIndex(before === null ? [] : parseIndex(decoder.decode(before)), sums);
  const indexText = formatIndex(index);

  if (before === null || decoder.decode(before) !== indexText) {
    await store.put(KEYS.index, indexText, "text/plain; charset=utf-8");
    log(`updated ${KEYS.index} (${new Set(index.map((s) => s.version)).size} version(s))`);
  }

  const script = installScript({ site, index });
  const published = await store.get(KEYS.script);

  if (published === null || decoder.decode(published) !== script) {
    await store.put(KEYS.script, script, "text/plain; charset=utf-8");
    log(`published ${KEYS.script}`);
  } else log(`${KEYS.script} unchanged`);

  const problems = await verify(site, sums, script);

  for (const p of problems) log(`FAIL: ${p}`);

  if (problems.length > 0) {
    log(`not recorded: the site does not serve this release correctly yet. Is the website deployed with the CLI bucket (deploy.ts)? Rerunning this is safe.`);
  } else {
    log(`PASS: ${site} serves every ${version} binary with its SHA-256, and the script just written`);
    const check = await installCheck(site);

    log(`${check.ok ? "PASS" : "FAIL"}: curl -fsSL ${site}/install | sh (${check.detail})`);
    const scriptHash = createHash("sha256").update(script).digest("hex");

    if (check.ok && args.stage !== "local") {
      const recorded = readCliReleases(args.stage).some((r) => r.version === version && r.script === scriptHash);

      if (!recorded) appendCliRelease({ version, stage: args.stage, at: new Date().toISOString(), sha: revision, site, binaries, sums, script: scriptHash });
      log(recorded ? "release record: already has this release" : `release record: ${version} on ${args.stage}`);
    }

    if (check.ok && args.stage === "production") log(startBrewUpdate(version));

    code = check.ok ? 0 : 1;
  }

  if (code === 0) {
    log(`\nInstall: curl -fsSL ${site}/install | sh`);

    for (const s of sums) log(`  ${s.sha256}  ${binaryName(s.target)}`);
  }

  if (args.stage === "local" && args.serve) {
    log(`\nserving ${site}/install and ${site}/cli/ from ${args.dir}; Ctrl-C stops`);
    await new Promise<void>((done) => process.once("SIGINT", () => done()));
  }
} finally {
  rmSync(work, { recursive: true, force: true });
  await close();
}

process.exit(code);
