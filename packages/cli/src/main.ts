#!/usr/bin/env bun
// apm: a thin layer over bun, npm, pnpm or yarn. It checks before it installs, runs or publishes,
// then hands the real work to the package manager the project already uses.
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { z } from "zod";
import { ambiguousPaths, analyze, describeSkip, finalize, findSecrets, isValidPackageName, missingEntries, readTarball, SCORE_FLOOR, type FileLike } from "@apm/core";
import { Api, ApiError, AuditResponse, NameResponse, ResolveFail, ResolveOk, ResolvePending, ScoreResponse, Tree, encodeName, parseSpec, type Capability, type InstallWarning, type Report } from "./api.ts";
import { installedPackages, isValidRange } from "./audit.ts";
import { explainCommand, searchCommand, type AgentIo } from "./agent.ts";
import { childEnv, registryArgs, scopeOverrides, scopesOf, withoutSecrets, type Override } from "./child.ts";
import { DEFAULT_REGISTRY, isApmToken, loadConfig, sameRegistry, saveToken, type Config } from "./config.ts";
import { capabilityLines } from "./capabilities.ts";
import { bunKeyNames, findLockfile, isLockPm, isRegistryVersion, lockedEntry, projectPins, type LockNode, type LockPm } from "./lockfile.ts";
import type { Mismatch } from "./verify.ts";
import { addArgs, detectPm, packArgs, publishArgs, runCmd, undoArgs, type Detection, type Pm } from "./pm.ts";
import { addedGraph, checkGraph, DEFAULT_CHECK, idOf, installedIds, wholeGraph, type Before, type CheckPolicy, type GraphVerdict, type InstalledGraph } from "./installed.ts";
import { bunInstallDir, hadLockfile, removeInstalled, restore, snapshot, undoAdd, verifyNodes, type Snapshot } from "./verify.ts";

const VERSION = "0.1.0";
const VALUE_FLAGS = new Set(["pm", "reason", "username", "email", "bump", "tag", "since", "cooldown", "floor", "password", "otp"]);

type Args = { cmd: string; positional: string[]; flags: Map<string, string | true>; raw: string[] };

function parseArgs(argv: string[]): Args {
  const [cmd = "help", ...rest] = argv;
  const positional: string[] = [];
  const flags = new Map<string, string | true>();
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i] ?? "";
    if (a === "-D") {
      flags.set("dev", true);
      continue;
    }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const key = eq > 0 ? a.slice(2, eq) : a.slice(2);
      if (eq > 0) flags.set(key, a.slice(eq + 1));
      else if (VALUE_FLAGS.has(key) && i + 1 < rest.length) flags.set(key, rest[++i] ?? "");
      else flags.set(key, true);
      continue;
    }
    positional.push(a);
  }
  return { cmd, positional, flags, raw: rest };
}

function flag(a: Args, k: string): string | null {
  const v = a.flags.get(k);
  return typeof v === "string" ? v : null;
}
function has(a: Args, k: string): boolean {
  return a.flags.has(k);
}

// ---------- output ----------
const useColor = process.stdout.isTTY === true && !process.env.NO_COLOR;
const paint = (code: string) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = paint("31");
const green = paint("32");
const yellow = paint("33");
const dim = paint("2");
const bold = paint("1");

let jsonMode = false;
let jsonDone = false;
let lastError: string | null = null;
function say(line = ""): void {
  (jsonMode ? process.stderr : process.stdout).write(`${line}\n`);
}
function warn(line: string): void {
  process.stderr.write(`${line}\n`);
}

/** A failure: printed to stderr, and kept for the --json result. */
function fail(line: string): void {
  lastError = line;
  warn(red(line));
}

/** With --json every apm command prints exactly one JSON document on stdout; the first one wins. */
function emit<Doc extends { ok: boolean }>(doc: Doc): void {
  if (!jsonMode || jsonDone) return;
  jsonDone = true;
  process.stdout.write(`${JSON.stringify(doc)}\n`);
}

function gradeColor(score: number): (s: string) => string {
  return score >= 75 ? green : score >= 40 ? yellow : red;
}

function printCard(title: string, report: Report | null, opts: { maxEvidence?: number } = {}): void {
  if (!report) {
    say(`${bold(title)}  ${dim("score unknown (not analyzed)")}`);
    return;
  }
  const c = gradeColor(report.score);
  say(`${bold(title)}  ${c(`score ${report.score}/100 (${report.grade})`)}`);
  const bad = report.signals.filter((s) => s.points < 0);
  const info = report.signals.filter((s) => s.points >= 0);
  if (bad.length === 0) say(`  ${green("✓")} no risk signals found`);
  for (const s of bad) {
    const pts = String(s.points).padStart(4);
    say(`  ${s.confidence === "possible" ? dim(pts) : red(pts)} ${s.id}${s.confidence === "possible" ? " (possible)" : ""}  ${dim(s.label)}`);
    for (const e of s.evidence.slice(0, opts.maxEvidence ?? 2)) say(`        ${dim(e)}`);
  }
  for (const s of info) say(`  ${dim(`   · ${s.id}  ${s.label}${s.evidence[0] ? ` (${s.evidence[0]})` : ""}`)}`);
  printCapabilities(report.capabilities);
}

/** What the package can do, with its declaration and the variables read outside it. Never scored on its own. */
function printCapabilities(list: readonly Capability[]): void {
  for (const line of capabilityLines(list, { bold, dim, green, yellow })) say(line);
}

// ---------- shared ----------
function env(): Record<string, string | undefined> {
  return { ...process.env };
}

/** Reads the config and says so when APM_TOKEN is held back from a registry it was not issued for. */
function config(cwd: string): Config {
  const cfg = loadConfig(cwd, env());

  if (cfg.withheld) warn(yellow(`apm: APM_TOKEN is for ${cfg.withheld}, so it is not sent to ${cfg.registry} (set by a project .npmrc or npm_config_registry)`));

  return cfg;
}

/**
 * Child env for the package manager: no credentials (install scripts and package binaries run with it), and
 * the registry and the given scopes pinned to the registry apm just checked.
 */
function pmEnv(registry: string, scopes: string[] = []): Record<string, string | undefined> {
  return childEnv({ parent: process.env, registry, scopes, keepAuth: false });
}

/** Refuses when a config file would fetch (or publish) a scope from a registry other than the one apm checked. */
function refuseOverrides(overrides: Override[], registry: string, action: string): boolean {
  if (overrides.length === 0) return false;

  for (const o of overrides) fail(`refused: ${o.source} sends ${o.scope} to ${o.registry}, but apm checked ${registry}`);
  say(`apm will not ${action} a package from a registry it did not check. Remove those lines, or point APM_REGISTRY at that registry.`);

  return true;
}

async function readPassword(a: Args): Promise<string> {
  const given = flag(a, "password");
  if (given) return given;
  if (has(a, "password-stdin")) {
    const text = await new Response(Bun.stdin.stream()).text();
    return text.split(/\r?\n/)[0] ?? "";
  }
  if (!process.stdin.isTTY) throw new Error("This needs your account password. Pass it with --password-stdin.");
  const tty = jsonMode ? process.stderr : process.stdout;
  tty.write("Password: ");
  const answer = await readHidden();
  tty.write("\n");
  return answer;
}

type Proof = { password?: string; otp?: string };

/**
 * The second factor for revoke, restore, incident and owner changes: --otp <code>, or a password on
 * legacy password registries. Without either, a terminal is asked for the code; Enter skips it, which
 * works when you approved this exact command on the website in the last 10 minutes (the error links there).
 */
async function readProof(a: Args): Promise<Proof> {
  if (flag(a, "password") || has(a, "password-stdin")) return { password: await readPassword(a) };
  const otp = flag(a, "otp");
  if (otp) return { otp };
  if (!process.stdin.isTTY) return {};
  const answer = prompt("Code from your authenticator app (Enter to skip if you approved this command on the website):");
  return answer && answer.trim() ? { otp: answer.trim() } : {};
}

function errorOf(body: unknown, status: number): string {
  if (typeof body === "object" && body !== null) {
    if ("message" in body && typeof body.message === "string") return body.message;
    if ("error" in body && typeof body.error === "string") return body.error;
  }
  return `HTTP ${status}`;
}

function readHidden(): Promise<string> {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    let buf = "";
    stdin.setRawMode(true);
    stdin.resume();
    const onData = (d: Buffer): void => {
      for (const ch of d.toString("utf8")) {
        if (ch === "\r" || ch === "\n" || ch === "\u0004") {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.off("data", onData);
          resolve(buf);
          return;
        }
        if (ch === "\u0003") process.exit(130);
        if (ch === "\u007f") buf = buf.slice(0, -1);
        else buf += ch;
      }
    };
    stdin.on("data", onData);
  });
}

function pmFor(a: Args, cwd: string): Detection {
  return detectPm(cwd, flag(a, "pm"));
}

// ---------- add / x ----------
type UncheckedDeps = z.infer<typeof Tree>["uncheckedDeps"];

/**
 * `forceable`: --force would get past this refusal, because some version is held back only by the score floor
 * or the cooldown. Revoked and yanked versions, unknown names and dangerous dependencies never are.
 */
type TreePackages = z.infer<typeof Tree>["packages"];

/**
 * `tree`: the packages the registry checked under this one; every scope among them is pinned to that registry.
 * `warnings`: what installs anyway, and why it was flagged (published inside the cooldown, a low or incomplete
 * score, no score, a failed lookup). `projectPeers`: required peers the project provides, and the version checked for each.
 */
type Resolved = {
  name: string;
  version: string | null;
  report: Report | null;
  skipped: { version: string; reason: string; revokeReason?: string | null | undefined }[];
  blocked: string | null;
  forceable: boolean;
  source: string;
  unchecked: UncheckedDeps;
  tree: TreePackages;
  warnings: InstallWarning[];
  projectPeers: z.infer<typeof Tree>["projectPeers"];
};

const FORCEABLE = /^(published \d+h ago|score \d+\/100 is below)/;

/**
 * Strict mode: refuse a version inside the 24-hour cooldown, a score under 40, an incomplete analysis, a version apm cannot score or has not scored yet, and
 * a dependency the registry could not look up, as apm did before scores became warnings. --strict or APM_STRICT=1.
 */
function strictMode(a: Args): boolean {
  return has(a, "strict") || process.env.APM_STRICT === "1";
}

/**
 * How long `apm add` and `apm x` keep asking about a version the registry is still analysing: 90 s in all, each ask
 * itself waiting up to about 20 s at the registry. APM_PENDING_WAIT_MS sets another bound (tests).
 */
export const PENDING_WAIT_MS = 90_000;

function pendingWaitMs(): number {
  const n = Number(process.env.APM_PENDING_WAIT_MS);

  return Number.isFinite(n) && n >= 0 ? n : PENDING_WAIT_MS;
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * GET /resolve, asked again while the registry answers 202 (still analysing) until PENDING_WAIT_MS is over, with a
 * progress line each time. The last answer is returned: a 202 then still means pending, and is refused.
 */
async function resolveWaiting(api: Api, name: string, params: URLSearchParams): Promise<{ status: number; body: unknown }> {
  const started = Date.now();
  const limit = pendingWaitMs();

  for (;;) {
    const r = await api.raw(`-/apm/v1/resolve?${params}`);
    const pending = r.status === 202 ? ResolvePending.safeParse(r.body) : null;
    const elapsed = Date.now() - started;

    if (!pending?.success || elapsed >= limit) return r;
    const count = pending.data.pendingCount ?? pending.data.pending.length;

    say(dim(`apm: ${name}: ${count === 1 ? "1 version is" : `${count} versions are`} still being analysed (${pending.data.pending.slice(0, 3).map((p) => `${p.name}@${p.version}`).join(", ")}${count > 3 ? ", …" : ""}); waiting, ${Math.round(elapsed / 1000)}s of ${Math.round(limit / 1000)}s`));
    // at least a second between asks, whatever the registry says
    await sleep(Math.min(Math.max(1, pending.data.retryAfter ?? 5) * 1000, Math.max(0, limit - elapsed)));
  }
}

/**
 * What a resolve is asked for besides the package: the project's direct dependencies, each `name`, `name@version` (the
 * version its lockfile pins) or `name@?` (a lockfile apm cannot read, or an entry it cannot pin), so the early answer
 * checks a peer the project provides at the version its lockfile pins (review of 1924692, finding 1). It is advisory:
 * the check after the install reads what the package manager really installed (review of 16fc8b5, findings 1 to 3).
 * No os or cpu: the registry then checks every platform's optional packages (review of 1924692, findings 2 and 3).
 * `left out`: why a project's context was not sent whole (too many names for one request); it is never cut short.
 */
type ResolveContext = { installed: readonly string[]; leftOut: string | null };

/** The names the registry takes in one resolve's `installed` (MAX_INSTALLED_NAMES there). */
const MAX_INSTALLED_NAMES = 500;

/**
 * The bytes `installed` may take in a resolve's URL: well under what an edge takes in a request line (an HTTP 414 at
 * about 16 KB on Cloudflare), so a project with long scoped names is told so rather than refused by the edge.
 */
const MAX_INSTALLED_BYTES = 8_000;

const ProjectManifest = z.object({
  dependencies: z.record(z.string(), z.unknown()).optional().catch(undefined),
  devDependencies: z.record(z.string(), z.unknown()).optional().catch(undefined),
  optionalDependencies: z.record(z.string(), z.unknown()).optional().catch(undefined),
  peerDependencies: z.record(z.string(), z.unknown()).optional().catch(undefined),
});

/** The project's direct dependency names, from the nearest package.json: what is already installed beside a new package. */
function projectNames(cwd: string): string[] {
  let dir = cwd;

  for (let i = 0; i < 20; i++) {
    const p = join(dir, "package.json");

    if (existsSync(p)) {
      try {
        const m = ProjectManifest.safeParse(JSON.parse(readFileSync(p, "utf8")));

        if (!m.success) return [];
        const names = new Set([m.data.dependencies, m.data.devDependencies, m.data.optionalDependencies, m.data.peerDependencies].flatMap((d) => Object.keys(d ?? {})));

        return [...names].filter((n) => isValidPackageName(n));
      } catch {
        return [];
      }
    }

    const parent = dirname(dir);

    if (parent === dir) break;
    dir = parent;
  }

  return [];
}

/** The context of a resolve for the package manager `pm` runs from `cwd`; `installed` only where apm add adds to a project. */
function resolveContext(input: { pm: Detection["pm"]; cwd: string; project: boolean }): ResolveContext {
  if (!input.project) return { installed: [], leftOut: null };
  const names = projectNames(input.cwd);

  // never a part of it: the early answer goes without, and the check after the install reads every installed package
  if (names.length > MAX_INSTALLED_NAMES) return { installed: [], leftOut: `your package.json lists ${names.length} dependencies, more than the ${MAX_INSTALLED_NAMES} the registry's early check takes` };
  const pins = projectPins({ cwd: input.cwd, pm: input.pm, names });

  const installed = names.map((n) => {
    const pin = pins.get(n);

    if (pin === undefined) return n;

    switch (pin.kind) {
      case "pinned":
        return `${n}@${pin.version}`;
      case "unknown":
        return `${n}@?`;
      default: {
        const _exhaustive: never = pin;

        return _exhaustive;
      }
    }
  });

  const bytes = encodeURIComponent(installed.join(",")).length;

  if (bytes > MAX_INSTALLED_BYTES) return { installed: [], leftOut: `your package.json's ${names.length} dependencies take ${bytes} bytes, more than the ${MAX_INSTALLED_BYTES} the registry's early check takes in one request` };

  return { installed, leftOut: null };
}

async function resolveSpec(api: Api, spec: string, a: Args, ctx: ResolveContext): Promise<Resolved> {
  const { name, range } = parseSpec(spec);
  const force = has(a, "force");
  const strict = strictMode(a);
  // no os or cpu: every platform's optional packages are checked (ResolveContext)
  const params = new URLSearchParams({ name, range: range ?? "latest" });

  if (ctx.installed.length > 0) params.set("installed", ctx.installed.join(","));

  if (strict) params.set("strict", "1");
  // --force overrides this package's score floor and cooldown; revoked and yanked versions stay blocked,
  // and the registry still checks its dependency tree at the default floor
  if (has(a, "no-cooldown") || force) params.set("cooldown", "0");
  else if (flag(a, "cooldown")) params.set("cooldown", flag(a, "cooldown") ?? "24h");
  if (force) params.set("floor", "0");
  else if (flag(a, "floor")) params.set("floor", flag(a, "floor") ?? "40");
  const r = await resolveWaiting(api, name, params);
  if (r.status === 200) {
    const ok = ResolveOk.parse(r.body);

    return { name, version: ok.version, report: ok.report, skipped: ok.skipped, blocked: null, forceable: false, source: ok.source ?? "apm", unchecked: ok.tree?.uncheckedDeps ?? [], tree: ok.tree?.packages ?? [], warnings: ok.warnings, projectPeers: ok.tree?.projectPeers ?? [] };
  }
  if (r.status === 422) {
    const f = ResolveFail.extend({ newest: z.object({ version: z.string(), report: z.unknown() }).nullable().optional(), tree: z.object({ blocks: z.array(z.unknown()) }).loose().optional() }).parse(r.body);
    const newestReport = f.newest ? (await scoreOf(api, name, f.newest.version)) : null;
    const treeBlocked = (f.tree?.blocks.length ?? 0) > 0;
    const forceable = !force && !treeBlocked && f.skipped.some((s) => FORCEABLE.test(s.reason));

    return { name, version: f.newest?.version ?? null, report: newestReport, skipped: f.skipped, blocked: f.error, forceable, source: "apm", unchecked: [], tree: [], warnings: [], projectPeers: [] };
  }

  if (r.status === 503) {
    // the registry or npm could not be asked about the package or a dependency (strict), or the package itself
    const said = z.object({ error: z.string() }).safeParse(r.body);
    const msg = said.success ? said.data.error : `the registry could not check ${name} (HTTP 503)`;

    return { name, version: null, report: null, skipped: [], blocked: msg, forceable: false, source: "apm", unchecked: [], tree: [], warnings: [], projectPeers: [] };
  }

  if (r.status === 202) {
    // still pending after the wait (strict): no score is not a pass, and --force cannot lift it
    const p = ResolvePending.parse(r.body);
    const count = p.pendingCount ?? p.pending.length;
    const listed = p.pending.slice(0, 5).map((d) => `${d.name}@${d.version}`).join(", ");

    return {
      name,
      version: p.version,
      report: null,
      skipped: [],
      blocked: `${name}${p.version ? `@${p.version}` : ""} is still being analysed, try again in a minute (${count === 1 ? "1 version has" : `${count} versions have`} no score yet: ${listed}${count > 5 ? ", …" : ""})`,
      forceable: false,
      source: "apm",
      unchecked: [],
      tree: [],
      warnings: [],
      projectPeers: [],
    };
  }
  if (r.status === 404) {
    const msg = typeof r.body === "object" && r.body !== null && "error" in r.body ? String(r.body.error) : "not found";

    return { name, version: null, report: null, skipped: [], blocked: `${name}: ${msg}`, forceable: false, source: "none", unchecked: [], tree: [], warnings: [], projectPeers: [] };
  }
  if (r.status === 414) throw new ApiError(r.status, `resolve failed for ${name}: the request was too long for ${api.cfg.registry} (HTTP 414). apm sends the project's direct dependencies with it; nothing was installed`, r.body);

  if (r.status === 400) throw new ApiError(r.status, `resolve failed for ${name}: ${errorOf(r.body, r.status)}`, r.body);
  throw new ApiError(r.status, `resolve failed for ${name} (HTTP ${r.status})`, r.body);
}

async function scoreOf(api: Api, name: string, version: string): Promise<Report | null> {
  try {
    return await api.get(`-/apm/v1/score/${encodeName(name)}/${encodeURIComponent(version)}`, ScoreResponse);
  } catch {
    return null;
  }
}

function printResolved(r: Resolved): void {
  printCard(`${r.blocked ? red("✗") : r.warnings.length > 0 ? yellow("!") : green("✓")} ${r.name}@${r.version ?? "?"}`, r.report);
  for (const s of r.skipped.slice(0, 5)) say(`  ${dim(`skipped ${s.version}: ${s.reason}${s.revokeReason ? ` (${s.revokeReason})` : ""}`)}`);
  // dependencies apm could not score install unchecked: say which, so nobody reads silence as clean. A registry that
  // sends each as a warning of its own (review of 93274c8, finding 4) has them printed with the warnings instead
  const warnedEach = r.warnings.some((w) => w.kind === "unchecked" && w.via.length > 0);

  if (!warnedEach) {
    for (const u of r.unchecked.slice(0, 10)) say(`  ${yellow("!")} not checked: ${u.dependency} (${u.reason})`);
    if (r.unchecked.length > 10) say(`  ${yellow("!")} and ${r.unchecked.length - 10} more dependencies not checked`);
  }

  // a peer the project provides: which of its versions apm checked. One it could not tell is a warning of its own
  for (const p of r.projectPeers.slice(0, 10)) {
    if (p.kind === "lockfile") say(`  ${dim(`peer ${p.dependency}: your project provides it; apm checked ${p.version ?? "?"}, the version your lockfile pins`)}`);
    else if (p.kind === "newest" || p.kind === undefined) say(`  ${dim(`peer ${p.dependency}: your package.json lists it with no lockfile entry; apm checked the newest in range${p.version ? `, ${p.version}` : ""}, and checks the version your package manager picks once it is installed`)}`);
  }

  printWarnings({ warnings: r.warnings, binaries: r.tree.filter((p) => p.platform !== undefined), allFamilies: true, closing: EARLY_CLOSING });
}

/**
 * The family a platform binary belongs to, for grouping: its scope and the first part of its name, as
 * `@next/swc-*` for @next/swc-linux-x64-gnu or `@img/sharp-*` for @img/sharp-libvips-darwin-arm64.
 */
function platformFamily(name: string): string {
  const slash = name.startsWith("@") ? name.indexOf("/") + 1 : 0;
  const dash = name.indexOf("-", slash);

  return dash < 0 ? name : `${name.slice(0, dash + 1)}*`;
}

/** A warning in a few words, for a family's summary line. */
function shortReason(w: InstallWarning): string {
  switch (w.kind) {
    case "cooldown":
      return "inside the 24-hour cooldown";
    case "low-score":
      return `scored under ${SCORE_FLOOR}`;
    case "incomplete":
      return "analysis incomplete";
    case "unscorable":
      return /too large/.test(w.text) ? "too large to analyze" : "cannot be scored";
    case "pending":
      return "not scored yet";
    case "unavailable":
      return "could not be looked up";
    case "unchecked":
      return "not checked";
    default: {
      const _exhaustive: never = w.kind;

      return _exhaustive;
    }
  }
}

/** "2 too large to analyze, 1 inside the 24-hour cooldown": how many of `warnings` say each thing. */
function reasonCounts(warnings: readonly InstallWarning[]): string {
  const counts = new Map<string, number>();

  for (const w of warnings) counts.set(shortReason(w), (counts.get(shortReason(w)) ?? 0) + 1);

  return [...counts].map(([why, n]) => `${n} ${why}`).join(", ");
}

/**
 * The platform binaries among `binaries`, one line a family: every platform's are checked, since the package manager
 * may install any of them, so they are summed up rather than listed (`--json` lists each warning). `all`: a line for a
 * family with no warning too. Returns the warnings left to print one by one.
 */
function printPlatformFamilies(warnings: readonly InstallWarning[], binaries: readonly { name: string; version: string }[], opts: { all: boolean }): InstallWarning[] {
  const families = new Map<string, Set<string>>();

  for (const p of binaries) {
    const members = families.get(platformFamily(p.name)) ?? new Set<string>();
    members.add(idOf(p));
    families.set(platformFamily(p.name), members);
  }

  if (families.size === 0) return [...warnings];
  const familyOf = new Map([...families].flatMap(([f, members]) => [...members].map((m): [string, string] => [m, f])));
  const rest: InstallWarning[] = [];
  const grouped = new Map<string, InstallWarning[]>();

  for (const w of warnings) {
    const f = familyOf.get(idOf(w));

    if (f === undefined) rest.push(w);
    else grouped.set(f, [...(grouped.get(f) ?? []), w]);
  }

  const shown = [...families].filter(([f]) => opts.all || grouped.has(f));

  if (shown.length > 0) say();

  for (const [family, members] of shown) {
    const flagged = grouped.get(family) ?? [];
    const head = `${members.size} platform ${members.size === 1 ? "binary" : "binaries"} (${family})`;

    say(flagged.length > 0 ? `${yellow(bold("WARNING"))} ${head}: ${reasonCounts(flagged)}` : dim(`${head}: no warnings`));
  }

  return rest;
}

/** At most this many warnings are printed per package; --json has them all. */
const MAX_PRINTED_WARNINGS = 10;

const EARLY_CLOSING = "apm installs it anyway: a score or a fresh publish informs, it does not block. To refuse these instead, run with --strict (or APM_STRICT=1).";

/**
 * Each warning on an install that goes ahead, as a block: what, why (up to three reasons, each with its file and
 * line) and where to read more. A score never refuses by default; this is how the person installing is told.
 * `closing`: the line after them, if any.
 */
function printWarnings(input: { warnings: readonly InstallWarning[]; binaries: readonly { name: string; version: string }[]; allFamilies: boolean; closing: string | null }): void {
  const all = input.warnings;
  const warnings = printPlatformFamilies(all, input.binaries, { all: input.allFamilies });

  if (all.length === 0) return;
  say();

  for (const w of warnings.slice(0, MAX_PRINTED_WARNINGS)) {
    say(`${yellow(bold("WARNING"))} ${bold(`${w.name}@${w.version}`)} ${w.text}${w.via.length > 0 ? dim(` (via ${w.via.join(" > ")})`) : ""}`);

    for (const reason of w.reasons) say(`  - ${reason}`);

    if (w.url) say(`  ${dim(w.url)}`);
  }

  if (warnings.length > MAX_PRINTED_WARNINGS) say(yellow(`and ${warnings.length - MAX_PRINTED_WARNINGS} more warnings (apm ... --json lists them all)`));

  if (input.closing !== null) say(yellow(input.closing));
}

/** What to tell someone whose install was refused: --force only when it would help, and what it does. */
function refusalAdvice(blocked: Resolved[], verb: "add" | "x", strict: boolean): void {
  const forceable = blocked.filter((b) => b.forceable);
  const stuck = blocked.filter((b) => !b.forceable);

  if (forceable.length > 0) {
    say(`Review the signals above. To ${verb === "add" ? "install" : "run"} anyway: apm ${verb} ${forceable.map((b) => b.name).join(" ")} --force`);
    say(dim("  --force lifts the score floor and the cooldown for the named package only; its dependencies are still checked."));
  }

  if (stuck.length > 0) say(`--force does not help for ${stuck.map((b) => b.name).join(", ")}: revoked or yanked versions, versions apm reviewers confirmed malicious and unknown names stay blocked${strict ? "; in strict mode, so do versions apm has not scored or cannot score, and dependencies under the floor or inside their cooldown" : ""}.`);

  const analysing = blocked.filter((b) => b.blocked?.includes("still being analysed") || b.blocked?.includes("could not be checked"));

  if (analysing.length > 0) say(`Run apm ${verb} ${analysing.map((b) => b.name).join(" ")} again in a minute${strict ? ", or without --strict to install with a warning" : ""}.`);
}

const DistSchema = z.object({ versions: z.record(z.string(), z.object({ dist: z.object({ integrity: z.string().optional(), tarball: z.string().optional() }).loose() }).loose()) }).loose();

/**
 * Before the install: a lockfile entry for an added name@version must hold the integrity the checked registry
 * serves. bun and pnpm keep a locked name@version even when told another registry, so an entry pinned to
 * another artifact is refused before anything is fetched. The whole tree is checked after the install.
 */
async function lockMismatches(input: { api: Api; cwd: string; pm: Pm; results: Resolved[] }): Promise<string[]> {
  const { api, cwd, pm } = input;
  const problems: string[] = [];

  for (const r of input.results) {
    if (r.version === null) continue;
    const locked = lockedEntry({ cwd, pm, name: r.name, version: r.version });

    if (!locked?.integrity) continue;

    let expected: string | undefined;

    try {
      expected = (await api.get(encodeName(r.name), DistSchema)).versions[r.version]?.dist.integrity;
    } catch {
      expected = undefined;
    }

    if (!expected) warn(yellow(`apm: ${api.cfg.registry} gave no integrity for ${r.name}@${r.version}; the lockfile entry was not compared`));
    else if (expected !== locked.integrity) problems.push(`${r.name}@${r.version}: the lockfile has ${locked.integrity}${locked.resolved ? ` from ${locked.resolved}` : ""}, but ${api.cfg.registry} serves ${expected}`);
  }

  return problems;
}

/** Every scope in the checked trees: the added packages, what the registry walked under them, and what it could not check. */
function treeScopes(results: Resolved[]): string[] {
  return scopesOf(results.flatMap((r) => [r.name, ...r.tree.map((p) => p.name), ...r.unchecked.map((u) => u.dependency)]));
}

/**
 * What the check after an install found, for the --json result. `source`: where apm read the installed graph.
 * `refused`: apm refused it, so no install script ran. `restored`: what apm did to undo a refused add, and which of the
 * refused or added versions are still on disk.
 */
type InstalledReport = {
  source: "lockfile" | "node_modules";
  checked: number;
  blocked: { name: string; version: string; reason: string }[];
  warnings: InstallWarning[];
  refused: boolean;
  restored: { command: string | null; code: number | null; left: string[] } | null;
};

/**
 * The policy the check after an install applies, as resolveSpec asks the registry for it: --force and --no-cooldown
 * turn the cooldown off (resolve's cooldown is the whole tree's), --cooldown and --floor set them, and --force lifts the
 * score floor and the cooldown of the named packages only.
 */
function checkPolicy(a: Args, results: readonly Resolved[]): CheckPolicy {
  const force = has(a, "force");
  const floor = Number(flag(a, "floor"));

  return {
    cooldown: has(a, "no-cooldown") || force ? "0" : flag(a, "cooldown"),
    floor: !force && flag(a, "floor") !== null && Number.isFinite(floor) ? floor : null,
    lifted: new Set(force ? results.flatMap((r) => (r.version === null ? [] : [idOf({ name: r.name, version: r.version })])) : []),
  };
}

/** The early answer's warnings, as `name@version:kind`, so the check after the install prints each once. */
function earlyKeys(results: readonly Resolved[]): Set<string> {
  return new Set(results.flatMap((r) => r.warnings.map((w) => `${idOf(w)}:${w.kind}`)));
}

/** The check after an install: what apm could not read, a lockfile entry that is not the checked artifact, or the verdict. */
type PostCheck =
  | { kind: "unreadable"; reason: string }
  | { kind: "mismatch"; bad: Mismatch[] }
  | { kind: "checked"; graph: Extract<InstalledGraph, { kind: "lockfile" | "node_modules" }>; verdict: GraphVerdict; refused: boolean };

/**
 * Checks what the package manager installed, at the exact versions it wrote, before any install script runs: each
 * lockfile entry must be the artifact the registry serves, then every package is asked about in one pass (scan). A
 * revoked, yanked or confirmed malicious version refuses in every mode; strict mode refuses every warning too. Prints
 * the verdict: the warnings of the real graph, without those the early answer printed already, and where the package
 * manager installed another version than the early answer checked.
 */
async function checkInstalled(input: { api: Api; graph: InstalledGraph; pm: Pm; strict: boolean; results: readonly Resolved[]; installed: string; policy: CheckPolicy }): Promise<PostCheck> {
  const { api, graph, strict } = input;

  if (graph.kind === "unreadable") return { kind: "unreadable", reason: graph.reason };
  const verdict = await checkGraph({ api, packages: graph.packages, notFromRegistry: graph.notFromRegistry, waitMs: pendingWaitMs(), progress: (line) => say(dim(line)), policy: input.policy });

  if (graph.kind === "lockfile") {
    // a version the registry does not list may be one it revoked or yanked: the verdict says so, with its reason
    const blocked = new Set(verdict.blocked.map(idOf));
    const integrity = await verifyNodes({ api, nodes: graph.nodes });
    const bad = integrity.kind === "mismatch" ? integrity.bad.filter((b) => b.served || !blocked.has(idOf(b.node))) : [];

    if (bad.length > 0) return { kind: "mismatch", bad };
  }

  const refused = verdict.blocked.length > 0 || (strict && verdict.warnings.length > 0);
  const total = graph.packages.length + graph.notFromRegistry.length;

  say();
  say(dim(`apm: checked the ${total} package${total === 1 ? "" : "s"} ${input.installed} at the versions ${input.pm} installed (${graph.kind === "lockfile" ? graph.path.split("/").at(-1) ?? "its lockfile" : "node_modules"}), before any install script`));

  if (graph.kind === "node_modules") for (const u of graph.unreadable.slice(0, 5)) say(`  ${yellow("!")} not read: ${u.id} (${u.reason})`);

  // the early answer checked a version the package manager did not install: say which one it installed instead
  const installedIds = new Set(graph.packages.map(idOf));
  const swapped = input.results.flatMap((r) => r.tree.filter((p) => !installedIds.has(idOf(p))).flatMap((p) => {
    const instead = graph.packages.filter((g) => g.name === p.name).map((g) => g.version);

    return instead.length > 0 ? [`${p.name}: the early check read ${p.version}, ${input.pm} installed ${instead.join(" and ")}`] : [];
  }));

  for (const line of [...new Set(swapped)].slice(0, 5)) say(dim(`  ${line}; that is the version checked here`));

  for (const b of verdict.blocked) fail(`refused: ${b.name}@${b.version}: ${b.reason}`);
  const binaries = graph.packages.filter((p) => p.platform);

  if (strict) {
    printWarnings({ warnings: verdict.warnings, binaries, allFamilies: false, closing: null });

    if (verdict.warnings.length > 0) fail(`refused: strict mode refuses ${verdict.warnings.length === 1 ? "this warning" : `these ${verdict.warnings.length} warnings`} (${[...new Set(verdict.warnings.map(idOf))].slice(0, 5).join(", ")}${verdict.warnings.length > 5 ? ", …" : ""})`);
  } else {
    const early = earlyKeys(input.results);
    const fresh = verdict.warnings.filter((w) => !early.has(`${idOf(w)}:${w.kind}`));
    const seen = verdict.warnings.length - fresh.length;

    printWarnings({ warnings: fresh, binaries, allFamilies: false, closing: fresh.length > 0 && !refused ? "apm installed them anyway: a score or a fresh publish informs, it does not block. To refuse these instead, run with --strict (or APM_STRICT=1)." : null });

    if (seen > 0) say(dim(`apm: ${seen} warning${seen === 1 ? " is" : "s are"} the early check's, shown above`));
  }

  if (!refused && verdict.warnings.length === 0) say(dim("apm: no warnings"));

  return { kind: "checked", graph, verdict, refused };
}

/** The report of a check, for --json. */
function reportOf(post: Extract<PostCheck, { kind: "checked" }>, restored: InstalledReport["restored"]): InstalledReport {
  return { source: post.graph.kind, checked: post.graph.packages.length + post.graph.notFromRegistry.length, blocked: post.verdict.blocked, warnings: post.verdict.warnings, refused: post.refused, restored };
}

/**
 * Runs the install scripts `apm add` held back, now that the tree is verified: npm rebuilds the packages
 * that have them, pnpm builds what it recorded as pending, and bun reinstalls them from its verified
 * lockfile (bun only runs scripts while installing a package, and only for trusted ones).
 */
async function runHeldScripts(input: { pm: LockPm; cwd: string; nodes: LockNode[]; registry: string; scopes: string[]; quiet: boolean }): Promise<number> {
  const { pm, cwd } = input;
  const withScripts = input.nodes.filter((n) => n.hasInstallScript);
  const env = pmEnv(input.registry, input.scopes);
  const opts = { cwd, env, stdoutToStderr: jsonMode || input.quiet };

  switch (pm) {
    case "npm": {
      const names = [...new Set(withScripts.map((n) => n.name))];

      return names.length === 0 ? 0 : (await runCmd(["npm", "rebuild", ...names], opts)).code;
    }

    case "pnpm":
      return (await runCmd(["pnpm", "rebuild", "--pending"], opts)).code;
    case "bun": {
      if (withScripts.length === 0) return 0;
      const lock = findLockfile(cwd, "bun");
      const root = lock ? dirname(lock) : cwd;

      for (const n of withScripts) rmSync(bunInstallDir(root, bunKeyNames(n.key)), { recursive: true, force: true });

      return (await runCmd(["bun", "install", "--frozen-lockfile", ...registryArgs("bun", input.registry, input.scopes)], opts)).code;
    }

    default: {
      const _exhaustive: never = pm;

      return _exhaustive;
    }
  }
}

/**
 * Undoes an add apm refused after the install: package.json and the lockfile go back to their bytes from before it,
 * the package manager puts node_modules back in step with scripts off (undoArgs), and what the add brought in that is
 * still there is removed. Says exactly what is left on disk. Returns what it did, for --json.
 */
async function undoRefusedAdd(input: { cwd: string; pm: Pm; before: Snapshot; beforeIds: Before; beforeNames: ReadonlySet<string>; results: readonly Resolved[]; post: Extract<PostCheck, { kind: "checked" }>; registry: string; scopes: string[] }): Promise<InstalledReport["restored"]> {
  const { cwd, pm, before, post } = input;
  const addedNames = input.results.map((r) => r.name).filter((n) => !input.beforeNames.has(n));
  const reinstall = undoArgs(pm, { hadLockfile: hadLockfile(before), addedNames });
  const cmd = reinstall === null ? null : [...reinstall, ...registryArgs(pm, input.registry, input.scopes)];
  const refusedIds = [...post.verdict.blocked.map(idOf), ...(post.refused ? post.verdict.warnings.map(idOf) : [])];
  const added = post.graph.packages.filter((p) => !input.beforeIds.ids.has(idOf(p)));
  const watch = [...new Set([...refusedIds, ...added.map(idOf)])];

  if (cmd !== null) say(dim(`→ ${cmd.join(" ")}  (putting the project back)`));
  const undone = await undoAdd({ cwd, before, reinstall: cmd, added, watch, run: async (c) => (await runCmd(c, { cwd, env: { ...pmEnv(input.registry, input.scopes), npm_config_ignore_scripts: "true" }, stdoutToStderr: true })).code });
  const files = before.files.map((f) => f.path.split("/").at(-1) ?? f.path).join(" and ");
  const scripts = pm === "yarn" ? "yarn ran install scripts while it installed (apm cannot hold them back under yarn); apm runs none of its own" : "No install script ran";

  say();
  say(`${scripts}. apm put ${files} back as they were before apm add${cmd === null ? "" : `, then ran ${cmd.slice(0, 3).join(" ")} … (exit ${undone.code ?? "?"}) to put node_modules back`}.`);
  const blockedIds = new Set(post.verdict.blocked.map(idOf));
  const stayed = undone.left.filter((id) => input.beforeIds.ids.has(id) && blockedIds.has(id));
  const leftover = undone.left.filter((id) => !input.beforeIds.ids.has(id));

  if (leftover.length > 0) say(yellow(`Still in node_modules, never run by apm: ${leftover.slice(0, 10).join(", ")}${leftover.length > 10 ? `, and ${leftover.length - 10} more` : ""}. Delete node_modules and reinstall to be sure.`));
  else say("Nothing this add installed is left in node_modules.");

  if (stayed.length > 0) say(yellow(`Your project installed ${stayed.join(", ")} before this add, and still does: run apm audit.`));

  return { command: cmd === null ? null : cmd.join(" "), code: undone.code, left: undone.left };
}

async function cmdAdd(a: Args): Promise<number> {
  const cwd = process.cwd();
  const cfg = config(cwd);
  const api = new Api(cfg);
  const det = pmFor(a, cwd);
  const specs = a.positional;
  const strict = strictMode(a);

  if (specs.length === 0) {
    say(dim(`apm: no packages given, running ${det.pm} install`));
    const code = (await runCmd([det.pm, "install"], { cwd, env: withoutSecrets(process.env), stdoutToStderr: jsonMode })).code;
    emit({ ok: code === 0, pm: det.pm, packages: [] });

    return code;
  }

  const results: Resolved[] = [];
  const ctx = resolveContext({ pm: det.pm, cwd, project: true });

  if (ctx.leftOut !== null) say(dim(`apm: ${ctx.leftOut}, so it goes without them; the check after the install reads every installed package`));
  for (const spec of specs) results.push(await resolveSpec(api, spec, a, ctx));
  for (const r of results) printResolved(r);
  const blocked = results.filter((r) => r.blocked !== null || r.version === null);

  if (blocked.length > 0) {
    say();
    for (const b of blocked) say(red(`refused: ${b.blocked ?? `${b.name}: nothing to install`}`));
    refusalAdvice(blocked, "add", strict);
    emitJson({ ok: false, det, results });

    return 1;
  }

  const scopes = treeScopes(results);

  if (refuseOverrides(scopeOverrides({ cwd, env: env(), registry: cfg.registry, scopes }), cfg.registry, "install")) {
    emitJson({ ok: false, det, results, error: lastError });

    return 1;
  }

  const pinnedElsewhere = await lockMismatches({ api, cwd, pm: det.pm, results });

  for (const m of pinnedElsewhere) fail(`refused: the lockfile pins another artifact: ${m}`);

  if (pinnedElsewhere.length > 0) {
    say(`Delete ${pinnedElsewhere.length === 1 ? "that entry" : "those entries"} from the lockfile, then run apm add again.`);
    emitJson({ ok: false, det, results, error: lastError });
    return 1;
  }

  const pinned = results.map((r) => `${r.name}@${r.version}`);
  const lockPm = isLockPm(det.pm) ? det.pm : null;
  // what the project held before, so a refused add can be undone and only what it brought in is its own
  const before = snapshot({ cwd, pm: det.pm });
  const beforeIds = installedIds({ cwd, pm: lockPm });
  const beforeNames = new Set(projectNames(cwd));
  // bun, npm and pnpm install with every script held back; they run once the installed graph is checked
  const cmd = [...addArgs(det.pm, pinned, { dev: has(a, "dev"), ignoreScripts: lockPm !== null }), ...registryArgs(det.pm, cfg.registry, scopes)];
  say(dim(`→ ${cmd.join(" ")}  (${det.pm}: ${det.why})`));
  const run = await runCmd(cmd, { cwd, env: pmEnv(cfg.registry, scopes), stdoutToStderr: jsonMode });

  if (run.code !== 0) {
    emitJson({ ok: false, det, results });

    return run.code;
  }

  const graph = addedGraph({ cwd, pm: lockPm, roots: results.map((r) => r.name), before: beforeIds });
  const post = await checkInstalled({ api, graph, pm: det.pm, strict, results, installed: "this add installed", policy: checkPolicy(a, results) });

  switch (post.kind) {
    case "unreadable":
      fail(`refused: apm could not confirm what ${det.pm} installed: ${post.reason}`);
      say("Install scripts were not run. Turn the lockfile back on (apm compares it with the registry it checked), then run apm add again.");
      emitJson({ ok: false, det, results, error: lastError });

      return 1;
    case "mismatch": {
      for (const b of post.bad) fail(`refused: ${b.node.name}@${b.node.version} is not the checked artifact: ${b.why}`);
      restore(before);
      const removed = removeInstalled({ cwd, nodes: post.bad.map((b) => b.node) });

      say(`Install scripts were not run. apm put package.json and the lockfile back${removed.length > 0 ? ` and removed ${removed.length} unverified package director${removed.length === 1 ? "y" : "ies"}` : ""}.`);
      say("Check the lockfile and .npmrc for another registry, delete the stale lockfile entries, then run apm add again.");
      emitJson({ ok: false, det, results, error: lastError });

      return 1;
    }

    case "checked":
      break;
    default: {
      const _exhaustive: never = post;

      return _exhaustive;
    }
  }

  if (post.refused) {
    const error = lastError;
    const restored = await undoRefusedAdd({ cwd, pm: det.pm, before, beforeIds, beforeNames, results, post, registry: cfg.registry, scopes });

    if (post.verdict.blocked.length === 0) say(`Run apm add ${results.map((r) => r.name).join(" ")} without --strict to install with these warnings.`);
    emitJson({ ok: false, det, results, error, installed: reportOf(post, restored) });

    return 1;
  }

  if (lockPm !== null && post.graph.kind === "lockfile") {
    say(dim(`apm: ${post.graph.nodes.length} installed package${post.graph.nodes.length === 1 ? "" : "s"} match ${api.cfg.registry}; running install scripts`));
    const code = await runHeldScripts({ pm: lockPm, cwd, nodes: post.graph.nodes, registry: api.cfg.registry, scopes, quiet: false });

    if (code !== 0) fail(`apm: the install scripts failed (exit ${code})`);
    emitJson({ ok: code === 0, det, results, error: code === 0 ? null : lastError, installed: reportOf(post, null) });

    return code;
  }

  emitJson({ ok: true, det, results, installed: reportOf(post, null) });

  return 0;
}

function emitJson(input: { ok: boolean; det: Detection; results: Resolved[]; error?: string | null; installed?: InstalledReport }): void {
  emit({
    ok: input.ok,
    pm: input.det.pm,
    error: input.error ?? null,
    packages: input.results.map((r) => ({
      name: r.name,
      version: r.version,
      score: r.report?.score ?? null,
      grade: r.report?.grade ?? null,
      signals: r.report?.signals.map((s) => ({ id: s.id, points: s.points })) ?? [],
      skipped: r.skipped,
      unchecked: r.unchecked,
      warnings: r.warnings,
      // review of 1924692, finding 1: the peers the project provides, and the version checked for each
      projectPeers: r.projectPeers,
      blocked: r.blocked !== null,
      reason: r.blocked,
      forceable: r.forceable,
    })),
    // review of 16fc8b5: the check of what the package manager really installed (null when nothing was installed)
    installed: input.installed ?? null,
  });
}

/** A package's `bin`: one binary named like the package (`null`), or each binary's name. */
const BinField = z.object({ bin: z.union([z.string().transform(() => null), z.record(z.string(), z.string()).transform((r) => Object.keys(r))]).optional() }).loose();

/** The binary `apm x <name>` runs, as npx picks it: the only one, else the one named like the package. */
function binOf(dir: string, name: string): { kind: "found"; bin: string; path: string } | { kind: "none"; why: string } {
  const unscoped = name.split("/").at(-1) ?? name;
  let field: z.infer<typeof BinField>["bin"];

  try {
    field = BinField.parse(JSON.parse(readFileSync(join(dir, "node_modules", name, "package.json"), "utf8"))).bin;
  } catch {
    return { kind: "none", why: `apm could not read ${name}'s package.json` };
  }

  const names = field === undefined ? [] : field === null ? [unscoped] : field;
  const bin = names.length === 1 ? names[0] : names.find((n) => n === unscoped);

  if (bin === undefined) return { kind: "none", why: names.length === 0 ? `${name} has no binary to run` : `${name} has several binaries (${names.join(", ")}) and none is named ${unscoped}` };
  const path = join(dir, "node_modules", ".bin", bin);

  return existsSync(path) ? { kind: "found", bin, path } : { kind: "none", why: `${name}'s binary ${bin} was not installed` };
}

/**
 * apm x: the package is installed into a directory of its own with every script held back, the graph the package
 * manager installed is checked as apm add checks it, and only then do its install scripts and its binary run. The
 * directory is removed afterwards.
 */
async function cmdX(a: Args): Promise<number> {
  const cwd = process.cwd();
  const [spec, ...rest] = a.positional;
  if (!spec) {
    warn("usage: apm x <package>[@version] [args...]");
    return 2;
  }

  const cfg = config(cwd);
  const api = new Api(cfg);
  const det = pmFor(a, cwd);
  const strict = strictMode(a);
  const r = await resolveSpec(api, spec, a, resolveContext({ pm: det.pm, cwd, project: false }));
  printResolved(r);
  if (r.blocked !== null || r.version === null) {
    say(red(`refused to run ${r.name}: ${r.blocked ?? "no version"}`));
    refusalAdvice([r], "x", strict);
    return 1;
  }

  const scopes = treeScopes([r]);

  if (refuseOverrides(scopeOverrides({ cwd, env: env(), registry: cfg.registry, scopes }), cfg.registry, "run")) return 1;
  // yarn's own runner gives no lockfile to read; npm's install does the same job
  const xpm: LockPm = isLockPm(det.pm) ? det.pm : "npm";
  const dir = mkdtempSync(join(tmpdir(), "apm-x-"));

  try {
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "apm-x", version: "0.0.0", private: true }));
    const install = [...addArgs(xpm, [`${r.name}@${r.version}`], { dev: false, ignoreScripts: true }), ...registryArgs(xpm, cfg.registry, scopes)];

    say(dim(`→ ${install.join(" ")}  (in a directory of its own, checked before anything runs)`));
    const installed = await runCmd(install, { cwd: dir, env: pmEnv(cfg.registry, scopes), stdoutToStderr: true });

    if (installed.code !== 0) {
      fail(`apm x: ${xpm} could not install ${r.name}@${r.version} (exit ${installed.code})`);

      return installed.code;
    }

    const post = await checkInstalled({ api, graph: wholeGraph({ cwd: dir, pm: xpm }), pm: xpm, strict, results: [r], installed: `apm x installed for ${r.name}`, policy: checkPolicy(a, [r]) });

    if (post.kind === "unreadable") {
      fail(`refused to run ${r.name}: apm could not confirm what ${xpm} installed: ${post.reason}`);

      return 1;
    }

    if (post.kind === "mismatch") {
      for (const b of post.bad) fail(`refused to run ${r.name}: ${b.node.name}@${b.node.version} is not the checked artifact: ${b.why}`);

      return 1;
    }

    if (post.refused) {
      say(`apm ran nothing: no install script and no binary, and the directory it installed into is removed.${post.verdict.blocked.length === 0 ? ` Run apm x ${r.name} without --strict to run it with these warnings.` : ""}`);

      return 1;
    }

    if (post.graph.kind === "lockfile") {
      const code = await runHeldScripts({ pm: xpm, cwd: dir, nodes: post.graph.nodes, registry: cfg.registry, scopes, quiet: true });

      if (code !== 0) {
        fail(`apm x: the install scripts failed (exit ${code})`);

        return code;
      }
    }

    const bin = binOf(dir, r.name);

    if (bin.kind === "none") {
      fail(`apm x: ${bin.why}`);

      return 1;
    }

    const passArgs = a.raw.slice(a.raw.indexOf(spec) + 1).filter((x) => !["--force", "--no-cooldown", "--strict"].includes(x));
    const args = rest.length > 0 ? passArgs : [];

    say(dim(`→ ${bin.bin}${args.length > 0 ? ` ${args.join(" ")}` : ""}`));

    return (await runCmd([bin.path, ...args], { cwd, env: pmEnv(cfg.registry, scopes) })).code;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ---------- score / name ----------
async function cmdScore(a: Args): Promise<number> {
  const spec = a.positional[0];
  if (!spec) {
    warn("usage: apm score <package>[@version] [--json]");
    return 2;
  }

  const api = new Api(config(process.cwd()));
  const { name, range } = parseSpec(spec);
  const s = await api.get(`-/apm/v1/score/${encodeName(name)}${range ? `/${encodeURIComponent(range)}` : ""}`, ScoreResponse);

  if (jsonMode) {
    emit({ ok: true, ...s });
    return 0;
  }
  printCard(`${s.name}@${s.version}`, s, { maxEvidence: 3 });
  say(dim(`  published ${s.publishedAt} by ${s.publishedBy}${s.status !== "active" ? `, status: ${s.status}` : ""}`));
  if (s.previous) say(dim(`  previous ${s.previous.version}: ${s.previous.score}/100${s.changes.length ? `; changed: ${s.changes.join("; ")}` : ""}`));
  for (const n of s.notChecked ?? []) say(dim(`  not checked: ${n}`));
  return 0;
}

async function cmdName(a: Args): Promise<number> {
  const q = a.positional[0];
  if (!q) {
    warn("usage: apm name <name>");
    return 2;
  }

  const cfg = config(process.cwd());
  const api = new Api(cfg);
  let user = "";
  if (cfg.token) {
    const me = await api.raw("-/whoami");
    if (me.status === 200 && typeof me.body === "object" && me.body !== null && "username" in me.body) user = String(me.body.username);
  }
  const r = await api.get(`-/apm/v1/names?q=${encodeURIComponent(q)}${user ? `&user=${encodeURIComponent(user)}` : ""}`, NameResponse);

  if (jsonMode) {
    emit({ ok: true, ...r });
    return 0;
  }
  if (!r.valid) say(red(`✗ ${r.query} is not a valid package name`));
  else if (r.taken) say(`${red("✗")} ${bold(r.query)} is taken${r.owners.length ? ` (by ${r.owners.join(", ")})` : ""}${r.latest ? `, latest ${r.latest.version}${r.latest.score !== null ? `, score ${r.latest.score}/100` : ""}` : ""}`);
  else if (r.available) say(`${green("✓")} ${bold(r.query)} is available`);
  else say(`${yellow("!")} ${bold(r.query)} is free but not available: ${r.conflicts.map((c) => c.reason).join("; ")}`);
  for (const s of r.similar ?? []) say(dim(`  similar: ${s.reason}`));
  const alts = r.suggestions.filter((s) => s.available).slice(0, 4);
  if (alts.length) say(dim(`  available alternatives: ${alts.map((s) => s.name).join(", ")}`));
  return 0;
}

// ---------- explain / search (agent-facing; the work is in agent.ts) ----------
function io(): AgentIo {
  return { say, warn, emit, json: jsonMode, paint: { green, yellow, red, dim, bold, grade: gradeColor } };
}

async function cmdExplain(a: Args): Promise<number> {
  const cwd = process.cwd();

  // the mode apm add would run in here (review of 93274c8, finding 6: --strict was ignored)
  return explainCommand({ api: new Api(config(cwd)), spec: a.positional[0], io: io(), strict: strictMode(a) });
}

async function cmdSearch(a: Args): Promise<number> {
  return searchCommand({ api: new Api(config(process.cwd())), words: a.positional, size: flag(a, "size"), io: io() });
}

// ---------- audit ----------
/**
 * apm audit: every package in node_modules at its exact version, checked by the code apm add uses after an install
 * (installed.ts), plus the advisories the upstream registry has for them. A revoked, yanked or confirmed malicious
 * version is a critical finding; a warning (a fresh version, a low or incomplete score, one apm cannot score) is a
 * finding too; what could not be checked or is still being analysed is unchecked. Any of them fails the audit.
 */
async function cmdAudit(): Promise<number> {
  const cwd = process.cwd();
  const api = new Api(config(cwd));
  const { packages: installed, unchecked: unreadable } = installedPackages(cwd);

  if (installed.size === 0 && unreadable.length === 0) {
    say(dim("apm audit: nothing installed (run apm install first)"));
    emit({ ok: true, checked: 0, findings: [], unchecked: [] });
    return 0;
  }
  const query: Record<string, string[]> = {};
  for (const [n, vs] of installed) query[n] = [...vs];
  const audit = installed.size > 0 ? await api.post("-/apm/v1/audit", query, AuditResponse) : { advisories: {}, unavailable: [] };
  const all = [...installed].flatMap(([name, vs]) => [...vs].map((version) => ({ name, version, integrity: null, platform: false })));
  const verdict = await checkGraph({ api, packages: all.filter((p) => isRegistryVersion(p.version)), notFromRegistry: all.filter((p) => !isRegistryVersion(p.version)), waitMs: pendingWaitMs(), progress: (line) => say(dim(line)), policy: DEFAULT_CHECK });
  const findings: { id: string; severity: string; text: string }[] = verdict.blocked.map((b) => ({ id: idOf(b), severity: "critical", text: b.reason }));
  // checks that could not run: an audit with any of these is not a pass
  const unchecked: { id: string; reason: string }[] = [
    ...unreadable,
    ...audit.unavailable.flatMap((name) => [...(installed.get(name) ?? [])].map((v) => ({ id: `${name}@${v}`, reason: "advisories could not be fetched from the upstream registry" }))),
  ];

  for (const w of verdict.warnings) {
    if (w.kind === "unchecked" || w.kind === "pending") unchecked.push({ id: idOf(w), reason: w.text });
    else findings.push({ id: idOf(w), severity: "warning", text: w.text });
  }

  for (const [name, advisories] of Object.entries(audit.advisories)) {
    for (const adv of advisories) {
      // Bun.semver.satisfies matches every version against a malformed range; such an advisory is unchecked, not a hit
      if (!isValidRange(adv.vulnerable_versions)) {
        unchecked.push({ id: name, reason: `advisory "${adv.title}" has an unparseable range ${JSON.stringify(adv.vulnerable_versions)}` });
        continue;
      }
      for (const v of installed.get(name) ?? []) {
        if (Bun.semver.satisfies(v, adv.vulnerable_versions) && !findings.some((f) => f.id === `${name}@${v}` && f.text === adv.title)) findings.push({ id: `${name}@${v}`, severity: adv.severity, text: adv.title });
      }
    }
  }
  const ok = findings.length === 0 && unchecked.length === 0;

  if (jsonMode) {
    emit({ ok, checked: installed.size, findings, unchecked });
    return ok ? 0 : 1;
  }
  if (ok) {
    say(green(`✓ ${installed.size} packages checked, no revoked or dangerous versions found`));
    return 0;
  }
  for (const f of findings) say(`${(f.severity === "warning" ? yellow : red)(f.severity.padEnd(8))} ${bold(f.id)}  ${f.text}`);

  for (const u of unchecked.slice(0, 20)) say(`${yellow("unchecked".padEnd(8))} ${bold(u.id)}  ${u.reason}`);

  if (unchecked.length > 20) say(dim(`  … and ${unchecked.length - 20} more not checked`));
  say();
  if (findings.length > 0) say(`${findings.length} problem${findings.length === 1 ? "" : "s"} in ${installed.size} packages. Upgrade or remove them; revoked versions stop installing soon.`);

  if (unchecked.length > 0) say(`${unchecked.length} item${unchecked.length === 1 ? "" : "s"} could not be checked, so this audit is not a pass.`);
  return 1;
}

// ---------- version states ----------
async function cmdState(a: Args, action: "yank" | "unyank" | "revoke" | "restore"): Promise<number> {
  const spec = a.positional[0];
  const parsed = spec ? parseSpec(spec) : null;
  if (!parsed?.range) {
    warn(`usage: apm ${action} <package>@<version>${action === "revoke" || action === "yank" ? " --reason \"...\"" : ""}`);
    return 2;
  }

  const api = new Api(config(process.cwd()));
  const reason = flag(a, "reason");
  if (action === "revoke" && !reason) {
    warn("apm revoke needs --reason; everyone with this version installed will see it.");
    return 2;
  }
  // yank and unyank take --otp too: a login token needs a fresh code to change what installs
  const needsFactor = action === "revoke" || action === "restore";
  const otp = flag(a, "otp");
  const proof = needsFactor ? await readProof(a) : otp ? { otp } : {};
  const r = await api.raw(`-/apm/v1/${action}`, { method: "POST", body: { name: parsed.name, version: parsed.range, ...(reason ? { reason } : {}), ...proof } });
  if (r.status !== 200) {
    fail(`apm ${action} failed: ${errorOf(r.body, r.status)}`);
    return 1;
  }
  const body = z.object({ status: z.string(), finalAt: z.string().optional(), note: z.string().optional() }).loose().parse(r.body);
  say(`${green("✓")} ${parsed.name}@${parsed.range} is now ${bold(body.status)}`);
  if (body.finalAt) say(dim(`  becomes a full revoke at ${body.finalAt}. ${body.note ?? ""}`));
  emit({ ok: true, name: parsed.name, version: parsed.range, status: body.status, finalAt: body.finalAt ?? null, note: body.note ?? null });
  return 0;
}

async function cmdIncident(a: Args): Promise<number> {
  const since = flag(a, "since");
  if (!since) {
    warn("usage: apm incident --since <ISO time of your last trusted publish> [--reason ...] [--dry-run]");
    return 2;
  }

  const api = new Api(config(process.cwd()));
  const proof = await readProof(a);
  const body = { since, reason: flag(a, "reason") ?? "account compromised", ...proof, dryRun: has(a, "dry-run") };
  const r = await api.raw("-/apm/v1/incident", { method: "POST", body });
  if (r.status !== 200) {
    fail(`apm incident failed: ${errorOf(r.body, r.status)}`);
    return 1;
  }
  const res = z.object({ revoked: z.array(z.string()), tokensRevoked: z.number(), dryRun: z.boolean().optional() }).loose().parse(r.body);
  say(res.dryRun ? bold("Preview (nothing changed):") : bold("Incident response done:"));
  for (const id of res.revoked) say(`  revoke ${id}`);
  say(`  ${res.dryRun ? "would revoke" : "revoked"} ${res.tokensRevoked} token(s)`);
  emit({ ok: true, dryRun: res.dryRun ?? false, revoked: res.revoked, tokensRevoked: res.tokensRevoked });
  return 0;
}

// ---------- login ----------
const DeviceStart = z.object({ deviceCode: z.string(), userCode: z.string(), verificationUrl: z.string(), verificationUrlComplete: z.string(), interval: z.number(), expiresIn: z.number() });
const DeviceDone = z.object({ token: z.string(), username: z.string() });

/** Saves a token the registry handed out, after checking it is one: a newline in it would write extra .npmrc lines. */
function storeToken(cfg: Config, token: string): boolean {
  if (!isApmToken(token)) {
    fail(`login failed: ${cfg.registry} returned a token that is not an apm token; nothing was saved`);

    return false;
  }

  saveToken(cfg.userconfig, cfg.registry, token);

  return true;
}

function openBrowser(url: string): void {
  const cmd = process.platform === "darwin" ? ["open", url] : process.platform === "win32" ? ["cmd", "/c", "start", "", url] : ["xdg-open", url];
  try {
    Bun.spawn(cmd, { stdout: "ignore", stderr: "ignore", stdin: "ignore" }).unref();
  } catch {
    // no browser here: the URL is printed
  }
}

/** Device login: the browser signs in (GitHub or Vercel) and approves the code; the CLI gets a token that stages publishes. */
async function cmdLogin(a: Args): Promise<number> {
  if (flag(a, "username") || flag(a, "password") || has(a, "password-stdin")) return cmdPasswordLogin(a);
  const cfg = config(process.cwd());
  const api = new Api({ ...cfg, token: null });
  const start = await api.raw("-/apm/v1/login/device", { method: "POST", body: {} });
  const d = DeviceStart.safeParse(start.body);
  if (start.status !== 200 || !d.success) {
    fail(`login failed: ${errorOf(start.body, start.status)}`);
    return 1;
  }
  const code = d.data.userCode.length === 8 ? `${d.data.userCode.slice(0, 4)}-${d.data.userCode.slice(4)}` : d.data.userCode;
  say(`Open ${d.data.verificationUrlComplete}\nand check that it shows the code ${bold(code)}, then approve.`);
  const canOpen = !has(a, "no-browser") && process.stdout.isTTY === true && (process.platform !== "linux" || Boolean(process.env.DISPLAY || process.env.WAYLAND_DISPLAY));
  if (canOpen) openBrowser(d.data.verificationUrlComplete);
  say(dim("Waiting for the browser…"));
  let interval = Math.max(1, d.data.interval) * 1000;
  const deadline = Date.now() + d.data.expiresIn * 1000;
  while (Date.now() < deadline) {
    await Bun.sleep(interval);
    const r = await api.raw("-/apm/v1/login/device/token", { method: "POST", body: { deviceCode: d.data.deviceCode } });
    if (r.status === 200) {
      const done = DeviceDone.parse(r.body);

      if (!storeToken(cfg, done.token)) return 1;
      say(`${green("✓")} logged in to ${cfg.registry} as ${bold(done.username)}`);
      say(dim(`  token saved to ${cfg.userconfig}; npm, pnpm and bun read it from there`));
      say(dim(`  publishes with it wait for you to approve them in the browser`));
      emit({ ok: true, registry: cfg.registry, username: done.username, userconfig: cfg.userconfig });
      return 0;
    }
    const err = typeof r.body === "object" && r.body !== null && "error" in r.body ? String(r.body.error) : "";
    if (err === "authorization_pending") continue;
    if (err === "slow_down") {
      interval += 1000;
      continue;
    }

    fail(`login failed: ${errorOf(r.body, r.status)}`);
    return 1;
  }

  fail("login failed: the code expired before it was approved. Run apm login again.");
  return 1;
}

/** npm's password login, for registries that run with legacy auth on. */
async function cmdPasswordLogin(a: Args): Promise<number> {
  const cfg = config(process.cwd());
  const username = flag(a, "username") ?? (process.stdin.isTTY ? prompt("Username:") : null);
  if (!username) {
    warn("usage: apm login --username <name> --password-stdin");
    return 2;
  }
  const password = await readPassword(a);
  const api = new Api({ ...cfg, token: null });
  const r = await api.raw(`-/user/org.couchdb.user:${encodeURIComponent(username)}`, {
    method: "PUT",
    body: { _id: `org.couchdb.user:${username}`, name: username, password, email: flag(a, "email") ?? "", type: "user", roles: [] },
  });
  const tok = z.object({ token: z.string() }).safeParse(r.body);
  if ((r.status !== 201 && r.status !== 200) || !tok.success) {
    fail(`login failed: ${errorOf(r.body, r.status)}`);
    return 1;
  }

  if (!storeToken(cfg, tok.data.token)) return 1;
  say(`${green("✓")} logged in to ${cfg.registry} as ${bold(username)}`);
  say(dim(`  token saved to ${cfg.userconfig}; npm, pnpm and bun read it from there`));
  emit({ ok: true, registry: cfg.registry, username, userconfig: cfg.userconfig });
  return 0;
}

async function cmdWhoami(): Promise<number> {
  const cfg = config(process.cwd());
  const api = new Api(cfg);
  const r = await api.raw("-/whoami");
  if (r.status !== 200) {
    fail(`not logged in to ${cfg.registry} (run apm login)`);
    return 1;
  }
  const me = z.object({ username: z.string() }).parse(r.body);
  say(`${me.username} ${dim(`on ${cfg.registry}`)}`);
  emit({ ok: true, username: me.username, registry: cfg.registry });
  return 0;
}

// ---------- publish ----------
function bump(version: string, kind: string): string {
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (!m) throw new Error(`cannot bump version ${version}`);
  const [maj, min, pat] = [Number(m[1]), Number(m[2]), Number(m[3])];
  if (kind === "major") return `${maj + 1}.0.0`;
  if (kind === "minor") return `${maj}.${min + 1}.0`;
  if (kind === "patch") return version.includes("-") ? `${maj}.${min}.${pat}` : `${maj}.${min}.${pat + 1}`;
  if (/^\d+\.\d+\.\d+/.test(kind)) return kind;
  throw new Error("--bump takes patch, minor, major or an exact version");
}

function walkFiles(root: string, limit = 5000): FileLike[] {
  const out: FileLike[] = [];
  const visit = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      if (out.length >= limit) return;
      // never packed by npm, pnpm or bun
      if (entry === "node_modules" || entry === ".git" || entry === ".npmrc") continue;
      const p = join(dir, entry);
      const st = statSync(p);
      if (st.isDirectory()) visit(p);
      else if (st.isFile() && st.size <= 2_000_000) out.push({ path: relative(root, p), data: new Uint8Array(readFileSync(p)) });
    }
  };
  visit(root);
  return out;
}

function fmtSize(n: number): string {
  return n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} kB` : `${(n / 1024 / 1024).toFixed(1)} MB`;
}

const Manifest = z.object({ name: z.string(), version: z.string(), files: z.array(z.string()).optional(), publishConfig: z.object({ registry: z.string().optional() }).loose().optional() }).loose();
const Published = z.object({ versions: z.record(z.string(), z.object({ version: z.string() }).loose()) }).loose();

async function cmdPublish(a: Args): Promise<number> {
  const cwd = process.cwd();
  const pjPath = join(cwd, "package.json");
  if (!existsSync(pjPath)) {
    warn("apm publish: no package.json here");
    return 2;
  }

  const cfg = config(cwd);
  const det = pmFor(a, cwd);
  const pj = Manifest.parse(JSON.parse(readFileSync(pjPath, "utf8")));
  // The upload goes to the registry apm checks and previews for, or nowhere: publishConfig and scoped
  // registry lines in .npmrc or bunfig would otherwise send it elsewhere (npm's public registry, say).
  const scopes = scopesOf([pj.name]);
  const target = pj.publishConfig?.registry;

  if (target && !sameRegistry(target, cfg.registry)) {
    fail(`refused: package.json publishConfig.registry is ${target}, but apm publishes to ${cfg.registry}`);
    say("Remove publishConfig.registry, or set APM_REGISTRY to that registry if it is the one you mean.");

    return 1;
  }

  if (refuseOverrides(scopeOverrides({ cwd, env: env(), registry: cfg.registry, scopes }), cfg.registry, "publish")) return 1;
  const bumpKind = flag(a, "bump");
  const dry = has(a, "dry-run");
  let version = pj.version;
  if (bumpKind) {
    version = bump(pj.version, bumpKind);
    if (!dry) {
      const full: unknown = JSON.parse(readFileSync(pjPath, "utf8"));
      writeFileSync(pjPath, `${JSON.stringify({ ...Object(full), version }, null, 2)}\n`);
    }
    say(dim(`version ${pj.version} → ${version}${dry ? " (dry run, package.json unchanged)" : ""}`));
  }
  const id = `${pj.name}@${version}`;

  // 1. Without a "files" allowlist, what ships depends on the package manager (npm ships .env.production,
  //    bun does not), so any secret-shaped file in the folder blocks the publish.
  if (!pj.files) {
    const local = findSecrets(walkFiles(cwd)).findings;
    if (local.length > 0) {
      for (const s of local) say(red(`✗ ${s.path}: ${s.kind}`));
      fail(`Refusing to publish ${id}: secret-shaped files sit in the package folder and package.json has no "files" allowlist,`);
      say(`so whether they ship depends on the package manager. Add "files": ["dist", ...] to package.json, or delete them.`);
      return 1;
    }
  }

  // 2. Pack with the project's own package manager and inspect exactly what would upload.
  const dest = mkdtempSync(join(tmpdir(), "apm-pack-"));
  process.once("exit", () => rmSync(dest, { recursive: true, force: true }));
  // packing runs the project's prepack and prepare scripts: no credentials in their env
  const packed = await runCmd(packArgs(det.pm, dest), { cwd, env: pmEnv(cfg.registry, scopes), quiet: true });
  const tgzName = readdirSync(dest).find((f) => f.endsWith(".tgz"));
  if (packed.code !== 0 || !tgzName) {
    warn(packed.out);
    fail(`apm publish: ${det.pm} pack failed`);
    return 1;
  }
  const tgzPath = join(dest, tgzName);
  const files = readTarball(new Uint8Array(readFileSync(tgzPath)));
  const tarPj = files.find((f) => f.path === "package.json");
  const manifestParsed: unknown = tarPj ? JSON.parse(new TextDecoder().decode(tarPj.data)) : {};
  const manifest: Record<string, unknown> = typeof manifestParsed === "object" && manifestParsed !== null ? { ...manifestParsed } : {};
  if (bumpKind && dry) manifest.version = version;

  const secrets = findSecrets(files);
  if (secrets.findings.length > 0) {
    for (const s of secrets.findings) say(red(`✗ ${s.path}: ${s.kind}`));
    fail(`Refusing to publish ${id}: the tarball contains secrets. Narrow the "files" allowlist in package.json.`);
    return 1;
  }

  for (const s of secrets.skipped) say(yellow(`! ${describeSkip(s)} was not scanned for secrets; check it yourself.`));
  const ambiguous = ambiguousPaths(files);

  if (ambiguous.length > 0) {
    fail(`Refusing to publish ${id}: the tarball has duplicate or escaping paths (${ambiguous.slice(0, 5).join(", ")}).`);

    return 1;
  }

  const missing = missingEntries(manifest, files);
  if (missing.length > 0) {
    for (const m of missing) say(red(`✗ "${m.field}" points to ${m.path}, which is not in the tarball`));
    fail(`Refusing to publish ${id}. Run your build first, or fix "files" in package.json.`);
    return 1;
  }

  say(bold(`${id}  ${files.length} files, ${fmtSize(files.reduce((n, f) => n + f.size, 0))}`));
  for (const f of [...files].sort((x, y) => x.path.localeCompare(y.path)).slice(0, 40)) say(`  ${dim(fmtSize(f.size).padStart(9))}  ${f.path}`);
  if (files.length > 40) say(dim(`  … and ${files.length - 40} more`));
  const analysis = analyze({ name: pj.name, manifest, files, publisher: "you", previousPublishers: [] });
  const report = finalize(analysis, { publishedAt: Number.NEGATIVE_INFINITY, now: Date.now(), deprecated: null, status: "active", statusReason: null });
  printCard("preview", report);

  const summary = { name: pj.name, version, registry: cfg.registry, files: files.length, score: report.score, grade: report.grade };
  if (dry) {
    say(dim(`dry run: nothing uploaded (it would go to ${cfg.registry})`));
    emit({ ok: true, status: "dry-run", ...summary });
    return 0;
  }
  const tag = flag(a, "tag") ?? (version.includes("-") ? "next" : null);
  // `publish <tarball>` runs no package scripts, so the credential variables an .npmrc may name stay; APM_TOKEN does not
  const pubEnv = childEnv({ parent: process.env, registry: cfg.registry, scopes, keepAuth: true });
  const pub = await runCmd([...publishArgs(det.pm, tgzPath, tag), ...registryArgs(det.pm, cfg.registry, scopes)], { cwd, env: pubEnv, quiet: true });
  if (pub.code !== 0) {
    warn(pub.out.trim());
    fail(`apm publish: ${det.pm} publish failed for ${id}`);
    return pub.code;
  }
  // A login token stages the version: the registry answers with an approval link in its notice.
  const approval = /(https?:\/\/\S+?\/approve\/[A-Za-z0-9_-]+)/.exec(pub.out)?.[1];
  if (approval) {
    say(`${yellow("●")} ${bold(id)} is uploaded but not live yet: it is waiting for approval.`);
    say(`  Approve it within 24h with your passkey or authenticator code: ${bold(approval)}`);
    say(dim("  If an agent ran this publish, it should hand this link to you."));
    emit({ ok: true, status: "staged", approval, ...summary });
    return 0;
  }

  // The package manager said it published; confirm the version is on the registry apm checked.
  const landed = await new Api(cfg).raw(encodeName(pj.name));
  const doc = Published.safeParse(landed.body);

  if (landed.status !== 200 || !doc.success || !(version in doc.data.versions)) {
    fail(`apm publish: ${det.pm} reported success, but ${cfg.registry} does not have ${id}. Check where it was uploaded (npm config get registry).`);

    return 1;
  }

  say(`${green("✓")} published ${bold(id)}${tag ? ` with tag ${tag}` : ""} to ${cfg.registry} via ${det.pm}`);
  emit({ ok: true, status: "published", tag, ...summary });
  return 0;
}

// ---------- help / passthrough ----------
const HELP = `apm ${VERSION}: checks before you install, run or publish; your package manager does the rest.

  apm add <pkg>[@range]...   resolve, warn on a version under 24h old or a score under 40, then <pm> add the exact version
  apm x <pkg> [args]         show the risk card and any warning, then run it (bunx / npx)
  apm publish [--bump patch|minor|major] [--dry-run] [--tag t]
  apm score <pkg>[@version]  explained security score     apm name <name>   is this name free?
  apm explain <pkg>[@range]  install, review-first or do-not-install, and why (exit 0, 3 or 1)
  apm search <words>         search apm and npm, with scores
  apm audit                  installed versions vs revocations and advisories
  apm yank|unyank <pkg>@<v>  hide from new installs (lockfiles keep working)
  apm revoke <pkg>@<v> --reason "..."   pull a malicious version (asks for your authenticator code)
  apm restore <pkg>@<v>      undo a mistaken revoke (back to yanked)
  apm incident --since <time> [--dry-run]   account compromised: revoke tokens and recent versions
  apm login | whoami        sign in through the browser; publishes then wait for your approval
  apm <anything else>        passed to your package manager (apm run dev = bun run dev)

Flags: --pm bun|npm|pnpm|yarn, --strict, --force, --no-cooldown, --json, --otp <code>, --no-browser
  --strict (or APM_STRICT=1): refuse a version inside the 24-hour cooldown (the newest older one is used), a score
  under 40, an incomplete analysis, no score yet or ever, and a dependency the registry could not look up, instead
  of warning about them. --no-cooldown: no cooldown warning (strict: no refusal) for anything in the tree
Registry: APM_REGISTRY or registry= in .npmrc (default ${DEFAULT_REGISTRY})`;

// Commands that run package install scripts: their env gets no credentials. `apm run` keeps the env, as `bun run` would.
const INSTALLS = new Set(["install", "i", "ci", "update", "upgrade", "up", "rebuild", "add", "remove", "rm", "uninstall", "link"]);

// Commands that print one JSON document with --json (everything else is the package manager's).
const JSON_COMMANDS = new Set(["add", "install", "i", "score", "name", "explain", "search", "audit", "yank", "unyank", "revoke", "restore", "incident", "publish", "login", "whoami"]);

async function passthrough(a: Args): Promise<number> {
  const cwd = process.cwd();
  const det = pmFor(a, cwd);
  const args = a.raw.filter((x, i, arr) => x !== "--pm" && arr[i - 1] !== "--pm");

  return (await runCmd([det.pm, a.cmd, ...args], { cwd, env: INSTALLS.has(a.cmd) ? withoutSecrets(process.env) : env() })).code;
}

async function main(a: Args): Promise<number> {
  switch (a.cmd) {
    case "help":
    case "--help":
    case "-h":
      say(HELP);
      return 0;
    case "--version":
    case "-v":
      say(VERSION);
      return 0;
    case "add":
      return cmdAdd(a);
    case "install":
    case "i":
      return a.positional.length > 0 ? cmdAdd(a) : passthrough(a);
    case "x":
    case "exec":
    case "dlx":
      return cmdX(a);
    case "score":
      return cmdScore(a);
    case "name":
      return cmdName(a);
    case "explain":
      return cmdExplain(a);
    case "search":
      return cmdSearch(a);
    case "audit":
      return cmdAudit();
    case "yank":
    case "unyank":
    case "revoke":
    case "restore":
      return cmdState(a, a.cmd);
    case "incident":
      return cmdIncident(a);
    case "publish":
      return cmdPublish(a);
    case "login":
      return cmdLogin(a);
    case "whoami":
      return cmdWhoami();
    default:
      return passthrough(a);
  }
}

const args = parseArgs(process.argv.slice(2));

// `apm install` with no packages is the package manager's own install, and so is its --json
const ownsJson = JSON_COMMANDS.has(args.cmd) && !((args.cmd === "install" || args.cmd === "i") && args.positional.length === 0);

jsonMode = has(args, "json");
try {
  process.exitCode = await main(args);

  if (ownsJson) emit({ ok: process.exitCode === 0, error: lastError });
} catch (e) {
  fail(`apm: ${e instanceof Error ? e.message : String(e)}`);

  if (ownsJson) emit({ ok: false, error: lastError });
  process.exitCode = 1;
}
