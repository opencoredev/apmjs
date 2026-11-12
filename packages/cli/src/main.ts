#!/usr/bin/env bun
// apm: a thin layer over bun, npm, pnpm or yarn. It checks before it installs, runs or publishes,
// then hands the real work to the package manager the project already uses.
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { z } from "zod";
import { analyze, describeSkip, finalize, findSecrets, missingEntries, readTarball, type FileLike } from "@apm/core";
import { Api, ApiError, AuditResponse, NameResponse, ResolveFail, ResolveOk, ScanResponse, ScoreResponse, Tree, encodeName, parseSpec, type Report } from "./api.ts";
import { loadConfig, saveToken } from "./config.ts";
import { addArgs, detectPm, execArgs, packArgs, publishArgs, runCmd, type Detection } from "./pm.ts";

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
function say(line = ""): void {
  (jsonMode ? process.stderr : process.stdout).write(`${line}\n`);
}
function warn(line: string): void {
  process.stderr.write(`${line}\n`);
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
    say(`  ${red(String(s.points).padStart(4))} ${s.id}  ${dim(s.label)}`);
    for (const e of s.evidence.slice(0, opts.maxEvidence ?? 2)) say(`        ${dim(e)}`);
  }
  for (const s of info) say(`  ${dim(`   · ${s.id}  ${s.label}${s.evidence[0] ? ` (${s.evidence[0]})` : ""}`)}`);
}

// ---------- shared ----------
function env(): Record<string, string | undefined> {
  return { ...process.env };
}

/** Child env for the package manager: it installs from the same registry apm just checked. */
function pmEnv(registry: string): Record<string, string | undefined> {
  return { ...process.env, npm_config_registry: registry, NPM_CONFIG_REGISTRY: registry };
}

async function readPassword(a: Args): Promise<string> {
  const given = flag(a, "password");
  if (given) return given;
  if (has(a, "password-stdin")) {
    const text = await new Response(Bun.stdin.stream()).text();
    return text.split(/\r?\n/)[0] ?? "";
  }
  if (!process.stdin.isTTY) throw new Error("This needs your account password. Pass it with --password-stdin.");
  process.stdout.write("Password: ");
  const answer = await readHidden();
  process.stdout.write("\n");
  return answer;
}

type Proof = { password?: string; otp?: string };

/**
 * The second factor for revoke, restore, incident and owner changes: --otp <code>, or a password on
 * legacy password registries. Without either, a terminal is asked for the code; Enter skips it, which
 * works when you confirmed with your passkey on the website in the last 10 minutes.
 */
async function readProof(a: Args): Promise<Proof> {
  if (flag(a, "password") || has(a, "password-stdin")) return { password: await readPassword(a) };
  const otp = flag(a, "otp");
  if (otp) return { otp };
  if (!process.stdin.isTTY) return {};
  const answer = prompt("Code from your authenticator app (Enter to skip if you just confirmed on the website):");
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
type Resolved = { name: string; version: string | null; report: Report | null; skipped: { version: string; reason: string }[]; blocked: string | null; source: string; unchecked: UncheckedDeps };

async function resolveSpec(api: Api, spec: string, a: Args): Promise<Resolved> {
  const { name, range } = parseSpec(spec);
  const force = has(a, "force");
  const params = new URLSearchParams({ name, range: range ?? "latest" });
  // --force overrides the score floor and the cooldown; revoked and yanked versions stay blocked
  if (has(a, "no-cooldown") || force) params.set("cooldown", "0");
  else if (flag(a, "cooldown")) params.set("cooldown", flag(a, "cooldown") ?? "24h");
  if (force) params.set("floor", "0");
  else if (flag(a, "floor")) params.set("floor", flag(a, "floor") ?? "40");
  const r = await api.raw(`-/apm/v1/resolve?${params}`);
  if (r.status === 200) {
    const ok = ResolveOk.parse(r.body);
    return { name, version: ok.version, report: ok.report, skipped: ok.skipped, blocked: null, source: ok.source ?? "apm", unchecked: ok.tree?.uncheckedDeps ?? [] };
  }
  if (r.status === 422) {
    const f = ResolveFail.extend({ newest: z.object({ version: z.string(), report: z.unknown() }).nullable().optional() }).parse(r.body);
    const newestReport = f.newest ? (await scoreOf(api, name, f.newest.version)) : null;
    return { name, version: f.newest?.version ?? null, report: newestReport, skipped: f.skipped, blocked: f.error, source: "apm", unchecked: [] };
  }
  if (r.status === 404) {
    const msg = typeof r.body === "object" && r.body !== null && "error" in r.body ? String(r.body.error) : "not found";
    return { name, version: null, report: null, skipped: [], blocked: `${name}: ${msg}`, source: "none", unchecked: [] };
  }
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
  printCard(`${r.blocked ? red("✗") : green("✓")} ${r.name}@${r.version ?? "?"}`, r.report);
  for (const s of r.skipped.slice(0, 5)) say(`  ${dim(`skipped ${s.version}: ${s.reason}`)}`);
  // dependencies apm could not score install unchecked: say which, so nobody reads silence as clean
  for (const u of r.unchecked.slice(0, 10)) say(`  ${yellow("!")} not checked: ${u.dependency} (${u.reason})`);
  if (r.unchecked.length > 10) say(`  ${yellow("!")} and ${r.unchecked.length - 10} more dependencies not checked`);
}

async function cmdAdd(a: Args): Promise<number> {
  const cwd = process.cwd();
  const cfg = loadConfig(cwd, env());
  const api = new Api(cfg);
  const det = pmFor(a, cwd);
  const specs = a.positional;
  if (specs.length === 0) {
    say(dim(`apm: no packages given, running ${det.pm} install`));
    return (await runCmd([det.pm, "install"], { cwd, env: env() })).code;
  }
  const results: Resolved[] = [];
  for (const spec of specs) results.push(await resolveSpec(api, spec, a));
  for (const r of results) printResolved(r);
  const blocked = results.filter((r) => r.blocked !== null || r.version === null);
  if (blocked.length > 0) {
    say();
    for (const b of blocked) say(red(`refused: ${b.blocked ?? `${b.name}: nothing to install`}`));
    say(`Review the signals above. To install anyway: apm add ${blocked.map((b) => b.name).join(" ")} --force`);
    if (jsonMode) emitJson(false, det, results);
    return 1;
  }
  const pinned = results.map((r) => `${r.name}@${r.version}`);
  const cmd = addArgs(det.pm, pinned, has(a, "dev"));
  say(dim(`→ ${cmd.join(" ")}  (${det.pm}: ${det.why})`));
  const run = await runCmd(cmd, { cwd, env: pmEnv(cfg.registry), stdoutToStderr: jsonMode });
  if (jsonMode) emitJson(run.code === 0, det, results);
  return run.code;
}

function emitJson(ok: boolean, det: Detection, results: Resolved[]): void {
  process.stdout.write(
    `${JSON.stringify({
      ok,
      pm: det.pm,
      packages: results.map((r) => ({
        name: r.name,
        version: r.version,
        score: r.report?.score ?? null,
        grade: r.report?.grade ?? null,
        signals: r.report?.signals.map((s) => ({ id: s.id, points: s.points })) ?? [],
        skipped: r.skipped,
        unchecked: r.unchecked,
        blocked: r.blocked !== null,
        reason: r.blocked,
      })),
    })}\n`,
  );
}

async function cmdX(a: Args): Promise<number> {
  const cwd = process.cwd();
  const [spec, ...rest] = a.positional;
  if (!spec) {
    warn("usage: apm x <package>[@version] [args...]");
    return 2;
  }
  const cfg = loadConfig(cwd, env());
  const api = new Api(cfg);
  const det = pmFor(a, cwd);
  const r = await resolveSpec(api, spec, a);
  printResolved(r);
  if (r.blocked !== null || r.version === null) {
    say(red(`refused to run ${r.name}: ${r.blocked ?? "no version"}`));
    say(`To run it anyway: apm x ${spec} --force`);
    return 1;
  }
  const passArgs = a.raw.slice(a.raw.indexOf(spec) + 1).filter((x) => !["--force", "--no-cooldown"].includes(x));
  const cmd = execArgs(det.pm, `${r.name}@${r.version}`, rest.length > 0 ? passArgs : []);
  say(dim(`→ ${cmd.join(" ")}`));
  return (await runCmd(cmd, { cwd, env: pmEnv(cfg.registry) })).code;
}

// ---------- score / name ----------
async function cmdScore(a: Args): Promise<number> {
  const spec = a.positional[0];
  if (!spec) {
    warn("usage: apm score <package>[@version] [--json]");
    return 2;
  }
  const api = new Api(loadConfig(process.cwd(), env()));
  const { name, range } = parseSpec(spec);
  const s = await api.get(`-/apm/v1/score/${encodeName(name)}${range ? `/${encodeURIComponent(range)}` : ""}`, ScoreResponse);
  if (has(a, "json")) {
    process.stdout.write(`${JSON.stringify(s)}\n`);
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
  const cfg = loadConfig(process.cwd(), env());
  const api = new Api(cfg);
  let user = "";
  if (cfg.token) {
    const me = await api.raw("-/whoami");
    if (me.status === 200 && typeof me.body === "object" && me.body !== null && "username" in me.body) user = String(me.body.username);
  }
  const r = await api.get(`-/apm/v1/names?q=${encodeURIComponent(q)}${user ? `&user=${encodeURIComponent(user)}` : ""}`, NameResponse);
  if (has(a, "json")) {
    process.stdout.write(`${JSON.stringify(r)}\n`);
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

// ---------- audit ----------
function installedPackages(root: string): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  const visit = (nm: string, depth: number): void => {
    if (depth > 8 || !existsSync(nm)) return;
    for (const entry of readdirSync(nm)) {
      if (entry.startsWith(".")) continue;
      const dirs = entry.startsWith("@") ? readdirSync(join(nm, entry)).map((s) => join(entry, s)) : [entry];
      for (const d of dirs) {
        const pj = join(nm, d, "package.json");
        if (!existsSync(pj)) continue;
        try {
          const parsed = z.object({ name: z.string(), version: z.string() }).safeParse(JSON.parse(readFileSync(pj, "utf8")));
          if (parsed.success) {
            const set = out.get(parsed.data.name) ?? new Set<string>();
            set.add(parsed.data.version);
            out.set(parsed.data.name, set);
          }
        } catch {
          // skip unreadable package.json
        }
        visit(join(nm, d, "node_modules"), depth + 1);
      }
    }
  };
  visit(join(root, "node_modules"), 0);
  return out;
}

/** Packages per scan request: what the registry checks without a token. */
const SCAN_BATCH = 200;

async function cmdAudit(a: Args): Promise<number> {
  const cwd = process.cwd();
  const api = new Api(loadConfig(cwd, env()));
  const installed = installedPackages(cwd);
  if (installed.size === 0) {
    say(dim("apm audit: nothing installed (run apm install first)"));
    return 0;
  }
  const query: Record<string, string[]> = {};
  for (const [n, vs] of installed) query[n] = [...vs];
  const audit = await api.post("-/apm/v1/audit", query, AuditResponse);
  // the registry checks at most 200 packages per scan without a token, so large trees go in batches
  const all = [...installed].flatMap(([name, vs]) => [...vs].map((version) => ({ name, version })));
  const batches = Array.from({ length: Math.ceil(all.length / SCAN_BATCH) }, (_, i) => all.slice(i * SCAN_BATCH, (i + 1) * SCAN_BATCH));
  const parts = await Promise.all(batches.map((packages) => api.post("-/apm/v1/scan", { packages }, ScanResponse)));
  const scan = { advisories: parts.flatMap((p) => p.advisories), unchecked: parts.flatMap((p) => p.unchecked) };
  const findings: { id: string; severity: string; text: string }[] = [];
  // checks that could not run: an audit with any of these is not a pass
  const unchecked: { id: string; reason: string }[] = [
    ...audit.unavailable.flatMap((name) => [...(installed.get(name) ?? [])].map((v) => ({ id: `${name}@${v}`, reason: "advisories could not be fetched from the upstream registry" }))),
    ...scan.unchecked.map((u) => ({ id: `${u.package}@${u.version}`, reason: u.reason })),
  ];
  for (const [name, advisories] of Object.entries(audit.advisories)) {
    for (const adv of advisories) {
      for (const v of installed.get(name) ?? []) {
        if (Bun.semver.satisfies(v, adv.vulnerable_versions)) findings.push({ id: `${name}@${v}`, severity: adv.severity, text: adv.title });
      }
    }
  }
  for (const s of scan.advisories) {
    if (!findings.some((f) => f.id === `${s.package}@${s.version}`)) findings.push({ id: `${s.package}@${s.version}`, severity: "critical", text: s.description });
  }
  const ok = findings.length === 0 && unchecked.length === 0;
  if (has(a, "json")) {
    process.stdout.write(`${JSON.stringify({ ok, checked: installed.size, findings, unchecked })}\n`);
    return ok ? 0 : 1;
  }
  if (ok) {
    say(green(`✓ ${installed.size} packages checked, no revoked or dangerous versions found`));
    return 0;
  }
  for (const f of findings) say(`${red(f.severity.padEnd(8))} ${bold(f.id)}  ${f.text}`);
  for (const u of unchecked) say(`${yellow("unchecked".padEnd(8))} ${bold(u.id)}  ${u.reason}`);
  say();
  if (findings.length > 0) say(`${findings.length} problem${findings.length === 1 ? "" : "s"} in ${installed.size} packages. Upgrade or remove them; revoked versions stop installing soon.`);
  if (unchecked.length > 0) say(`${unchecked.length} package version${unchecked.length === 1 ? "" : "s"} could not be checked, so this audit is not a pass.`);
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
  const api = new Api(loadConfig(process.cwd(), env()));
  const reason = flag(a, "reason");
  if (action === "revoke" && !reason) {
    warn("apm revoke needs --reason; everyone with this version installed will see it.");
    return 2;
  }
  const needsFactor = action === "revoke" || action === "restore";
  const proof = needsFactor ? await readProof(a) : {};
  const r = await api.raw(`-/apm/v1/${action}`, { method: "POST", body: { name: parsed.name, version: parsed.range, ...(reason ? { reason } : {}), ...proof } });
  if (r.status !== 200) {
    warn(red(`apm ${action} failed: ${typeof r.body === "object" && r.body !== null && "error" in r.body ? String(r.body.error) : `HTTP ${r.status}`}`));
    return 1;
  }
  const body = z.object({ status: z.string(), finalAt: z.string().optional(), note: z.string().optional() }).loose().parse(r.body);
  say(`${green("✓")} ${parsed.name}@${parsed.range} is now ${bold(body.status)}`);
  if (body.finalAt) say(dim(`  becomes a full revoke at ${body.finalAt}. ${body.note ?? ""}`));
  return 0;
}

async function cmdIncident(a: Args): Promise<number> {
  const since = flag(a, "since");
  if (!since) {
    warn("usage: apm incident --since <ISO time of your last trusted publish> [--reason ...] [--dry-run]");
    return 2;
  }
  const api = new Api(loadConfig(process.cwd(), env()));
  const proof = await readProof(a);
  const body = { since, reason: flag(a, "reason") ?? "account compromised", ...proof, dryRun: has(a, "dry-run") };
  const r = await api.raw("-/apm/v1/incident", { method: "POST", body });
  if (r.status !== 200) {
    warn(red(`apm incident failed: ${typeof r.body === "object" && r.body !== null && "error" in r.body ? String(r.body.error) : `HTTP ${r.status}`}`));
    return 1;
  }
  const res = z.object({ revoked: z.array(z.string()), tokensRevoked: z.number(), dryRun: z.boolean().optional() }).loose().parse(r.body);
  say(res.dryRun ? bold("Preview (nothing changed):") : bold("Incident response done:"));
  for (const id of res.revoked) say(`  revoke ${id}`);
  say(`  ${res.dryRun ? "would revoke" : "revoked"} ${res.tokensRevoked} token(s)`);
  return 0;
}

// ---------- login ----------
const DeviceStart = z.object({ deviceCode: z.string(), userCode: z.string(), verificationUrl: z.string(), verificationUrlComplete: z.string(), interval: z.number(), expiresIn: z.number() });
const DeviceDone = z.object({ token: z.string(), username: z.string() });

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
  const cfg = loadConfig(process.cwd(), env());
  const api = new Api({ ...cfg, token: null });
  const start = await api.raw("-/apm/v1/login/device", { method: "POST", body: {} });
  const d = DeviceStart.safeParse(start.body);
  if (start.status !== 200 || !d.success) {
    warn(red(`login failed: ${errorOf(start.body, start.status)}`));
    return 1;
  }
  const code = d.data.userCode.length === 8 ? `${d.data.userCode.slice(0, 4)}-${d.data.userCode.slice(4)}` : d.data.userCode;
  process.stdout.write(`Open ${d.data.verificationUrlComplete}\nand check that it shows the code ${bold(code)}, then approve.\n`);
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
      saveToken(cfg.userconfig, cfg.registry, done.token);
      say(`${green("✓")} logged in to ${cfg.registry} as ${bold(done.username)}`);
      say(dim(`  token saved to ${cfg.userconfig}; npm, pnpm and bun read it from there`));
      say(dim(`  publishes with it wait for you to approve them in the browser`));
      return 0;
    }
    const err = typeof r.body === "object" && r.body !== null && "error" in r.body ? String(r.body.error) : "";
    if (err === "authorization_pending") continue;
    if (err === "slow_down") {
      interval += 1000;
      continue;
    }
    warn(red(`login failed: ${errorOf(r.body, r.status)}`));
    return 1;
  }
  warn(red("login failed: the code expired before it was approved. Run apm login again."));
  return 1;
}

/** npm's password login, for registries that run with legacy auth on. */
async function cmdPasswordLogin(a: Args): Promise<number> {
  const cfg = loadConfig(process.cwd(), env());
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
    warn(red(`login failed: ${errorOf(r.body, r.status)}`));
    return 1;
  }
  saveToken(cfg.userconfig, cfg.registry, tok.data.token);
  say(`${green("✓")} logged in to ${cfg.registry} as ${bold(username)}`);
  say(dim(`  token saved to ${cfg.userconfig}; npm, pnpm and bun read it from there`));
  return 0;
}

async function cmdWhoami(): Promise<number> {
  const cfg = loadConfig(process.cwd(), env());
  const api = new Api(cfg);
  const r = await api.raw("-/whoami");
  if (r.status !== 200) {
    warn(`not logged in to ${cfg.registry} (run apm login)`);
    return 1;
  }
  const me = z.object({ username: z.string() }).parse(r.body);
  say(`${me.username} ${dim(`on ${cfg.registry}`)}`);
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

const Manifest = z.object({ name: z.string(), version: z.string(), files: z.array(z.string()).optional() }).loose();

async function cmdPublish(a: Args): Promise<number> {
  const cwd = process.cwd();
  const pjPath = join(cwd, "package.json");
  if (!existsSync(pjPath)) {
    warn("apm publish: no package.json here");
    return 2;
  }
  const det = pmFor(a, cwd);
  const pj = Manifest.parse(JSON.parse(readFileSync(pjPath, "utf8")));
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
      say(`Refusing to publish ${id}: secret-shaped files sit in the package folder and package.json has no "files" allowlist,`);
      say(`so whether they ship depends on the package manager. Add "files": ["dist", ...] to package.json, or delete them.`);
      return 1;
    }
  }

  // 2. Pack with the project's own package manager and inspect exactly what would upload.
  const dest = mkdtempSync(join(tmpdir(), "apm-pack-"));
  process.once("exit", () => rmSync(dest, { recursive: true, force: true }));
  const packed = await runCmd(packArgs(det.pm, dest), { cwd, env: env(), quiet: true });
  const tgzName = readdirSync(dest).find((f) => f.endsWith(".tgz"));
  if (packed.code !== 0 || !tgzName) {
    warn(packed.out);
    warn(red(`apm publish: ${det.pm} pack failed`));
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
    say(`Refusing to publish ${id}: the tarball contains secrets. Narrow the "files" allowlist in package.json.`);
    return 1;
  }
  for (const s of secrets.skipped) say(yellow(`! ${describeSkip(s)} is too large to scan for secrets; check it yourself.`));
  const missing = missingEntries(manifest, files);
  if (missing.length > 0) {
    for (const m of missing) say(red(`✗ "${m.field}" points to ${m.path}, which is not in the tarball`));
    say(`Refusing to publish ${id}. Run your build first, or fix "files" in package.json.`);
    return 1;
  }

  say(bold(`${id}  ${files.length} files, ${fmtSize(files.reduce((n, f) => n + f.size, 0))}`));
  for (const f of [...files].sort((x, y) => x.path.localeCompare(y.path)).slice(0, 40)) say(`  ${dim(fmtSize(f.size).padStart(9))}  ${f.path}`);
  if (files.length > 40) say(dim(`  … and ${files.length - 40} more`));
  const analysis = analyze({ name: pj.name, manifest, files, publisher: "you", previousPublishers: [] });
  const report = finalize(analysis, { publishedAt: Number.NEGATIVE_INFINITY, now: Date.now(), deprecated: null, status: "active", statusReason: null });
  printCard("preview", report);

  if (dry) {
    say(dim("dry run: nothing uploaded"));
    return 0;
  }
  const tag = flag(a, "tag") ?? (version.includes("-") ? "next" : null);
  const pub = await runCmd(publishArgs(det.pm, tgzPath, tag), { cwd, env: env(), quiet: true });
  if (pub.code !== 0) {
    warn(pub.out.trim());
    warn(red(`apm publish: ${det.pm} publish failed for ${id}`));
    return pub.code;
  }
  // A login token stages the version: the registry answers with an approval link in its notice.
  const approval = /(https?:\/\/\S+?\/approve\/[A-Za-z0-9_-]+)/.exec(pub.out)?.[1];
  if (approval) {
    say(`${yellow("●")} ${bold(id)} is uploaded but not live yet: it is waiting for approval.`);
    say(`  Approve it within 24h with your passkey or authenticator code: ${bold(approval)}`);
    say(dim("  If an agent ran this publish, it should hand this link to you."));
    return 0;
  }
  say(`${green("✓")} published ${bold(id)}${tag ? ` with tag ${tag}` : ""} via ${det.pm}`);
  return 0;
}

// ---------- help / passthrough ----------
const HELP = `apm ${VERSION}: checks before you install, run or publish; your package manager does the rest.

  apm add <pkg>[@range]...   resolve with a 24h cooldown and score floor, then <pm> add the exact version
  apm x <pkg> [args]         show the risk card, then run it (bunx / npx)
  apm publish [--bump patch|minor|major] [--dry-run] [--tag t]
  apm score <pkg>[@version]  explained security score     apm name <name>   is this name free?
  apm audit                  installed versions vs revocations and advisories
  apm yank|unyank <pkg>@<v>  hide from new installs (lockfiles keep working)
  apm revoke <pkg>@<v> --reason "..."   pull a malicious version (asks for your authenticator code)
  apm restore <pkg>@<v>      undo a mistaken revoke (back to yanked)
  apm incident --since <time> [--dry-run]   account compromised: revoke tokens and recent versions
  apm login | whoami        sign in through the browser; publishes then wait for your approval
  apm <anything else>        passed to your package manager (apm run dev = bun run dev)

Flags: --pm bun|npm|pnpm|yarn, --force, --no-cooldown, --json, --otp <code>, --no-browser
Registry: APM_REGISTRY or registry= in .npmrc (default ${"https://apmjs.dev/"})`;

async function passthrough(a: Args): Promise<number> {
  const cwd = process.cwd();
  const det = pmFor(a, cwd);
  const args = a.raw.filter((x, i, arr) => x !== "--pm" && arr[i - 1] !== "--pm");
  return (await runCmd([det.pm, a.cmd, ...args], { cwd, env: env() })).code;
}

async function main(argv: string[]): Promise<number> {
  const a = parseArgs(argv);
  jsonMode = has(a, "json");
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
    case "audit":
      return cmdAudit(a);
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

try {
  process.exitCode = await main(process.argv.slice(2));
} catch (e) {
  if (e instanceof ApiError) warn(red(`apm: ${e.message}`));
  else warn(red(`apm: ${e instanceof Error ? e.message : String(e)}`));
  process.exitCode = 1;
}
