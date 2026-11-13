// Bun security scanner: asks the apm registry about every package before bun installs it.
// No dependencies on purpose: a scanner must be small enough to read in one sitting.
//
// It asks exactly one registry: APM_REGISTRY, else `[install] registry` in bunfig.toml. It never takes a
// host from package data such as a tarball URL, so a lockfile cannot pick who vouches for it or who
// learns what you install. Every package it could not check gets its own warning, and with
// APM_SCANNER_STRICT=1 any unchecked package cancels the install.
//
// A score never cancels an install by default (the project owner's policy since 2026-11): a version published inside
// the 24-hour cooldown, a score under 40, an incomplete analysis, a version apm cannot score, one still being analysed
// after PENDING_WAIT_MS and a package the registry could not look up are each a warning, and the install goes ahead. In a terminal they are `warn`
// advisories, which bun shows and asks about; anywhere else (CI) bun cancels on a `warn` advisory, so the scanner
// prints them instead. APM_SCANNER_STRICT=1 makes each of them fatal. A revoked version, and one an apm reviewer
// confirmed malicious, are fatal in both modes.
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

type ScanAdvisory = { package: string; version: string; level: "fatal" | "warn"; description: string; url: string | null };
type Env = Record<string, string | undefined>;
/** A version the registry could not judge (not found, upstream down, analysis failed). Not the same as clean. */
type RegistryUnchecked = { package: string; version: string; reason: string };
type Unchecked = { id: string; reason: string };

/** A version the registry has queued for analysis and not scored yet. */
type Pending = { package: string; version: string };

function isScanAdvisory(v: unknown): v is ScanAdvisory {
  if (typeof v !== "object" || v === null) return false;
  return "package" in v && typeof v.package === "string" && "level" in v && (v.level === "fatal" || v.level === "warn") && "description" in v && typeof v.description === "string";
}

/** A package and version, as `pending` lists them and every `unchecked` entry starts. */
function isPending(v: unknown): v is Pending {
  if (typeof v !== "object" || v === null) return false;
  return "package" in v && typeof v.package === "string" && "version" in v && typeof v.version === "string";
}

function isUnchecked(v: unknown): v is RegistryUnchecked {
  return isPending(v) && "reason" in v && typeof v.reason === "string";
}

/** How long the scanner waits for queued versions to be scored before it warns (strict: cancels): 60 s. */
export const PENDING_WAIT_MS = 60_000;

/** How often it asks again while it waits. */
const PENDING_POLL_MS = 3_000;

/** A registry base URL ending in "/", or null when `value` is not an http(s) URL. */
function registryUrl(value: string): string | null {
  try {
    const u = new URL(value);

    if (u.protocol !== "https:" && u.protocol !== "http:") return null;

    return u.href.endsWith("/") ? u.href : `${u.href}/`;
  } catch {
    return null;
  }
}

/** `[install] registry` from a bunfig.toml: a URL, or a table with `url`. */
function bunfigRegistry(path: string): string | null {
  if (!existsSync(path)) return null;

  try {
    const doc: unknown = Bun.TOML.parse(readFileSync(path, "utf8"));

    if (!(doc instanceof Object) || !("install" in doc) || !(doc.install instanceof Object) || !("registry" in doc.install)) return null;

    const reg: unknown = doc.install.registry;

    return registryUrl(String(reg instanceof Object && "url" in reg ? reg.url : reg));
  } catch {
    return null;
  }
}

/** The one registry the scanner trusts: APM_REGISTRY, then bunfig.toml in the project, then the global bunfig. */
export function configuredRegistry(input: { env: Env; cwd: string }): string | null {
  if (input.env.APM_REGISTRY) return registryUrl(input.env.APM_REGISTRY);

  const home = input.env.HOME ?? homedir();
  const files = [join(input.cwd, "bunfig.toml"), ...(input.env.XDG_CONFIG_HOME ? [join(input.env.XDG_CONFIG_HOME, ".bunfig.toml")] : []), join(home, ".bunfig.toml")];

  for (const f of files) {
    const reg = bunfigRegistry(f);

    if (reg) return reg;
  }

  return null;
}

function originOf(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/** A package in a scan request that failed: the registry was never asked about it, so it is unchecked, nothing more. */
type Failed = { id: string; reason: string };

/**
 * What the registry said. `failed` lists the packages of the batches that could not be asked when others could: their
 * answer is unknown, and every other batch's advisories still count.
 */
type Answer = { kind: "advisories"; advisories: ScanAdvisory[]; unchecked: RegistryUnchecked[]; pending: Pending[]; failed: Failed[] } | { kind: "unavailable"; reason: string };

/** One request's answer, before batches are merged. */
type BatchAnswer = { kind: "advisories"; advisories: ScanAdvisory[]; unchecked: RegistryUnchecked[]; pending: Pending[] } | { kind: "unavailable"; reason: string };

async function ask(registry: string, packages: Bun.Security.Package[], strict: boolean): Promise<BatchAnswer> {
  try {
    const res = await fetch(`${registry}-/apm/v1/scan`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      // the platform this install is for: bun is handed every platform's optional binaries and installs only this
      // one's, so the registry skips the others a scanned package lists as optional instead of judging them
      body: JSON.stringify({ packages: packages.map((p) => ({ name: p.name, version: p.version })), strict, os: process.platform, cpu: process.arch }),
      signal: AbortSignal.timeout(20_000),
    });

    if (res.status === 404) return { kind: "unavailable", reason: `${registry} has no apm scan API (is it an apm registry?)` };
    if (!res.ok) return { kind: "unavailable", reason: `${registry} answered HTTP ${res.status}` };

    const body: unknown = await res.json();

    if (!(body instanceof Object) || !("advisories" in body) || !Array.isArray(body.advisories)) return { kind: "unavailable", reason: `${registry} sent an answer the scanner does not understand` };

    const unchecked = "unchecked" in body && Array.isArray(body.unchecked) ? body.unchecked.filter(isUnchecked) : [];
    const pending = "pending" in body && Array.isArray(body.pending) ? body.pending.filter(isPending) : [];

    return { kind: "advisories", advisories: body.advisories.filter(isScanAdvisory), unchecked, pending };
  } catch (e) {
    return { kind: "unavailable", reason: `could not reach ${registry} (${e instanceof Error ? e.message : String(e)})` };
  }
}

/** Packages per scan request: the registry checks at most this many without a token. */
const BATCH = 200;

/**
 * Asks about every package, BATCH at a time in parallel. Unavailable only when no batch could be asked. A batch that
 * failed while others answered leaves its packages unchecked and keeps every other batch's advisories: before this
 * (review of a76b9fc, finding 2), a 503 on batch 2 of 201 packages dropped batch 1's fatal advisory, and the scan
 * returned nothing but "unchecked" warnings.
 */
async function askAll(registry: string, packages: Bun.Security.Package[], strict: boolean): Promise<Answer> {
  const batches = Array.from({ length: Math.ceil(packages.length / BATCH) }, (_, i) => packages.slice(i * BATCH, (i + 1) * BATCH));
  const answers = await Promise.all(batches.map((b) => ask(registry, b, strict)));
  const advisories: ScanAdvisory[] = [];
  const unchecked: RegistryUnchecked[] = [];
  const pending: Pending[] = [];
  const failed: Failed[] = [];
  let reason: string | null = null;

  for (const [i, a] of answers.entries()) {
    if (a.kind === "unavailable") {
      reason ??= a.reason;

      for (const p of batches[i] ?? []) failed.push({ id: `${p.name}@${p.version}`, reason: a.reason });
      continue;
    }

    advisories.push(...a.advisories);
    unchecked.push(...a.unchecked);
    pending.push(...a.pending);
  }

  if (reason !== null && failed.length === packages.length) return { kind: "unavailable", reason };

  return { kind: "advisories", advisories, unchecked, pending, failed };
}

const keyOf = (p: { package: string; version: string }): string => `${p.package}@${p.version}`;

/**
 * Asks about every package, then asks again about the pending ones until none is pending or `waitMs` is over. What
 * landed meanwhile replaces its pending entry; what is still pending at the end is returned as pending.
 */
async function askUntilScored(input: { registry: string; packages: Bun.Security.Package[]; strict: boolean; waitMs: number; pollMs: number; warn: (line: string) => void; sleep: (ms: number) => Promise<void> }): Promise<Answer> {
  const first = await askAll(input.registry, input.packages, input.strict);

  if (first.kind === "unavailable" || first.pending.length === 0) return first;
  const started = Date.now();
  let answer = first;

  while (answer.pending.length > 0 && Date.now() - started < input.waitMs) {
    input.warn(`apm scanner: waiting for ${answer.pending.length} package(s) the registry is still analysing (${Math.round((Date.now() - started) / 1000)}s of ${Math.round(input.waitMs / 1000)}s): ${answer.pending.slice(0, 5).map(keyOf).join(", ")}${answer.pending.length > 5 ? ", …" : ""}`);
    await input.sleep(Math.min(input.pollMs, Math.max(0, input.waitMs - (Date.now() - started))));
    const waiting = new Set(answer.pending.map(keyOf));
    const again = await askAll(input.registry, input.packages.filter((p) => waiting.has(`${p.name}@${p.version}`)), input.strict);

    // the registry could not be asked again: what was pending stays pending, and is warned about (strict: blocked) below
    if (again.kind === "unavailable") break;
    // a batch of the asking again that failed: its packages are still pending, not answered
    const unanswered = new Set(again.failed.map((f) => f.id));
    const asked = (p: { package: string; version: string }): boolean => waiting.has(keyOf(p)) && !unanswered.has(keyOf(p));

    answer = {
      kind: "advisories",
      advisories: [...answer.advisories, ...again.advisories],
      unchecked: [...answer.unchecked.filter((u) => !asked(u)), ...again.unchecked],
      pending: [...again.pending, ...answer.pending.filter((p) => unanswered.has(keyOf(p)))],
      failed: answer.failed,
    };
  }

  return answer;
}

/**
 * A version a registry serves: strict semver, prereleases and build metadata included. Bun.semver.satisfies(v, "*")
 * is false for every prerelease, so it cannot tell registry versions from git, file and link specs.
 */
export function isRegistryVersion(version: string): boolean {
  return /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.test(version);
}

/**
 * Whether bun can ask the person installing about a `warn` advisory: both stdin and stdout are a terminal. Bun
 * cancels the install on a `warn` advisory when it cannot ask.
 */
function canAsk(): boolean {
  return process.stdin.isTTY === true && process.stdout.isTTY === true;
}

/**
 * The scan itself, with its inputs explicit so tests can drive it. `waitMs` and `sleep` default to PENDING_WAIT_MS
 * (or APM_SCANNER_WAIT_MS) and a timer; `interactive` (whether bun can ask about a warning) to the terminal's.
 */
export async function scanPackages(input: { packages: Bun.Security.Package[]; env: Env; cwd: string; warn: (line: string) => void; waitMs?: number; pollMs?: number; sleep?: (ms: number) => Promise<void>; interactive?: boolean }): Promise<Bun.Security.Advisory[]> {
  const strict = input.env.APM_SCANNER_STRICT === "1";
  const interactive = input.interactive ?? canAsk();
  // git, file and link dependencies are not on a registry: nothing can vouch for them, so each is reported
  const onRegistry = input.packages.filter((p) => isRegistryVersion(p.version));
  const registry = configuredRegistry({ env: input.env, cwd: input.cwd });

  const unchecked: Unchecked[] = input.packages
    .filter((p) => !isRegistryVersion(p.version))
    .map((p) => ({ id: `${p.name}@${p.version}`, reason: "not a registry version (git, file or link dependency), so no registry can check it" }));

  const out: Bun.Security.Advisory[] = [];

  if (!registry) {
    for (const pkg of onRegistry) unchecked.push({ id: `${pkg.name}@${pkg.version}`, reason: "no apm registry configured (set APM_REGISTRY, or [install] registry in bunfig.toml)" });
  } else if (onRegistry.length > 0) {
    const envWait = Number(input.env.APM_SCANNER_WAIT_MS);
    const waitMs = input.waitMs ?? (Number.isFinite(envWait) && envWait >= 0 ? envWait : PENDING_WAIT_MS);
    const sleep = input.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
    const answer = await askUntilScored({ registry, packages: onRegistry, strict, waitMs, pollMs: input.pollMs ?? PENDING_POLL_MS, warn: input.warn, sleep });

    if (answer.kind === "unavailable") {
      for (const pkg of onRegistry) unchecked.push({ id: `${pkg.name}@${pkg.version}`, reason: answer.reason });
    } else {
      const advisories: Bun.Security.Advisory[] = answer.advisories.map((a) => ({ level: a.level, package: a.package, url: a.url, description: a.description }));
      const stillPending = new Set(answer.pending.map(keyOf));

      // no score yet is not a pass: a warning, with when it will have one (strict: the install is cancelled)
      for (const p of answer.pending) {
        advisories.push({
          level: strict ? "fatal" : "warn",
          package: p.package,
          url: null,
          description: strict
            ? `${keyOf(p)} is still being analysed by ${registry} (waited ${Math.round(waitMs / 1000)}s). APM_SCANNER_STRICT=1 installs no version before it has a score; try again in a minute.`
            : `${keyOf(p)}: not scored yet: ${registry} is still analysing it (waited ${Math.round(waitMs / 1000)}s). apm lets it install; APM_SCANNER_STRICT=1 refuses it.`,
        });
      }

      // a warning bun cannot ask about would cancel the install, so outside a terminal it is printed and the install goes ahead
      for (const a of advisories) {
        if (a.level === "fatal" || interactive) out.push(a);
        else {
          const text = a.description ?? `${a.package}: flagged by ${registry}`;

          input.warn(`apm scanner: warning: ${text.split("\n").join("\n  ")}${a.url && !text.includes(a.url) ? `\n  ${a.url}` : ""}`);
        }
      }

      for (const u of answer.unchecked) if (!stillPending.has(keyOf(u))) unchecked.push({ id: `${u.package}@${u.version}`, reason: `${registry} could not check it: ${u.reason}` });

      // the packages of a batch the registry could not be asked about: unchecked, and nothing else is lost
      for (const f of answer.failed) unchecked.push({ id: f.id, reason: f.reason });

      // The verdict is about the registry's copy; bun is fetching this one from another host.
      const origin = new URL(registry).origin;

      for (const pkg of onRegistry) {
        if (originOf(pkg.tarball) !== origin) unchecked.push({ id: `${pkg.name}@${pkg.version}`, reason: `bun downloads it from ${pkg.tarball}, not from ${registry}` });
      }
    }
  }

  for (const u of unchecked) input.warn(`apm scanner: not checked: ${u.id}: ${u.reason}`);

  if (unchecked.length > 0 && input.env.APM_SCANNER_STRICT === "1") {
    throw new Error(`apm scanner: ${unchecked.length} package(s) not checked and APM_SCANNER_STRICT=1, so the install is cancelled`);
  }

  return out;
}

export const scanner: Bun.Security.Scanner = {
  version: "1",
  scan({ packages }) {
    return scanPackages({ packages, env: process.env, cwd: process.cwd(), warn: (line) => process.stderr.write(`${line}\n`) });
  },
};
