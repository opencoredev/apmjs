// Bun security scanner: asks the apm registry about every package before bun installs it.
// No dependencies on purpose: a scanner must be small enough to read in one sitting.
//
// It asks exactly one registry: APM_REGISTRY, else `[install] registry` in bunfig.toml. It never takes a
// host from package data such as a tarball URL, so a lockfile cannot pick who vouches for it or who
// learns what you install. Every package it could not check gets its own warning, and with
// APM_SCANNER_STRICT=1 any unchecked package cancels the install.
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

type ScanAdvisory = { package: string; version: string; level: "fatal" | "warn"; description: string; url: string | null };
type Env = Record<string, string | undefined>;
/** A version the registry could not judge (not found, upstream down, analysis failed). Not the same as clean. */
type RegistryUnchecked = { package: string; version: string; reason: string };
type Unchecked = { id: string; reason: string };

function isScanAdvisory(v: unknown): v is ScanAdvisory {
  if (typeof v !== "object" || v === null) return false;
  return "package" in v && typeof v.package === "string" && "level" in v && (v.level === "fatal" || v.level === "warn") && "description" in v && typeof v.description === "string";
}

function isUnchecked(v: unknown): v is RegistryUnchecked {
  if (typeof v !== "object" || v === null) return false;
  return "package" in v && typeof v.package === "string" && "version" in v && typeof v.version === "string" && "reason" in v && typeof v.reason === "string";
}

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

type Answer = { kind: "advisories"; advisories: ScanAdvisory[]; unchecked: RegistryUnchecked[] } | { kind: "unavailable"; reason: string };

async function ask(registry: string, packages: Bun.Security.Package[]): Promise<Answer> {
  try {
    const res = await fetch(`${registry}-/apm/v1/scan`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ packages: packages.map((p) => ({ name: p.name, version: p.version })) }),
      signal: AbortSignal.timeout(20_000),
    });

    if (res.status === 404) return { kind: "unavailable", reason: `${registry} has no apm scan API (is it an apm registry?)` };
    if (!res.ok) return { kind: "unavailable", reason: `${registry} answered HTTP ${res.status}` };

    const body: unknown = await res.json();

    if (!(body instanceof Object) || !("advisories" in body) || !Array.isArray(body.advisories)) return { kind: "unavailable", reason: `${registry} sent an answer the scanner does not understand` };

    const unchecked = "unchecked" in body && Array.isArray(body.unchecked) ? body.unchecked.filter(isUnchecked) : [];

    return { kind: "advisories", advisories: body.advisories.filter(isScanAdvisory), unchecked };
  } catch (e) {
    return { kind: "unavailable", reason: `could not reach ${registry} (${e instanceof Error ? e.message : String(e)})` };
  }
}

/** Packages per scan request: the registry checks at most this many without a token. */
const BATCH = 200;

/** Asks about every package, BATCH at a time in parallel. Unavailable when any batch could not be asked. */
async function askAll(registry: string, packages: Bun.Security.Package[]): Promise<Answer> {
  const batches = Array.from({ length: Math.ceil(packages.length / BATCH) }, (_, i) => packages.slice(i * BATCH, (i + 1) * BATCH));
  const answers = await Promise.all(batches.map((b) => ask(registry, b)));
  const advisories: ScanAdvisory[] = [];
  const unchecked: RegistryUnchecked[] = [];

  for (const a of answers) {
    if (a.kind === "unavailable") return a;
    advisories.push(...a.advisories);
    unchecked.push(...a.unchecked);
  }

  return { kind: "advisories", advisories, unchecked };
}

/**
 * A version a registry serves: strict semver, prereleases and build metadata included. Bun.semver.satisfies(v, "*")
 * is false for every prerelease, so it cannot tell registry versions from git, file and link specs.
 */
export function isRegistryVersion(version: string): boolean {
  return /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.test(version);
}

/** The scan itself, with its inputs explicit so tests can drive it. */
export async function scanPackages(input: { packages: Bun.Security.Package[]; env: Env; cwd: string; warn: (line: string) => void }): Promise<Bun.Security.Advisory[]> {
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
    const answer = await askAll(registry, onRegistry);

    if (answer.kind === "unavailable") {
      for (const pkg of onRegistry) unchecked.push({ id: `${pkg.name}@${pkg.version}`, reason: answer.reason });
    } else {
      for (const a of answer.advisories) out.push({ level: a.level, package: a.package, url: a.url, description: a.description });

      for (const u of answer.unchecked) unchecked.push({ id: `${u.package}@${u.version}`, reason: `${registry} could not check it: ${u.reason}` });

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
