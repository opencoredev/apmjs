// Bun security scanner: asks the apm registry about every package before bun installs it.
// No dependencies on purpose: a scanner must be small enough to read in one sitting.

type ScanAdvisory = { package: string; version: string; level: "fatal" | "warn"; description: string; url: string | null };
/** A version the registry could not judge (not found, upstream down, analysis failed). Not the same as clean. */
type Unchecked = { package: string; version: string; reason: string };
type ScanResult = { advisories: ScanAdvisory[]; unchecked: Unchecked[] };

function isScanAdvisory(v: unknown): v is ScanAdvisory {
  if (typeof v !== "object" || v === null) return false;
  return "package" in v && typeof v.package === "string" && "level" in v && (v.level === "fatal" || v.level === "warn") && "description" in v && typeof v.description === "string";
}

function isUnchecked(v: unknown): v is Unchecked {
  if (typeof v !== "object" || v === null) return false;
  return "package" in v && typeof v.package === "string" && "version" in v && typeof v.version === "string" && "reason" in v && typeof v.reason === "string";
}

/** The registry base a tarball came from: everything before "<name>/-/". */
export function registryOf(pkg: Bun.Security.Package): string | null {
  const marker = `${pkg.name}/-/`;
  const i = pkg.tarball.indexOf(marker);
  if (i <= 0 || !/^https?:\/\//.test(pkg.tarball)) return null;
  return pkg.tarball.slice(0, i);
}

async function ask(registry: string, packages: Bun.Security.Package[]): Promise<ScanResult | null> {
  try {
    const res = await fetch(`${registry}-/apm/v1/scan`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ packages: packages.map((p) => ({ name: p.name, version: p.version })) }),
      signal: AbortSignal.timeout(20_000),
    });
    if (res.status === 404) return { advisories: [], unchecked: [] }; // not an apm registry
    if (!res.ok) return null;
    const body: unknown = await res.json();
    if (typeof body !== "object" || body === null || !("advisories" in body) || !Array.isArray(body.advisories)) return null;
    const unchecked = "unchecked" in body && Array.isArray(body.unchecked) ? body.unchecked.filter(isUnchecked) : [];
    return { advisories: body.advisories.filter(isScanAdvisory), unchecked };
  } catch {
    return null;
  }
}

export const scanner: Bun.Security.Scanner = {
  version: "1",
  async scan({ packages }) {
    const fallback = process.env.APM_REGISTRY ? (process.env.APM_REGISTRY.endsWith("/") ? process.env.APM_REGISTRY : `${process.env.APM_REGISTRY}/`) : null;
    const groups = new Map<string, Bun.Security.Package[]>();
    for (const p of packages) {
      if (!Bun.semver.satisfies(p.version, "*")) continue; // git, file and link deps are not on a registry
      const reg = registryOf(p) ?? fallback;
      if (!reg) continue;
      const list = groups.get(reg) ?? [];
      list.push(p);
      groups.set(reg, list);
    }
    const strict = process.env.APM_SCANNER_STRICT === "1";
    const out: Bun.Security.Advisory[] = [];
    for (const [reg, list] of groups) {
      const found = await ask(reg, list);
      if (found === null) {
        const msg = `apm scanner: could not reach ${reg}; ${list.length} package(s) not checked`;
        if (strict) throw new Error(msg);
        process.stderr.write(`${msg}\n`);
        continue;
      }
      for (const a of found.advisories) out.push({ level: a.level, package: a.package, url: a.url, description: a.description });
      if (found.unchecked.length > 0) {
        const names = found.unchecked.map((u) => `${u.package}@${u.version} (${u.reason})`).join(", ");
        const msg = `apm scanner: ${reg} could not check ${found.unchecked.length} package(s): ${names}`;
        if (strict) throw new Error(msg);
        process.stderr.write(`${msg}\n`);
      }
    }
    return out;
  },
};
