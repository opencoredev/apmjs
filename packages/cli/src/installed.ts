// What the package manager actually installed, and the registry's verdict on every package of it. The resolve walk
// predicts the install graph; lockfile pins, nested peers, overrides and the project's own ranges can make the real one
// differ (review of 16fc8b5, findings 1 to 3), so apm add, apm x and apm audit check the graph the package manager
// wrote, at the exact versions, before any install script runs. See docs/ARCHITECTURE.md, "After the install".
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join, sep } from "node:path";
import { z } from "zod";
import { InstallWarning, type Api } from "./api.ts";
import { installedPackages } from "./audit.ts";
import { isRegistryVersion, lockedTree, type LockNode, type LockPm } from "./lockfile.ts";

/** A package as the check asks about it. `platform`: built for one os or cpu, so summed up with its family when printed. */
export type InstalledPackage = { name: string; version: string; integrity: string | null; platform: boolean };

/** `name@version`, the key of everything here. */
export const idOf = (p: { name: string; version: string }): string => `${p.name}@${p.version}`;

/**
 * What an install left, as apm reads it: from the lockfile the package manager just wrote, or (no lockfile apm can read,
 * yarn's for one) from node_modules. `nodes` are the lockfile's entries (for the integrity check and held scripts).
 */
export type InstalledGraph =
  | { kind: "lockfile"; path: string; nodes: LockNode[]; packages: InstalledPackage[]; notFromRegistry: InstalledPackage[] }
  | { kind: "node_modules"; packages: InstalledPackage[]; notFromRegistry: InstalledPackage[]; unreadable: { id: string; reason: string }[] }
  | { kind: "unreadable"; reason: string };

/** What was installed before an add: every name@version, from the lockfile or node_modules. */
export type Before = { ids: ReadonlySet<string> };

/** Every name@version installed in `cwd` now: the lockfile's (all of it), else node_modules'. */
export function installedIds(input: { cwd: string; pm: LockPm | null }): Before {
  if (input.pm !== null) {
    const read = lockedTree({ cwd: input.cwd, pm: input.pm, roots: { kind: "all" } });

    if (read.kind === "read") return { ids: new Set(read.nodes.map(idOf)) };
  }

  const disk = installedPackages(input.cwd);

  return { ids: new Set([...disk.packages].flatMap(([name, versions]) => [...versions].map((version) => idOf({ name, version })))) };
}

const asPackage = (n: { name: string; version: string; integrity: string | null; platform: boolean }): InstalledPackage => ({ name: n.name, version: n.version, integrity: n.integrity, platform: n.platform });

/** Installed packages: from a registry, and not (git, file and link entries). */
type Split = { packages: InstalledPackage[]; notFromRegistry: InstalledPackage[] };

/** One entry per name@version (the first integrity seen); git, file and link entries apart. */
function split(nodes: readonly InstalledPackage[]): Split {
  const seen = new Map<string, InstalledPackage>();

  for (const n of nodes) if (!seen.has(idOf(n))) seen.set(idOf(n), n);
  const all = [...seen.values()];

  return { packages: all.filter((p) => isRegistryVersion(p.version)), notFromRegistry: all.filter((p) => !isRegistryVersion(p.version)) };
}

/**
 * The graph an add brought in: every node under the added packages (whatever version the package manager reused for
 * them, a peer included), and every name@version that is new since `before` anywhere in the project (an override, a
 * re-resolved peer). Nothing is truncated. A package installed before and untouched by the add is not this add's.
 */
export function addedGraph(input: { cwd: string; pm: LockPm | null; roots: readonly string[]; before: Before }): InstalledGraph {
  const { cwd, pm, roots, before } = input;

  if (pm !== null) {
    const all = lockedTree({ cwd, pm, roots: { kind: "all" } });
    const under = lockedTree({ cwd, pm, roots: { kind: "under", names: [...roots] } });

    if (all.kind === "read" && under.kind === "read") {
      const missing = roots.filter((r) => !under.nodes.some((n) => n.name === r));

      if (missing.length > 0) return { kind: "unreadable", reason: `${under.path} has no entry for ${missing.join(", ")}` };
      const keys = new Set(under.nodes.map((n) => n.key));
      const nodes = [...under.nodes, ...all.nodes.filter((n) => !keys.has(n.key) && !before.ids.has(idOf(n)))];

      return { kind: "lockfile", path: under.path, nodes, ...split(nodes.map(asPackage)) };
    }

    if (all.kind === "unreadable") return { kind: "unreadable", reason: `${all.path} could not be read (${all.reason})` };
  }

  // no lockfile apm can read: node_modules, followed the way node resolves a require
  const disk = nodeModulesGraph({ cwd, roots });
  const now = installedPackages(cwd);
  const fresh = [...now.packages].flatMap(([name, versions]) => [...versions].flatMap((version): InstalledPackage[] => (before.ids.has(idOf({ name, version })) ? [] : [{ name, version, integrity: null, platform: false }])));

  return { kind: "node_modules", ...split([...disk.packages, ...fresh]), unreadable: [...disk.unreadable, ...now.unchecked] };
}

/** Every package in a lockfile (apm x's own install, which is all new) or, without one, in node_modules. */
export function wholeGraph(input: { cwd: string; pm: LockPm | null }): InstalledGraph {
  return addedGraph({ cwd: input.cwd, pm: input.pm, roots: [], before: { ids: new Set() } });
}

// ---------- node_modules ----------
const OnDisk = z
  .object({
    name: z.string(),
    version: z.string(),
    dependencies: z.record(z.string(), z.unknown()).optional().catch(undefined),
    optionalDependencies: z.record(z.string(), z.unknown()).optional().catch(undefined),
    peerDependencies: z.record(z.string(), z.unknown()).optional().catch(undefined),
    os: z.unknown().optional(),
    cpu: z.unknown().optional(),
  })
  .loose();

/** Directories a node_modules walk reads at most. */
const DISK_BUDGET = 50_000;

/**
 * The packages under `roots` as node would load them: each package's dependencies and peers looked up from its real
 * directory upward, `<dir>/node_modules/<name>` at each level, as require() does. A dependency that is not on disk (an
 * optional one for another platform) is not installed, so not followed.
 */
/** Packages node_modules holds under some roots, and the directories apm could not read. */
type DiskGraph = { packages: InstalledPackage[]; unreadable: { id: string; reason: string }[] };

function nodeModulesGraph(input: { cwd: string; roots: readonly string[] }): DiskGraph {
  const packages: InstalledPackage[] = [];
  const unreadable: { id: string; reason: string }[] = [];
  const seen = new Set<string>();
  let budget = DISK_BUDGET;

  const real = (p: string): string => {
    try {
      return realpathSync(p);
    } catch {
      return p;
    }
  };

  const find = (from: string, name: string): string | null => {
    for (let dir = from; ; dir = dirname(dir)) {
      if (!dir.endsWith(`${sep}node_modules`)) {
        const candidate = join(dir, "node_modules", name);

        if (existsSync(join(candidate, "package.json"))) return real(candidate);
      }

      if (dirname(dir) === dir) return null;
    }
  };

  const queue = input.roots.flatMap((r) => find(input.cwd, r) ?? []);

  for (let i = 0; i < queue.length && budget-- > 0; i++) {
    const dir = queue[i];

    if (dir === undefined || seen.has(dir)) continue;
    seen.add(dir);
    let m: z.infer<typeof OnDisk>;

    try {
      const parsed = OnDisk.safeParse(JSON.parse(readFileSync(join(dir, "package.json"), "utf8")));

      if (!parsed.success) {
        unreadable.push({ id: dir, reason: "package.json has no name or version" });
        continue;
      }

      m = parsed.data;
    } catch {
      unreadable.push({ id: dir, reason: "unreadable package.json" });
      continue;
    }

    packages.push({ name: m.name, version: m.version, integrity: null, platform: m.os !== undefined || m.cpu !== undefined });

    for (const dep of Object.keys({ ...m.dependencies, ...m.optionalDependencies, ...m.peerDependencies })) {
      const at = find(dir, dep);

      if (at !== null) queue.push(at);
    }
  }

  if (budget < 0) unreadable.push({ id: "node_modules", reason: `more than ${DISK_BUDGET} package directories` });

  return { packages, unreadable };
}

// ---------- the registry's verdict ----------
/** A version refused in every mode: revoked, yanked, confirmed malicious, or not the bytes the registry serves. */
export type Blocked = { name: string; version: string; reason: string };

/**
 * The verdict on an installed graph. `blocked`: refused in every mode. `warnings`: what the default mode installs with a
 * warning and strict mode refuses (a fresh version, a low or incomplete score, a version apm cannot score or has not
 * scored yet, one the registry could not look up or check, one not from a registry).
 */
export type GraphVerdict = { checked: number; blocked: Blocked[]; warnings: InstallWarning[] };

const Scan = z.object({
  advisories: z.array(z.object({ package: z.string(), version: z.string(), level: z.string(), description: z.string() }).loose()).default([]),
  blocked: z.array(z.object({ package: z.string(), version: z.string(), kind: z.string(), reason: z.string() })).default([]),
  warnings: z.array(InstallWarning).default([]),
  unchecked: z.array(z.object({ package: z.string(), version: z.string(), reason: z.string() })).default([]),
  pending: z.array(z.object({ package: z.string(), version: z.string() })).default([]),
  retryAfter: z.number().min(0).optional(),
});

type ScanAnswer = z.infer<typeof Scan>;

/** Packages per scan request: what the registry checks without a token. */
export const SCAN_BATCH = 200;

/** Scan requests in flight at once. */
const SCAN_PARALLEL = 4;

/** A warning apm makes itself (the registry sent none): unchecked or pending, with no score and no page. */
function ownWarning(input: { name: string; version: string; kind: "unchecked" | "pending"; text: string }): InstallWarning {
  return { name: input.name, version: input.version, kind: input.kind, score: null, grade: null, text: input.text, reasons: [], url: "", via: [] };
}

/**
 * The policy a check applies, as apm add's flags set it: `cooldown` (a duration, as resolve takes it) and `floor` for
 * every package, and `lifted`, the name@versions --force names, whose score floor and cooldown are lifted.
 */
export type CheckPolicy = { cooldown: string | null; floor: number | null; lifted: ReadonlySet<string> };

export const DEFAULT_CHECK: CheckPolicy = { cooldown: null, floor: null, lifted: new Set() };

/** One batch's answer, or why it could not be had. */
async function scanBatch(api: Api, batch: readonly InstalledPackage[], policy: CheckPolicy): Promise<{ kind: "answer"; answer: ScanAnswer } | { kind: "failed"; reason: string }> {
  try {
    // an unknown integrity, cooldown or floor is left out of the JSON (undefined), so the registry's default applies
    const packages = batch.map((p) => ({ name: p.name, version: p.version, integrity: p.integrity ?? undefined }));
    const body = { packages, strict: false, cooldown: policy.cooldown ?? undefined, floor: policy.floor ?? undefined };
    const r = await api.raw("-/apm/v1/scan", { method: "POST", body });

    if (r.status === 404) return { kind: "failed", reason: `${api.cfg.registry} has no apm scan API` };

    if (r.status !== 200) return { kind: "failed", reason: `${api.cfg.registry} answered HTTP ${r.status}` };
    const parsed = Scan.safeParse(r.body);

    return parsed.success ? { kind: "answer", answer: parsed.data } : { kind: "failed", reason: `${api.cfg.registry} sent a scan answer apm does not understand` };
  } catch (e) {
    return { kind: "failed", reason: `could not reach ${api.cfg.registry} (${e instanceof Error ? e.message : String(e)})` };
  }
}

/** Every package asked about, SCAN_BATCH a request, SCAN_PARALLEL requests at a time. */
async function scanAll(api: Api, packages: readonly InstalledPackage[], policy: CheckPolicy): Promise<{ answers: ScanAnswer[]; failed: { p: InstalledPackage; reason: string }[] }> {
  const batches = Array.from({ length: Math.ceil(packages.length / SCAN_BATCH) }, (_, i) => packages.slice(i * SCAN_BATCH, (i + 1) * SCAN_BATCH));
  const answers: ScanAnswer[] = [];
  const failed: { p: InstalledPackage; reason: string }[] = [];

  for (let i = 0; i < batches.length; i += SCAN_PARALLEL) {
    const group = batches.slice(i, i + SCAN_PARALLEL);
    const got = await Promise.all(group.map((b) => scanBatch(api, b, policy)));

    for (const [j, g] of got.entries()) {
      if (g.kind === "answer") answers.push(g.answer);
      else for (const p of group[j] ?? []) failed.push({ p, reason: g.reason });
    }
  }

  return { answers, failed };
}

/**
 * Asks the registry about every package of `packages` at its exact version (and integrity, where the lockfile has it),
 * then again about those still being analysed until none is or `waitMs` is over. `progress` says what it waits for.
 * Never strict at the registry: the caller applies the mode to the verdict.
 */
export async function checkGraph(input: { api: Api; packages: readonly InstalledPackage[]; notFromRegistry: readonly InstalledPackage[]; waitMs: number; progress: (line: string) => void; policy: CheckPolicy }): Promise<GraphVerdict> {
  const { api, policy } = input;
  const byId = new Map(input.packages.map((p) => [idOf(p), p]));
  const blocked = new Map<string, Blocked>();
  const warnings = new Map<string, InstallWarning>();
  const unchecked = new Map<string, string>();
  let pending: InstalledPackage[] = [];

  const take = (answers: readonly ScanAnswer[]): void => {
    for (const a of answers) {
      for (const b of a.blocked) blocked.set(idOf({ name: b.package, version: b.version }), { name: b.package, version: b.version, reason: b.reason });

      // a fatal advisory with strict off is refused in every mode (an older registry sends no `blocked`)
      for (const adv of a.advisories) {
        const id = idOf({ name: adv.package, version: adv.version });

        if (adv.level === "fatal" && !blocked.has(id)) blocked.set(id, { name: adv.package, version: adv.version, reason: adv.description });
      }

      for (const w of a.warnings) warnings.set(`${idOf(w)}:${w.kind}`, w);
      const waiting = new Set(a.pending.map((p) => idOf({ name: p.package, version: p.version })));

      for (const u of a.unchecked) if (!waiting.has(idOf({ name: u.package, version: u.version }))) unchecked.set(idOf({ name: u.package, version: u.version }), u.reason);
      pending.push(...[...waiting].flatMap((id) => byId.get(id) ?? []));
    }
  };

  const first = await scanAll(api, input.packages, policy);

  take(first.answers);

  for (const f of first.failed) unchecked.set(idOf(f.p), f.reason);
  const started = Date.now();

  while (pending.length > 0 && Date.now() - started < input.waitMs) {
    const elapsed = Date.now() - started;
    const retry = Math.max(1, Math.min(5, ...first.answers.flatMap((a) => (a.retryAfter === undefined ? [] : [a.retryAfter]))));

    input.progress(`apm: ${pending.length === 1 ? "1 installed version is" : `${pending.length} installed versions are`} still being analysed (${pending.slice(0, 3).map(idOf).join(", ")}${pending.length > 3 ? ", …" : ""}); waiting, ${Math.round(elapsed / 1000)}s of ${Math.round(input.waitMs / 1000)}s`);
    await new Promise((resolve) => setTimeout(resolve, Math.min(retry * 1000, Math.max(0, input.waitMs - elapsed))));
    const asking = pending;

    pending = [];
    const again = await scanAll(api, asking, policy);

    take(again.answers);

    // not answered this time: still pending
    pending.push(...again.failed.map((f) => f.p));
  }

  for (const p of pending) warnings.set(`${idOf(p)}:pending`, ownWarning({ name: p.name, version: p.version, kind: "pending", text: `not scored yet: ${api.cfg.registry} is still analysing it` }));

  for (const [id, reason] of unchecked) {
    const p = byId.get(id);

    if (p && !blocked.has(id)) warnings.set(`${id}:unchecked`, ownWarning({ name: p.name, version: p.version, kind: "unchecked", text: `not checked: ${reason}` }));
  }

  for (const p of input.notFromRegistry) warnings.set(`${idOf(p)}:unchecked`, ownWarning({ name: p.name, version: p.version, kind: "unchecked", text: "not from a registry (git, file or link), so no registry can check it" }));

  // a blocked version needs no warning on top; --force lifts the floor and the cooldown of the packages it names
  const lifted = (w: InstallWarning): boolean => policy.lifted.has(idOf(w)) && (w.kind === "low-score" || w.kind === "cooldown");
  const shown = [...warnings.values()].filter((w) => !blocked.has(idOf(w)) && !lifted(w));

  return { checked: input.packages.length, blocked: [...blocked.values()], warnings: shown };
}
