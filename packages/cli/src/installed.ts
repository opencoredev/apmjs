// The registry's verdict on every package of a lockfile. apm add and apm x have the package manager compute the
// lockfile in a directory of their own, then check every package of it here, at the exact version and integrity it
// locks, before anything is installed (see docs/ARCHITECTURE.md, "How `apm add` makes the package manager install what apm checked"). apm audit checks node_modules
// with the same code.
import { z } from "zod";
import { InstallWarning, type Api } from "./api.ts";
import type { LockNode, Origin } from "./lockfile.ts";

/**
 * A registry package as the check asks about it. `integrity`: the lockfile's, which the registry compares with the bytes
 * it serves. `platform`: built for one os or cpu, so summed up with its family when printed.
 */
export type InstalledPackage = { name: string; version: string; integrity: string | null; platform: boolean };

/** A package from somewhere no registry can check: git, a file, a link, the project's own workspace, a remote tarball. */
export type LocalPackage = { name: string; version: string; origin: Exclude<Origin, { kind: "registry" }> };

/** `name@version`, the key of everything here. */
export const idOf = (p: { name: string; version: string }): string => `${p.name}@${p.version}`;

/**
 * What a lockfile asks the check about. `packages`: every registry package, one per name@version (a nested leaf@1.0.0
 * beside a hoisted leaf@2.0.0 is two). `local`: the rest, kept with their origin. `conflicts`: a name@version the
 * lockfile locks to two different artifacts, refused in every mode. `noIntegrity`: registry entries with no integrity,
 * whose bytes apm cannot confirm. `bundled`: entries inside their parent's tarball, which the parent's score covers.
 */
export type LockGraph = { packages: InstalledPackage[]; local: LocalPackage[]; conflicts: Blocked[]; noIntegrity: InstalledPackage[]; bundled: number };

/** Every node of a lockfile, as the check takes them. `integrityKnown`: false for yarn, whose checksums are not the registry's. */
export function lockGraph(nodes: readonly LockNode[], opts: { integrityKnown: boolean }): LockGraph {
  const byId = new Map<string, InstalledPackage>();
  const local = new Map<string, LocalPackage>();
  const conflicts = new Map<string, Blocked>();
  let bundled = 0;

  for (const n of nodes) {
    if (n.bundled) {
      bundled++;
      continue;
    }

    if (n.origin.kind !== "registry") {
      local.set(`${idOf(n)} ${n.origin.source}`, { name: n.name, version: n.version, origin: n.origin });
      continue;
    }

    const id = idOf(n);
    const seen = byId.get(id);

    if (seen === undefined) byId.set(id, { name: n.name, version: n.version, integrity: n.integrity, platform: n.platform });
    else if (seen.integrity === null) byId.set(id, { ...seen, integrity: n.integrity });
    else if (n.integrity !== null && n.integrity !== seen.integrity) conflicts.set(id, { name: n.name, version: n.version, reason: `the lockfile locks ${id} to two different artifacts (${seen.integrity} and ${n.integrity})` });
  }

  const packages = [...byId.values()];

  return { packages, local: [...local.values()], conflicts: [...conflicts.values()], noIntegrity: opts.integrityKnown ? packages.filter((p) => p.integrity === null) : [], bundled };
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
export async function checkGraph(input: { api: Api; packages: readonly InstalledPackage[]; local: readonly LocalPackage[]; noIntegrity: readonly InstalledPackage[]; waitMs: number; progress: (line: string) => void; policy: CheckPolicy }): Promise<GraphVerdict> {
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

  // git, file, link and workspace entries keep their origin: no registry can check them (strict refuses each)
  for (const p of input.local) warnings.set(`${idOf(p)}:unchecked`, ownWarning({ name: p.name, version: p.version, kind: "unchecked", text: `not checked: it comes from ${p.origin.kind === "workspace" ? "your own workspace" : `a ${p.origin.kind}`} (${p.origin.source}), not a registry, so no registry can check it` }));

  for (const p of input.noIntegrity) if (!blocked.has(idOf(p))) warnings.set(`${idOf(p)}:unchecked`, ownWarning({ name: p.name, version: p.version, kind: "unchecked", text: "not checked: the lockfile records no integrity for it, so apm cannot confirm it is the artifact the registry serves" }));

  // a blocked version needs no warning on top; --force lifts the floor and the cooldown of the packages it names
  const lifted = (w: InstallWarning): boolean => policy.lifted.has(idOf(w)) && (w.kind === "low-score" || w.kind === "cooldown");
  const shown = [...warnings.values()].filter((w) => !blocked.has(idOf(w)) && !lifted(w));

  return { checked: input.packages.length, blocked: [...blocked.values()], warnings: shown };
}
