// Review of a2227d1: apm add and apm x are lockfile first. The package manager computes the add's lockfile in a copy
// of the project; apm checks every package of it; a refusal leaves the project byte-identical, with nothing to undo.
// Only a lockfile that passes is written back (package.json and the lockfile, nothing else), installed with every
// install script held back, verified to be what was installed, and only then are install scripts run.
//
// The registry is a stand-in that answers resolve with a predicted graph and the scan with each exact version's state.
// The package managers are stand-ins (fixtures/fake-pm.ts) that write the lockfile a test describes, in each one's
// format, and lay the node_modules it describes. tests/acceptance/lockfile-first.test.ts runs the real ones.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import type { Scenario } from "./fixtures/fake-pm.ts";
import { treeHash } from "./fixtures/tree-hash.ts";

type Pm = "npm" | "pnpm" | "bun";

const PMS: readonly Pm[] = ["npm", "pnpm", "bun"];

/**
 * A package in a lockfile. `deps`, `peers`: names (the graph's first node of that name) or exact `name@version`s.
 * `key`: npm's or bun's install path when it is not the top (`node_modules/a/node_modules/leaf`, `a/leaf`).
 * `resolved`: npm's resolved, for a file or git entry. `integrity`: null for none. `bundled`: npm's inBundle.
 */
type Node = { name: string; version: string; deps?: string[]; peers?: string[]; script?: boolean; key?: { npm: string; bun: string }; resolved?: string; integrity?: string | null; bundled?: boolean };

/** A graph: `top`, the project's direct dependencies. `bins`: a binary's script by package. */
type Graph = { top: string[]; nodes: Node[]; bins?: Record<string, string> };

type State = "clean" | "fresh" | "revoked" | "yanked" | "low";

const integrity = (n: { name: string; version: string }): string => `sha512-${n.name}-${n.version}`;

function nodeOf(g: Graph, ref: string): Node {
  const at = ref.indexOf("@", 1);
  const n = at > 0 ? g.nodes.find((x) => `${x.name}@${x.version}` === ref) : g.nodes.find((x) => x.name === ref);

  if (!n) throw new Error(`fixture graph has no ${ref}`);

  return n;
}

const depName = (ref: string): string => (ref.indexOf("@", 1) > 0 ? ref.slice(0, ref.indexOf("@", 1)) : ref);

const rangesOf = (g: Graph, refs: readonly string[] | undefined, range: (n: Node) => string): Record<string, string> | undefined => (refs === undefined ? undefined : Object.fromEntries(refs.map((d) => [depName(d), range(nodeOf(g, d))])));

const topOf = (g: Graph): Record<string, string> => Object.fromEntries(g.top.map((t) => [t, nodeOf(g, t).version]));

const integrityOf = (n: Node): string | undefined => (n.integrity === null ? undefined : (n.integrity ?? integrity(n)));

/** A package-lock.json entry as the fixtures write it: undefined fields are left out of the JSON. */
type NpmEntry = { version: string; resolved: string; integrity: string | undefined; inBundle: true | undefined; dependencies: Record<string, string> | undefined; peerDependencies: Record<string, string> | undefined; hasInstallScript: true | undefined };

function npmLock(g: Graph, registry: string): string {
  const entries = g.nodes.map((n): [string, NpmEntry] => [
    n.key?.npm ?? `node_modules/${n.name}`,
    {
      version: n.version,
      resolved: n.resolved ?? `${registry}${n.name}/-/${n.name}-${n.version}.tgz`,
      integrity: n.bundled ? undefined : integrityOf(n),
      inBundle: n.bundled ? true : undefined,
      dependencies: rangesOf(g, n.deps, (d) => `^${d.version}`),
      peerDependencies: rangesOf(g, n.peers, () => ">=1.0.0"),
      hasInstallScript: n.script ? true : undefined,
    },
  ]);

  return JSON.stringify({ name: "project", lockfileVersion: 3, requires: true, packages: { "": { name: "project", dependencies: topOf(g) }, ...Object.fromEntries(entries) } });
}

function bunLock(g: Graph): string {
  const packages = Object.fromEntries(
    g.nodes.map((n) => {
      const meta = { dependencies: rangesOf(g, n.deps, (d) => `^${d.version}`), peerDependencies: rangesOf(g, n.peers, () => ">=1.0.0"), hasInstallScript: n.script ? true : undefined };
      const spec = n.resolved?.startsWith("file:") ? n.resolved : n.version;

      return [n.key?.bun ?? n.name, spec === n.version ? [`${n.name}@${n.version}`, "", meta, integrityOf(n) ?? ""] : [`${n.name}@${spec}`, meta]];
    }),
  );

  return JSON.stringify({ lockfileVersion: 1, workspaces: { "": { name: "project", dependencies: topOf(g) } }, packages });
}

/** pnpm's lockfile, written as JSON (which YAML reads): a peer is part of the snapshot key and its dependencies, as pnpm records it. */
function pnpmLock(g: Graph): string {
  const key = (n: Node): string => `${n.name}@${n.resolved?.startsWith("file:") ? n.resolved : n.version}${n.peers ? n.peers.map((p) => `(${depName(p)}@${nodeOf(g, p).version})`).join("") : ""}`;
  const resolution = (n: Node) => (n.resolved?.startsWith("file:") ? { tarball: n.resolved } : { integrity: integrityOf(n) });
  const packages = Object.fromEntries(g.nodes.map((n) => [key(n).replace(/\(.*$/, ""), { resolution: resolution(n), requiresBuild: n.script ? true : undefined }]));
  const snapshots = Object.fromEntries(g.nodes.map((n) => [key(n), { dependencies: Object.fromEntries([...(n.deps ?? []), ...(n.peers ?? [])].map((d) => [depName(d), key(nodeOf(g, d)).slice(depName(d).length + 1)])) }]));
  const dependencies = Object.fromEntries(g.top.map((t) => [t, { specifier: nodeOf(g, t).version, version: key(nodeOf(g, t)).slice(t.length + 1) }]));

  return JSON.stringify({ lockfileVersion: "9.0", importers: { ".": { dependencies } }, packages, snapshots });
}

const LOCKFILE: Record<Pm, string> = { npm: "package-lock.json", pnpm: "pnpm-lock.yaml", bun: "bun.lock" };

function lockText(pm: Pm, g: Graph, registry: string): string {
  switch (pm) {
    case "npm":
      return npmLock(g, registry);
    case "pnpm":
      return pnpmLock(g);
    case "bun":
      return bunLock(g);
    default: {
      const _exhaustive: never = pm;

      return _exhaustive;
    }
  }
}

/** The directories an install lays for a graph: npm's and bun's keys are install paths; pnpm's are laid flat here. */
function modulesOf(pm: Pm, g: Graph): Scenario["modules"] {
  return g.nodes.map((n) => {
    const path = pm === "npm" && n.key ? n.key.npm : pm === "bun" && n.key ? n.key.bun.split("/").map((p) => `node_modules/${p}`).join("/") : `node_modules/${n.name}`;

    return { path, name: n.name, version: n.version, bin: g.bins?.[n.name] };
  });
}

// ---------- the stand-in registry ----------
const states = new Map<string, State>();
const resolveAsked = new Map<string, URLSearchParams>();
const scanned: string[] = [];
const scanSizes: number[] = [];
const scanBodies: z.infer<typeof ScanBody>[] = [];
const predicted = new Map<string, { name: string; version: string }[]>();

const ScanBody = z.object({ packages: z.array(z.object({ name: z.string(), version: z.string(), integrity: z.string().optional(), bundled: z.boolean().optional() })), cooldown: z.string().optional(), floor: z.number().optional() });

type Warning = { name: string; version: string; kind: "cooldown" | "low-score"; score: number | null; grade: string | null; text: string; reasons: string[]; url: string; via: string[] };

/** The scan's answer, as apm's registry gives it: the cooldown and floor the request asks for, and integrity compared. */
function scanAnswer(body: z.infer<typeof ScanBody>) {
  const advisories: { package: string; version: string; level: "fatal" | "warn"; description: string; url: null }[] = [];
  const blocked: { package: string; version: string; kind: string; reason: string }[] = [];
  const warnings: Warning[] = [];
  const unchecked: { package: string; version: string; reason: string }[] = [];

  for (const p of body.packages) {
    const id = `${p.name}@${p.version}`;
    const state = states.get(id);

    scanned.push(id);

    // a bundled version: only its state counts, and one the registry does not know is its parent's to vouch for
    if (p.bundled === true) {
      if (state === "revoked") blocked.push({ package: p.name, version: p.version, kind: "revoked", reason: `${id} was revoked by its maintainer: compromised` });
      else if (state === "yanked") blocked.push({ package: p.name, version: p.version, kind: "yanked", reason: `${id} was yanked by its maintainer` });
      continue;
    }

    if (state === undefined) unchecked.push({ package: p.name, version: p.version, reason: "no such version" });
    else if (p.integrity !== undefined && p.integrity !== integrity(p)) blocked.push({ package: p.name, version: p.version, kind: "integrity", reason: `${id}: the lockfile's integrity ${p.integrity} is not the ${integrity(p)} this registry serves` });
    else if (state === "revoked") blocked.push({ package: p.name, version: p.version, kind: "revoked", reason: `${id} was revoked by its maintainer: compromised` });
    else if (state === "yanked") blocked.push({ package: p.name, version: p.version, kind: "yanked", reason: `${id} was yanked by its maintainer` });
    else if (state === "fresh" && body.cooldown !== "0") warnings.push({ name: p.name, version: p.version, kind: "cooldown", score: null, grade: null, text: "published 1h ago, inside the 24-hour cooldown", reasons: [], url: "", via: [] });
    else if (state === "low" && 50 < Math.max(body.floor ?? 40, 40)) warnings.push({ name: p.name, version: p.version, kind: "low-score", score: 50, grade: "C", text: `score 50/100 is below ${Math.max(body.floor ?? 40, 40)}`, reasons: [], url: "", via: [] });
  }

  return { advisories, blocked, warnings, unchecked, pending: [] };
}

let server: ReturnType<typeof Bun.serve>;
let root: string;
let bin: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "apm-lockfirst-unit-"));
  bin = join(root, "bin");
  mkdirSync(bin);
  const fake = join(import.meta.dir, "fixtures", "fake-pm.ts");

  for (const pm of [...PMS, "yarn"]) {
    writeFileSync(join(bin, pm), `#!/bin/sh\nexec "${process.execPath}" "${fake}" ${pm} "$@"\n`);
    chmodSync(join(bin, pm), 0o755);
  }

  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const url = new URL(req.url);

      if (url.pathname === "/-/apm/v1/resolve") {
        const name = url.searchParams.get("name") ?? "";
        const range = url.searchParams.get("range") ?? "latest";
        const version = /^\d/.test(range) ? range : "1.0.0";

        resolveAsked.set(name, url.searchParams);

        return Response.json({ name, range, source: "local", version, report: { score: 95, grade: "A", signals: [] }, skipped: [], tree: { unchecked: 0, uncheckedDeps: [], packages: predicted.get(name) ?? [], projectPeers: [] }, warnings: [] });
      }

      if (url.pathname === "/-/apm/v1/scan" && req.method === "POST") {
        const body = ScanBody.parse(await req.json());

        scanSizes.push(body.packages.length);
        scanBodies.push(body);

        return Response.json(scanAnswer(body));
      }

      return Response.json({ error: "not found" }, { status: 404 });
    },
  });
});

afterAll(() => {
  server.stop(true);
  rmSync(root, { recursive: true, force: true });
});

const Json = z.object({
  ok: z.boolean(),
  error: z.string().nullish(),
  installed: z
    .object({ checked: z.number(), refused: z.boolean(), touched: z.boolean(), stage: z.string(), recovery: z.array(z.string()).nullable(), blocked: z.array(z.object({ name: z.string(), version: z.string() })), warnings: z.array(z.object({ name: z.string(), version: z.string(), kind: z.string() })) })
    .nullish(),
});

type Run = { code: number; text: string; out: string; json: z.infer<typeof Json> | null; pmCalls: { args: string[]; cwd: string; production?: string }[]; scripts: string[]; dir: string; fake: string; leftInTmp: string[] };

/** package.json fields a test project sets besides its name. */
type PackageFields = { dependencies?: Record<string, string>; devDependencies?: Record<string, string>; workspaces?: string[]; description?: string };

let counter = 0;

/**
 * A project (`dir`) with package.json `pkg`, the lockfile of `before` (if any) and its node_modules, where the package
 * manager's add writes the lockfile of `after`. `prepare` changes the project before apm runs (a patch, a workspace).
 */
async function apmRun(input: {
  pm: Pm | "yarn";
  pkg: PackageFields;
  before: Graph | null;
  after: Graph;
  spec: string;
  strict: boolean;
  cmd?: "add" | "x";
  args?: string[];
  scenario?: Partial<Scenario>;
  prepare?: (dir: string) => void;
  cwd?: (dir: string) => string;
  lockText?: string;
  /** A directory of stand-ins found before the shared ones on PATH. */
  binFirst?: string;
  /** More environment for apm (npm_config_omit, say). */
  env?: Record<string, string>;
}): Promise<Run & { before: ReturnType<typeof treeHash> }> {
  const base = join(root, `case-${++counter}`);
  const dir = join(base, "project");
  const fake = join(base, "fake");
  const lockPm: Pm = input.pm === "yarn" ? "npm" : input.pm;
  const lockfile = input.pm === "yarn" ? "yarn.lock" : LOCKFILE[lockPm];

  mkdirSync(dir, { recursive: true });
  mkdirSync(fake, { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "project", version: "1.0.0", private: true, ...input.pkg }));

  if (input.before) {
    writeFileSync(join(dir, lockfile), input.pm === "yarn" ? "# yarn lockfile v1\n" : lockText(lockPm, input.before, server.url.href));

    for (const m of modulesOf(lockPm, input.before)) {
      mkdirSync(join(dir, m.path), { recursive: true });
      writeFileSync(join(dir, m.path, "package.json"), JSON.stringify({ name: m.name, version: m.version }));
    }
  }

  input.prepare?.(dir);

  const runIn = input.cwd?.(dir) ?? dir;
  const lockAt = input.scenario?.lockAt ?? lockfile;
  const edits = input.scenario?.editsProject;

  const scenario: Scenario = {
    lockAt,
    lock: input.lockText ?? lockText(lockPm, input.after, server.url.href),
    deps: { [input.spec.replace(/(.)@[^@]*$/, "$1")]: "1.0.0" },
    modules: modulesOf(lockPm, input.after),
    ...input.scenario,
    // a file of the real project, which only this function knows the place of
    editsProject: edits === undefined ? undefined : join(dir, edits),
  };

  writeFileSync(join(fake, "scenario.json"), JSON.stringify(scenario));
  const before = treeHash(dir);
  const cmd = input.cmd ?? "add";
  // apm x passes what follows the package to its binary, so its own flags go first
  const argv = cmd === "x" ? ["x", "--pm", input.pm, ...(input.strict ? ["--strict"] : []), ...(input.args ?? []), input.spec, "world"] : ["add", input.spec, "--pm", input.pm, "--json", ...(input.strict ? ["--strict"] : []), ...(input.args ?? [])];
  const scratch = join(base, "tmp");

  mkdirSync(scratch);

  const proc = Bun.spawn([process.execPath, join(import.meta.dir, "..", "src", "main.ts"), ...argv], {
    cwd: runIn,
    env: { PATH: `${input.binFirst === undefined ? "" : `${input.binFirst}:`}${bin}:/usr/bin:/bin`, HOME: root, TMPDIR: scratch, APM_REGISTRY: server.url.href, APM_FAKE_DIR: fake, NO_COLOR: "1", APM_PENDING_WAIT_MS: "0", ...input.env },
    stdout: "pipe",
    stderr: "pipe",
  });

  const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
  const text = out + err;
  const pmCalls = existsSync(join(fake, "pm.log")) ? readFileSync(join(fake, "pm.log"), "utf8").trim().split("\n").map((l) => z.object({ args: z.array(z.string()), cwd: z.string(), production: z.string().optional() }).parse(JSON.parse(l))) : [];
  let json: z.infer<typeof Json> | null = null;

  if (cmd === "add") {
    try {
      json = Json.parse(JSON.parse(out));
    } catch {
      throw new Error(`apm add printed no JSON result:\n${text}`);
    }
  }

  const scripts = existsSync(join(fake, "scripts-ran")) ? readFileSync(join(fake, "scripts-ran"), "utf8").trim().split("\n") : [];

  // what apm left under TMPDIR: nothing, but the backup of an add that stopped after writing the project
  return { code, text, out, json, pmCalls, scripts, dir, fake, before, leftInTmp: readdirSync(scratch) };
}

/** A refusal: exit 1, nothing installed or run, the project byte-identical, no frozen install or rebuild started. */
function expectUntouched(r: Run & { before: ReturnType<typeof treeHash> }): void {
  expect(r.code, r.text).toBe(1);
  expect(r.scripts, r.text).toEqual([]);
  expect(treeHash(r.dir).lines, r.text).toEqual(r.before.lines);
  expect(r.json?.installed?.touched ?? false, r.text).toBe(false);
  expect(r.leftInTmp, r.text).toEqual([]);

  // only the lockfile-only add ran, in a directory other than the project
  for (const c of r.pmCalls) expect(c.cwd.startsWith(r.dir), `${r.text}\n${JSON.stringify(r.pmCalls)}`).toBe(false);
}

const warned = (r: Run): string[] => r.json?.installed?.warnings.map((w) => `${w.name}@${w.version}`) ?? [];

// ---------- the graphs ----------
const existing: Graph = { top: ["existing"], nodes: [{ name: "existing", version: "1.0.0", deps: ["leaf"] }, { name: "leaf", version: "1.0.0", script: true }] };

/** existing@1.0.0 pins leaf@1.0.0; adding transitive-root (leaf ^1.0.0) reuses it. */
const transitive: Graph = { top: ["existing", "transitive-root"], nodes: [...existing.nodes, { name: "transitive-root", version: "1.0.0", deps: ["leaf"], script: true }] };

beforeAll(() => {
  for (const id of ["existing@1.0.0", "transitive-root@1.0.0", "leaf@1.1.0", "leaf@2.0.0", "consumer@1.0.0", "hoist-root@1.0.0", "up@1.0.0", "up@2.0.0", "tool@1.0.0", "helper@1.0.0", "bundle-root@1.0.0", "a@1.0.0", "other@1.0.0"]) states.set(id, "clean");
  // the version the lockfile holds is the fresh one; the walk predicts the clean one
  states.set("leaf@1.0.0", "fresh");
  states.set("forced@1.0.0", "fresh");
  states.set("lowdep@1.0.0", "low");
  predicted.set("transitive-root", [{ name: "leaf", version: "1.1.0" }]);
});

describe.each(PMS)("%s stand-in: a refused add leaves the project byte-identical", (pm) => {
  test("transitive lockfile pin: strict refuses the fresh leaf@1.0.0, and only the copy ever saw the package manager", async () => {
    const r = await apmRun({ pm, pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: true });

    expect(warned(r)).toEqual(["leaf@1.0.0"]);
    expect(r.text).toContain("the early check read 1.1.0, the lockfile holds 1.0.0");
    expect(r.text).toContain("apm changed nothing");
    expect(r.pmCalls.map((c) => c.args.find((a) => a.includes("lock")) ?? c.args[0])).toEqual([pm === "npm" ? "--package-lock-only" : "--lockfile-only"]);
    expectUntouched(r);
  });

  test("a dirty project with a hand patch in node_modules", async () => {
    const r = await apmRun({
      pm,
      pkg: { dependencies: { existing: "1.0.0" }, description: "edited, not installed" },
      before: existing,
      after: transitive,
      spec: "transitive-root",
      strict: true,
      prepare: (dir) => writeFileSync(join(dir, "node_modules", "leaf", "index.js"), "module.exports = 'patched';\n"),
    });

    expectUntouched(r);
    expect(readFileSync(join(r.dir, "node_modules", "leaf", "index.js"), "utf8")).toBe("module.exports = 'patched';\n");
  });

  test("a workspace: the add runs in the member's copy and the root lockfile is checked", async () => {
    const r = await apmRun({
      pm,
      pkg: { workspaces: ["packages/*"] },
      before: existing,
      after: transitive,
      spec: "transitive-root",
      strict: true,
      scenario: { lockAt: `../../${LOCKFILE[pm]}` },
      prepare: (dir) => {
        mkdirSync(join(dir, "packages", "app"), { recursive: true });
        writeFileSync(join(dir, "packages", "app", "package.json"), JSON.stringify({ name: "app", version: "1.0.0", dependencies: { existing: "1.0.0" } }));
        writeFileSync(join(dir, "pnpm-workspace.yaml"), "packages:\n  - packages/*\n");
      },
      cwd: (dir) => join(dir, "packages", "app"),
    });

    expect(warned(r)).toContain("leaf@1.0.0");
    expect(r.pmCalls[0]?.cwd.endsWith(join("packages", "app")), JSON.stringify(r.pmCalls)).toBe(true);
    expectUntouched(r);
  });

  test("no lockfile and no node_modules", async () => {
    const r = await apmRun({ pm, pkg: { dependencies: { existing: "1.0.0" } }, before: null, after: transitive, spec: "transitive-root", strict: true });

    expect(warned(r)).toEqual(["leaf@1.0.0"]);
    expectUntouched(r);
    expect(existsSync(join(r.dir, LOCKFILE[pm]))).toBe(false);
  });

  test("an existing dependency upgraded: up@1.0.0 keeps its lockfile entry and directory", async () => {
    const before: Graph = { top: ["existing", "up"], nodes: [...existing.nodes, { name: "up", version: "1.0.0" }] };
    const after: Graph = { top: ["existing", "up"], nodes: [...existing.nodes, { name: "up", version: "2.0.0", deps: ["leaf"] }] };
    const r = await apmRun({ pm, pkg: { dependencies: { existing: "1.0.0", up: "1.0.0" } }, before, after, spec: "up@2.0.0", strict: true });

    expect(warned(r)).toEqual(["leaf@1.0.0"]);
    expectUntouched(r);
  });

  test("a revoked version refuses in the default mode", async () => {
    states.set("leaf@1.0.0", "revoked");

    try {
      const r = await apmRun({ pm, pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: false });

      expect(r.json?.installed?.blocked.map((b) => `${b.name}@${b.version}`)).toEqual(["leaf@1.0.0"]);
      expect(r.text).toContain("refused: leaf@1.0.0: leaf@1.0.0 was revoked by its maintainer: compromised");
      expectUntouched(r);
    } finally {
      states.set("leaf@1.0.0", "fresh");
    }
  });

  test("an integrity the registry does not serve refuses in the default mode", async () => {
    const after: Graph = { ...transitive, nodes: transitive.nodes.map((n) => (n.name === "leaf" ? { ...n, integrity: "sha512-someone-else" } : n)) };
    const r = await apmRun({ pm, pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after, spec: "transitive-root", strict: false });

    expect(r.text).toContain("refused: leaf@1.0.0: leaf@1.0.0: the lockfile's integrity sha512-someone-else is not");
    expectUntouched(r);
  });

  test("the package manager fails to compute: nothing changes", async () => {
    const r = await apmRun({ pm, pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: false, scenario: { addFails: 3 } });

    expect(r.code, r.text).toBe(3);
    expect(r.text).toContain("Your project is unchanged");
    expect(treeHash(r.dir).lines).toEqual(r.before.lines);
  });

  test("a lockfile apm cannot read refuses in the default mode, with nothing changed", async () => {
    const r = await apmRun({ pm, pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: false, lockText: pm === "npm" ? JSON.stringify({ lockfileVersion: 1, dependencies: {} }) : "{ not a lockfile" });

    expect(r.text).toContain(`refused: apm could not read the ${LOCKFILE[pm]} ${pm} computed`);
    expectUntouched(r);
  });

  test("the package manager also changing a copied file apm never copies back refuses", async () => {
    const r = await apmRun({ pm, pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: false, scenario: { alsoChanges: ".npmrc" }, prepare: (dir) => writeFileSync(join(dir, ".npmrc"), "fund=false\n") });

    expect(r.text).toContain("the package manager also changed .npmrc, which apm does not copy into your project");
    expectUntouched(r);
  });

  test("package.json edited while apm checked: refused, and the edit is kept", async () => {
    const r = await apmRun({ pm, pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: false, scenario: { editsProject: "package.json" } });
    const pkg = JSON.stringify({ name: "project", version: "1.0.0", private: true, dependencies: { existing: "1.0.0" } });

    expect(r.code, r.text).toBe(1);
    expect(r.text).toContain("package.json changed while apm checked the add, so apm wrote nothing");
    expect(readFileSync(join(r.dir, "package.json"), "utf8")).toBe(`${pkg} `);
    expect(treeHash(r.dir).lines.filter((l) => !l.startsWith("package.json "))).toEqual(r.before.lines.filter((l) => !l.startsWith("package.json ")));
    expect(r.scripts).toEqual([]);
  });
});

describe.each(PMS)("%s stand-in: an add that passes", (pm) => {
  test("writes the checked package.json and lockfile, installs them frozen with scripts held back, then runs scripts for what it installed", async () => {
    const r = await apmRun({ pm, pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: false });

    expect(r.code, r.text).toBe(0);
    expect(r.json?.installed?.stage).toBe("done");
    expect(r.json?.installed?.touched).toBe(true);
    expect(readFileSync(join(r.dir, LOCKFILE[pm]), "utf8")).toBe(lockText(pm, transitive, server.url.href));
    expect(JSON.parse(readFileSync(join(r.dir, "package.json"), "utf8"))).toEqual({ name: "project", version: "1.0.0", private: true, dependencies: { existing: "1.0.0", "transitive-root": "1.0.0" } });
    const install = r.pmCalls[1];

    expect(install?.cwd).toBe(r.dir);
    expect(install?.args).toContain("--ignore-scripts");
    expect(install?.args.slice(0, 2)).toEqual(pm === "npm" ? ["install", "--ignore-scripts"] : ["install", "--frozen-lockfile"]);
    // leaf@1.0.0 was in place before the add: only transitive-root, which this add installed, has its script run
    // npm rebuilds that exact directory, pnpm that exact version (never --pending, which also ran builds left from before
    // and the project's own postinstall; review of 2a098b1, finding 6)
    expect(r.scripts, r.text).toEqual([pm === "npm" ? `npm rebuild ${join(realpathSync(r.dir), "node_modules", "transitive-root")}` : pm === "pnpm" ? "pnpm rebuild transitive-root@1.0.0" : "bun install --frozen-lockfile --registry=" + server.url.href]);
    expect(r.leftInTmp, r.text).toEqual([]);
  });

  test("no node_modules before: npm uses ci, which installs exactly the lockfile", async () => {
    const r = await apmRun({ pm, pkg: { dependencies: { existing: "1.0.0" } }, before: null, after: transitive, spec: "transitive-root", strict: false });

    expect(r.code, r.text).toBe(0);
    expect(r.pmCalls[1]?.args[0]).toBe(pm === "npm" ? "ci" : "install");
  });

  test("an install that is not the checked lockfile: refused before any script, left as installed, with the commands that put it back", async () => {
    const extra: Graph = { ...transitive, nodes: [...transitive.nodes, { name: "stowaway", version: "6.6.6" }] };
    const r = await apmRun({ pm, pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: false, scenario: { modules: modulesOf(pm, extra) } });

    expect(r.code, r.text).toBe(1);
    expect(r.text).toContain("node_modules holds a package the checked lockfile does not: stowaway@6.6.6");
    expect(r.text).toContain("No install script ran");
    expect(r.text).toContain("apm does not undo installs");
    expect(r.scripts).toEqual([]);
    expect(r.json?.installed?.stage).toBe("verify");
    const recovery = r.json?.installed?.recovery ?? [];

    expect(recovery[0], r.text).toMatch(/^cp '.*apm-backup-.*' '.*package\.json'$/);
    expect(recovery.at(-1)).toContain(pm === "npm" ? "npm install --ignore-scripts" : `${pm} install --frozen-lockfile --ignore-scripts`);
    // the backup holds the files from before the add, so the commands work
    const cp = /^cp '([^']+)' '([^']+)'$/.exec(recovery[0] ?? "");

    expect(readFileSync(cp?.[1] ?? "", "utf8")).toBe(JSON.stringify({ name: "project", version: "1.0.0", private: true, dependencies: { existing: "1.0.0" } }));
  });

  test("a package manager that rewrites the lockfile while installing: refused before any script", async () => {
    const r = await apmRun({ pm, pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: false, scenario: { installRewritesLock: lockText(pm, existing, server.url.href) } });

    expect(r.code, r.text).toBe(1);
    expect(r.text).toContain(`${LOCKFILE[pm]} is not the lockfile apm checked`);
    expect(r.scripts).toEqual([]);
  });

  test("unreadable package directories after the install: strict refuses before any script, the default mode warns", async () => {
    const modules = [...modulesOf(pm, transitive), { path: "node_modules/broken", name: "broken", version: "0.0.0", raw: "{ not json" }];
    const strict = await apmRun({ pm, pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: true, args: ["--no-cooldown"], scenario: { modules } });

    expect(strict.text).toContain("not read: node_modules/broken (unreadable package.json)");
    expect(strict.text).toContain("refused: strict mode refuses a package directory apm could not read");
    expect(strict.code, strict.text).toBe(1);
    expect(strict.scripts).toEqual([]);
    const loose = await apmRun({ pm, pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: false, scenario: { modules } });

    expect(loose.text).toContain("not read: node_modules/broken");
    expect(loose.code, loose.text).toBe(0);
  });
});

describe("what the check covers", () => {
  test("hoisting: a version that existed elsewhere and now moves into an existing consumer's path is checked (strict refuses it)", async () => {
    // before: consumer resolves leaf@2.0.0 at the top, leaf@1.0.0 sits nested under other; the add hoists leaf@1.0.0
    const before: Graph = { top: ["consumer", "other"], nodes: [{ name: "consumer", version: "1.0.0", deps: ["leaf@2.0.0"] }, { name: "leaf", version: "2.0.0" }, { name: "other", version: "1.0.0", deps: ["leaf@1.0.0"] }, { name: "leaf", version: "1.0.0", key: { npm: "node_modules/other/node_modules/leaf", bun: "other/leaf" } }] };
    const after: Graph = { top: ["consumer", "other", "hoist-root"], nodes: [{ name: "consumer", version: "1.0.0", deps: ["leaf@1.0.0"] }, { name: "leaf", version: "1.0.0" }, { name: "other", version: "1.0.0", deps: ["leaf@1.0.0"] }, { name: "hoist-root", version: "1.0.0" }] };
    const r = await apmRun({ pm: "npm", pkg: { dependencies: { consumer: "1.0.0", other: "1.0.0" } }, before, after, spec: "hoist-root", strict: true });

    // on a2227d1: only hoist-root was checked, since leaf@1.0.0 existed somewhere before
    expect(warned(r)).toEqual(["leaf@1.0.0"]);
    expectUntouched(r);
  });

  test("nested leaf@1.0.0 beside leaf@2.0.0: both are checked, and npm rebuilds only the exact version this add installed", async () => {
    const before: Graph = { top: ["other"], nodes: [{ name: "other", version: "1.0.0", deps: ["leaf"] }, { name: "leaf", version: "1.0.0", script: true }] };
    const after: Graph = { top: ["other", "consumer"], nodes: [...before.nodes, { name: "consumer", version: "1.0.0", deps: ["leaf@2.0.0"] }, { name: "leaf", version: "2.0.0", script: true, key: { npm: "node_modules/consumer/node_modules/leaf", bun: "consumer/leaf" } }] };

    scanned.length = 0;
    const r = await apmRun({ pm: "npm", pkg: { dependencies: { other: "1.0.0" } }, before, after, spec: "consumer", strict: false });

    expect(r.code, r.text).toBe(0);
    expect(scanned).toContain("leaf@1.0.0");
    expect(scanned).toContain("leaf@2.0.0");
    // on a2227d1: npm rebuild leaf, which ran both copies' scripts; on 2a098b1: npm rebuild leaf@2.0.0, which also runs a
    // same-version copy elsewhere. Now the exact directory this add installed
    expect(r.scripts).toEqual([`npm rebuild ${join(realpathSync(r.dir), "node_modules", "consumer", "node_modules", "leaf")}`]);
  });

  test("git, file and workspace entries keep their origin: they warn, and strict refuses them", async () => {
    const after: Graph = { top: ["existing", "local-leaf"], nodes: [{ name: "existing", version: "1.0.0" }, { name: "local-leaf", version: "1.0.0", resolved: "file:../local-leaf-1.0.0.tgz" }] };

    for (const pm of PMS) {
      const r = await apmRun({ pm, pkg: { dependencies: { existing: "1.0.0" } }, before: null, after, spec: "local-leaf", strict: true });

      // on a2227d1: a file entry with a plain version was asked about as a registry package, and passed strict
      expect(r.json?.installed?.warnings.map((w) => `${w.name}:${w.kind}`), r.text).toEqual(["local-leaf:unchecked"]);
      expect(r.text).toContain("comes from a file (file:../local-leaf-1.0.0.tgz)");
      expectUntouched(r);
    }
  });

  test("a registry entry with no integrity is unchecked: strict refuses it, the default warns", async () => {
    const after: Graph = { ...transitive, nodes: transitive.nodes.map((n) => (n.name === "transitive-root" ? { ...n, integrity: null } : n)) };
    const r = await apmRun({ pm: "npm", pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after, spec: "transitive-root", strict: true, args: ["--no-cooldown"] });

    expect(r.text).toContain("transitive-root@1.0.0 not checked: the lockfile records no integrity for it");
    expectUntouched(r);
  });

  test("bundled dependencies are covered by their parent's score: asked about only for their state", async () => {
    const after: Graph = { top: ["bundle-root"], nodes: [{ name: "bundle-root", version: "1.0.0", deps: ["inner"] }, { name: "inner", version: "9.9.9", bundled: true, key: { npm: "node_modules/bundle-root/node_modules/inner", bun: "bundle-root/inner" } }] };

    scanned.length = 0;
    scanBodies.length = 0;
    const r = await apmRun({ pm: "npm", pkg: {}, before: null, after, spec: "bundle-root", strict: true });

    expect(r.code, r.text).toBe(0);
    expect(scanned.toSorted()).toEqual(["bundle-root@1.0.0", "inner@9.9.9"]);
    expect(scanBodies.flatMap((b) => b.packages).find((p) => p.name === "inner")?.bundled).toBe(true);
    expect(r.text).toContain("1 bundled package ships inside its parent's tarball: the parent's score covers its code, and apm checked that it is not revoked, yanked or confirmed malicious");
  });

  test("--force lifts the cooldown of the named version only: a fresh transitive version still refuses in strict mode", async () => {
    const after: Graph = { top: ["forced"], nodes: [{ name: "forced", version: "1.0.0", deps: ["leaf"] }, { name: "leaf", version: "1.0.0" }] };

    scanBodies.length = 0;
    const r = await apmRun({ pm: "npm", pkg: {}, before: null, after, spec: "forced", strict: true, args: ["--force"] });

    // on a2227d1: the scan was sent cooldown 0, so leaf@1.0.0 never warned and the add passed
    expect(warned(r)).toEqual(["leaf@1.0.0"]);
    expect(scanBodies.every((b) => b.cooldown === undefined)).toBe(true);
    expectUntouched(r);
  });

  test("--force --floor 80 keeps the floor of 80 for every other package", async () => {
    const after: Graph = { top: ["forced"], nodes: [{ name: "forced", version: "1.0.0", deps: ["lowdep"] }, { name: "lowdep", version: "1.0.0" }] };

    scanBodies.length = 0;
    const r = await apmRun({ pm: "npm", pkg: {}, before: null, after, spec: "forced", strict: true, args: ["--force", "--floor", "80"] });

    // on a2227d1: --force reset the floor to the default for the dependencies
    expect(scanBodies.every((b) => b.floor === 80)).toBe(true);
    expect(warned(r)).toEqual(["lowdep@1.0.0"]);
    expectUntouched(r);
  });

  test("npm-shrinkwrap.json beats package-lock.json: it is what apm copies, checks and writes", async () => {
    const r = await apmRun({
      pm: "npm",
      pkg: { dependencies: { existing: "1.0.0" } },
      before: existing,
      after: transitive,
      spec: "transitive-root",
      strict: false,
      scenario: { lockAt: "npm-shrinkwrap.json" },
      prepare: (dir) => writeFileSync(join(dir, "npm-shrinkwrap.json"), readFileSync(join(dir, "package-lock.json"))),
    });

    const stale = lockText("npm", existing, server.url.href);

    expect(r.code, r.text).toBe(0);
    expect(r.text).toContain("in the npm-shrinkwrap.json npm computed");
    expect(readFileSync(join(r.dir, "npm-shrinkwrap.json"), "utf8")).toBe(lockText("npm", transitive, server.url.href));
    expect(readFileSync(join(r.dir, "package-lock.json"), "utf8")).toBe(stale);
  });

  test("a project apm cannot write to: the write fails before anything installs, and apm says how to put it back", async () => {
    const r = await apmRun({ pm: "npm", pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: false, prepare: (dir) => chmodSync(dir, 0o555) });

    chmodSync(r.dir, 0o755);
    expect(r.code, r.text).toBe(1);
    expect(r.text).toContain("apm add: writing the checked files failed");
    expect(r.text).toContain("To put your project back as it was before apm add, run:");
    expect(r.pmCalls).toHaveLength(1);
    expect(r.scripts).toEqual([]);
    expect(treeHash(r.dir).lines).toEqual(r.before.lines);
  });

  test("bun's binary bun.lockb alone is refused before anything runs", async () => {
    const r = await apmRun({ pm: "bun", pkg: {}, before: null, after: transitive, spec: "transitive-root", strict: false, prepare: (dir) => writeFileSync(join(dir, "bun.lockb"), new Uint8Array([0, 1, 2])) });

    expect(r.text).toContain("bun.lockb is bun's binary lockfile, which apm cannot read");
    expect(r.pmCalls).toEqual([]);
    expectUntouched(r);
  });
});

describe("yarn", () => {
  test("strict refuses before anything runs", async () => {
    const r = await apmRun({ pm: "yarn", pkg: {}, before: existing, after: transitive, spec: "transitive-root", strict: true });

    expect(r.text).toContain("refused: apm cannot check yarn installs before yarn runs their scripts.");
    expect(r.pmCalls).toEqual([]);
    expectUntouched(r);
  });

  const berryLock = (g: Graph): string =>
    `__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"project@workspace:.":\n  version: 0.0.0-use.local\n  resolution: "project@workspace:."\n  languageName: unknown\n  linkType: soft\n\n${g.nodes.map((n) => `"${n.name}@npm:^${n.version}":\n  version: ${n.version}\n  resolution: "${n.name}@npm:${n.version}"\n  checksum: 10c0/abc\n  languageName: node\n  linkType: hard\n`).join("\n")}`;

  test("berry: the lockfile yarn computes in a copy is checked, and a revoked version refuses with the project untouched", async () => {
    states.set("leaf@1.0.0", "revoked");

    try {
      const r = await apmRun({ pm: "yarn", pkg: {}, before: existing, after: transitive, spec: "transitive-root", strict: false, lockText: berryLock(transitive), scenario: { yarnVersion: "4.5.0" } });

      expect(r.text).toContain("apm: yarn runs install scripts while it installs, before apm can check what it installed");
      expect(r.text).toContain("in the yarn.lock yarn computed for this add");
      expect(r.text).toContain("refused: leaf@1.0.0");
      expect(r.pmCalls.map((c) => c.args.join(" "))).toEqual(["--version", "add --mode update-lockfile transitive-root@1.0.0"]);
      expectUntouched(r);
    } finally {
      states.set("leaf@1.0.0", "fresh");
    }
  });

  test("berry: a lockfile that passes is written, and yarn installs it, running scripts it says apm could not check first", async () => {
    const r = await apmRun({ pm: "yarn", pkg: {}, before: existing, after: transitive, spec: "transitive-root", strict: false, lockText: berryLock(transitive), scenario: { yarnVersion: "4.5.0" } });

    expect(r.code, r.text).toBe(0);
    expect(r.text).toContain("yarn now installs exactly it and runs its install scripts, which apm cannot hold back or check first");
    expect(r.text).not.toContain("before any install script");
    expect(r.scripts).toEqual(["yarn install --immutable"]);
  });

  test("review of 2a098b1, finding 11: berry installs immutably, and what it installed must be the checked lockfile, or apm says how to put the project back", async () => {
    const rewrites = await apmRun({ pm: "yarn", pkg: {}, before: existing, after: transitive, spec: "transitive-root", strict: false, lockText: berryLock(transitive), scenario: { yarnVersion: "4.5.0", installRewritesLock: berryLock(existing) } });

    expect(rewrites.pmCalls.at(-1)?.args).toEqual(["install", "--immutable"]);
    // on 2a098b1: exit 0, stage done, the backup deleted
    expect(rewrites.code, rewrites.text).toBe(1);
    expect(rewrites.text).toContain("refused: what yarn installed is not the checked lockfile: yarn.lock is not the lockfile apm checked");
    expect(rewrites.text).toContain("Install scripts may have run: yarn ran them as it installed.");
    expect(rewrites.json?.installed?.stage).toBe("verify");
    expect(rewrites.json?.installed?.recovery?.[0], rewrites.text).toMatch(/^cp '.*apm-backup-.*' /);

    const stowaway = await apmRun({ pm: "yarn", pkg: {}, before: existing, after: transitive, spec: "transitive-root", strict: false, lockText: berryLock(transitive), scenario: { yarnVersion: "4.5.0", modules: [...modulesOf("npm", transitive), { path: "node_modules/stowaway", name: "stowaway", version: "6.6.6" }] } });

    expect(stowaway.code, stowaway.text).toBe(1);
    expect(stowaway.text).toContain("node_modules holds a package the checked lockfile does not: stowaway@6.6.6");
  });

  test("classic yarn: no lockfile-only mode, so apm says it checks only after yarn installed and ran scripts", async () => {
    states.set("leaf@1.0.0", "revoked");

    try {
      const r = await apmRun({ pm: "yarn", pkg: {}, before: existing, after: transitive, spec: "transitive-root", strict: false, scenario: { yarnVersion: "1.22.22" } });

      expect(r.text).toContain("yarn 1.22.22 has no lockfile-only mode, so apm cannot check this add before yarn installs it and runs its install scripts");
      expect(r.text).toContain("in node_modules after yarn installed them and ran their install scripts");
      expect(r.text).toContain("refused: leaf@1.0.0");
      expect(r.code, r.text).toBe(1);
    } finally {
      states.set("leaf@1.0.0", "fresh");
    }
  });
});

describe.each(PMS)("apm x with the %s stand-in", (pm) => {
  const tool: Graph = { top: ["tool"], nodes: [{ name: "tool", version: "1.0.0", deps: ["helper"], script: true }, { name: "helper", version: "1.0.0" }], bins: { tool: '#!/bin/sh\nexec helper "$@"\n', helper: '#!/bin/sh\necho "checked helper $*"\n' } };

  test("the checked installation's binaries are on PATH: the tool's helper runs, not one from the caller's PATH", async () => {
    const r = await apmRun({ pm, pkg: {}, before: null, after: tool, spec: "tool", strict: false, cmd: "x", prepare: () => writeFileSync(join(bin, "helper"), '#!/bin/sh\necho impostor\n', { mode: 0o755 }) });

    rmSync(join(bin, "helper"), { force: true });
    // on a2227d1: exit 127, helper: not found (or the caller's helper ran)
    expect(r.code, r.text).toBe(0);
    expect(r.out).toContain("checked helper world");
    expect(r.out).not.toContain("impostor");
  });

  test("strict: a fresh version in its lockfile refuses, and nothing is installed or run", async () => {
    const fresh: Graph = { ...tool, nodes: [...tool.nodes.map((n) => (n.name === "helper" ? { ...n, deps: ["leaf"] } : n)), { name: "leaf", version: "1.0.0" }] };
    const r = await apmRun({ pm, pkg: {}, before: null, after: fresh, spec: "tool", strict: true, cmd: "x" });

    expect(r.code, r.text).toBe(1);
    expect(r.text).toContain("apm ran nothing: it installed nothing");
    expect(r.pmCalls).toHaveLength(1);
    expect(r.out).not.toContain("checked helper");
  });
});

describe("501 dependencies", () => {
  const fillers = Array.from({ length: 500 }, (_, i) => `dep${i}`);
  const deps = Object.fromEntries([...fillers.map((d) => [d, "1.0.0"]), ["leaf", "1.0.0"]]);
  const graph: Graph = { top: [...fillers, "leaf", "transitive-root"], nodes: [...fillers.map((name) => ({ name, version: "1.0.0" })), { name: "leaf", version: "1.0.0" }, { name: "transitive-root", version: "1.0.0", deps: ["leaf"] }] };

  beforeAll(() => {
    for (const d of fillers) states.set(`${d}@1.0.0`, "clean");
  });

  test.each(PMS)("%s: nothing is dropped: no partial context, every package scanned in batches, and strict refuses leaf@1.0.0", async (pm) => {
    scanned.length = 0;
    scanSizes.length = 0;
    const r = await apmRun({ pm, pkg: { dependencies: deps }, before: null, after: graph, spec: "transitive-root", strict: true });

    expect(resolveAsked.get("transitive-root")?.get("installed") ?? null).toBeNull();
    expect(r.text).toContain("your package.json lists 501 dependencies, more than the 500 the registry's early check takes");
    expect(new Set(scanned).size).toBe(502);
    expect(Math.max(...scanSizes)).toBeLessThanOrEqual(200);
    expect(warned(r)).toEqual(["leaf@1.0.0"]);
    expectUntouched(r);
  });
});

describe("review of 2a098b1", () => {
  const bundle: Graph = { top: ["bundle-root"], nodes: [{ name: "bundle-root", version: "1.0.0", deps: ["inner"] }, { name: "inner", version: "9.9.9", bundled: true, key: { npm: "node_modules/bundle-root/node_modules/inner", bun: "bundle-root/inner" } }] };

  test("finding 2: a revoked bundled version refuses in every mode, with nothing installed (on 2a098b1: strict exited 0)", async () => {
    states.set("inner@9.9.9", "revoked");

    try {
      for (const strict of [true, false]) {
        const r = await apmRun({ pm: "npm", pkg: {}, before: null, after: bundle, spec: "bundle-root", strict });

        expect(r.json?.installed?.blocked.map((b) => `${b.name}@${b.version}`), r.text).toEqual(["inner@9.9.9"]);
        expectUntouched(r);
      }
    } finally {
      states.delete("inner@9.9.9");
    }
  });

  test("finding 8: pnpm leaves a bundled package out of its lockfile; inside a bundling parent it is checked for its state, not refused as extra", async () => {
    const after: Graph = { top: ["bundle-root"], nodes: [{ name: "bundle-root", version: "1.0.0" }] };

    const modules = [
      { path: "node_modules/bundle-root", name: "bundle-root", version: "1.0.0", raw: JSON.stringify({ name: "bundle-root", version: "1.0.0", bundleDependencies: ["inner"] }) },
      { path: "node_modules/bundle-root/node_modules/inner", name: "inner", version: "9.9.9" },
    ];

    const ok = await apmRun({ pm: "pnpm", pkg: {}, before: null, after, spec: "bundle-root", strict: true, scenario: { modules } });

    // on 2a098b1: refused, "node_modules holds a package the checked lockfile does not: inner@9.9.9"
    expect(ok.code, ok.text).toBe(0);
    expect(ok.text).toContain("1 package ships inside a checked package's tarball (inner@9.9.9)");
    states.set("inner@9.9.9", "revoked");

    try {
      const bad = await apmRun({ pm: "pnpm", pkg: {}, before: null, after, spec: "bundle-root", strict: false, scenario: { modules } });

      expect(bad.code, bad.text).toBe(1);
      expect(bad.text).toContain("refused: inner@9.9.9, bundled in bundle-root@1.0.0: inner@9.9.9 was revoked by its maintainer");
      expect(bad.json?.installed?.stage).toBe("verify");
      expect(bad.scripts).toEqual([]);
    } finally {
      states.delete("inner@9.9.9");
    }
  });

  test.each(PMS)("finding 4 (%s): a required package the install did not lay refuses before any script, in every mode (on 2a098b1: exit 0, stage done)", async (pm) => {
    const modules = modulesOf(pm, transitive).filter((m) => m.name !== "transitive-root");
    const r = await apmRun({ pm, pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: false, scenario: { modules } });

    expect(r.code, r.text).toBe(1);
    expect(r.text).toContain("transitive-root (transitive-root@1.0.0), which your project needs, is not installed");
    expect(r.json?.installed?.stage).toBe("verify");
    expect(r.scripts).toEqual([]);
  });

  test("finding 4: a package directory with no package.json warns, and strict refuses it", async () => {
    const modules = [...modulesOf("npm", transitive), { path: "node_modules/nameless", name: "nameless", version: "0.0.0", bare: true }];
    const strict = await apmRun({ pm: "npm", pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: true, args: ["--no-cooldown"], scenario: { modules } });

    // on 2a098b1: neither an inventory entry nor a warning, and strict exited 0
    expect(strict.text).toContain("not read: node_modules/nameless (no package.json)");
    expect(strict.code, strict.text).toBe(1);
    expect(strict.scripts).toEqual([]);
    const loose = await apmRun({ pm: "npm", pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: false, scenario: { modules } });

    expect(loose.text).toContain("not read: node_modules/nameless (no package.json)");
    expect(loose.code, loose.text).toBe(0);
  });

  test("findings 3 and 4: a package left in node_modules from before, outside the lockfile, warns, and strict refuses it", async () => {
    const prepare = (dir: string): void => {
      mkdirSync(join(dir, "node_modules", "old-thing"), { recursive: true });
      writeFileSync(join(dir, "node_modules", "old-thing", "package.json"), JSON.stringify({ name: "old-thing", version: "1.0.0" }));
    };

    const loose = await apmRun({ pm: "npm", pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: false, scenario: { keep: true }, prepare });

    expect(loose.code, loose.text).toBe(0);
    expect(loose.text).toContain("old-thing@1.0.0 (node_modules/old-thing) is in node_modules but not in the checked lockfile: it was there before, and install scripts could load it");
    const strict = await apmRun({ pm: "npm", pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: true, args: ["--no-cooldown"], scenario: { keep: true }, prepare });

    expect(strict.code, strict.text).toBe(1);
    expect(strict.text).toContain("refused: strict mode refuses a package in node_modules outside the checked lockfile");
    expect(strict.scripts).toEqual([]);
  });

  test("finding 7: bun runs a local dependency's install script, found where the lockfile resolves it (on 2a098b1: held forever)", async () => {
    const after: Graph = { top: ["local-leaf"], nodes: [{ name: "local-leaf", version: "1.0.0", resolved: "file:../local-leaf-1.0.0.tgz", script: true }] };
    const r = await apmRun({ pm: "bun", pkg: {}, before: null, after, spec: "local-leaf", strict: false });

    expect(r.code, r.text).toBe(0);
    expect(r.scripts, r.text).toEqual([`bun install --frozen-lockfile --registry=${server.url.href}`]);
  });

  test("finding 9: a nested copy with no integrity is unchecked though the hoisted copy has one: strict refuses it (on 2a098b1: exit 0)", async () => {
    states.set("host@1.0.0", "clean");
    const after: Graph = { top: ["a", "host"], nodes: [{ name: "a", version: "1.0.0" }, { name: "host", version: "1.0.0" }, { name: "a", version: "1.0.0", integrity: null, key: { npm: "node_modules/host/node_modules/a", bun: "host/a" } }] };
    const r = await apmRun({ pm: "npm", pkg: {}, before: null, after, spec: "host", strict: true });

    expect(r.text).toContain("a@1.0.0 not checked: the lockfile records no integrity for it");
    expectUntouched(r);
  });

  test("finding 12: a package manager that cannot start after the write still says how to put the project back (on 2a098b1: only ENOENT)", async () => {
    const breaks = join(root, "bin-breaks");
    const fake = join(import.meta.dir, "fixtures", "fake-pm.ts");

    mkdirSync(breaks, { recursive: true });
    // computes the lockfile, then loses its interpreter, so the install cannot even start
    writeFileSync(join(breaks, "npm"), `#!/bin/sh\n"${process.execPath}" "${fake}" npm "$@"\ncode=$?\nprintf '#!/nonexistent/interpreter\\n' > "$0"\nexit $code\n`, { mode: 0o755 });
    const r = await apmRun({ pm: "npm", pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: false, binFirst: breaks });

    expect(r.code, r.text).toBe(1);
    expect(r.text).toContain("apm add: installing the checked lockfile failed");
    expect(r.text).toContain("No install script ran.");
    expect(r.text).toContain("To put your project back as it was before apm add, run:");
    expect(r.json?.installed?.stage).toBe("install");
    expect(r.json?.installed?.recovery?.[0], r.text).toMatch(/^cp '.*apm-backup-.*' '.*package\.json'$/);
  });

  /** An npm workspace's lockfile: packages/app (at `memberVersion`) needs transitive-root. */
  const workspaceLock = (memberVersion: string): string =>
    JSON.stringify({
      name: "project",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "project", workspaces: ["packages/*"] },
        "node_modules/app": { resolved: "packages/app", link: true },
        "packages/app": { name: "app", version: memberVersion, dependencies: { "transitive-root": "1.0.0" } },
        "node_modules/transitive-root": { version: "1.0.0", resolved: `${server.url.href}transitive-root/-/transitive-root-1.0.0.tgz`, integrity: integrity({ name: "transitive-root", version: "1.0.0" }) },
      },
    });

  const inWorkspace = (memberVersion: string) =>
    apmRun({
      pm: "npm",
      pkg: { workspaces: ["packages/*"] },
      before: null,
      after: { top: ["transitive-root"], nodes: [{ name: "transitive-root", version: "1.0.0" }] },
      spec: "transitive-root",
      strict: true,
      lockText: workspaceLock(memberVersion),
      scenario: { lockAt: "../../package-lock.json" },
      prepare: (dir) => {
        mkdirSync(join(dir, "packages", "app"), { recursive: true });
        writeFileSync(join(dir, "packages", "app", "package.json"), JSON.stringify({ name: "app", version: "1.0.0" }));
      },
      cwd: (dir) => join(dir, "packages", "app"),
    });

  test("strict workspaces: a member bound to its folder, name and version is trusted, so a clean add passes (on 2a098b1: refused as unchecked)", async () => {
    const r = await inWorkspace("1.0.0");

    expect(r.code, r.text).toBe(0);
    expect(r.json?.installed?.warnings).toEqual([]);
    expect(r.text).toContain("app@1.0.0: your workspace's own member, matched to its folder, name and version, so not asked about");
  });

  test("strict workspaces: a lockfile naming the member at another version is not the member: strict refuses it", async () => {
    const r = await inWorkspace("6.6.6");

    expect(r.json?.installed?.warnings.map((w) => `${w.name}@${w.version}:${w.kind}`), r.text).toEqual(["app@6.6.6:unchecked"]);
    expectUntouched(r);
  });

  test("a workspace member's package.json edited while apm checked: refused, nothing written (the lockfile was computed from the old one)", async () => {
    const r = await apmRun({
      pm: "npm",
      pkg: { workspaces: ["packages/*"], dependencies: { existing: "1.0.0" } },
      before: existing,
      after: transitive,
      spec: "transitive-root",
      strict: false,
      scenario: { editsProject: "packages/other/package.json" },
      prepare: (dir) => {
        mkdirSync(join(dir, "packages", "other"), { recursive: true });
        writeFileSync(join(dir, "packages", "other", "package.json"), JSON.stringify({ name: "other", version: "1.0.0" }));
      },
    });

    // on 2a098b1: only the two files apm writes were compared, so the add went ahead
    expect(r.code, r.text).toBe(1);
    expect(r.text).toContain("packages/other/package.json changed while apm checked the add, so apm wrote nothing");
    expect(r.json?.installed?.touched).toBe(false);
    expect(r.scripts).toEqual([]);
  });
});

/** A stand-in at `dir/<pm>` that runs the shared one, then `after` (a script run with the same arguments) when it exits 0. */
function wrapped(input: { pm: Pm; name: string; after: string }): string {
  const dir = join(root, input.name);
  const helper = join(dir, "helper.ts");

  mkdirSync(dir);
  writeFileSync(
    helper,
    `import { chmodSync, mkdirSync, writeFileSync } from "node:fs";\nimport { join } from "node:path";\nconst args = process.argv.slice(2);\nconst p = Bun.spawn([${JSON.stringify(process.execPath)}, ${JSON.stringify(join(import.meta.dir, "fixtures", "fake-pm.ts"))}, ${JSON.stringify(input.pm)}, ...args], { stdout: "inherit", stderr: "inherit", env: process.env });\nconst code = await p.exited;\nif (code === 0) { ${input.after} }\nprocess.exit(code);\n`,
  );
  writeFileSync(join(dir, input.pm), `#!/bin/sh\nexec "${process.execPath}" "${helper}" "$@"\n`);
  chmodSync(join(dir, input.pm), 0o755);

  return dir;
}

describe("review of 2b7767f", () => {
  test("finding 1: strict refuses an external pnpm store whose a@1.0.0 loads leaf@9.9.9 where the lockfile locks 2.0.0 (on 2b7767f: exit 0, stage done)", async () => {
    const store = join(root, "external-store");
    const a = join(store, "a@1.0.0", "node_modules", "a");

    mkdirSync(join(a, "node_modules", "leaf"), { recursive: true });
    writeFileSync(join(a, "package.json"), JSON.stringify({ name: "a", version: "1.0.0" }));
    writeFileSync(join(a, "node_modules", "leaf", "package.json"), JSON.stringify({ name: "leaf", version: "9.9.9" }));
    const after: Graph = { top: ["a"], nodes: [{ name: "a", version: "1.0.0", deps: ["leaf@2.0.0"] }, { name: "leaf", version: "2.0.0" }] };

    const r = await apmRun({
      pm: "pnpm",
      pkg: {},
      before: null,
      after,
      spec: "a",
      strict: true,
      scenario: { modules: [], keep: true },
      prepare: (dir) => {
        mkdirSync(join(dir, "node_modules"));
        symlinkSync(store, join(dir, "node_modules", ".pnpm"));
        symlinkSync(".pnpm/a@1.0.0/node_modules/a", join(dir, "node_modules", "a"));
      },
    });

    expect(r.code, r.text).toBe(1);
    expect(r.json?.installed?.stage).toBe("verify");
    expect(r.text).toContain("resolves leaf to leaf@9.9.9");
    expect(r.scripts).toEqual([]);
  });

  describe("finding 3: a production install", () => {
    const tool = { name: "tool", version: "1.0.0" };
    const devonly = { name: "devonly", version: "1.0.0" };
    const tarball = (n: { name: string; version: string }): string => `${server.url.href}${n.name}/-/${n.name}-${n.version}.tgz`;

    // `script`: tool has an install script, so apm releases it after the check (a rebuild, or bun's second install)
    const locks: Record<Pm, (script?: boolean) => string> = {
      npm: (script) =>
        JSON.stringify({
          name: "project",
          lockfileVersion: 3,
          requires: true,
          packages: { "": { name: "project", dependencies: { tool: "1.0.0" }, devDependencies: { devonly: "1.0.0" } }, "node_modules/tool": { version: "1.0.0", resolved: tarball(tool), integrity: integrity(tool), hasInstallScript: script }, "node_modules/devonly": { version: "1.0.0", resolved: tarball(devonly), integrity: integrity(devonly), dev: true, hasInstallScript: script } },
        }),
      pnpm: (script) =>
        JSON.stringify({
          lockfileVersion: "9.0",
          importers: { ".": { dependencies: { tool: { specifier: "1.0.0", version: "1.0.0" } }, devDependencies: { devonly: { specifier: "1.0.0", version: "1.0.0" } } } },
          packages: { "tool@1.0.0": { resolution: { integrity: integrity(tool) }, requiresBuild: script }, "devonly@1.0.0": { resolution: { integrity: integrity(devonly) }, requiresBuild: script } },
          snapshots: { "tool@1.0.0": {}, "devonly@1.0.0": {} },
        }),
      bun: (script) => JSON.stringify({ lockfileVersion: 1, workspaces: { "": { name: "project", dependencies: { tool: "1.0.0" }, devDependencies: { devonly: "1.0.0" } } }, packages: { tool: ["tool@1.0.0", "", { hasInstallScript: script }, integrity(tool)], devonly: ["devonly@1.0.0", "", { hasInstallScript: script }, integrity(devonly)] } }),
    };

    // how each package manager is asked for a production install, and the flag apm hands its frozen install
    const asks: Record<Pm, { env?: Record<string, string>; args?: string[]; flag: string }> = {
      npm: { env: { npm_config_omit: "dev" }, flag: "--omit=dev" },
      pnpm: { env: { npm_config_production: "true" }, flag: "--prod" },
      bun: { args: ["--production"], flag: "--production" },
    };

    beforeAll(() => {
      states.set("devonly@1.0.0", "clean");
    });

    for (const pm of PMS) {
      test(`${pm}: the devDependency left out is what was asked, so the add passes and the install is told so (on 2b7767f: refused after the write)`, async () => {
        const ask = asks[pm];
        const r = await apmRun({ pm, pkg: { devDependencies: { devonly: "1.0.0" } }, before: null, after: { top: ["tool"], nodes: [tool] }, spec: "tool", strict: true, lockText: locks[pm](), env: ask.env, args: ask.args, scenario: { modules: [{ path: "node_modules/tool", ...tool }] } });

        expect(r.code, r.text).toBe(0);
        expect(r.json?.installed?.stage).toBe("done");
        // the frozen install, the one call that runs in the project itself
        expect(r.pmCalls.find((c) => c.cwd === r.dir)?.args, JSON.stringify(r.pmCalls)).toContain(ask.flag);
      });

      // review of efef668, finding 1: the release keeps the omission, so bun's second install does not put devonly back
      // asked by apm's own flag, which is in no environment the rebuild could inherit
      test(`${pm}: the command that runs tool's held install script is told the omission again (on efef668: neither bun's second install nor npm's and pnpm's rebuild was)`, async () => {
        const ask = asks[pm];
        const r = await apmRun({ pm, pkg: { devDependencies: { devonly: "1.0.0" } }, before: null, after: { top: ["tool"], nodes: [tool] }, spec: "tool", strict: true, lockText: locks[pm](true), args: [pm === "npm" ? "--omit=dev" : pm === "pnpm" ? "--prod" : "--production"], scenario: { modules: [{ path: "node_modules/tool", ...tool }] } });
        const inProject = r.pmCalls.filter((c) => c.cwd === r.dir);
        const release = inProject.at(-1);

        expect(r.code, r.text).toBe(0);
        expect(r.json?.installed?.stage).toBe("done");
        // the frozen install, then the release: npm and pnpm rebuild, bun installs again with scripts on
        expect(inProject.length, JSON.stringify(r.pmCalls)).toBe(2);
        expect(r.scripts.length, r.text).toBe(1);

        if (pm === "pnpm") {
          expect(release?.args[0]).toBe("rebuild");
          expect(release?.production, JSON.stringify(release)).toBe("true");
        } else {
          expect(release?.args[0]).toBe(pm === "npm" ? "rebuild" : "install");
          expect(release?.args, JSON.stringify(release)).toContain(ask.flag);
        }
      });

      test(`${pm}: without it, the same tree is missing the devDependency and is refused`, async () => {
        const r = await apmRun({ pm, pkg: { devDependencies: { devonly: "1.0.0" } }, before: null, after: { top: ["tool"], nodes: [tool] }, spec: "tool", strict: true, lockText: locks[pm](), scenario: { modules: [{ path: "node_modules/tool", ...tool }] } });

        expect(r.code, r.text).toBe(1);
        expect(r.text).toContain("devonly (devonly@1.0.0), which your project needs, is not installed");
      });
    }
  });

  test("review of efef668, finding 2: strict npm, devonly left out, leaf below it installed without its child: refused at verify, no rebuild (on efef668: exit 0, npm rebuild node_modules/leaf)", async () => {
    for (const id of ["prod@1.0.0", "devonly@1.0.0", "leaf@1.0.0", "child@1.0.0"]) states.set(id, "clean");
    const entry = (name: string, extra: { dev?: true; dependencies?: Record<string, string>; hasInstallScript?: true } = {}) => ({ version: "1.0.0", resolved: `${server.url.href}${name}/-/${name}-1.0.0.tgz`, integrity: integrity({ name, version: "1.0.0" }), ...extra });

    const lock = JSON.stringify({
      name: "project",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "project", dependencies: { prod: "1.0.0" }, devDependencies: { devonly: "1.0.0" } },
        "node_modules/prod": entry("prod"),
        "node_modules/devonly": entry("devonly", { dev: true, dependencies: { leaf: "1.0.0" } }),
        "node_modules/leaf": entry("leaf", { dev: true, dependencies: { child: "1.0.0" }, hasInstallScript: true }),
        "node_modules/child": entry("child", { dev: true }),
      },
    });

    const r = await apmRun({ pm: "npm", pkg: { devDependencies: { devonly: "1.0.0" } }, before: null, after: { top: [], nodes: [] }, spec: "prod", strict: true, lockText: lock, env: { npm_config_omit: "dev" }, scenario: { modules: [{ path: "node_modules/prod", name: "prod", version: "1.0.0" }, { path: "node_modules/leaf", name: "leaf", version: "1.0.0" }] } });

    expect(r.code, r.text).toBe(1);
    expect(r.json?.installed?.stage).toBe("verify");
    expect(r.text).toContain("child (child@1.0.0), which leaf@1.0.0 (node_modules/leaf) needs, is not installed");
    expect(r.pmCalls.filter((c) => c.args[0] === "rebuild"), JSON.stringify(r.pmCalls)).toEqual([]);
    expect(r.scripts).toEqual([]);
  });

  test("finding 5: pnpm leaves held the script of a version with an older copy, and says how to run it (on 2b7767f: pnpm rebuild leaf@1.0.0 ran both)", async () => {
    for (const id of ["new-root@1.0.0", "peer@1.0.0", "peer@2.0.0"]) states.set(id, "clean");
    const n = (name: string, version: string) => ({ name, version });

    const lock = JSON.stringify({
      lockfileVersion: "9.0",
      importers: { ".": { dependencies: { existing: { specifier: "1.0.0", version: "1.0.0" }, "new-root": { specifier: "1.0.0", version: "1.0.0" } } } },
      packages: Object.fromEntries([n("existing", "1.0.0"), n("new-root", "1.0.0"), n("leaf", "1.0.0"), n("peer", "1.0.0"), n("peer", "2.0.0")].map((x) => [`${x.name}@${x.version}`, { resolution: { integrity: integrity(x) }, requiresBuild: x.name === "leaf" ? true : undefined }])),
      snapshots: {
        "existing@1.0.0": { dependencies: { leaf: "1.0.0(peer@1.0.0)", peer: "1.0.0" } },
        "new-root@1.0.0": { dependencies: { leaf: "1.0.0(peer@2.0.0)", peer: "2.0.0" } },
        "leaf@1.0.0(peer@1.0.0)": { dependencies: { peer: "1.0.0" } },
        "leaf@1.0.0(peer@2.0.0)": { dependencies: { peer: "2.0.0" } },
        "peer@1.0.0": {},
        "peer@2.0.0": {},
      },
    });

    const old = [
      { path: "node_modules/existing", name: "existing", version: "1.0.0" },
      { path: "node_modules/existing/node_modules/leaf", name: "leaf", version: "1.0.0" },
      { path: "node_modules/existing/node_modules/peer", name: "peer", version: "1.0.0" },
    ];

    const fresh = [
      { path: "node_modules/new-root", name: "new-root", version: "1.0.0" },
      { path: "node_modules/new-root/node_modules/leaf", name: "leaf", version: "1.0.0" },
      { path: "node_modules/new-root/node_modules/peer", name: "peer", version: "2.0.0" },
    ];

    const r = await apmRun({
      pm: "pnpm",
      pkg: { dependencies: { existing: "1.0.0" } },
      before: null,
      after: { top: [], nodes: [] },
      spec: "new-root",
      strict: false,
      lockText: lock,
      scenario: { modules: [...old, ...fresh] },
      prepare: (dir) => {
        for (const m of old) {
          mkdirSync(join(dir, m.path), { recursive: true });
          writeFileSync(join(dir, m.path, "package.json"), JSON.stringify({ name: m.name, version: m.version }));
        }
      },
    });

    expect(r.code, r.text).toBe(0);
    expect(r.pmCalls.filter((c) => c.args[0] === "rebuild"), JSON.stringify(r.pmCalls)).toEqual([]);
    expect(r.scripts).toEqual([]);
    expect(r.text).toContain("pnpm cannot run leaf@1.0.0's install script for only the new copy; run `pnpm rebuild leaf@1.0.0` yourself if you want it");
  });

  test("finding 6: bun's second install bringing a new package is refused, with the recovery kept (on 2b7767f: exit 0, stage done, stowaway kept)", async () => {
    const binFirst = wrapped({ pm: "bun", name: "bun-stowaway", after: `if (args[0] === "install" && !args.includes("--ignore-scripts")) { const d = join(process.cwd(), "node_modules", "stowaway"); mkdirSync(d, { recursive: true }); writeFileSync(join(d, "package.json"), JSON.stringify({ name: "stowaway", version: "6.6.6" })); }` });
    const r = await apmRun({ pm: "bun", pkg: {}, before: null, after: { top: ["tool"], nodes: [{ name: "tool", version: "1.0.0", script: true }] }, spec: "tool", strict: true, binFirst });

    expect(r.code, r.text).toBe(1);
    expect(r.json?.installed?.stage).toBe("scripts");
    expect(r.json?.installed?.touched).toBe(true);
    expect(r.json?.installed?.recovery?.length ?? 0).toBeGreaterThan(0);
    expect(r.text).toContain("after bun installed packages again to run their scripts");
    expect(r.text).toContain("stowaway@6.6.6");
    expect(r.leftInTmp.some((x) => x.startsWith("apm-backup")), r.text).toBe(true);
  });

  test("finding 7: removing the copy failing after the write still reports the stage and the recovery (on 2b7767f: only an error, no recovery)", async () => {
    const binFirst = wrapped({ pm: "npm", name: "cleanup-fails", after: `if (args.includes("--package-lock-only")) { const d = join(process.cwd(), "locked"); mkdirSync(join(d, "inner"), { recursive: true }); chmodSync(d, 0o500); }` });
    const r = await apmRun({ pm: "npm", pkg: {}, before: null, after: { top: ["tool"], nodes: [{ name: "tool", version: "1.0.0" }] }, spec: "tool", strict: true, binFirst });

    for (const entry of r.leftInTmp) {
      const locked = join(r.dir, "..", "tmp", entry, "locked");

      if (existsSync(locked)) chmodSync(locked, 0o700);
    }

    expect(r.code, r.text).toBe(1);
    expect(r.json?.installed?.stage, r.text).toBe("install");
    expect(r.json?.installed?.touched).toBe(true);
    expect(r.json?.installed?.recovery?.length ?? 0).toBeGreaterThan(0);
    expect(r.text).toContain("apm could not remove its copy of your project");
    expect(r.text).toContain("No install script ran.");
    expect(r.scripts).toEqual([]);
    // the checked package.json was written, and the backup to put it back is kept
    expect(readFileSync(join(r.dir, "package.json"), "utf8")).toContain("tool");
    expect(r.leftInTmp.some((x) => x.startsWith("apm-backup")), r.text).toBe(true);
  });
});

// Review of a24c6aa, finding 5: a pnpm virtual store outside the project, behind a parent directory that denies
// search, read as no store at all: strict mode found nothing unreadable, finished and ran tool's script.
describe("review of a24c6aa", () => {
  test("finding 5: an external store behind a parent that denies search is unreadable, and strict refuses before any script (on a24c6aa: done, pnpm rebuild ran)", async () => {
    for (const denied of [false, true]) {
      let parent = "";

      const prepare = (dir: string): void => {
        parent = join(dir, "..", "private");
        const store = join(parent, "store");

        mkdirSync(store, { recursive: true });
        writeFileSync(join(store, "payload.js"), "unexplained");
        mkdirSync(join(dir, "node_modules", ".pnpm"), { recursive: true });
        writeFileSync(join(dir, "node_modules", ".pnpm", "lock.yaml"), "lockfileVersion: '9.0'\n");
        writeFileSync(join(dir, "node_modules", ".modules.yaml"), `virtualStoreDir: ${store}\n`);

        if (denied) chmodSync(parent, 0o000);
      };

      let r: Run;

      try {
        r = await apmRun({ pm: "pnpm", pkg: {}, before: null, after: { top: ["tool"], nodes: [{ name: "tool", version: "1.0.0", script: true }] }, spec: "tool", strict: true, scenario: { keep: true }, prepare });
      } finally {
        if (parent !== "") chmodSync(parent, 0o700);
      }

      // readable: the unknown payload.js is reported; denied: the store itself, at the path apm tried
      expect(r.code, r.text).toBe(1);
      expect(r.json?.installed?.stage, r.text).toBe("verify");
      expect(r.scripts, r.text).toEqual([]);
      expect(r.text).toContain(denied ? "pnpm's virtual store could not be inspected (EACCES)" : "payload.js");
    }
  });
});
