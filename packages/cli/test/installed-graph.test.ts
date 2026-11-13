// Review of 16fc8b5, findings 1 to 3: the registry's resolve walk predicts the install graph, and lockfile pins,
// nested peers, overrides, the project's own ranges and a 500-entry cut let npm, pnpm and bun install versions apm
// never checked. apm add now checks the graph the package manager wrote, every package at its exact version, before
// any install script runs: a revoked or yanked version refuses in every mode, and a warning refuses in strict mode.
//
// The registry is a stand-in that answers resolve with the reviewer's predicted graph (leaf@1.1.0, clean) and the scan
// with each exact version's state. The package managers are stand-ins (fixtures/fake-pm.ts) that write the graph the
// reviewer showed npm installing (offline Arborist, /tmp/apm-final-review.p6iv5s31/npm-tree.jsonl), in each one's
// lockfile format. Each test fails on 16fc8b5: there apm add read only integrity after the install.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";

type Pm = "npm" | "pnpm" | "bun";

const PMS: readonly Pm[] = ["npm", "pnpm", "bun"];

/** A package in a lockfile: its dependencies and peers name the version the graph holds of each. */
type Node = { name: string; version: string; deps?: string[]; peers?: string[]; script?: boolean };

/** A flat graph: one version of each name, `top` the project's direct dependencies. `bins`: binaries by package. */
type Graph = { top: string[]; nodes: Node[]; bins?: Record<string, string> };

type State = "clean" | "fresh" | "revoked" | "yanked";

const integrity = (n: { name: string; version: string }): string => `sha512-${n.name}-${n.version}`;

function versionOf(g: Graph, name: string): string {
  const n = g.nodes.find((x) => x.name === name);

  if (!n) throw new Error(`fixture graph has no ${name}`);

  return n.version;
}

/** A lockfile entry's dependency map: undefined (left out of the JSON) when the node has none. */
const rangesOf = (g: Graph, names: readonly string[] | undefined, range: (name: string) => string): Record<string, string> | undefined => (names === undefined ? undefined : Object.fromEntries(names.map((d) => [d, range(d)])));

/** The project's direct dependencies, at the versions the graph holds. */
const topOf = (g: Graph): Record<string, string> => Object.fromEntries(g.top.map((t) => [t, versionOf(g, t)]));

type NpmEntry = { version: string; resolved: string; integrity: string; dependencies?: Record<string, string> | undefined; peerDependencies?: Record<string, string> | undefined; hasInstallScript?: true | undefined };

function npmLock(g: Graph, registry: string): string {
  const entries = g.nodes.map((n): [string, NpmEntry] => [
    `node_modules/${n.name}`,
    {
      version: n.version,
      resolved: `${registry}${n.name}/-/${n.name}-${n.version}.tgz`,
      integrity: integrity(n),
      dependencies: rangesOf(g, n.deps, (d) => `^${versionOf(g, d)}`),
      peerDependencies: rangesOf(g, n.peers, () => ">=1.0.0"),
      hasInstallScript: n.script ? true : undefined,
    },
  ]);

  return JSON.stringify({ name: "project", lockfileVersion: 3, requires: true, packages: { "": { name: "project", dependencies: topOf(g) }, ...Object.fromEntries(entries) } });
}

function bunLock(g: Graph): string {
  const packages = Object.fromEntries(
    g.nodes.map((n) => {
      const meta = { dependencies: rangesOf(g, n.deps, (d) => `^${versionOf(g, d)}`), peerDependencies: rangesOf(g, n.peers, () => ">=1.0.0"), hasInstallScript: n.script ? true : undefined };

      return [n.name, [`${n.name}@${n.version}`, "", meta, integrity(n)]];
    }),
  );

  return JSON.stringify({ lockfileVersion: 1, workspaces: { "": { name: "project", dependencies: topOf(g) } }, packages });
}

/** pnpm's lockfile, written as JSON (which YAML reads): a peer is part of the snapshot key and its dependencies, as pnpm records it. */
function pnpmLock(g: Graph): string {
  const key = (n: Node): string => `${n.name}@${n.version}${n.peers ? n.peers.map((p) => `(${p}@${versionOf(g, p)})`).join("") : ""}`;
  const node = (name: string): Node => g.nodes.find((x) => x.name === name) ?? { name, version: "0.0.0" };
  const packages = Object.fromEntries(g.nodes.map((n) => [`${n.name}@${n.version}`, { resolution: { integrity: integrity(n) }, requiresBuild: n.script ? true : undefined }]));
  const snapshots = Object.fromEntries(g.nodes.map((n) => [key(n), { dependencies: Object.fromEntries([...(n.deps ?? []), ...(n.peers ?? [])].map((d) => [d, key(node(d)).slice(d.length + 1)])) }]));
  const dependencies = Object.fromEntries(g.top.map((t) => [t, { specifier: versionOf(g, t), version: key(node(t)).slice(t.length + 1) }]));

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

// ---------- the stand-in registry ----------
/** Every exact version the registry has, and its state. */
const states = new Map<string, State>();

/** What each resolve asked for, by package. */
const resolveAsked = new Map<string, URLSearchParams>();

/** Every name@version a scan was asked about, and each request's size. */
const scanned: string[] = [];
const scanSizes: number[] = [];

/** The walk's prediction: what resolve checked under each package. */
const predicted = new Map<string, { name: string; version: string }[]>();

const ScanBody = z.object({ packages: z.array(z.object({ name: z.string(), version: z.string(), integrity: z.string().optional() })) });

type Advisory = { package: string; version: string; level: "fatal" | "warn"; description: string; url: null };

type BlockedEntry = { package: string; version: string; kind: "revoked" | "yanked"; reason: string };

type Warning = { name: string; version: string; kind: "cooldown"; score: null; grade: null; text: string; reasons: string[]; url: string; via: string[] };

type Unchecked = { package: string; version: string; reason: string };

/** The scan's answer, as apm's registry gives it, for each exact version's state. */
function scanAnswer(packages: z.infer<typeof ScanBody>["packages"]) {
  const advisories: Advisory[] = [];
  const blocked: BlockedEntry[] = [];
  const warnings: Warning[] = [];
  const unchecked: Unchecked[] = [];

  for (const p of packages) {
    const id = `${p.name}@${p.version}`;
    const state = states.get(id);

    scanned.push(id);

    if (state === undefined) unchecked.push({ package: p.name, version: p.version, reason: "no such version" });
    else if (state === "revoked") {
      advisories.push({ package: p.name, version: p.version, level: "fatal", description: `${id} was revoked by its maintainer: compromised`, url: null });
      blocked.push({ package: p.name, version: p.version, kind: "revoked", reason: `${id} was revoked by its maintainer: compromised` });
    } else if (state === "yanked") blocked.push({ package: p.name, version: p.version, kind: "yanked", reason: `${id} was yanked by its maintainer` });
    else if (state === "fresh") {
      const text = "published 1h ago, inside the 24-hour cooldown";

      advisories.push({ package: p.name, version: p.version, level: "warn", description: text, url: null });
      warnings.push({ name: p.name, version: p.version, kind: "cooldown", score: null, grade: null, text, reasons: [], url: `https://web.test/package/${p.name}/v/${p.version}`, via: [] });
    }
  }

  return { advisories, blocked, warnings, unchecked, pending: [], unscorable: [], unavailable: [], strict: false };
}

let server: ReturnType<typeof Bun.serve>;
let root: string;
let bin: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "apm-installed-graph-"));
  bin = join(root, "bin");
  mkdirSync(bin);
  const fake = join(import.meta.dir, "fixtures", "fake-pm.ts");

  for (const pm of PMS) {
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

        resolveAsked.set(name, url.searchParams);

        return Response.json({ name, range: "latest", source: "local", version: "1.0.0", report: { score: 95, grade: "A", signals: [] }, skipped: [], tree: { unchecked: 0, uncheckedDeps: [], packages: predicted.get(name) ?? [], projectPeers: [] }, warnings: [] });
      }

      if (url.pathname === "/-/apm/v1/audit" && req.method === "POST") return Response.json({ advisories: {}, unavailable: [] });

      if (url.pathname === "/-/apm/v1/scan" && req.method === "POST") {
        const body = ScanBody.parse(await req.json());

        scanSizes.push(body.packages.length);

        return Response.json(scanAnswer(body.packages));
      }

      // a packument: the versions the registry serves (a revoked or yanked one is left out, as apm's registry does)
      const name = decodeURIComponent(url.pathname.slice(1));
      const versions = [...states].flatMap(([id, state]) => (id.startsWith(`${name}@`) && state !== "revoked" && state !== "yanked" ? [id.slice(name.length + 1)] : []));

      if (versions.length === 0) return Response.json({ error: "not found" }, { status: 404 });

      return Response.json({ name, versions: Object.fromEntries(versions.map((v) => [v, { name, version: v, dist: { integrity: integrity({ name, version: v }) } }])) });
    },
  });
});

afterAll(() => {
  server.stop(true);
  rmSync(root, { recursive: true, force: true });
});

const Json = z.object({
  ok: z.boolean(),
  installed: z.object({ checked: z.number(), refused: z.boolean(), blocked: z.array(z.object({ name: z.string(), version: z.string() })), warnings: z.array(z.object({ name: z.string(), version: z.string(), kind: z.string() })) }).nullish(),
});

type Run = { code: number; text: string; out: string; json: z.infer<typeof Json>; pmCalls: string[][]; scriptsRan: boolean; dir: string; lockBefore: string | null };

/**
 * A project with `pkg` (package.json fields), the lockfile of `before` (if any) and its node_modules, where the
 * package manager's add of `spec` writes the lockfile of `after`.
 */
/** The package.json fields a test project sets besides its name. */
type PackageFields = { dependencies?: Record<string, string>; overrides?: Record<string, string>; resolutions?: Record<string, string>; pnpm?: { overrides: Record<string, string> } };

async function add(input: { pm: Pm; name: string; pkg: PackageFields; before: Graph | null; after: Graph; spec: string; strict: boolean; cmd?: "add" | "x" | "audit"; args?: string[] }): Promise<Run> {
  const dir = join(root, `${input.name}-${input.pm}-${input.strict ? "strict" : "default"}`);
  const fake = join(dir, ".fake");

  mkdirSync(fake, { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "project", version: "1.0.0", private: true, ...input.pkg }));
  const modules = (g: Graph | null) => (g?.nodes ?? []).map((n) => ({ name: n.name, version: n.version, bin: g?.bins?.[n.name] }));
  const lockBefore = input.before ? lockText(input.pm, input.before, server.url.href) : null;

  if (lockBefore !== null) writeFileSync(join(dir, LOCKFILE[input.pm]), lockBefore);

  for (const m of modules(input.before)) {
    mkdirSync(join(dir, "node_modules", m.name), { recursive: true });
    writeFileSync(join(dir, "node_modules", m.name, "package.json"), JSON.stringify(m));
  }

  writeFileSync(join(fake, "before.json"), JSON.stringify({ modules: modules(input.before) }));
  writeFileSync(join(fake, "after.json"), JSON.stringify({ lockfile: LOCKFILE[input.pm], lock: lockText(input.pm, input.after, server.url.href), deps: { [input.spec]: "1.0.0" }, modules: modules(input.after) }));

  const cmd = input.cmd ?? "add";
  // apm x passes what follows the package to its binary, so its own flags go first
  const argv = cmd === "audit" ? ["audit", "--json"] : cmd === "x" ? ["x", "--pm", input.pm, ...(input.strict ? ["--strict"] : []), input.spec, ...(input.args ?? [])] : ["add", input.spec, "--pm", input.pm, "--json", ...(input.strict ? ["--strict"] : [])];

  const proc = Bun.spawn([process.execPath, join(import.meta.dir, "..", "src", "main.ts"), ...argv], {
    cwd: dir,
    env: { PATH: `${bin}:/usr/bin:/bin`, HOME: root, APM_REGISTRY: server.url.href, APM_FAKE_DIR: fake, NO_COLOR: "1", APM_PENDING_WAIT_MS: "0" },
    stdout: "pipe",
    stderr: "pipe",
  });

  const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
  const text = out + err;
  const pmCalls = existsSync(join(fake, "pm.log")) ? readFileSync(join(fake, "pm.log"), "utf8").trim().split("\n").map((l) => z.object({ pm: z.string(), args: z.array(z.string()) }).parse(JSON.parse(l)).args) : [];
  let json: z.infer<typeof Json> = { ok: code === 0, installed: null };

  try {
    if (cmd === "add") json = Json.parse(JSON.parse(out));
  } catch {
    throw new Error(`apm add printed no JSON result:\n${text}`);
  }

  return { code, text, out, json, pmCalls, scriptsRan: existsSync(join(fake, "scripts-ran")), dir, lockBefore };
}

/** What a refused add must leave: no install script run, package.json and the lockfile as they were, nothing new in node_modules. */
function expectRestored(r: Run, input: { pkg: PackageFields; added: string }): void {
  expect(r.scriptsRan, r.text).toBe(false);
  expect(JSON.parse(readFileSync(join(r.dir, "package.json"), "utf8")), r.text).toEqual({ name: "project", version: "1.0.0", private: true, ...input.pkg });
  const lock = join(r.dir, LOCKFILE[pmOf(r)]);

  if (r.lockBefore === null) expect(existsSync(lock), r.text).toBe(false);
  else expect(readFileSync(lock, "utf8"), r.text).toBe(r.lockBefore);
  expect(existsSync(join(r.dir, "node_modules", input.added)), r.text).toBe(false);
  expect(r.text).toContain("No install script ran");
}

/** The package manager a run's directory was made for. */
function pmOf(r: Run): Pm {
  return PMS.find((pm) => r.dir.includes(`-${pm}-`)) ?? "npm";
}

// ---------- the reviewer's graphs ----------
const existing: Graph = { top: ["existing"], nodes: [{ name: "existing", version: "1.0.0", deps: ["leaf"] }, { name: "leaf", version: "1.0.0", script: true }] };

/** existing@1.0.0 pins leaf@1.0.0; adding transitive-root (leaf ^1.0.0) reuses it. */
const transitive: Graph = { top: ["existing", "transitive-root"], nodes: [...existing.nodes, { name: "transitive-root", version: "1.0.0", deps: ["leaf"] }] };

/** peer-root -> plugin, whose peer leaf is met by the leaf@1.0.0 existing pins. */
const nestedPeer: Graph = { top: ["existing", "peer-root"], nodes: [...existing.nodes, { name: "peer-root", version: "1.0.0", deps: ["plugin"] }, { name: "plugin", version: "1.0.0", peers: ["leaf"] }] };

/** overrides: { leaf: "1.0.0" } makes override-root's leaf ^1.0.0 install 1.0.0. */
const overridden: Graph = { top: ["override-root"], nodes: [{ name: "override-root", version: "1.0.0", deps: ["leaf"] }, { name: "leaf", version: "1.0.0", script: true }] };

/** No lockfile: package.json pins otherhost 1.0.0, which unlocked-plugin's peer >=1.0.0 takes. */
const unlocked: Graph = { top: ["otherhost", "unlocked-plugin"], nodes: [{ name: "otherhost", version: "1.0.0", script: true }, { name: "unlocked-plugin", version: "1.0.0", peers: ["otherhost"] }] };

beforeAll(() => {
  for (const id of ["existing@1.0.0", "transitive-root@1.0.0", "peer-root@1.0.0", "plugin@1.0.0", "override-root@1.0.0", "unlocked-plugin@1.0.0", "leaf@1.1.0", "otherhost@2.0.0", "host-plugin@1.0.0"]) states.set(id, "clean");
  // the version npm installs is the fresh one; the walk predicted the clean one
  states.set("leaf@1.0.0", "fresh");
  states.set("otherhost@1.0.0", "fresh");
  states.set("host@1.0.0", "fresh");

  for (const root of ["transitive-root", "peer-root", "override-root"]) predicted.set(root, [{ name: "leaf", version: "1.1.0" }]);
  predicted.set("unlocked-plugin", [{ name: "otherhost", version: "2.0.0" }]);
});

describe.each(PMS)("apm add checks what %s installed", (pm) => {
  test("transitive lockfile pin: strict refuses the fresh leaf@1.0.0 npm reused, and puts the project back", async () => {
    const r = await add({ pm, name: "transitive", pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: true });

    // on 16fc8b5: exit 0, ok:true, no warning, the scripts ran
    expect(r.code, r.text).toBe(1);
    expect(r.json.ok).toBe(false);
    expect(r.json.installed?.warnings.map((w) => `${w.name}@${w.version}:${w.kind}`)).toEqual(["leaf@1.0.0:cooldown"]);
    expect(r.text).toContain("refused: strict mode refuses this warning (leaf@1.0.0)");
    expect(r.text).toContain(`the early check read 1.1.0, ${pm} installed 1.0.0`);
    expectRestored(r, { pkg: { dependencies: { existing: "1.0.0" } }, added: "transitive-root" });
    // the package manager's frozen install put node_modules back, with scripts off
    expect(r.pmCalls.at(-1)?.[0]).toBe("install");
    expect(r.pmCalls.at(-1)).toContain("--ignore-scripts");
    // what was installed before the add is still there
    expect(existsSync(join(r.dir, "node_modules", "leaf", "package.json"))).toBe(true);
  });

  test("transitive lockfile pin: the default mode warns about leaf@1.0.0, the version installed, then runs the scripts", async () => {
    const r = await add({ pm, name: "transitive", pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: false });

    expect(r.code, r.text).toBe(0);
    expect(r.text).toContain("WARNING leaf@1.0.0 published 1h ago, inside the 24-hour cooldown");
    expect(r.text).toContain("apm installed them anyway");
    expect(r.json.installed?.refused).toBe(false);
    expect(r.scriptsRan, r.text).toBe(true);
  });

  test("overrides: strict refuses the leaf@1.0.0 an override installs", async () => {
    const pkg = { dependencies: {}, overrides: { leaf: "1.0.0" }, pnpm: { overrides: { leaf: "1.0.0" } }, resolutions: { leaf: "1.0.0" } };
    const r = await add({ pm, name: "override", pkg, before: null, after: overridden, spec: "override-root", strict: true });

    expect(r.code, r.text).toBe(1);
    expect(r.json.installed?.warnings.map((w) => `${w.name}@${w.version}`)).toEqual(["leaf@1.0.0"]);
    expectRestored(r, { pkg, added: "override-root" });
  });

  test("nested peer: strict refuses the leaf@1.0.0 that meets plugin's peer below peer-root", async () => {
    const r = await add({ pm, name: "nested-peer", pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: nestedPeer, spec: "peer-root", strict: true });

    expect(r.code, r.text).toBe(1);
    expect(r.json.installed?.warnings.map((w) => `${w.name}@${w.version}`)).toEqual(["leaf@1.0.0"]);
    expectRestored(r, { pkg: { dependencies: { existing: "1.0.0" } }, added: "peer-root" });
  });

  test("no lockfile: the check uses the otherhost@1.0.0 package.json pins, not the newest in range", async () => {
    const pkg = { dependencies: { otherhost: "1.0.0" } };
    const r = await add({ pm, name: "unlocked", pkg, before: null, after: unlocked, spec: "unlocked-plugin", strict: true });

    expect(r.code, r.text).toBe(1);
    expect(r.json.installed?.warnings.map((w) => `${w.name}@${w.version}`)).toEqual(["otherhost@1.0.0"]);
    expect(scanned).toContain("otherhost@1.0.0");
    // no lockfile and no node_modules before: the add's are removed, and nothing is installed again
    expectRestored(r, { pkg, added: "unlocked-plugin" });
    expect(existsSync(join(r.dir, "node_modules")), r.text).toBe(false);
  });

  test("a revoked transitive version pinned by the lockfile is refused in the default mode, with no scripts run and the project restored", async () => {
    states.set("leaf@1.0.0", "revoked");

    try {
      const r = await add({ pm, name: "revoked", pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: false });

      // on 16fc8b5: refused as "does not serve" (the packument leaves it out), with the reason lost and leaf deleted
      expect(r.code, r.text).toBe(1);
      expect(r.json.installed?.blocked.map((b) => `${b.name}@${b.version}`)).toEqual(["leaf@1.0.0"]);
      expect(r.text).toContain("refused: leaf@1.0.0: leaf@1.0.0 was revoked by its maintainer: compromised");
      expectRestored(r, { pkg: { dependencies: { existing: "1.0.0" } }, added: "transitive-root" });
      expect(r.text).toContain("Your project installed leaf@1.0.0 before this add, and still does: run apm audit.");
    } finally {
      states.set("leaf@1.0.0", "fresh");
    }
  });

  test("a yanked transitive version is refused in the default mode too", async () => {
    states.set("leaf@1.0.0", "yanked");

    try {
      const r = await add({ pm, name: "yanked", pkg: { dependencies: { existing: "1.0.0" } }, before: existing, after: transitive, spec: "transitive-root", strict: false });

      expect(r.code, r.text).toBe(1);
      expect(r.text).toContain("refused: leaf@1.0.0: leaf@1.0.0 was yanked by its maintainer");
      expectRestored(r, { pkg: { dependencies: { existing: "1.0.0" } }, added: "transitive-root" });
    } finally {
      states.set("leaf@1.0.0", "fresh");
    }
  });
});

describe("501 dependencies", () => {
  /** dep0 to dep499, then host, the 501st, at a fresh 1.0.0 that host-plugin's peer takes. */
  const fillers = Array.from({ length: 500 }, (_, i) => `dep${i}`);
  const deps = Object.fromEntries([...fillers.map((d) => [d, "1.0.0"]), ["host", "1.0.0"]]);
  const graph: Graph = { top: [...fillers, "host", "host-plugin"], nodes: [...fillers.map((name) => ({ name, version: "1.0.0" })), { name: "host", version: "1.0.0" }, { name: "host-plugin", version: "1.0.0", peers: ["host"] }] };

  beforeAll(() => {
    for (const d of fillers) states.set(`${d}@1.0.0`, "clean");
  });

  test.each(PMS)("%s: nothing is dropped: no partial context, every installed package scanned, and strict refuses host@1.0.0", async (pm) => {
    scanned.length = 0;
    scanSizes.length = 0;
    const r = await add({ pm, name: "overflow", pkg: { dependencies: deps }, before: null, after: graph, spec: "host-plugin", strict: true });

    // on 16fc8b5: installed held dep0..dep499 and left host out, and the add passed
    expect(resolveAsked.get("host-plugin")?.get("installed") ?? null).toBeNull();
    expect(r.text).toContain("your package.json lists 501 dependencies, more than the 500 the registry's early check takes");
    expect(new Set(scanned).size).toBe(502);
    expect(Math.max(...scanSizes)).toBeLessThanOrEqual(200);
    expect(r.code, r.text).toBe(1);
    expect(r.json.installed?.warnings.map((w) => `${w.name}@${w.version}`)).toEqual(["host@1.0.0"]);
  });
});

describe.each(PMS)("apm x checks what %s installed before anything runs", (pm) => {
  const xGraph: Graph = { ...transitive, top: ["transitive-root"], nodes: transitive.nodes.filter((n) => n.name !== "existing"), bins: { "transitive-root": "hello from transitive-root" } };

  test("strict: the fresh leaf@1.0.0 the install brought in refuses, and neither a script nor the binary runs", async () => {
    const r = await add({ pm, name: "x", pkg: {}, before: null, after: xGraph, spec: "transitive-root", strict: true, cmd: "x" });

    // on 16fc8b5: the package manager's own runner was started at once
    expect(r.code, r.text).toBe(1);
    expect(r.text).toContain(`apm: checked the 2 packages apm x installed for transitive-root at the versions ${pm} installed`);
    expect(r.text).toContain("refused: strict mode refuses this warning (leaf@1.0.0)");
    expect(r.text).toContain("apm ran nothing");
    expect(r.text).not.toContain("hello from transitive-root");
    expect(r.scriptsRan, r.text).toBe(false);
  });

  test("default: it warns about leaf@1.0.0, the version installed, then runs the install scripts and the binary", async () => {
    const r = await add({ pm, name: "x", pkg: {}, before: null, after: xGraph, spec: "transitive-root", strict: false, cmd: "x", args: ["world", "--loud"] });

    expect(r.code, r.text).toBe(0);
    expect(r.text).toContain("WARNING leaf@1.0.0 published 1h ago");
    expect(r.out).toContain("hello from transitive-root world --loud");
    expect(r.scriptsRan, r.text).toBe(true);
  });
});

describe("apm audit uses the same check", () => {
  test("a revoked version is a critical finding and a warning is a warning, each at the version installed", async () => {
    states.set("leaf@1.0.0", "revoked");

    try {
      const r = await add({ pm: "npm", name: "audit", pkg: {}, before: { top: ["existing", "otherhost"], nodes: [...existing.nodes, { name: "otherhost", version: "1.0.0" }] }, after: transitive, spec: "", strict: false, cmd: "audit" });
      const Audit = z.object({ ok: z.boolean(), findings: z.array(z.object({ id: z.string(), severity: z.string() })) });
      const body = Audit.parse(JSON.parse(r.out));

      expect(r.code, r.text).toBe(1);
      // on 16fc8b5 the cooldown warning was a "critical" finding
      expect(body.findings.map((f) => `${f.id}:${f.severity}`).toSorted()).toEqual(["leaf@1.0.0:critical", "otherhost@1.0.0:warning"]);
    } finally {
      states.set("leaf@1.0.0", "fresh");
    }
  });
});
