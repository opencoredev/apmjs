// What the resolve walk and the scan decide about a tree (review of 2fbf383, the walk-policy findings). Each package
// lives in this registry's database, with as many versions as a case needs, each with its own age, state and manifest
// (dependencies, optional ones with os and cpu, peers), so every case is local and exact.
//
// 1. A dependency or root inside the 24-hour cooldown was refused in every mode: `apm add next` failed for a day
//    whenever any package in its tree published. It is now a warning, and the version checked is the one installed.
// 2. Required peers were never walked: a root with one answered 200 with nothing checked and nothing unchecked.
// 4. The root's candidates stopped at 20: 20 yanked releases above an installable one answered 422.
// 5. Optional dependencies were walked for every platform: a win32 binary could refuse a Linux install.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { Effect, Layer, Option } from "effect";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Client } from "pg";
import { z } from "zod";
import { analyze, type Analysis as Scored } from "@apm/core";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis } from "../src/analysis.ts";
import { MAX_ROOT_CANDIDATES, resolveResponse, scanResponse } from "../src/apm.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { RegistryConfig } from "../src/config.ts";
import { Store } from "../src/db.ts";
import { MemoryPool, RequestMemory } from "../src/memory.ts";

const POOL = new MemoryPool();
const NOW = Date.parse("2026-11-13T00:00:00Z");
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const encoder = new TextEncoder();

/** One version of a seeded package: its manifest's extra fields, its age, and its state. */
type V = {
  version: string;
  ageMs?: number;
  status?: "active" | "yanked" | "revoke-pending" | "revoked";
  statusReason?: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  peerDependenciesMeta?: Record<string, { optional: boolean }>;
  os?: string[];
  cpu?: string[];
  /** Filler in the manifest, to make a row big. */
  pad?: string;
};

type P = { name: string; latest?: string; versions: V[] };

/**
 * Whole version rows a resolve read, what its pool had charged as each versionsWithin read began, and that pool.
 * `afterSizes`: run once, right after the next size read answers (a row that changes between its measuring and its read).
 */
type WholeReads = { rows: number; chargedAtRead: number[]; pool: MemoryPool | null; afterSizes: (() => Promise<void>) | null };

/** A version published ten days ago with no dependencies. */
const v = (version: string, extra: Omit<V, "version"> = {}): V => ({ version, ...extra });

/** A one-version package. */
const pkg = (name: string, extra: Omit<V, "version"> = {}): P => ({ name, versions: [v("1.0.0", extra)] });

/** A small clean package's stored analysis. */
function analysisOf(name: string, version: string): Scored {
  const manifest = { name, version, main: "index.js", license: "MIT" };
  const file = (path: string, text: string) => ({ path, size: text.length, mode: 0o644, data: encoder.encode(text) });

  return analyze({ name, manifest, files: [file("package.json", JSON.stringify(manifest)), file("index.js", "module.exports = 1;\n")], publisher: "u", previousPublishers: [] });
}

async function seed(url: string, packages: readonly P[]): Promise<void> {
  const c = new Client({ connectionString: url });
  await c.connect();

  try {
    await c.query(`INSERT INTO users (name, password_hash, email, created_at) VALUES ('u', 'x', 'u@example.test', 0)`);

    for (const p of packages) {
      const latest = p.latest ?? p.versions.at(-1)?.version ?? "1.0.0";
      await c.query(`INSERT INTO packages (name, created_at, modified_at, dist_tags) VALUES ($1, 0, 0, $2::jsonb)`, [p.name, JSON.stringify({ latest })]);

      for (const x of p.versions) {
        const { version, ageMs, status, statusReason, ...fields } = x;
        const manifest = { name: p.name, version, main: "index.js", license: "MIT", ...fields };
        await c.query(
          `INSERT INTO versions (package, version, manifest, shasum, integrity, size, tarball_key, published_at, published_by, score, status, status_reason)
           VALUES ($1, $2, $3::jsonb, $4, 'sha1-x', 10, 'sha512/x', $5, 'u', $6::jsonb, $7, $8)`,
          [p.name, version, JSON.stringify(manifest), "0".repeat(40), NOW - (ageMs ?? 10 * DAY), JSON.stringify(analysisOf(p.name, version)), status ?? "active", statusReason ?? null],
        );
      }
    }
  } finally {
    await c.end();
  }
}

const noBlobs = Layer.succeed(
  Blobs,
  Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }),
);

/** One case the reviewer ran through npm's arborist: each node it installs, and where each of its peer edges goes. */
const NpmCase = z.object({ case: z.string(), nodes: z.array(z.object({ path: z.string(), name: z.string(), version: z.string(), peers: z.record(z.string(), z.string()) })) });

const Warning = z.object({ name: z.string(), version: z.string(), kind: z.string(), text: z.string(), via: z.array(z.string()) });

const ResolveBody = z.object({
  version: z.string().nullish(),
  error: z.string().optional(),
  skipped: z.array(z.object({ version: z.string(), reason: z.string() })).default([]),
  warnings: z.array(Warning).default([]),
  tree: z
    .object({
      blocks: z.array(z.object({ name: z.string(), version: z.string(), reason: z.string() })).default([]),
      unchecked: z.number(),
      uncheckedDeps: z.array(z.object({ dependency: z.string(), reason: z.string() })),
      packages: z.array(z.object({ name: z.string(), version: z.string() })),
      skippedForPlatform: z.array(z.object({ dependency: z.string(), version: z.string(), reason: z.string() })).default([]),
    })
    .optional(),
});

const ScanBody = z.object({
  advisories: z.array(z.object({ package: z.string(), version: z.string(), level: z.string(), description: z.string() })),
  blocked: z.array(z.object({ package: z.string(), version: z.string(), kind: z.string(), reason: z.string() })).default([]),
  warnings: z.array(Warning),
  unchecked: z.array(z.object({ package: z.string(), version: z.string(), reason: z.string() })),
});

describe("the resolve walk and the scan, for the tree that installs", () => {
  let db: Awaited<ReturnType<typeof freshDatabase>>;

  // every package of every case, seeded once: names keep the cases apart
  const packages: P[] = [
    // 1. the cooldown
    pkg("fresh-dep", { ageMs: 2 * HOUR }),
    pkg("cool-app", { dependencies: { "fresh-dep": "^1.0.0" } }),
    { name: "fresh-root", versions: [v("1.0.0"), v("1.1.0", { ageMs: 5 * HOUR })] },
    { name: "only-fresh", versions: [v("1.0.0", { ageMs: 30 * 60_000 })] },
    // 2. peers
    pkg("peer-a"),
    pkg("needs-peer", { peerDependencies: { "peer-a": "^1.0.0" } }),
    pkg("optional-peer", { peerDependencies: { "peer-a": "^1.0.0" }, peerDependenciesMeta: { "peer-a": { optional: true } } }),
    { name: "react", versions: [v("1.0.0"), v("2.0.0")] },
    pkg("plugin-1", { peerDependencies: { react: "^1.0.0" } }),
    pkg("plugin-2", { peerDependencies: { react: "^2.0.0" } }),
    pkg("met-by-sibling", { dependencies: { react: "^1.0.0", "plugin-1": "^1.0.0" } }),
    pkg("unmet-by-sibling", { dependencies: { react: "^1.0.0", "plugin-2": "^1.0.0" } }),
    pkg("react-dom", { peerDependencies: { react: "^2.0.0" } }),
    pkg("met-by-top-peer", { peerDependencies: { react: "^2.0.0", "react-dom": "^1.0.0" } }),
    pkg("git-peer", { peerDependencies: { thing: "github:someone/thing" } }),
    pkg("missing-peer", { peerDependencies: { "no-such-peer": "^1.0.0" } }),
    pkg("git-dep", { dependencies: { thing: "github:someone/thing" } }),
    // review of 93274c8, finding 3: an ancestor installed under an alias does not meet a peer of its real name
    // (tests/fixtures/npm-peers.jsonl, case "alias": the same packages, installed by npm 9.2.0's arborist)
    pkg("root", { dependencies: { alias: "npm:foo@1.0.0" } }),
    { name: "foo", versions: [v("1.0.0", { dependencies: { plugin: "1.0.0" } }), v("1.1.0", { ageMs: HOUR })] },
    pkg("plugin", { peerDependencies: { foo: "^1.0.0" } }),
    pkg("project-plugin", { peerDependencies: { "host-p": "^1.0.0" } }),
    // review of 1924692, finding 1: the project pins host-p@1.0.0, inside the cooldown, and the newest in range is 1.1.0
    { name: "host-p", versions: [v("1.0.0", { ageMs: HOUR }), v("1.0.1", { status: "revoked", statusReason: "malware" }), v("1.1.0")] },
    // 4. the root's candidates
    { name: "many-yanked", versions: [v("1.0.0"), ...Array.from({ length: 25 }, (_, i) => v(`2.0.${i}`, { status: "yanked", statusReason: "bad build" }))] },
    { name: "many-fresh", versions: [v("1.0.0"), ...Array.from({ length: 45 }, (_, i) => v(`2.0.${i}`, { ageMs: HOUR }))] },
    { name: "all-fresh", versions: Array.from({ length: MAX_ROOT_CANDIDATES + 30 }, (_, i) => v(`3.0.${i}`, { ageMs: HOUR })) },
    // review of 16fc8b5, findings 4 and 5: a local dependency with five big rows, and a root whose row grows
    { name: "big-dep", versions: ["1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"].map((x) => v(x, { pad: "x".repeat(30_000) })) },
    pkg("big-parent", { dependencies: { "big-dep": "^1.0.0" } }),
    pkg("grow-root"),
    // 5. platforms
    pkg("win-helper"),
    pkg("bin-win", { os: ["win32"], cpu: ["x64"], ageMs: HOUR, dependencies: { "win-helper": "^1.0.0", "no-such-win-dep": "^1.0.0" } }),
    pkg("bin-linux", { os: ["linux"], cpu: ["x64"] }),
    pkg("bin-mac", { os: ["darwin"], cpu: ["arm64"] }),
    pkg("bin-not-win", { os: ["!win32"] }),
    pkg("native-app", { optionalDependencies: { "bin-win": "^1.0.0", "bin-linux": "^1.0.0", "bin-mac": "^1.0.0", "bin-not-win": "^1.0.0" } }),
    pkg("needs-win", { dependencies: { "bin-win": "^1.0.0" } }),
    pkg("bin-revoked", { os: ["win32"], status: "revoked", statusReason: "malware" }),
    pkg("revoked-optional-app", { optionalDependencies: { "bin-revoked": "^1.0.0" } }),
    pkg("revoked-required-app", { dependencies: { "bin-revoked": "^1.0.0" } }),
    // review of 93274c8, finding 1: a parent's optional ask for an older version must not hide the one installed
    pkg("scan-parent", { optionalDependencies: { "scan-bin": "1.0.0" } }),
    { name: "scan-bin", versions: [v("1.0.0", { os: ["win32"] }), v("2.0.0", { os: ["win32"], status: "revoked", statusReason: "malware" })] },
  ];

  beforeAll(async () => {
    db = await freshDatabase();
    await seed(db.url, packages);
  });

  afterAll(async () => {
    await db.drop();
  });

  const layers = () => {
    const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: null, legacyAuth: false, namePolicy: "open", admins: [] } as const;

    return Layer.mergeAll(Store.postgres(db.url), Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs, Layer.succeed(RegistryConfig, settings), RequestMemory.layer(POOL));
  };

  /**
   * Whole version rows (manifest and score) the store has read since the counter was reset, by any read, and what the
   * request's pool had charged when each versionsWithin read began.
   */
  const whole: WholeReads = { rows: 0, chargedAtRead: [], pool: null, afterSizes: null };

  /** The real store, counting every whole version row it reads. */
  const countingStore = () =>
    Layer.provideMerge(
      Layer.effect(
        Store,
        Effect.gen(function* () {
          const real = yield* Store;

          const counted = <A extends readonly unknown[]>(rows: A): A => {
            whole.rows += rows.length;

            return rows;
          };

          return Store.of({
            ...real,
            listVersions: (n) => Effect.map(real.listVersions(n), counted),
            getVersion: (n, v) => Effect.map(real.getVersion(n, v), (row) => (row === null ? null : (counted([row])[0] ?? null))),
            versionSizes: (vs) =>
              Effect.flatMap(real.versionSizes(vs), (sizes) =>
                Effect.promise(async () => {
                  const hook = whole.afterSizes;

                  whole.afterSizes = null;

                  if (hook) await hook();

                  return sizes;
                }),
              ),
            versionsWithin: (sizes) =>
              Effect.suspend(() => {
                whole.chargedAtRead.push(whole.pool?.charged ?? -1);

                return Effect.map(real.versionsWithin(sizes), counted);
              }),
            activeVersionsOf: (ns) => Effect.map(real.activeVersionsOf(ns), counted),
          });
        }),
      ),
      Store.postgres(db.url),
    );

  const resolve = async (name: string, params: Record<string, string> = {}, pool: MemoryPool = POOL) => {
    whole.pool = pool;
    const u = new URL(`http://registry.test/-/apm/v1/resolve?${new URLSearchParams({ name, range: "latest", ...params })}`);
    const program = Effect.flatMap(resolveResponse(u), (res) => Effect.promise(async () => ({ status: res.status, raw: await res.text() })));
    const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: null, legacyAuth: false, namePolicy: "open", admins: [] } as const;
    const provided = Layer.mergeAll(countingStore(), Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs, Layer.succeed(RegistryConfig, settings), RequestMemory.layer(pool));
    const out = await Effect.runPromise(program.pipe(Effect.provide(provided), Effect.scoped));

    return { status: out.status, body: ResolveBody.parse(JSON.parse(out.raw)), raw: out.raw };
  };

  const scan = async (body: { packages: { name: string; version: string; integrity?: string; bundled?: boolean }[]; strict?: boolean; os?: string; cpu?: string; cooldown?: string; floor?: number }) => {
    const req = new Request("http://registry.test/-/apm/v1/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const program = Effect.flatMap(scanResponse(req, { kind: "anon" }), (res) => Effect.promise(async () => ({ status: res.status, text: await res.text() })));
    const out = await Effect.runPromise(program.pipe(Effect.provide(layers()), Effect.scoped));

    return { status: out.status, body: out.status === 200 ? ScanBody.parse(JSON.parse(out.text)) : null, raw: out.text };
  };

  const names = (r: Awaited<ReturnType<typeof resolve>>) => (r.body.tree?.packages ?? []).map((p) => `${p.name}@${p.version}`).toSorted();

  describe("1. the cooldown warns, and strict mode and the ~safe view refuse", () => {
    test("a dependency published 2 hours ago installs with a warning, and is the version checked", async () => {
      const r = await resolve("cool-app");

      // on 2fbf383: 422, "would install dangerous dependencies: fresh-dep@1.0.0 published 2h ago (cooldown 24h)"
      expect(r.status).toBe(200);
      expect(r.body.version).toBe("1.0.0");
      expect(names(r)).toEqual(["fresh-dep@1.0.0"]);
      expect(r.body.tree?.blocks).toEqual([]);
      expect(r.body.warnings).toEqual([{ name: "fresh-dep", version: "1.0.0", kind: "cooldown", text: "published 2 hours ago, inside apm's 24-hour cooldown", via: ["cool-app@1.0.0"] }]);
    });

    test("strict mode refuses it, listing it as the block", async () => {
      const r = await resolve("cool-app", { strict: "1" });

      expect(r.status).toBe(422);
      expect(r.body.tree?.blocks.map((b) => [b.name, b.reason])).toEqual([["fresh-dep", "published 2 hours ago, inside apm's 24-hour cooldown"]]);
    });

    test("a root's newest version inside the cooldown is the one picked, with a warning; strict mode falls back", async () => {
      const r = await resolve("fresh-root");

      // on 2fbf383: 1.0.0, the newest version past the cooldown, which npm would not install for ^1 or latest
      expect(r.status).toBe(200);
      expect(r.body.version).toBe("1.1.0");
      expect(r.body.skipped).toEqual([]);
      expect(r.body.warnings.map((w) => [w.kind, w.text, w.via])).toEqual([["cooldown", "published 5 hours ago, inside apm's 24-hour cooldown", []]]);

      const strict = await resolve("fresh-root", { strict: "1" });
      expect(strict.body.version).toBe("1.0.0");
      expect(strict.body.skipped.map((s) => s.reason)).toEqual(["published 5h ago (cooldown 24h)"]);
    });

    test("a package with only a fresh version installs with a warning; --no-cooldown sends no warning", async () => {
      const r = await resolve("only-fresh");

      // on 2fbf383: 422, nothing in range passes
      expect(r.status).toBe(200);
      expect(r.body.warnings[0]?.text).toBe("published under an hour ago, inside apm's 24-hour cooldown");
      expect((await resolve("only-fresh", { cooldown: "0" })).body.warnings).toEqual([]);
      expect((await resolve("only-fresh", { strict: "1" })).status).toBe(422);
    });
  });

  describe("2. required peers are walked unless the tree already has them", () => {
    test("a root's required peer is checked", async () => {
      const r = await resolve("needs-peer");

      // on 2fbf383: 200 with nothing checked, nothing unchecked and no warning
      expect(r.status).toBe(200);
      expect(names(r)).toEqual(["peer-a@1.0.0"]);
      expect(r.body.tree?.unchecked).toBe(0);
    });

    test("an optional peer is not walked", async () => {
      expect(names(await resolve("optional-peer"))).toEqual([]);
    });

    test("a peer met by a sibling already in the tree is not walked again", async () => {
      expect(names(await resolve("met-by-sibling"))).toEqual(["plugin-1@1.0.0", "react@1.0.0"]);
    });

    test("a peer the sibling does not meet is walked at the version its range picks", async () => {
      expect(names(await resolve("unmet-by-sibling"))).toEqual(["plugin-2@1.0.0", "react@1.0.0", "react@2.0.0"]);
    });

    test("a peer met by another peer the walk added beside it is not walked twice", async () => {
      const r = await resolve("met-by-top-peer");

      expect(names(r)).toEqual(["react-dom@1.0.0", "react@2.0.0"]);
      expect(r.body.tree?.unchecked).toBe(0);
    });

    test("a peer the walk cannot pick a version for is listed as unchecked with its reason, never silent", async () => {
      const git = await resolve("git-peer");

      expect(git.body.tree?.unchecked).toBe(1);
      expect(git.body.tree?.uncheckedDeps[0]?.reason).toStartWith("peer dependency: git dependency");
      const missing = await resolve("missing-peer");

      expect(missing.body.tree?.unchecked).toBe(1);
      expect(missing.body.tree?.uncheckedDeps[0]?.dependency).toBe("no-such-peer@^1.0.0");
      expect(missing.body.tree?.uncheckedDeps[0]?.reason).toStartWith("peer dependency: ");
    });

    // review of 93274c8, finding 3: npm installs plugin's peer foo@1.1.0 beside the alias. The reviewer's npm 9.2.0 run
    // (arborist's ideal tree) put foo@1.0.0 at node_modules/alias and foo@1.1.0 at node_modules/foo, and plugin's peer
    // edge goes to 1.1.0
    test("an ancestor installed under an alias does not meet a peer named for its real package", async () => {
      const r = await resolve("root");

      // on 93274c8: 200 with foo@1.0.0 and plugin@1.0.0 only; foo@1.1.0, the version npm installs, unchecked
      expect(names(r)).toEqual(["foo@1.0.0", "foo@1.1.0", "plugin@1.0.0"]);
      expect(r.body.warnings.map((w) => [w.kind, `${w.name}@${w.version}`])).toEqual([["cooldown", "foo@1.1.0"]]);
      // every peer npm resolved goes to a version the walk checked
      const npm = NpmCase.parse(JSON.parse(readFileSync(join(import.meta.dir, "..", "..", "..", "tests", "fixtures", "npm-peers.jsonl"), "utf8").split("\n")[0] ?? ""));
      const peerTargets = npm.nodes.flatMap((n) => Object.entries(n.peers).map(([peer, version]) => `${peer}@${version}`));

      expect(npm.case).toBe("alias");
      expect(peerTargets).toEqual(["foo@1.1.0"]);

      for (const t of peerTargets) expect(names(r)).toContain(t);

      const strict = await resolve("root", { strict: "1" });

      expect(strict.status).toBe(422);
      expect(strict.body.tree?.blocks.map((b) => `${b.name}@${b.version}`)).toEqual(["foo@1.1.0"]);
    });

    const Peers = z.object({ tree: z.object({ projectPeers: z.array(z.object({ dependency: z.string(), via: z.array(z.string()), kind: z.string(), version: z.string().nullable() })) }) });

    test("a peer the project lists with no lockfile entry is checked at the newest in range, and named as the project's", async () => {
      const told = await resolve("project-plugin", { installed: "host-p,left-pad" });

      expect(Peers.parse(JSON.parse(told.raw)).tree.projectPeers).toEqual([{ dependency: "host-p@^1.0.0", via: ["project-plugin@1.0.0"], kind: "newest", version: "1.1.0" }]);
      expect(names(told)).toEqual(["host-p@1.1.0"]);
      expect(Peers.parse(JSON.parse((await resolve("project-plugin")).raw)).tree.projectPeers).toEqual([]);
      expect((await resolve("project-plugin", { installed: "Not A Name" })).status).toBe(400);
      expect((await resolve("project-plugin", { installed: "host-p@^1.0.0" })).status).toBe(400);
      expect((await resolve("project-plugin", { installed: Array.from({ length: 501 }, (_, i) => `p${i}`).join(",") })).status).toBe(400);
    });

    // review of 1924692, finding 1: npm uses the project's pinned host@1.0.0, and the walk checked host@1.1.0, so strict
    // mode installed a version inside the cooldown with no warning
    test("a peer the project's lockfile pins is checked at that version: a warning, and strict mode refuses it", async () => {
      const r = await resolve("project-plugin", { installed: "host-p@1.0.0" });

      // on 1924692: host-p@1.1.0 checked, no warning
      expect(r.status).toBe(200);
      expect(names(r)).toEqual(["host-p@1.0.0"]);
      expect(r.body.warnings.map((w) => [w.kind, `${w.name}@${w.version}`])).toEqual([["cooldown", "host-p@1.0.0"]]);
      expect(Peers.parse(JSON.parse(r.raw)).tree.projectPeers).toEqual([{ dependency: "host-p@^1.0.0", via: ["project-plugin@1.0.0"], kind: "lockfile", version: "1.0.0" }]);

      const strict = await resolve("project-plugin", { installed: "host-p@1.0.0", strict: "1" });

      // on 1924692: 200
      expect(strict.status).toBe(422);
      expect(strict.body.tree?.blocks.map((b) => `${b.name}@${b.version}`)).toEqual(["host-p@1.0.0"]);
    });

    test("a pinned version that was revoked is refused in every mode", async () => {
      const r = await resolve("project-plugin", { installed: "host-p@1.0.1" });

      // on 1924692: 200, host-p@1.1.0 checked
      expect(r.status).toBe(422);
      expect(r.body.tree?.blocks.map((b) => [`${b.name}@${b.version}`, b.reason])).toEqual([["host-p@1.0.1", "revoked by its owner"]]);
    });

    test("a peer whose project version apm cannot tell is unchecked: a warning, and strict mode refuses it", async () => {
      const r = await resolve("project-plugin", { installed: "host-p@?" });

      expect(r.status).toBe(200);
      expect(names(r)).toEqual([]);
      expect(r.body.tree?.unchecked).toBe(1);
      expect(r.body.warnings.map((w) => [w.kind, w.name])).toEqual([["unchecked", "host-p"]]);
      expect(Peers.parse(JSON.parse(r.raw)).tree.projectPeers.map((p) => [p.kind, p.version])).toEqual([["unknown", null]]);
      expect((await resolve("project-plugin", { installed: "host-p@?", strict: "1" })).status).toBe(422);
    });
  });

  // review of 93274c8, finding 4: a git peer and a missing peer answered strict mode 200 with unchecked: 1, no warning
  // and no block
  describe("unchecked dependencies warn, and strict mode refuses them", () => {
    test("each unchecked dependency is a warning of its own in the default mode", async () => {
      const git = await resolve("git-peer");

      expect(git.status).toBe(200);
      expect(git.body.warnings.map((w) => [w.kind, w.name, w.version, w.via])).toEqual([["unchecked", "thing", "github:someone/thing", ["git-peer@1.0.0"]]]);
      expect(git.body.warnings[0]?.text).toStartWith("not checked: peer dependency: git dependency");
      expect((await resolve("missing-peer")).body.warnings.map((w) => [w.kind, w.name, w.version])).toEqual([["unchecked", "no-such-peer", "^1.0.0"]]);
      expect((await resolve("git-dep")).body.warnings.map((w) => w.kind)).toEqual(["unchecked"]);
    });

    test("strict mode refuses a tree with anything unchecked", async () => {
      for (const name of ["git-peer", "missing-peer", "git-dep"]) {
        const r = await resolve(name, { strict: "1" });

        // on 93274c8: 200
        expect([name, r.status]).toEqual([name, 422]);
        expect(r.body.tree?.blocks.length).toBe(1);
      }
    });
  });

  describe("4. the root's search is not cut short by versions it cannot install", () => {
    test("25 yanked releases above an installable one: the installable one is picked", async () => {
      const r = await resolve("many-yanked");

      // on 2fbf383: 422, the 20 newest yanked releases were all it looked at
      expect(r.status).toBe(200);
      expect(r.body.version).toBe("1.0.0");
      // the skipped list stays bounded
      expect(r.body.skipped.length).toBe(20);
      expect(r.body.skipped.every((s) => s.reason === "yanked: bad build")).toBe(true);
    });

    test("strict mode pages past 45 candidates it skips to the one that passes", async () => {
      const r = await resolve("many-fresh", { strict: "1" });

      // on 2fbf383: 422 after 20 candidates
      expect(r.status).toBe(200);
      expect(r.body.version).toBe("1.0.0");
      expect(r.body.skipped.length).toBe(20);
    });

    test("the search stops at its limit and says so", async () => {
      const r = await resolve("all-fresh", { strict: "1" });

      expect(r.status).toBe(422);
      expect(r.body.error).toContain(`apm looked at the newest ${MAX_ROOT_CANDIDATES} versions it could install`);
    });

    // review of 93274c8, finding 5: 230 versions read whole ten times over (2,300 rows) and charged to no lease
    test("each page reads every version as a head and only its own candidates whole, charged to the request", async () => {
      const pool = new MemoryPool();
      whole.rows = 0;
      const r = await resolve("all-fresh", { strict: "1" }, pool);

      expect(r.status).toBe(422);
      // ten pages of 21 (20 candidates and the one that says another page follows): on 93274c8, 2,300
      expect(whole.rows).toBeLessThanOrEqual(10 * 21);
      // on 93274c8: 0, nothing a local page held was charged
      expect(pool.peakCharged).toBeGreaterThan(0);
      expect(pool.charged).toBe(0);
    });

    // review of 1924692, finding 4: the picked rows were read whole, then charged, so a one-byte pool still got one
    test("the picked rows are reserved before they are read: a one-byte pool refuses before any whole row comes", async () => {
      whole.rows = 0;
      whole.chargedAtRead = [];
      const tiny = new MemoryPool(1);
      const r = await resolve("fresh-root", {}, tiny);

      // on 1924692: 503 too, but after one whole row was read with nothing charged
      expect(r.status).toBe(503);
      expect(whole.rows).toBe(0);
      expect(whole.chargedAtRead).toEqual([]);
      expect(tiny.charged).toBe(0);

      // with room, the rows' reservation is already taken when the read begins
      whole.chargedAtRead = [];
      const roomy = new MemoryPool();
      expect((await resolve("fresh-root", {}, roomy)).status).toBe(200);
      expect(whole.chargedAtRead.length).toBeGreaterThan(0);
      expect(whole.chargedAtRead.every((c) => c > 0)).toBe(true);
      expect(roomy.charged).toBe(0);
    });
  });

  describe("review of 16fc8b5, findings 4 and 5: every local row a walk reads is reserved before it comes", () => {
    test("a local dependency's versions are read as heads, and only the one it picks whole, charged before the read", async () => {
      whole.rows = 0;
      whole.chargedAtRead = [];
      const pool = new MemoryPool();
      const r = await resolve("big-parent", {}, pool);

      expect(r.status).toBe(200);
      expect(names(r)).toEqual(["big-dep@1.0.4"]);
      // the root's one version and big-dep's pick; on 16fc8b5 all five 30 KB rows of big-dep were read, uncharged
      expect(whole.rows).toBe(2);
      expect(whole.chargedAtRead.every((c) => c > 0)).toBe(true);
      // a 30 KB row was charged while it was read; on 16fc8b5 the request's peak stayed under 10 KB
      expect(pool.peakCharged).toBeGreaterThan(60_000);
      expect(pool.charged).toBe(0);
    });

    test("a local dependency's pick that does not fit is unchecked, never read", async () => {
      whole.rows = 0;
      const pool = new MemoryPool(60_000);
      const r = await resolve("big-parent", {}, pool);

      expect(r.status).toBe(200);
      expect(r.body.tree?.uncheckedDeps.map((d) => d.dependency)).toEqual(["big-dep@^1.0.0"]);
      // only the root's row: on 16fc8b5 big-dep's five rows were read whatever the pool held
      expect(whole.rows).toBe(1);
    });

    const grow = (): Promise<void> =>
      (async () => {
        const c = new Client({ connectionString: db.url });

        await c.connect();

        try {
          await c.query(`UPDATE versions SET manifest = manifest || jsonb_build_object('pad', repeat('x', 200000)) WHERE package = 'grow-root'`);
        } finally {
          await c.end();
        }
      })();

    const shrink = async (): Promise<void> => {
      const c = new Client({ connectionString: db.url });

      await c.connect();

      try {
        await c.query(`UPDATE versions SET manifest = manifest - 'pad' WHERE package = 'grow-root'`);
      } finally {
        await c.end();
      }
    };

    test("a row that grows after it was measured is not read past its reservation: measured again, then refused", async () => {
      whole.rows = 0;
      whole.chargedAtRead = [];
      whole.afterSizes = grow;
      const tight = new MemoryPool(100_000);

      try {
        const r = await resolve("grow-root", {}, tight);

        // on 16fc8b5: 503 as well, but after the grown 200 KB row was read under a 7 KB reservation
        expect(r.status).toBe(503);
        expect(whole.rows).toBe(0);
        expect(tight.charged).toBe(0);
      } finally {
        await shrink();
      }
    });

    test("with room, the grown row is measured again and read under its new size", async () => {
      whole.rows = 0;
      whole.chargedAtRead = [];
      whole.afterSizes = grow;
      const roomy = new MemoryPool();

      try {
        const r = await resolve("grow-root", {}, roomy);

        expect(r.status).toBe(200);
        // the first read sent nothing (the row had grown), the second sent it, reserved at its new size
        expect(whole.rows).toBe(1);
        expect(whole.chargedAtRead.length).toBe(2);
        expect(whole.chargedAtRead.at(-1) ?? 0).toBeGreaterThan(400_000);
        expect(roomy.charged).toBe(0);
      } finally {
        await shrink();
      }
    });
  });

  describe("review of 16fc8b5: the scan apm add asks after the install", () => {
    test("revoked and yanked versions are listed as blocked; a yanked one is no advisory, so the Bun scanner lets a lockfile keep it", async () => {
      const r = await scan({ packages: [{ name: "host-p", version: "1.0.1" }, { name: "many-yanked", version: "2.0.3" }, { name: "peer-a", version: "1.0.0" }] });

      expect(r.status).toBe(200);
      expect(r.body?.blocked.map((b) => `${b.package}@${b.version}:${b.kind}`)).toEqual(["host-p@1.0.1:revoked", "many-yanked@2.0.3:yanked"]);
      expect(r.body?.advisories.map((a) => `${a.package}@${a.version}:${a.level}`)).toEqual(["host-p@1.0.1:fatal"]);
    });

    test("an integrity that names other bytes is blocked; one of another hash algorithm is not compared", async () => {
      const other = await scan({ packages: [{ name: "peer-a", version: "1.0.0", integrity: "sha1-y" }] });
      const algorithm = await scan({ packages: [{ name: "peer-a", version: "1.0.0", integrity: "sha512-abc" }] });
      const same = await scan({ packages: [{ name: "peer-a", version: "1.0.0", integrity: "sha1-x" }] });

      expect(other.body?.blocked.map((b) => b.kind)).toEqual(["integrity"]);
      expect(other.body?.advisories.map((a) => a.level)).toEqual(["fatal"]);
      expect(algorithm.body?.blocked).toEqual([]);
      expect(same.body?.blocked).toEqual([]);
    });

    test("the cooldown apm add asks for applies: 0 turns it off; a floor under the default is raised to it", async () => {
      const asked = await scan({ packages: [{ name: "fresh-dep", version: "1.0.0" }] });
      const off = await scan({ packages: [{ name: "fresh-dep", version: "1.0.0" }], cooldown: "0" });
      const low = await scan({ packages: [{ name: "fresh-dep", version: "1.0.0" }], cooldown: "0", floor: 0 });
      const bad = await scan({ packages: [{ name: "fresh-dep", version: "1.0.0" }], cooldown: "soon" });

      expect(asked.body?.warnings.map((w) => w.kind)).toEqual(["cooldown"]);
      expect(off.body?.warnings).toEqual([]);
      expect(low.body?.warnings).toEqual([]);
      expect(bad.status).toBe(400);
    });
  });

  describe("review of 2a098b1: integrity apm cannot compare, and bundled versions", () => {
    test("finding 1: an integrity of an algorithm the registry does not know is unverified: a warning, fatal in strict mode, never clean", async () => {
      const loose = await scan({ packages: [{ name: "peer-a", version: "1.0.0", integrity: "sha256-p6A28Td4tQL4GfvBkRK5iXJm/j9ByYvriNEepD83m8k=" }], cooldown: "0", floor: 0 });
      const strict = await scan({ packages: [{ name: "peer-a", version: "1.0.0", integrity: "sha256-p6A28Td4tQL4GfvBkRK5iXJm/j9ByYvriNEepD83m8k=" }], cooldown: "0", floor: 0, strict: true });

      // on 2a098b1: 200 with no blocked entries, no warnings and nothing unchecked, even in strict mode
      expect(loose.body?.blocked).toEqual([]);
      expect(loose.body?.warnings.map((w) => `${w.kind}: ${w.text.slice(0, 22)}`)).toEqual(["unchecked: integrity not verified"]);
      expect(strict.body?.advisories.map((a) => `${a.package}@${a.version}:${a.level}`)).toEqual(["peer-a@1.0.0:fatal"]);
    });

    test("finding 1: a matching weak hash does not vouch for a strongest hash the registry does not know, and a mismatching one in a shared algorithm refuses", async () => {
      const weak = await scan({ packages: [{ name: "peer-a", version: "1.0.0", integrity: "sha1-x sha512-ZZZZ" }], cooldown: "0", floor: 0 });
      const extra = await scan({ packages: [{ name: "peer-a", version: "1.0.0", integrity: "sha1-x sha1-y" }], cooldown: "0", floor: 0 });

      // on 2a098b1: both passed as clean
      expect(weak.body?.blocked).toEqual([]);
      expect(weak.body?.warnings.map((w) => w.kind)).toEqual(["unchecked"]);
      expect(extra.body?.blocked.map((b) => b.kind)).toEqual(["integrity"]);
    });

    test("finding 1: two integrities a lockfile holds for one version are each compared", async () => {
      const r = await scan({ packages: [{ name: "peer-a", version: "1.0.0", integrity: "sha1-x" }, { name: "peer-a", version: "1.0.0", integrity: "sha1-y" }], cooldown: "0", floor: 0 });

      // on 2a098b1: the second was dropped as a duplicate of peer-a@1.0.0
      expect(r.body?.blocked.map((b) => `${b.package}@${b.version}:${b.kind}`)).toEqual(["peer-a@1.0.0:integrity"]);
    });

    test("finding 2: a bundled version is refused when revoked or yanked, and is asked for no score, cooldown or integrity", async () => {
      const r = await scan({
        packages: [
          { name: "host-p", version: "1.0.1", bundled: true },
          { name: "many-yanked", version: "2.0.3", bundled: true },
          { name: "fresh-dep", version: "1.0.0", bundled: true, integrity: "sha512-other" },
          { name: "no-such-bundled", version: "1.0.0", bundled: true },
        ],
      });

      expect(r.body?.blocked.map((b) => `${b.package}@${b.version}:${b.kind}`)).toEqual(["host-p@1.0.1:revoked", "many-yanked@2.0.3:yanked"]);
      // fresh-dep is an hour old and has no matching integrity: neither counts for code that ships in its parent
      expect(r.body?.warnings).toEqual([]);
      expect(r.body?.unchecked).toEqual([]);
    });
  });

  describe("5. optional packages for another platform are skipped by the walk, never by the scan", () => {
    test("on linux x64, the win32 and darwin binaries are skipped with what they depend on, not unchecked", async () => {
      const r = await resolve("native-app", { os: "linux", cpu: "x64", strict: "1" });

      // on 2fbf383 (os and cpu ignored): bin-win, inside its cooldown, refused the install, and its missing dependency
      // was unchecked
      expect(r.status).toBe(200);
      expect(names(r)).toEqual(["bin-linux@1.0.0", "bin-not-win@1.0.0"]);
      expect(r.body.tree?.unchecked).toBe(0);
      expect(r.body.tree?.skippedForPlatform.map((s) => `${s.dependency}: ${s.reason}`).toSorted()).toEqual(["bin-mac: built for os darwin, not linux", "bin-win: built for os win32, not linux"]);
    });

    test("on win32 the !win32 package is skipped; with no platform, every one is walked", async () => {
      expect(names(await resolve("native-app", { os: "win32", cpu: "x64" }))).toEqual(["bin-win@1.0.0", "win-helper@1.0.0"]);
      const any = await resolve("native-app");

      expect(names(any)).toEqual(["bin-linux@1.0.0", "bin-mac@1.0.0", "bin-not-win@1.0.0", "bin-win@1.0.0", "win-helper@1.0.0"]);
      expect(any.body.tree?.skippedForPlatform).toEqual([]);
    });

    // review of 1924692, findings 2 and 3: the CLI asks about every platform, and groups the binaries it gets back
    test("each package built for particular platforms is marked with them, so a client can group them", async () => {
      const any = await resolve("native-app");
      const Marked = z.object({ tree: z.object({ packages: z.array(z.object({ name: z.string(), platform: z.object({ os: z.array(z.string()), cpu: z.array(z.string()) }).optional() })) }) });
      const marked = Object.fromEntries(Marked.parse(JSON.parse(any.raw)).tree.packages.map((p) => [p.name, p.platform ?? null]));

      expect(marked).toEqual({ "bin-linux": { os: ["linux"], cpu: ["x64"] }, "bin-mac": { os: ["darwin"], cpu: ["arm64"] }, "bin-not-win": { os: ["!win32"], cpu: [] }, "bin-win": { os: ["win32"], cpu: ["x64"] }, "win-helper": null });
    });

    test("a required dependency built for another platform is still walked", async () => {
      expect(names(await resolve("needs-win", { os: "linux", cpu: "x64" }))).toEqual(["bin-win@1.0.0", "win-helper@1.0.0"]);
    });

    test("an os or cpu apm cannot read is a 400, never any platform", async () => {
      const bad: Record<string, string>[] = [{ os: "Linux!" }, { cpu: "" }, { os: "x".repeat(40) }];

      for (const q of bad) expect((await resolve("native-app", q)).status).toBe(400);
    });

    test("the scan checks every package it is handed, whatever its platform and whoever lists it as optional", async () => {
      const handed = [
        { name: "scan-parent", version: "1.0.0" },
        { name: "scan-bin", version: "2.0.0" },
      ];

      // on 93274c8: scan-parent's optional ask for scan-bin@1.0.0 made every scan-bin optional, so the revoked 2.0.0
      // bun was about to install was skipped for its platform, with no advisory
      const r = await scan({ packages: handed, os: "linux", cpu: "x64", strict: true });

      expect(r.body?.advisories.map((a) => [a.package, a.version, a.level])).toEqual([["scan-bin", "2.0.0", "fatal"]]);
      expect(r.raw).not.toContain("skippedForPlatform");
      // the default mode, and an older scanner that sends no platform, see the same
      expect((await scan({ packages: handed })).body?.advisories.map((a) => a.level)).toEqual(["fatal"]);
      // a revoked win32 binary an optional parent lists is checked too: the scan never guesses what is optional
      const optional = await scan({ packages: [{ name: "revoked-optional-app", version: "1.0.0" }, { name: "bin-revoked", version: "1.0.0" }], os: "linux", cpu: "x64" });

      expect(optional.body?.advisories.map((a) => [a.package, a.level])).toEqual([["bin-revoked", "fatal"]]);
    });

    test("the scan warns about a version inside the cooldown, and strict mode refuses it", async () => {
      const r = await scan({ packages: [{ name: "fresh-dep", version: "1.0.0" }] });

      // on 2fbf383: no advisory, no warning
      expect(r.body?.advisories.map((a) => a.level)).toEqual(["warn"]);
      expect(r.body?.warnings.map((w) => [w.kind, w.text])).toEqual([["cooldown", "published 2 hours ago, inside apm's 24-hour cooldown"]]);
      const strict = await scan({ packages: [{ name: "fresh-dep", version: "1.0.0" }], strict: true });

      expect(strict.body?.advisories.map((a) => a.level)).toEqual(["fatal"]);
    });
  });
});
