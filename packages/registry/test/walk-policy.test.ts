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
};

type P = { name: string; latest?: string; versions: V[] };

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
  warnings: z.array(Warning),
  unchecked: z.array(z.object({ package: z.string(), version: z.string(), reason: z.string() })),
  skippedForPlatform: z.array(z.object({ package: z.string(), version: z.string(), reason: z.string() })).default([]),
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
    // 4. the root's candidates
    { name: "many-yanked", versions: [v("1.0.0"), ...Array.from({ length: 25 }, (_, i) => v(`2.0.${i}`, { status: "yanked", statusReason: "bad build" }))] },
    { name: "many-fresh", versions: [v("1.0.0"), ...Array.from({ length: 45 }, (_, i) => v(`2.0.${i}`, { ageMs: HOUR }))] },
    { name: "all-fresh", versions: Array.from({ length: MAX_ROOT_CANDIDATES + 30 }, (_, i) => v(`3.0.${i}`, { ageMs: HOUR })) },
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

  const resolve = async (name: string, params: Record<string, string> = {}) => {
    const u = new URL(`http://registry.test/-/apm/v1/resolve?${new URLSearchParams({ name, range: "latest", ...params })}`);
    const program = Effect.flatMap(resolveResponse(u), (res) => Effect.promise(async () => ({ status: res.status, raw: await res.text() })));
    const out = await Effect.runPromise(program.pipe(Effect.provide(layers()), Effect.scoped));

    return { status: out.status, body: ResolveBody.parse(JSON.parse(out.raw)), raw: out.raw };
  };

  const scan = async (body: { packages: { name: string; version: string }[]; strict?: boolean; os?: string; cpu?: string }) => {
    const req = new Request("http://registry.test/-/apm/v1/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const program = Effect.flatMap(scanResponse(req, { kind: "anon" }), (res) => Effect.promise(async () => ({ status: res.status, text: await res.text() })));
    const out = await Effect.runPromise(program.pipe(Effect.provide(layers()), Effect.scoped));

    return { status: out.status, body: out.status === 200 ? ScanBody.parse(JSON.parse(out.text)) : null };
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
  });

  describe("5. optional packages for another platform are skipped before any check", () => {
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

    test("a required dependency built for another platform is still walked", async () => {
      expect(names(await resolve("needs-win", { os: "linux", cpu: "x64" }))).toEqual(["bin-win@1.0.0", "win-helper@1.0.0"]);
    });

    test("an os or cpu apm cannot read is a 400, never any platform", async () => {
      const bad: Record<string, string>[] = [{ os: "Linux!" }, { cpu: "" }, { os: "x".repeat(40) }];

      for (const q of bad) expect((await resolve("native-app", q)).status).toBe(400);
    });

    test("the scan skips a revoked win32 binary a package lists only as optional, and checks it when it is required", async () => {
      const optional = await scan({ packages: [{ name: "revoked-optional-app", version: "1.0.0" }, { name: "bin-revoked", version: "1.0.0" }], os: "linux", cpu: "x64" });

      // on 2fbf383: a fatal advisory for bin-revoked, which bun never installs on linux, cancelled the install
      expect(optional.body?.advisories).toEqual([]);
      expect(optional.body?.skippedForPlatform).toEqual([{ package: "bin-revoked", version: "1.0.0", reason: "built for os win32, not linux" }]);
      expect(optional.body?.unchecked).toEqual([]);
      const required = await scan({ packages: [{ name: "revoked-required-app", version: "1.0.0" }, { name: "bin-revoked", version: "1.0.0" }], os: "linux", cpu: "x64" });

      expect(required.body?.advisories.map((a) => [a.package, a.level])).toEqual([["bin-revoked", "fatal"]]);
      // nothing in the scan lists it: a dependency of the project itself, so it is checked
      const alone = await scan({ packages: [{ name: "bin-revoked", version: "1.0.0" }], os: "linux", cpu: "x64" });

      expect(alone.body?.advisories.map((a) => a.level)).toEqual(["fatal"]);
      expect((await scan({ packages: [], os: "Linux" })).status).toBe(400);
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
