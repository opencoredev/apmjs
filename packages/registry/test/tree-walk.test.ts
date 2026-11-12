// The resolve walk's limits bound the database work of one request: repeated edges (npm: aliases to one package, a
// package many others depend on) read each package once, a level's catalogs are read in one batch, and a walk that
// keeps failing to resolve stops at its lookup budget. Every SQL statement the request runs is counted through
// Effect's statement hook; npm is a local stand-in that counts the packuments asked for.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { Effect, Layer, Option } from "effect";
import * as Statement from "effect/sql/Statement";
import { Client } from "pg";
import { z } from "zod";
import { analyze, SCORER, type Analysis as Scored } from "@apm/core";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis } from "../src/analysis.ts";
import { MAX_WALK_LEVELS, MAX_WALK_LOOKUPS, resolveResponse } from "../src/apm.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { Store } from "../src/db.ts";
import { Upstream } from "../src/upstream.ts";

const NOW = Date.parse("2026-11-12T00:00:00Z");
const DAY = 86_400_000;

type Pkg = { name: string; dependencies?: Record<string, string> };

const encoder = new TextEncoder();

/** The package.json fields these packages have. */
type Manifest = { name: string; version: string; main: string; license: string; dependencies?: Record<string, string> };

/** The package.json of a package's 1.0.0: no dependencies field when it has none, as npm writes it. */
function manifestOf(p: Pkg): Manifest {
  const manifest: Manifest = { name: p.name, version: "1.0.0", main: "index.js", license: "MIT" };

  if (p.dependencies) manifest.dependencies = p.dependencies;

  return manifest;
}

/** A small clean package's stored analysis, as publish (or the upstream analysis) stores it. */
function analysisOf(p: Pkg): Scored {
  const manifest = manifestOf(p);
  const file = (path: string, text: string) => ({ path, size: text.length, mode: 0o644, data: encoder.encode(text) });
  const files = [file("package.json", JSON.stringify(manifest)), file("index.js", "module.exports = 1;\n")];

  return analyze({ name: p.name, manifest, files, publisher: "u", previousPublishers: [] });
}

/** A sha512 integrity unique to the package, so its upstream analysis is keyed to these "bytes". */
const integrityOf = (name: string): string => `sha512-${createHash("sha512").update(name).digest("base64")}`;
const digestOfName = (name: string): string => `sha512-${createHash("sha512").update(name).digest("hex")}`;

/** Local packages get one version, 1.0.0, published ten days ago and scored; upstream ones get a stored analysis. */
async function seed(url: string, input: { local: readonly Pkg[]; upstream: readonly Pkg[] }): Promise<void> {
  const c = new Client({ connectionString: url });
  await c.connect();

  try {
    await c.query(`INSERT INTO users (name, password_hash, email, created_at) VALUES ('u', 'x', 'u@example.test', 0)`);

    for (const p of input.local) {
      await c.query(`INSERT INTO packages (name, created_at, modified_at, dist_tags) VALUES ($1, 0, 0, '{"latest":"1.0.0"}'::jsonb)`, [p.name]);
      await c.query(
        `INSERT INTO versions (package, version, manifest, shasum, integrity, size, tarball_key, published_at, published_by, score)
         VALUES ($1, '1.0.0', $2::jsonb, $3, 'sha1-x', 10, 'sha512/x', $4, 'u', $5::jsonb)`,
        [p.name, JSON.stringify(manifestOf(p)), "0".repeat(40), NOW - 10 * DAY, JSON.stringify(analysisOf(p))],
      );
    }

    for (const p of input.upstream) {
      await c.query(`INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ($1, '1.0.0', $2, $3, $4::jsonb, 0)`, [
        p.name,
        digestOfName(p.name),
        SCORER,
        JSON.stringify(analysisOf(p)),
      ]);
    }
  } finally {
    await c.end();
  }
}

/** A stand-in for npm: each package's packument, and how many were asked for. */
function fakeNpm(pkgs: readonly Pkg[]) {
  const byName = new Map(pkgs.map((p) => [p.name, p]));
  let asked = 0;

  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req): Response {
      asked++;
      const name = decodeURIComponent(new URL(req.url).pathname.slice(1));
      const p = byName.get(name);

      if (!p) return Response.json({ error: "Not found" }, { status: 404 });
      // the walk never downloads a tarball: its analysis is stored
      const dist = { tarball: `https://npm.invalid/${name}/-/${name}-1.0.0.tgz`, shasum: "1".repeat(40), integrity: integrityOf(name) };

      return Response.json({
        name,
        "dist-tags": { latest: "1.0.0" },
        versions: { "1.0.0": { ...manifestOf(p), dist } },
        time: { "1.0.0": new Date(NOW - 10 * DAY).toISOString() },
      });
    },
  });

  return { url: server.url.href, asked: () => asked, stop: () => server.stop(true) };
}

const ResolveBody = z.object({
  version: z.string().nullish(),
  tree: z.object({ unchecked: z.number(), packages: z.array(z.object({ name: z.string(), version: z.string() })), uncheckedDeps: z.array(z.object({ dependency: z.string(), reason: z.string() })) }),
});

type Resolved = { status: number; body: z.infer<typeof ResolveBody>; queries: number };

/** No tarball is read here: the walk only reads catalogs and stored analyses. */
const noBlobs = Layer.succeed(
  Blobs,
  Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }),
);

/** GET /-/apm/v1/resolve?name=… against the database (and npm, when given), counting every SQL statement it runs. */
async function resolve(input: { url: string; name: string; npm?: string }): Promise<Resolved> {
  let queries = 0;

  const counter: Statement.Transformer = (self) =>
    Effect.sync(() => {
      queries++;

      return self;
    });

  const u = new URL(`http://registry.test/-/apm/v1/resolve?${new URLSearchParams({ name: input.name, range: "latest" })}`);
  const store = Store.postgres(input.url);
  const base = Layer.mergeAll(store, Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs);
  const layers = input.npm === undefined ? base : Layer.provideMerge(Upstream.layer(input.npm, 60_000, null), base);

  const program = Effect.flatMap(resolveResponse(u), (res) => Effect.promise(async () => ({ status: res.status, body: ResolveBody.parse(await res.json()) })));

  const out = await Effect.runPromise(program.pipe(Effect.provideService(Statement.CurrentTransformer, counter), Effect.provide(layers), Effect.scoped));

  return { ...out, queries };
}

async function withDatabase(input: { local: readonly Pkg[]; upstream?: readonly Pkg[] }, fn: (url: string) => Promise<void>): Promise<void> {
  const db = await freshDatabase();

  try {
    await seed(db.url, { local: input.local, upstream: input.upstream ?? [] });
    await fn(db.url);
  } finally {
    await db.drop();
  }
}

const report = (label: string, r: Resolved, extra = ""): void => {
  process.stdout.write(`[tree-walk] ${label}: ${r.queries} SQL statements, ${r.body.tree.packages.length} checked, ${r.body.tree.unchecked} unchecked${extra}\n`);
};

describe("the resolve walk bounds its database work", () => {
  test("four npm: aliases to one leaf read the leaf's catalog once", () =>
    withDatabase(
      {
        local: [{ name: "leaf" }, { name: "root", dependencies: { a1: "npm:leaf@^1.0.0", a2: "npm:leaf@^1.0.0", a3: "npm:leaf@^1.0.0", a4: "npm:leaf@^1.0.0" } }],
      },
      async (url) => {
        const r = await resolve({ url, name: "root" });

        report("4 aliases to one leaf", r);
        expect(r.status).toBe(200);
        expect(r.body.tree.packages).toEqual([{ name: "leaf", version: "1.0.0" }]);
        expect(r.body.tree.unchecked).toBe(0);
        // the root's catalog (package, versions, dismissals) and the leaf's, once each; AI review is off
        expect(r.queries).toBeLessThanOrEqual(6);
      },
    ));

  test("a 300-package tree reads each level's catalogs in one batch", () => {
    // root -> 20 mids -> 14 leaves each (280); every package is scored and clean
    const leaves = Array.from({ length: 280 }, (_, i) => ({ name: `leaf${i}` }));
    const mids = Array.from({ length: 20 }, (_, m) => ({ name: `mid${m}`, dependencies: Object.fromEntries(Array.from({ length: 14 }, (_, k) => [`leaf${m * 14 + k}`, "^1.0.0"])) }));
    const root = { name: "root", dependencies: Object.fromEntries(mids.map((m) => [m.name, "^1.0.0"])) };

    return withDatabase({ local: [...leaves, ...mids, root] }, async (url) => {
      const r = await resolve({ url, name: "root" });

      report("300-package tree", r);
      expect(r.status).toBe(200);
      expect(r.body.tree.packages.length).toBe(300);
      expect(r.body.tree.unchecked).toBe(0);
      // the root, then one batch per level (mids, leaves): a handful of statements, not three per package
      expect(r.queries).toBeLessThanOrEqual(12);
    });
  });

  test("dependencies that never resolve count against the lookup budget and are reported unchecked", () => {
    // 600 dependencies on names nobody has: each is a lookup, and those past the budget are not looked up
    const root = { name: "root", dependencies: Object.fromEntries(Array.from({ length: 600 }, (_, i) => [`nope${i}`, "^1.0.0"])) };

    return withDatabase({ local: [root] }, async (url) => {
      const r = await resolve({ url, name: "root" });

      report("600 dependencies that resolve to nothing", r);
      expect(r.status).toBe(200);
      expect(r.body.tree.packages.length).toBe(0);
      expect(r.body.tree.unchecked).toBe(600);
      expect(r.body.tree.uncheckedDeps.some((d) => d.dependency === `${600 - MAX_WALK_LOOKUPS} more` && d.reason.includes(`${MAX_WALK_LOOKUPS} dependency lookups`))).toBe(true);
      expect(r.queries).toBeLessThanOrEqual(12);
    });
  });

  test("a long chain stops at the level limit and says so", () => {
    // c0 -> c1 -> ... -> c39: one package per level
    const chain: Pkg[] = Array.from({ length: 39 }, (_, i) => ({ name: `c${i}`, dependencies: { [`c${i + 1}`]: "^1.0.0" } }));
    chain.push({ name: "c39" });

    return withDatabase({ local: chain }, async (url) => {
      const r = await resolve({ url, name: "c0" });

      report("40-deep chain", r);
      expect(r.status).toBe(200);
      expect(r.body.tree.packages.length).toBe(MAX_WALK_LEVELS);
      expect(r.body.tree.unchecked).toBe(1);
      expect(r.body.tree.uncheckedDeps[0]?.reason).toBe(`the check stops after ${MAX_WALK_LEVELS} levels of dependencies`);
      // three statements per level read, plus the root's
      expect(r.queries).toBeLessThanOrEqual(3 * MAX_WALK_LEVELS + 6);
    });
  });

  describe("with npm upstream", () => {
    // root (here) -> 40 npm packages -> 5 of 60 shared npm leaves each: 100 npm packages, scored
    const leaves = Array.from({ length: 60 }, (_, i) => ({ name: `up-leaf${i}` }));
    const mids = Array.from({ length: 40 }, (_, m) => ({ name: `up-mid${m}`, dependencies: Object.fromEntries(Array.from({ length: 5 }, (_, k) => [`up-leaf${(m * 3 + k) % 60}`, "^1.0.0"])) }));
    const root = { name: "root", dependencies: Object.fromEntries(mids.map((m) => [m.name, "^1.0.0"])) };
    let npm: ReturnType<typeof fakeNpm>;

    beforeAll(() => {
      npm = fakeNpm([...leaves, ...mids]);
    });

    afterAll(() => npm.stop());

    test("each npm package is asked for once and its analyses are read in one batch per level", () =>
      withDatabase({ local: [root], upstream: [...leaves, ...mids] }, async (url) => {
        const before = npm.asked();
        const r = await resolve({ url, name: "root", npm: npm.url });
        const asked = npm.asked() - before;

        report("100 npm packages under one local root", r, `, ${asked} packuments asked for`);
        expect(r.status).toBe(200);
        expect(r.body.tree.packages.length).toBe(100);
        expect(r.body.tree.unchecked).toBe(0);
        expect(asked).toBe(100);
        // the root's catalog, then per level: this registry's packages (none here) and npm's analyses with dismissals
        expect(r.queries).toBeLessThanOrEqual(12);
      }));
  });
});
