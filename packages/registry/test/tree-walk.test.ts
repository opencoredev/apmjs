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
import { Auth } from "../src/auth.ts";
import { apmRoute, MAX_WALK_LEVELS, MAX_WALK_LOOKUPS, OVER_BUDGET_TEXT, REQUEST_METADATA_WEIGHT, resolveResponse } from "../src/apm.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { RegistryConfig } from "../src/config.ts";
import { Store } from "../src/db.ts";
import { Upstream } from "../src/upstream.ts";
import { MemoryPool, RequestMemory, type Lease } from "../src/memory.ts";

/** This file's memory pool: every request it runs takes a lease of it, as a Worker isolate's do. */
const POOL = new MemoryPool();

const NOW = Date.parse("2026-11-12T00:00:00Z");
const DAY = 86_400_000;

/**
 * `pad`: bytes of postinstall script its npm packument's version carries, which the registry keeps and so does a walk's
 * summary of the package (walk-catalog.ts), so the walk holds it for as long as it holds the package.
 */
type Pkg = { name: string; dependencies?: Record<string, string>; pad?: number };

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

/** The packument the stand-in sends: one version, and the padding a package asks for. */
type FakePackument = {
  name: string;
  "dist-tags": Record<string, string>;
  versions: Record<string, Manifest & { dist: { tarball: string; shasum: string; integrity: string }; scripts?: { postinstall: string } }>;
  time: Record<string, string>;
};

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

      const version: FakePackument["versions"][string] = { ...manifestOf(p), dist };

      if (p.pad !== undefined) version.scripts = { postinstall: "d".repeat(p.pad) };

      const packument: FakePackument = {
        name,
        "dist-tags": { latest: "1.0.0" },
        versions: { "1.0.0": version },
        time: { "1.0.0": new Date(NOW - 10 * DAY).toISOString() },
      };

      return Response.json(packument);
    },
  });

  return { url: server.url.href, asked: () => asked, stop: () => server.stop(true) };
}

const ResolveBody = z.object({
  version: z.string().nullish(),
  error: z.string().optional(),
  tree: z.object({
    unchecked: z.number(),
    packages: z.array(z.object({ name: z.string(), version: z.string() })),
    uncheckedDeps: z.array(z.object({ dependency: z.string(), reason: z.string() })),
    unavailable: z.array(z.object({ dependency: z.string(), via: z.array(z.string()) })).optional(),
  }),
  warnings: z.array(z.object({ name: z.string(), kind: z.string(), text: z.string() })).optional(),
});

type Resolved = { status: number; body: z.infer<typeof ResolveBody>; queries: number };

/** No tarball is read here: the walk only reads catalogs and stored analyses. */
const noBlobs = Layer.succeed(
  Blobs,
  Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }),
);

/** GET /-/apm/v1/resolve?name=… against the database (and npm, when given), counting every SQL statement it runs. */
async function resolve(input: { url: string; name: string; npm?: string; strict?: boolean }): Promise<Resolved> {
  let queries = 0;

  const counter: Statement.Transformer = (self) =>
    Effect.sync(() => {
      queries++;

      return self;
    });

  const params = new URLSearchParams({ name: input.name, range: "latest" });

  if (input.strict) params.set("strict", "1");
  const u = new URL(`http://registry.test/-/apm/v1/resolve?${params}`);
  const store = Store.postgres(input.url);
  const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: input.npm ?? null, legacyAuth: false, namePolicy: "open", admins: [] } as const;
  const base = Layer.mergeAll(store, Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs, Layer.succeed(RegistryConfig, settings), RequestMemory.layer(POOL));
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
        // the root (package, version heads, its picked versions' sizes, its picked versions, dismissals) and the leaf's
        // catalog, once each; AI review is off. The root reads heads first and only its candidates whole (review of
        // 93274c8, finding 5), reserved from their sizes before they are read (review of 1924692, finding 4). The leaf
        // is read the same way, in four statements (its dist-tags and heads, its picked version's size, that version,
        // dismissals), so it is reserved before it is read too (review of 16fc8b5, finding 4)
        expect(r.queries).toBeLessThanOrEqual(9);
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
      // the root, then one batch of four statements per level (mids, leaves): a handful, not four per package
      expect(r.queries).toBeLessThanOrEqual(14);
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

  test("a dependency nobody has is reported as not existing, with no upstream configured", () =>
    withDatabase({ local: [{ name: "root", dependencies: { "no-such-dep": "^1.0.0" } }] }, async (url) => {
      const r = await resolve({ url, name: "root" });

      expect(r.status).toBe(200);
      expect(r.body.tree.uncheckedDeps).toEqual([{ dependency: "no-such-dep@^1.0.0", reason: "not on this registry or upstream" }]);
    }));

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
      // four statements per level read (heads, the picked rows' sizes, the rows, dismissals: review of 16fc8b5,
      // finding 4), plus the root's
      expect(r.queries).toBeLessThanOrEqual(4 * MAX_WALK_LEVELS + 6);
      // a walk cut short at its limits installs with a warning that says so (at 5b5b492: 200 and no warning), and
      // strict mode refuses it
      expect(r.body.warnings?.map((w) => [w.name, w.kind])).toEqual([["c0", "unchecked"]]);
      expect(r.body.warnings?.[0]?.text).toBe(`1 more dependency was not checked: the check stops after ${MAX_WALK_LEVELS} levels of dependencies`);
      const strict = await resolve({ url, name: "c0", strict: true });

      expect(strict.status).toBe(422);
      expect(strict.body.error).toContain("not checked");
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
        // the root's catalog (its sizes read first), then per level: this registry's packages (none here) and npm's
        // analyses with dismissals
        expect(r.queries).toBeLessThanOrEqual(13);
      }));

    test("a dependency npm answers 404 for is reported as not existing, not as npm being unreachable", () =>
      withDatabase({ local: [{ name: "root", dependencies: { "up-leaf0": "^1.0.0", "no-such-dep": "^1.0.0" } }], upstream: [{ name: "up-leaf0" }] }, async (url) => {
        const r = await resolve({ url, name: "root", npm: npm.url });

        expect(r.status).toBe(200);
        expect(r.body.tree.packages).toEqual([{ name: "up-leaf0", version: "1.0.0" }]);
        expect(r.body.tree.uncheckedDeps).toEqual([{ dependency: "no-such-dep@^1.0.0", reason: "not on this registry or upstream" }]);
      }));

    test("a dependency npm could not answer for is reported as unknown, not as absent", () => {
      const down = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response("unavailable", { status: 503 }) });

      return withDatabase({ local: [{ name: "root", dependencies: { "some-npm-dep": "^1.0.0" } }] }, async (url) => {
        const r = await resolve({ url, name: "root", npm: down.url.href });

        // its own state, not a walk limit and not unchecked (review of 5b5b492, finding 2)
        expect(r.status).toBe(200);
        expect(r.body.tree.uncheckedDeps).toEqual([]);
        expect(r.body.tree.unavailable).toEqual([{ dependency: "some-npm-dep@^1.0.0", via: ["root@1.0.0"] }]);
        expect(r.body.warnings?.map((w) => w.kind)).toEqual(["unavailable"]);
        expect((await resolve({ url, name: "root", npm: down.url.href, strict: true })).status).toBe(503);
      }).finally(() => down.stop(true));
    });
  });
});

// Review of 89441a9, finding 3: a walk holds every catalog it read until it answers, read six at a time, and the
// isolate cache's eviction frees none a request still holds, so one request's package metadata had no bound.
describe("the resolve walk bounds the package metadata it holds", () => {
  test("past REQUEST_METADATA_WEIGHT the rest are unchecked with a warning, reads in flight included", () => {
    // twelve npm dependencies of about 8 MB kept each: 96 MB held once read, past the request's budget, which also
    // holds the text of the reads in flight, six at once, and each parse's moment
    const pad = 8 * 1024 * 1024;
    const deps = Array.from({ length: 12 }, (_, i) => ({ name: `big${i}`, pad }));
    const root = { name: "root", dependencies: Object.fromEntries(deps.map((d) => [d.name, "^1.0.0"])) };
    const npm = fakeNpm(deps);

    return withDatabase({ local: [root], upstream: deps }, async (url) => {
      const r = await resolve({ url, name: "root", npm: npm.url });
      const checked = r.body.tree.packages.length;

      report("12 packuments of 8 MB", r);
      expect(r.status).toBe(200);
      // on 89441a9 all eight were read, held and checked; what is held stays under the budget
      expect(checked).toBeGreaterThanOrEqual(2);
      expect(checked * pad).toBeLessThanOrEqual(REQUEST_METADATA_WEIGHT);
      expect(r.body.tree.unchecked).toBe(deps.length - checked);
      expect(r.body.tree.uncheckedDeps.map((d) => d.reason)).toEqual(Array.from({ length: deps.length - checked }, () => OVER_BUDGET_TEXT));
      // one warning for each dependency it could not check (review of 93274c8, finding 4)
      expect(r.body.warnings?.filter((w) => w.kind === "unchecked").map((w) => w.text)).toEqual(Array.from({ length: deps.length - checked }, () => `not checked: ${OVER_BUDGET_TEXT}`));
      // a walk cut short refuses in strict mode, as at its other limits
      expect((await resolve({ url, name: "root", npm: npm.url, strict: true })).status).not.toBe(200);
    }).finally(() => npm.stop());
  });
});

/** One read of npm's package metadata a request made: which method, and the lease it was made under. */
type LeasedRead = { readonly method: string; readonly lease: Lease };

/** The real Upstream layer, with every packument read noted with its lease. */
function recording(npm: string, reads: LeasedRead[]) {
  return Layer.effect(
    Upstream,
    Effect.gen(function* () {
      const u = yield* Upstream;

      const note = (method: string, lease: Lease): void => {
        reads.push({ method, lease });
      };

      return Upstream.of({
        ...u,
        probe: (n, lease) => Effect.suspend(() => (note("probe", lease), u.probe(n, lease))),
        probeWithin: (n, lease) => Effect.suspend(() => (note("probeWithin", lease), u.probeWithin(n, lease))),
        probeMany: (ns, lease) => Effect.suspend(() => (note("probeMany", lease), u.probeMany(ns, lease))),
        summaries: (ns, lease, keep) => Effect.suspend(() => (note("summaries", lease), u.summaries(ns, lease, keep))),
        listing: (n, lease) => Effect.suspend(() => (note("listing", lease), u.listing(n, lease))),
        get: (n, lease) => Effect.suspend(() => (note("get", lease), u.get(n, lease))),
        devDependencies: (n, lease) => Effect.suspend(() => (note("devDependencies", lease), u.devDependencies(n, lease))),
      });
    }),
  ).pipe(Layer.provide(Upstream.layer(npm, 60_000, null)));
}

/** GET `path` through the apm routes in a pool of its own, noting every packument read and the request's lease. */
async function leasedGet(input: { url: string; npm: string; path: string }): Promise<{ status: number; reads: LeasedRead[]; request: Lease; pool: MemoryPool }> {
  const pool = new MemoryPool();
  const reads: LeasedRead[] = [];
  const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: input.npm, legacyAuth: false, namePolicy: "open", admins: [] } as const;
  const base = Layer.mergeAll(Store.postgres(input.url), Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs, Layer.succeed(RegistryConfig, settings));
  // Better Auth is built on first use only, and these routes never sign anyone in
  const auth = Auth.layer({ databaseUrl: input.url, options: { secret: "test-secret-that-is-long-enough-for-better-auth" }, baseURL: "http://web.test/" });
  const layers = Layer.provideMerge(Layer.mergeAll(recording(input.npm, reads), auth), base);
  const request = pool.request();
  const req = new Request(`http://registry.test${input.path}`);
  const program = Effect.flatMap(input.path.includes("/resolve") ? resolveResponse(new URL(req.url)) : apmRoute(req, new URL(req.url), { kind: "anon" }), (res) => Effect.promise(async () => ({ status: res?.status ?? 0, text: (await res?.text()) ?? "" })));
  const out = await Effect.runPromise(program.pipe(Effect.provideService(RequestMemory, request), Effect.provide(layers), Effect.scoped));

  return { status: out.status, reads, request, pool };
}

// Review of 6862fc7, finding 4: resolve read its root, and read it again after waiting, outside the walk's budget, and
// popular-scores read four packages at once with no budget at all. Every read a handler makes is now under the one lease
// it opened, or a child of it.
describe("every packument a request reads is under the request's lease", () => {
  test("resolve: the root, its reloads and the walk share one lease, so the root counts against the walk", () => {
    // two npm roots, one with 10 MiB kept and one with nothing, each over 32 npm dependencies of 2 MiB of its own: 64
    // MiB of them, more than the request holds, so each walk checks as many as fit beside its root
    const pad = 2 * 1024 * 1024;
    const rootPad = 10 * 1024 * 1024;
    const depsOf = (p: string) => Array.from({ length: 32 }, (_, i) => ({ name: `${p}-dep${i}`, pad }));
    const rootOf = (name: string, deps: readonly Pkg[], padding: number) => ({ name, dependencies: Object.fromEntries(deps.map((d) => [d.name, "^1.0.0"])), pad: padding });
    const [bigDeps, smallDeps] = [depsOf("big"), depsOf("small")];
    const [big, small] = [rootOf("big-root", bigDeps, rootPad), rootOf("small-root", smallDeps, 0)];
    const all = [big, small, ...bigDeps, ...smallDeps];
    const npm = fakeNpm(all);

    return withDatabase({ local: [], upstream: all }, async (url) => {
      // each walk reads its own dependencies from npm, none from the isolate cache
      const withBig = await resolve({ url, name: "big-root", npm: npm.url });
      const withSmall = await resolve({ url, name: "small-root", npm: npm.url });
      const leased = await leasedGet({ url, npm: npm.url, path: "/-/apm/v1/resolve?name=big-root&range=latest&wait=0" });
      const [bigChecked, smallChecked] = [withBig.body.tree.packages.length, withSmall.body.tree.packages.length];

      report("an npm root of 10 MiB over 32 of 2 MiB", withBig);
      report("an npm root of 0 MiB over 32 of 2 MiB", withSmall);
      expect(leased.status).toBe(200);
      // on 6862fc7 the root was read with probe() and get() under no budget
      expect(leased.reads.length).toBeGreaterThan(1);
      expect(leased.reads.every((x) => x.lease.root === leased.request)).toBe(true);
      expect(leased.reads.map((x) => x.method)).toContain("summaries");
      expect(leased.request.peakTaken).toBeLessThanOrEqual(REQUEST_METADATA_WEIGHT);
      // the big root's 10 MiB leaves the walk room for about five fewer; on 6862fc7 both walks checked as many
      expect(bigChecked).toBeGreaterThanOrEqual(1);
      expect(bigChecked).toBeLessThanOrEqual(smallChecked - 3);
      expect(rootPad + bigChecked * pad).toBeLessThanOrEqual(REQUEST_METADATA_WEIGHT);
      expect(withBig.body.tree.uncheckedDeps.map((d) => d.reason)).toEqual(Array.from({ length: bigDeps.length - bigChecked }, () => OVER_BUDGET_TEXT));
    }).finally(() => npm.stop());
  });

  test("popular-scores: each name is read under a child of the request's lease, and together they stay within it", () => {
    // six names of 10 MiB, read four at once: 40 MiB each while it is parsed
    const pad = 10 * 1024 * 1024;
    const names = Array.from({ length: 6 }, (_, i) => ({ name: `popular${i}`, pad }));
    const npm = fakeNpm(names);

    return withDatabase({ local: [], upstream: names }, async (url) => {
      const r = await leasedGet({ url, npm: npm.url, path: `/-/apm/v1/popular-scores?names=${names.map((n) => n.name).join(",")}` });

      process.stdout.write(`[popular-scores] 6 names of 10 MiB: ${r.reads.length} reads, the request held ${(r.request.peakTaken / (1024 * 1024)).toFixed(1)} MiB at most, the pool ${(r.pool.peakCharged / (1024 * 1024)).toFixed(1)} MiB with the cache\n`);
      expect(r.status).toBe(200);
      expect(r.reads.length).toBe(names.length);
      // on 6862fc7: get() four at once, each under no budget
      expect(r.reads.every((x) => x.lease.root === r.request && x.lease !== r.request)).toBe(true);
      expect(new Set(r.reads.map((x) => x.lease)).size).toBe(names.length);
      expect(r.request.peakTaken).toBeLessThanOrEqual(REQUEST_METADATA_WEIGHT);
      expect(r.pool.peakCharged).toBeLessThanOrEqual(r.pool.limit);
      // each child gave back what it held once its name was answered: only the isolate cache's entries are left
      expect(r.request.taken).toBe(0);
    }).finally(() => npm.stop());
  });
});
