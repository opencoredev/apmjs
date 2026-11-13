// A summary is charged before it is built (review of 2fbf383, finding 3). On 2fbf383 the review's copy of a fetched
// package (upstream.ts, fetched) and the caller's summary (Upstream.summaries) were built first and their weight taken
// after, and the scored copy a summary is built from was given back before the summary's weight was taken: the pool's
// peakCharged missed what building them held. Now an upper bound on each version's summary and the JSON text weighing it
// writes is taken first, then settled to what it keeps, and the scored copy stays charged while the summary is built.
import { afterAll, beforeAll, describe, expect, spyOn, test } from "bun:test";
import { Effect, Layer, Option } from "effect";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis } from "../src/analysis.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { RegistryConfig } from "../src/config.ts";
import { Store, type VersionRecord } from "../src/db.ts";
import { ReleaseHooks } from "../src/hooks.ts";
import { MemoryPool, RequestMemory, type Lease } from "../src/memory.ts";
import { SCORED_WEIGHT, Upstream, type UpstreamPackage } from "../src/upstream.ts";
import { jsonBound, jsonWeight, keptSummary, reviewSummary, summarize, summaryVersion, type Catalog, type Reserve, type Summary } from "../src/walk-catalog.ts";

const KEY = 8;

/** A version with a manifest of `deps` dependencies, scripts with escapes, and fields a summary drops. */
function version(i: number, deps: number): VersionRecord {
  const dependencies = Object.fromEntries(Array.from({ length: deps }, (_, j) => [`dep-${j}`, `^${j}.0.0 || "x"`]));

  return {
    package: "big",
    version: `1.0.${i}`,
    manifest: {
      name: "big",
      version: `1.0.${i}`,
      dependencies,
      peerDependencies: { react: ">=18" },
      peerDependenciesMeta: { react: { optional: true } },
      os: ["linux", "!win32"],
      scripts: { postinstall: `node "setup.js"\n\t\u0001 \u{1f600}`, test: "x".repeat(500) },
      readme: "r".repeat(10_000),
    },
    published_at: 0,
    published_by: "someone",
    shasum: "1".repeat(40),
    integrity: `sha512-${"A".repeat(86)}==`,
    size: 10,
    tarball_key: "sha512/x",
    seq: i,
    status: "active",
    status_reason: null,
    status_at: null,
    status_by: null,
    deprecated: null,
    score: null,
  };
}

/** JSON nested as deep as a test needs: arrays and objects in turn. */
type Deep = string | Deep[] | { k: Deep };

/** What `lease` had taken when the builder wrote one JSON text, and that text's length. */
type Write = { taken: number; length: number };

/** Every JSON text written while `build` runs, with what `lease` had taken as it was written. */
function stringified<T>(lease: Lease, build: () => T) {
  const original = JSON.stringify.bind(JSON);
  const writes: Write[] = [];

  // the builder writes each summary's JSON with one argument
  // oxlint-disable-next-line anti-slop/no-unknown-parameters -- the spy stands in for JSON.stringify, which takes any value
  const spy = spyOn(JSON, "stringify").mockImplementation((value: unknown) => {
    const text = original(value);
    writes.push({ taken: lease.taken, length: text.length });

    return text;
  });

  try {
    return { result: build(), writes };
  } finally {
    spy.mockRestore();
  }
}

describe("a summary's weight is taken before it is built", () => {
  const versions = Array.from({ length: 12 }, (_, i) => version(i, 5 + i * 7));
  const catalog: Catalog = { kind: "upstream", name: "big", distTags: { latest: "1.0.11", next: "1.0.11" }, versions };
  // what each version keeps and the summary's head, from the uncharged build
  const weights = versions.map((v) => summaryVersion(v).weight);
  const head = summarize({ ...catalog, versions: [] }).weight;

  test("each version's summary and the JSON text weighing it are charged when that text is written", () => {
    const pool = new MemoryPool();
    const lease = pool.request();
    const { result, writes } = stringified(lease, () => keptSummary(catalog, lease));

    // the head's dist-tags, then one manifest a version
    expect(writes.length).toBe(1 + versions.length);
    let alive = head;

    for (const [i, w] of weights.entries()) {
      const write = writes[i + 1];

      if (!write) throw new Error(`no JSON text for version ${i}`);
      alive += KEY + w;
      // on 2fbf383 (summaries took the weight after keep returned): 0 taken at every write
      expect(write.taken).toBeGreaterThanOrEqual(alive + 2 * write.length);
    }

    // settled: what stays taken is what it keeps, the same weight as the uncharged build
    expect(result?.weight).toBe(summarize(catalog).weight);
    expect(lease.taken).toBe(summarize(catalog).weight);
    expect(pool.peakCharged).toBeGreaterThan(lease.taken);
    lease.release();
    expect(pool.charged).toBe(0);
  });

  test("the review's copy is reserved the same way, and settled to what it keeps", () => {
    const pool = new MemoryPool();
    const lease = pool.request();
    const { result, writes } = stringified(lease, () => reviewSummary({ name: "big", distTags: catalog.distTags, versions }, lease));
    const kept = versions.map((v) => summaryVersion({ ...v, score: null }, ["hasInstallScript"]).weight);
    let alive = head;

    expect(writes.length).toBe(1 + versions.length);

    for (const [i, w] of kept.entries()) {
      const write = writes[i + 1];

      if (!write) throw new Error(`no JSON text for version ${i}`);
      alive += KEY + w;
      expect(write.taken).toBeGreaterThanOrEqual(alive + 2 * write.length);
    }

    expect(result?.summary.versions.map((v) => v.manifest)).toEqual(versions.map(() => ({ scripts: { postinstall: `node "setup.js"\n\t\u0001 \u{1f600}` } })));
    expect(lease.taken).toBe(alive);
    lease.release();
  });

  test("a summary that does not fit builds nothing past what fit, and leaves nothing taken", () => {
    const pool = new MemoryPool();
    // room for the head and a few versions, not all twelve
    const lease = pool.request(head + weights.slice(0, 4).reduce((a, b) => a + b, 0) * 3);
    const { result, writes } = stringified(lease, () => keptSummary(catalog, lease));

    expect(result).toBeNull();
    expect(writes.length).toBeLessThan(1 + versions.length);
    expect(lease.taken).toBe(0);
    expect(pool.charged).toBe(0);
  });

  test("the bound is never under jsonWeight of the text, nor under its length", () => {
    let deep: Deep = "end";

    for (let i = 0; i < 20_000; i++) deep = i % 2 === 0 ? [deep] : { k: deep };

    const values = [
      {},
      { s: "" },
      { s: 'quote " back \\ newline \n tab \t nul \u0000 bell \u0007 lone \ud800 pair \u{1f600} é' },
      { "a:b": "c,d", "[": "{", n: -1.2345678901234567e-308, t: true, f: false, z: null, u: undefined, arr: [1, "2", [3, { x: [] }], undefined] },
      versions[11]?.manifest ?? {},
      { deep },
    ];

    for (const v of values) {
      const text = JSON.stringify(v);
      const b = jsonBound(v);

      expect(b.length).toBeGreaterThanOrEqual(text.length);
      expect(b.weight).toBeGreaterThanOrEqual(jsonWeight(text));
    }

    // only the named keys of the root
    const m = versions[3]?.manifest ?? {};
    const cut = { dependencies: m.dependencies, os: m.os };

    expect(jsonBound(m, ["dependencies", "os"]).weight).toBeGreaterThanOrEqual(jsonWeight(JSON.stringify(cut)));
    expect(jsonBound(m, ["dependencies", "os"]).weight).toBeLessThan(jsonBound(m).weight);
  });
});

const noBlobs = Layer.succeed(
  Blobs,
  Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }),
);

describe("Upstream charges a summary and the copy it is built from at once", () => {
  const COUNT = 600;
  const doc = (i: number) => ({ name: "wide", version: `2.0.${i}`, dependencies: { a: "^1.0.0", b: "^2.0.0" }, dist: { tarball: `https://registry.npmjs.org/wide/-/wide-2.0.${i}.tgz`, integrity: `sha512-${"B".repeat(86)}==`, shasum: "2".repeat(40) } });
  const versions = Object.fromEntries(Array.from({ length: COUNT }, (_, i) => [`2.0.${i}`, doc(i)]));
  const time = Object.fromEntries(Array.from({ length: COUNT }, (_, i) => [`2.0.${i}`, new Date(0).toISOString()]));
  const text = JSON.stringify({ name: "wide", "dist-tags": { latest: `2.0.${COUNT - 1}` }, versions, time });
  let db: Awaited<ReturnType<typeof freshDatabase>>;
  let npm: ReturnType<typeof Bun.serve>;

  beforeAll(async () => {
    db = await freshDatabase();
    npm = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: (req) => (new URL(req.url).pathname === "/wide" ? new Response(text, { headers: { "content-type": "application/json" } }) : Response.json({}, { status: 404 })) });
  });

  afterAll(async () => {
    await npm.stop(true);
    await db.drop();
  });

  const layers = (hooks: Layer.Layer<ReleaseHooks> | null) => {
    const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: npm.url.href, legacyAuth: false, namePolicy: "open", admins: [] } as const;
    const base = Layer.mergeAll(Store.postgres(db.url), Clock.fixed({ now: 1, wallNow: 1 }), Analysis.none, noBlobs, Layer.succeed(RegistryConfig, settings));
    const up = Layer.provideMerge(Upstream.layer(npm.url.href, 60_000, null), base);

    return hooks ? Layer.merge(up, hooks) : up;
  };

  const summaries = (request: Lease, keep: (pkg: UpstreamPackage, reserve: Reserve) => Summary<Catalog> | null, hooks: Layer.Layer<ReleaseHooks> | null = null) =>
    Effect.runPromise(Effect.flatMap(Upstream, (up) => up.summaries(["wide"], request, keep)).pipe(Effect.provideService(RequestMemory, request), Effect.provide(layers(hooks)), Effect.scoped));

  const all = (pkg: UpstreamPackage, reserve: Reserve) => keptSummary({ kind: "upstream", name: pkg.name, distTags: pkg.distTags, versions: pkg.versions }, reserve);
  const none = (pkg: UpstreamPackage, reserve: Reserve) => keptSummary({ kind: "upstream", name: pkg.name, distTags: pkg.distTags, versions: [] }, reserve);

  test("a package from the isolate cache: the scored copy and the summary built from it are charged together", async () => {
    const pool = new MemoryPool();
    const first = pool.request();
    await summaries(first, none);
    first.release();
    const cached = pool.charged;

    expect(cached).toBeGreaterThan(0);
    pool.resetPeak();
    const second = pool.request();
    const got = await summaries(second, all);
    const kept = got.get("wide");

    expect(kept?.kind).toBe("found");
    const weight = second.taken;
    // both alive at once while it is built: on 2fbf383 the copy was given back before the summary's weight was taken,
    // so the peak was the cache plus the larger of the two
    expect(pool.peakCharged - cached).toBeGreaterThanOrEqual(COUNT * SCORED_WEIGHT + weight);
    second.release();
    expect(pool.charged).toBe(cached);
  }, 60_000);

  test("a keep that does not reserve what it keeps still has it charged", async () => {
    const pool = new MemoryPool();
    const request = pool.request();
    let weight = 0;

    const got = await summaries(request, (pkg) => {
      const made = summarize({ kind: "upstream", name: pkg.name, distTags: pkg.distTags, versions: pkg.versions });
      weight = made.weight;

      return made;
    });

    expect(got.get("wide")?.kind).toBe("found");
    expect(request.taken).toBe(weight);
    request.release();
  }, 60_000);

  test("the review's copy of a fetched package is held at what it keeps, and nothing is left taken when it does not fit", async () => {
    const pool = new MemoryPool();
    const looks: { pkg: UpstreamPackage; held: Lease }[] = [];
    const hooks = Layer.succeed(ReleaseHooks, ReleaseHooks.of({ afterCommit: () => Effect.void, upstreamFetched: (pkg, held) => Effect.sync(() => void looks.push({ pkg, held })) }));
    const request = pool.request();
    await summaries(request, none, hooks);
    request.release();
    const look = looks[0];

    if (!look) throw new Error("the review was not handed the package");
    expect(look.pkg.versions.length).toBe(COUNT);
    // what it keeps, settled from the allowance taken while it was built
    const expected = reviewSummary({ name: look.pkg.name, distTags: look.pkg.distTags, versions: look.pkg.versions }, { take: () => true, give: () => undefined })?.weight;
    expect(look.held.taken).toBe(expected ?? -1);
    look.held.release();
    expect(pool.charged).toBe(pool.cache().taken);

    // a pool with room for the package but not for the review's copy: the review is not handed it, and nothing stays taken
    const small = new MemoryPool(Math.ceil(text.length * 4));
    const quiet = Layer.succeed(ReleaseHooks, ReleaseHooks.of({ afterCommit: () => Effect.void, upstreamFetched: (_pkg, held) => Effect.sync(() => held.release()) }));
    const tight = small.request();
    await summaries(tight, () => null, quiet);
    tight.release();
    expect(small.charged).toBe(small.cache().taken);
  }, 60_000);
});
