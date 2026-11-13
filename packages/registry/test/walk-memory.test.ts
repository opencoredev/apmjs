// What a resolve of next holds. next's packument weighs 26.6 MiB read and cached, and on 71ebc2d the walk kept it
// (the root) and every dependency's whole packument until it answered, with the isolate cache's blocks counted against
// the request too: `apm add next` warned that its 14 dependencies were not checked (over-budget). The walk now keeps
// of each package only the versions it picks (walk-catalog.ts), and a packument the isolate cache has stays the
// cache's, so next and every dependency fit with room to spare.
//
// next is its real packument, saved from registry.npmjs.org (APM_PACKUMENTS, not in the repository); its direct
// dependencies are fixtures of the shape npm sends for them: as many versions as each has, each version document as
// long as a real one, the @next/swc-* binaries with os and cpu.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { Effect, Layer, Option } from "effect";
import { z } from "zod";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis } from "../src/analysis.ts";
import { OVER_BUDGET_TEXT, REQUEST_METADATA_WEIGHT, resolveResponse, ResolveWait, scanResponse } from "../src/apm.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { RegistryConfig } from "../src/config.ts";
import { Store } from "../src/db.ts";
import { ReleaseHooks } from "../src/hooks.ts";
import { MemoryPool, RequestMemory, type Lease } from "../src/memory.ts";
import { Upstream, type UpstreamPackage } from "../src/upstream.ts";
import { summarize } from "../src/walk-catalog.ts";

const MiB = 1024 * 1024;
const DAY = 86_400_000;
const REAL = process.env.APM_PACKUMENTS ?? join(homedir(), ".cache", "apm-packuments");
const NEXT = join(REAL, "next.json");

const Packument = z.object({ "dist-tags": z.object({ latest: z.string() }), versions: z.record(z.string(), z.object({ dependencies: z.record(z.string(), z.string()).optional(), optionalDependencies: z.record(z.string(), z.string()).optional() }).loose()), time: z.record(z.string(), z.string()) });

/** How many versions npm lists for each of next 16's direct dependencies (the @next/* packages: about 2,800). */
const VERSIONS = new Map([
  ["postcss", 296],
  ["styled-jsx", 122],
  ["@swc/helpers", 82],
  ["caniuse-lite", 973],
  ["baseline-browser-mapping", 188],
  ["sharp", 194],
]);

/** A version a range is met by: an exact version itself, a caret range its lower bound. */
const versionFor = (range: string): string => range.replace(/^[\^~]/, "");

/** The platform fields an @next/swc-* binary's versions carry. */
type Platform = { os?: string[]; cpu?: string[] };

/** A version document as long as npm's for an @next/swc-* binary (about 2 KB), with its platform for those. */
function versionDoc(name: string, version: string, at: number) {
  const platform = /^@next\/swc-([a-z0-9]+)-([a-z0-9]+)/.exec(name);
  const digest = Buffer.from(`${name}@${version}`).toString("base64").padEnd(86, "A").slice(0, 86);
  const fields: Platform = {};

  if (platform?.[1] && platform[2]) {
    fields.os = [platform[1]];
    fields.cpu = [platform[2]];
  }

  return {
    name,
    version,
    license: "MIT",
    _id: `${name}@${version}`,
    maintainers: [{ name: "release-bot", email: "release@example.test" }, { name: "maintainer", email: "maintainer@example.test" }],
    homepage: "https://github.com/example/project#readme",
    bugs: { url: "https://github.com/example/project/issues" },
    ...fields,
    dist: {
      shasum: "1".repeat(40),
      tarball: `https://registry.npmjs.org/${name}/-/${name.split("/").at(-1)}-${version}.tgz`,
      fileCount: 3,
      integrity: `sha512-${digest}==`,
      signatures: [{ sig: `MEUCIQ${"s".repeat(90)}`, keyid: "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U" }],
      attestations: { url: `https://registry.npmjs.org/-/npm/v1/attestations/${name}@${version}`, provenance: { predicateType: "https://slsa.dev/provenance/v1" } },
      unpackedSize: 90_463_204,
    },
    main: "index.js",
    engines: { node: ">= 10" },
    _npmUser: { name: "GitHub Actions", email: "npm-oidc-no-reply@github.com" },
    description: `${name} ${"d".repeat(120)}`,
    repository: { url: "git+https://github.com/example/project.git", type: "git", directory: "packages/one" },
    _nodeVersion: "24.11.1",
    _npmVersion: "11.6.2",
    gitHead: "0".repeat(40),
    publishedAt: at,
  };
}

/** The packument npm sends for one of next's dependencies: `count` versions, the one next asks for the newest. */
function dependencyPackument(name: string, range: string, at: number): string {
  const wanted = versionFor(range);
  const count = VERSIONS.get(name) ?? 2800;
  const versions: Record<string, ReturnType<typeof versionDoc>> = {};
  const time: Record<string, string> = {};

  for (let i = 0; i < count - 1; i++) {
    const v = `0.${Math.floor(i / 100)}.${i % 100}`;
    versions[v] = versionDoc(name, v, at);
    time[v] = new Date(at).toISOString();
  }

  versions[wanted] = versionDoc(name, wanted, at);
  time[wanted] = new Date(at).toISOString();

  return JSON.stringify({ name, "dist-tags": { latest: wanted }, versions, time });
}

const Answer = z.object({
  status: z.number(),
  version: z.string().nullish(),
  tree: z.object({ unchecked: z.number(), packages: z.array(z.object({ name: z.string(), version: z.string() })), uncheckedDeps: z.array(z.object({ dependency: z.string(), reason: z.string() })) }),
});

const ScanAnswer = z.object({ unchecked: z.array(z.object({ package: z.string(), version: z.string(), reason: z.string() })) });

const noBlobs = Layer.succeed(
  Blobs,
  Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }),
);

describe.skipIf(!existsSync(NEXT))("a resolve of next holds its tree's summaries, not their packuments", () => {
  const nextText = existsSync(NEXT) ? readFileSync(NEXT, "utf8") : "{}";
  const next = Packument.parse(JSON.parse(nextText));
  const latest = next["dist-tags"].latest;
  const manifest = next.versions[latest];
  const deps = { ...manifest?.dependencies, ...manifest?.optionalDependencies };
  // a week after next's latest was published: nothing in the tree is inside its cooldown
  const now = Date.parse(next.time[latest] ?? "") + 7 * DAY;
  const texts = new Map(Object.entries(deps).map(([name, range]) => [name, dependencyPackument(name, range, now - 30 * DAY)]));
  let db: Awaited<ReturnType<typeof freshDatabase>>;
  let npm: ReturnType<typeof Bun.serve>;

  beforeAll(async () => {
    db = await freshDatabase();
    npm = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: (req) => {
        const name = decodeURIComponent(new URL(req.url).pathname.slice(1));
        const text = name === "next" ? nextText : texts.get(name);

        return text === undefined ? Response.json({ error: "Not found" }, { status: 404 }) : new Response(text, { headers: { "content-type": "application/json" } });
      },
    });
  });

  afterAll(async () => {
    await npm.stop(true);
    await db.drop();
  });

  /** The real Upstream layer over the stand-in npm, and what the routes read beside it. */
  const layers = () => {
    const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: npm.url.href, legacyAuth: false, namePolicy: "open", admins: [] } as const;
    const base = Layer.mergeAll(Store.postgres(db.url), Clock.fixed({ now, wallNow: now }), Analysis.none, noBlobs, Layer.succeed(RegistryConfig, settings), Layer.succeed(ResolveWait, { maxMs: 0, pollMs: 1 }));

    return Layer.provideMerge(Upstream.layer(npm.url.href, 60_000, null), base);
  };

  /** `program` against `layers`, under `request`. */
  const run = <A, E>(program: Effect.Effect<A, E, Layer.Success<ReturnType<typeof layers>> | RequestMemory>, request: Lease): Promise<A> =>
    Effect.runPromise(program.pipe(Effect.provideService(RequestMemory, request), Effect.provide(layers()), Effect.scoped));

  const resolveNext = (request: Lease) =>
    run(
      Effect.flatMap(resolveResponse(new URL("http://registry.test/-/apm/v1/resolve?name=next&range=latest")), (res) => Effect.promise(async () => Answer.parse({ status: res.status, ...z.object({}).loose().parse(await res.json()) }))),
      request,
    );

  test("every dependency of next is checked, none over-budget, cold and from the isolate cache", async () => {
    const pool = new MemoryPool();

    for (const pass of ["cold", "cached"]) {
      const request = pool.request();
      const r = await resolveNext(request);
      const overBudget = r.tree.uncheckedDeps.filter((d) => d.reason === OVER_BUDGET_TEXT);

      process.stdout.write(`[walk-memory] next ${pass}: ${r.tree.packages.length} checked, ${r.tree.unchecked} unchecked (${overBudget.length} over-budget); the request held ${(request.peakTaken / MiB).toFixed(1)} MiB at most and ${(request.taken / MiB).toFixed(2)} MiB once answered, the pool ${(pool.peakCharged / MiB).toFixed(1)} MiB\n`);
      expect(r.status).toBe(200);
      expect(r.version).toBe(latest);
      // on 71ebc2d: 7 or more of next's 15 dependencies over-budget
      expect(overBudget).toEqual([]);
      expect(r.tree.unchecked).toBe(0);
      expect(r.tree.packages.map((p) => p.name).toSorted()).toEqual(Object.keys(deps).toSorted());
      expect(request.peakTaken).toBeLessThanOrEqual(REQUEST_METADATA_WEIGHT);
      // what the request still holds is the root's summary, not next's 26.6 MiB packument
      expect(request.taken).toBeLessThan(1 * MiB);
      request.release();
      expect(pool.charged).toBe(pool.cache().taken);
    }
  }, 120_000);

  test("a package the isolate cache has is read through, never charged to the request", async () => {
    const pool = new MemoryPool();
    const keep = (pkg: UpstreamPackage) => summarize({ kind: "upstream", name: pkg.name, distTags: pkg.distTags, versions: pkg.versions.filter((v) => v.version === latest) });
    const read = (request: Lease) => run(Effect.flatMap(Upstream, (up) => up.summaries(["next"], request, keep)), request);
    const first = pool.request();
    const cold = await read(first);
    first.release();
    const cached = pool.cache().taken;
    const second = pool.request();
    const warm = await read(second);

    process.stdout.write(`[walk-memory] next's summary from the isolate cache: the request held ${(second.peakTaken / MiB).toFixed(2)} MiB at most beside the cache's ${(cached / MiB).toFixed(1)} MiB\n`);
    expect([cold.get("next")?.kind, warm.get("next")?.kind]).toEqual(["found", "found"]);
    // the cache kept next's packument, and the request that read it again held only the summary of one version
    expect(cached).toBeGreaterThan(20 * MiB);
    expect(second.peakTaken).toBeLessThan(1 * MiB);
    expect(pool.cache().taken).toBe(cached);
    second.release();
    expect(pool.charged).toBe(cached);
  }, 120_000);

  test("the review's look at next is handed what it reads, so it does not keep next's packument while it runs", async () => {
    const pool = new MemoryPool();
    const looks: { pkg: UpstreamPackage; held: Lease }[] = [];
    const hooks = Layer.succeed(ReleaseHooks, ReleaseHooks.of({ afterCommit: () => Effect.void, upstreamFetched: (pkg, held) => Effect.sync(() => void looks.push({ pkg, held })) }));
    const request = pool.request();
    const keep = (pkg: UpstreamPackage) => summarize({ kind: "upstream", name: pkg.name, distTags: pkg.distTags, versions: [] });
    await Effect.runPromise(Effect.flatMap(Upstream, (up) => up.summaries(["next"], request, keep)).pipe(Effect.provideService(RequestMemory, request), Effect.provide(Layer.merge(layers(), hooks)), Effect.scoped));
    request.release();
    const look = looks[0];

    if (!look) throw new Error("the review was not handed next");
    const cached = pool.cache().taken;
    process.stdout.write(`[walk-memory] the review's look at next holds ${(look.held.taken / MiB).toFixed(2)} MiB beside the cache's ${(cached / MiB).toFixed(1)} MiB\n`);
    // what considerUpstream reads: every version, each with its publish time and digest
    expect(look.pkg.versions.length).toBe(Object.keys(next.versions).length);
    expect(look.pkg.versions.find((v) => v.version === latest)?.integrity).toMatch(/^sha512-/);
    expect(look.pkg.distTags.latest).toBe(latest);
    // under 1 KiB a version, against 6.6 KiB a version for next's packument; on ed380b3 it held all 26.6 MiB
    expect(look.held.taken).toBeLessThan(look.pkg.versions.length * 1024);
    expect(look.held.taken).toBeLessThan(cached / 5);
    look.held.release();
    // the cache's entry is the only holder of next's packument now, so the pool may take it back
    expect(pool.charged).toBe(cached);
  }, 120_000);

  test("a scan of next's tree checks every package, none over-budget", async () => {
    const pool = new MemoryPool();
    const request = pool.request();
    const packages = [{ name: "next", version: latest }, ...Object.entries(deps).map(([name, range]) => ({ name, version: versionFor(range) }))];
    const req = new Request("http://registry.test/-/apm/v1/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ packages }) });
    const r = await run(Effect.flatMap(scanResponse(req, { kind: "anon" }), (res) => Effect.promise(async () => ScanAnswer.parse(await res.json()))), request);

    process.stdout.write(`[walk-memory] scan of next's ${packages.length} packages: ${r.unchecked.filter((u) => u.reason === OVER_BUDGET_TEXT).length} over-budget; the request held ${(request.peakTaken / MiB).toFixed(1)} MiB at most\n`);
    expect(r.unchecked.filter((u) => u.reason === OVER_BUDGET_TEXT)).toEqual([]);
    expect(request.peakTaken).toBeLessThanOrEqual(REQUEST_METADATA_WEIGHT);
    // each package's summary is given back once it is checked
    expect(request.taken).toBe(0);
    request.release();
  }, 120_000);
});
