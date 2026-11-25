// The OSSF malicious-packages feed (osv.ts): a name@version OSV lists under a MAL- id is refused by resolve and by
// scan in every mode, citing the id, and only that exact version is. A feed that does not answer refuses nothing.
// Found on 2026-11-25: ticket-symbol-stream-native@1.0.0 (MAL-2026-20520), a stub whose payload is a dependency on a
// URL tarball, scored 100/A with verdict install. npm and OSV are local stand-ins; the database is a real Postgres.
import { afterAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { Effect, Layer, Option } from "effect";
import { z } from "zod";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis } from "../src/analysis.ts";
import { resolveResponse, ResolveWait, scanResponse } from "../src/apm.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { RegistryConfig } from "../src/config.ts";
import type { Caller } from "../src/server.ts";
import { Store } from "../src/db.ts";
import { KnownMalicious, OSV_BATCH, osvFeed, REQUEST_BUDGET_MS, type PackageVersion } from "../src/osv.ts";
import { Client } from "pg";
import { Upstream } from "../src/upstream.ts";
import { MemoryPool, RequestMemory } from "../src/memory.ts";

const POOL = new MemoryPool();
const NOW = Date.parse("2026-11-12T00:00:00Z");
const DAY = 86_400_000;

/** npm's versions per package, oldest first, and each one's dependencies. */
const NPM = new Map(
  Object.entries({
    "evil-root": { versions: ["1.0.0"], dependencies: {} },
    "half-evil": { versions: ["1.0.0", "2.0.0"], dependencies: {} },
    "evil-dep": { versions: ["1.0.0"], dependencies: {} },
    "uses-evil": { versions: ["1.0.0"], dependencies: { "evil-dep": "^1.0.0" } },
    "plain-pkg": { versions: ["1.0.0"], dependencies: {} },
  }),
);

/** What the OSV stand-in lists: name@version to its advisory ids, a GHSA one included (not a MAL- id, so not malice). */
const LISTED = new Map(Object.entries({
  "evil-root@1.0.0": ["MAL-2026-0001"],
  "half-evil@2.0.0": ["MAL-2026-0002"],
  "evil-dep@1.0.0": ["MAL-2026-0003"],
  // listed, and no longer on npm (as getsolara@1.0.1 is not): a lockfile may still pin it
  "evil-dep@0.9.0": ["MAL-2026-0004"],
  "plain-pkg@1.0.0": ["GHSA-xxxx-yyyy-zzzz"],
  // a name published on this registry: npm's advisory is not about it
  "@local/evil@1.0.0": ["MAL-2026-0005"],
  // npm's 2.0.0 of a name this registry published 1.0.0 of: a different artifact, still npm's
  "@local/evil@2.0.0": ["MAL-2026-0007"],
}));

/** Versions whose first batch answer has no MAL- id but a next page that has one. */
const PAGED = new Map([["paged-pkg@1.0.0", "MAL-2026-0006"]]);

const npm = Bun.serve({
  port: 0,
  hostname: "127.0.0.1",
  fetch(req): Response {
    const name = decodeURIComponent(new URL(req.url).pathname.slice(1));
    const pkg = NPM.get(name);

    if (!pkg) return Response.json({ error: "Not found" }, { status: 404 });

    const integrity = `sha512-${createHash("sha512").update(name).digest("base64")}`;

    const versions = Object.fromEntries(
      pkg.versions.map((v) => [v, { name, version: v, main: "index.js", license: "MIT", dependencies: pkg.dependencies, dist: { tarball: `https://npm.invalid/${name}/-/${name}-${v}.tgz`, shasum: "1".repeat(40), integrity } }]),
    );

    const time = Object.fromEntries(pkg.versions.map((v) => [v, new Date(NOW - 10 * DAY).toISOString()]));

    return Response.json({ name, "dist-tags": { latest: pkg.versions.at(-1) }, versions, time });
  },
});

const OsvQuery = z.object({ queries: z.array(z.object({ package: z.object({ name: z.string(), ecosystem: z.string() }), version: z.string() })) });

/** OSV, standing in: counts the packages and batches asked about, fails while `down`, answers late while `stallMs`. */
const osv = { asked: 0, batches: 0, down: false, stallMs: 0, pagesDown: false };

const PageQuery = z.object({ package: z.object({ name: z.string() }), version: z.string(), page_token: z.string() });

const osvServer = Bun.serve({
  port: 0,
  hostname: "127.0.0.1",
  async fetch(req): Promise<Response> {
    if (osv.stallMs > 0) await Bun.sleep(osv.stallMs);

    if (osv.down) return new Response("unavailable", { status: 503 });

    if (new URL(req.url).pathname.endsWith("/v1/query")) {
      if (osv.pagesDown) return new Response("unavailable", { status: 503 });
      const q = PageQuery.parse(await req.json());
      const id = PAGED.get(`${q.package.name}@${q.version}`);

      return Response.json({ vulns: id ? [{ id, modified: "2026-11-24T00:00:00Z" }] : [] });
    }

    const body = OsvQuery.parse(await req.json());

    osv.asked += body.queries.length;
    osv.batches++;

    const answer = (q: z.infer<typeof OsvQuery>["queries"][number]) => {
      const key = `${q.package.name}@${q.version}`;

      if (PAGED.has(key)) return { vulns: [{ id: "GHSA-aaaa-bbbb-cccc", modified: "2026-11-24T00:00:00Z" }], next_page_token: "p2" };

      return { vulns: (q.package.ecosystem === "npm" ? (LISTED.get(key) ?? []) : []).map((id) => ({ id, modified: "2026-11-24T00:00:00Z" })) };
    };

    return Response.json({ results: body.queries.map(answer) });
  },
});

afterAll(() => {
  npm.stop(true);
  osvServer.stop(true);
});

const noBlobs = Layer.succeed(
  Blobs,
  Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }),
);

const SETTINGS = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: npm.url.href, legacyAuth: false, namePolicy: "open", admins: [] } as const;

let database: Promise<{ url: string }> | null = null;

/** Every service a request uses here, the feed at a fresh OSV root each call (its answers are kept by root). */
async function layers(feed: boolean) {
  database ??= freshDatabase();
  const { url } = await database;
  const base = Layer.mergeAll(Store.postgres(url), Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs, Layer.succeed(ResolveWait, { maxMs: 0, pollMs: 10 }), Layer.succeed(RegistryConfig, SETTINGS), RequestMemory.layer(POOL));
  const withFeed = feed ? Layer.provideMerge(osvFeed(`${osvServer.url.href}${crypto.randomUUID()}/`), base) : base;

  return Layer.provideMerge(Upstream.layer(npm.url.href, 60_000, null), withFeed);
}

const ResolveBody = z.object({
  error: z.string().optional(),
  version: z.string().nullish(),
  skipped: z.array(z.object({ version: z.string(), reason: z.string() })).optional(),
  knownMalicious: z.array(z.object({ name: z.string(), version: z.string(), ids: z.array(z.string()) })).optional(),
});

type Answer = { status: number; body: z.infer<typeof ResolveBody> };

async function resolve(name: string, opts: { strict?: boolean; feed?: boolean } = {}): Promise<Answer> {
  const params = new URLSearchParams({ name, range: "latest", wait: "0" });

  if (opts.strict) params.set("strict", "1");
  const program = Effect.flatMap(resolveResponse(new URL(`http://registry.test/-/apm/v1/resolve?${params}`)), (res) => Effect.promise(async () => ({ status: res.status, body: ResolveBody.parse(await res.json()) })));

  return Effect.runPromise(program.pipe(Effect.provide(await layers(opts.feed ?? true)), Effect.scoped));
}

const ScanAnswer = z.object({
  advisories: z.array(z.object({ package: z.string(), version: z.string(), level: z.string(), description: z.string(), url: z.string().nullable() })),
  blocked: z.array(z.object({ package: z.string(), version: z.string(), kind: z.string() })),
});

type ScanAnswer = z.infer<typeof ScanAnswer>;

async function scan(packages: PackageVersion[]): Promise<ScanAnswer> {
  const req = new Request("http://registry.test/-/apm/v1/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ packages }) });
  const caller: Caller = { kind: "user", user: "someone", tokenHash: "0".repeat(64), scope: "publish" };
  const program = Effect.flatMap(scanResponse(req, caller), (res) => Effect.promise(async () => ScanAnswer.parse(await res.json())));

  return Effect.runPromise(program.pipe(Effect.provide(await layers(true)), Effect.scoped));
}

describe("the OSSF malicious-packages feed", () => {
  test("a listed root version is refused in both modes, citing its MAL- id", async () => {
    for (const strict of [false, true]) {
      const r = await resolve("evil-root", { strict });

      expect(r.status).toBe(422);
      expect(r.body.knownMalicious).toEqual([{ name: "evil-root", version: "1.0.0", ids: ["MAL-2026-0001"] }]);
      expect(r.body.skipped?.[0]?.reason).toStartWith("known malicious:");
      expect(r.body.skipped?.[0]?.reason).toContain("MAL-2026-0001");
    }
  });

  test("only the listed version is skipped: an older one not listed is picked", async () => {
    const r = await resolve("half-evil");

    expect(r.status).toBe(200);
    expect(r.body.version).toBe("1.0.0");
    expect(r.body.skipped?.map((s) => s.version)).toEqual(["2.0.0"]);
  });

  test("a listed dependency refuses the install of what depends on it", async () => {
    const r = await resolve("uses-evil");

    expect(r.status).toBe(422);
    expect(r.body.error).toContain("evil-dep@1.0.0 (MAL-2026-0003)");
    expect(r.body.knownMalicious).toEqual([{ name: "evil-dep", version: "1.0.0", ids: ["MAL-2026-0003"] }]);
  });

  test("an advisory that is not a MAL- id is not malice, and without the feed nothing is refused", async () => {
    expect((await resolve("plain-pkg")).body.knownMalicious).toBeUndefined();
    expect((await resolve("plain-pkg")).status).toBe(200);
    expect((await resolve("evil-root", { feed: false })).status).toBe(200);
  });

  test("scan: a listed version is a fatal advisory and blocked, even one npm no longer has", async () => {
    const out = await scan([
      { name: "evil-dep", version: "1.0.0" },
      { name: "evil-dep", version: "0.9.0" },
      { name: "half-evil", version: "2.0.0" },
      { name: "half-evil", version: "1.0.0" },
    ]);

    expect(out.blocked.filter((b) => b.kind === "malicious").map((b) => `${b.package}@${b.version}`)).toEqual(["evil-dep@1.0.0", "evil-dep@0.9.0", "half-evil@2.0.0"]);
    const fatal = out.advisories.find((a) => a.package === "evil-dep");

    expect(fatal?.level).toBe("fatal");
    expect(fatal?.description).toContain("MAL-2026-0003");
    expect(fatal?.url).toBe("https://osv.dev/vulnerability/MAL-2026-0003");
    expect(out.blocked.some((b) => b.package === "half-evil" && b.version === "1.0.0")).toBe(false);
  });

  // review of bb6c5ae, finding 1, and of a02bd4b, finding 2: npm's advisory was applied to a version published here,
  // and then a version published here hid npm's other versions of that name
  test("a version published on this registry is not matched against npm's advisories; its name's other versions are", async () => {
    database ??= freshDatabase();
    const c = new Client({ connectionString: (await database).url });

    await c.connect();

    try {
      await c.query(`INSERT INTO users (name, password_hash, email, created_at) VALUES ('u', 'x', 'u@example.test', 0)`);
      await c.query(`INSERT INTO packages (name, created_at, modified_at, dist_tags) VALUES ('@local/evil', 0, 0, '{"latest":"1.0.0"}'::jsonb)`);
      await c.query(
        `INSERT INTO versions (package, version, manifest, shasum, integrity, size, tarball_key, published_at, published_by)
         VALUES ('@local/evil', '1.0.0', $1::jsonb, $2, 'sha1-x', 10, 'sha512/x', $3, 'u')`,
        [JSON.stringify({ name: "@local/evil", version: "1.0.0" }), "0".repeat(40), NOW - 10 * DAY],
      );
    } finally {
      await c.end();
    }

    const out = await scan([{ name: "@local/evil", version: "1.0.0" }, { name: "@local/evil", version: "2.0.0" }]);

    expect(out.blocked.filter((b) => b.kind === "malicious").map((b) => b.version)).toEqual(["2.0.0"]);
  });

  // review of bb6c5ae, finding 2: each page and each pass of a resolve waited on OSV's timeout again
  test("a stalled feed costs a resolve one budget at most, and it still answers", async () => {
    osv.stallMs = REQUEST_BUDGET_MS + 2_000;

    try {
      const t0 = performance.now();
      const r = await resolve("half-evil");

      expect(r.status).toBe(200);
      expect(performance.now() - t0).toBeLessThan(REQUEST_BUDGET_MS + 1_500);
    } finally {
      osv.stallMs = 0;
    }
  });
});

describe("osvFeed", () => {
  const lookup = (root: string, pkgs: PackageVersion[]) => Effect.runPromise(Effect.flatMap(KnownMalicious, (k) => k.lookup(pkgs)).pipe(Effect.provide(osvFeed(root))));

  test("an answer is kept: the same versions asked again cost no query", async () => {
    const root = `${osvServer.url.href}${crypto.randomUUID()}/`;
    const pkgs = [{ name: "evil-root", version: "1.0.0" }, { name: "plain-pkg", version: "1.0.0" }];
    const before = osv.asked;

    expect(await lookup(root, pkgs)).toEqual([{ name: "evil-root", version: "1.0.0", ids: ["MAL-2026-0001"] }]);
    expect(await lookup(root, pkgs)).toEqual([{ name: "evil-root", version: "1.0.0", ids: ["MAL-2026-0001"] }]);
    expect(osv.asked - before).toBe(2);
  });

  test("a feed that does not answer lists nothing, and that is not kept", async () => {
    const root = `${osvServer.url.href}${crypto.randomUUID()}/`;
    const pkgs = [{ name: "evil-root", version: "1.0.0" }];

    osv.down = true;

    try {
      expect(await lookup(root, pkgs)).toEqual([]);
    } finally {
      osv.down = false;
    }

    expect(await lookup(root, pkgs)).toEqual([{ name: "evil-root", version: "1.0.0", ids: ["MAL-2026-0001"] }]);
  });

  test("one feed's lookups share one budget: after a stall, the next lookup does not wait again", async () => {
    const root = `${osvServer.url.href}${crypto.randomUUID()}/`;

    const twice = Effect.gen(function* () {
      const k = yield* KnownMalicious;

      return [yield* k.lookup([{ name: "evil-root", version: "1.0.0" }]), yield* k.lookup([{ name: "evil-dep", version: "1.0.0" }])];
    });

    osv.stallMs = REQUEST_BUDGET_MS + 2_000;

    try {
      const t0 = performance.now();

      expect(await Effect.runPromise(twice.pipe(Effect.provide(osvFeed(root))))).toEqual([[], []]);
      expect(performance.now() - t0).toBeLessThan(REQUEST_BUDGET_MS + 1_000);
    } finally {
      osv.stallMs = 0;
    }
  });

  // Greptile on ac3383b: the budget was wall-clock from the first lookup, so a walk slower than it skipped the feed
  test("time spent outside OSV does not use the request's budget", async () => {
    const root = `${osvServer.url.href}${crypto.randomUUID()}/`;

    const slowWalk = Effect.gen(function* () {
      const k = yield* KnownMalicious;
      const first = yield* k.lookup([{ name: "evil-root", version: "1.0.0" }]);

      yield* Effect.promise(() => Bun.sleep(REQUEST_BUDGET_MS + 200));

      return [first, yield* k.lookup([{ name: "evil-dep", version: "1.0.0" }])];
    });

    expect(await Effect.runPromise(slowWalk.pipe(Effect.provide(osvFeed(root))))).toEqual([[{ name: "evil-root", version: "1.0.0", ids: ["MAL-2026-0001"] }], [{ name: "evil-dep", version: "1.0.0", ids: ["MAL-2026-0003"] }]]);
  });

  // review of bb6c5ae, finding 3: a result with more pages was read as its first page alone, and kept as clean
  test("a version's next pages are read, and an answer missing a page is not kept", async () => {
    const root = `${osvServer.url.href}${crypto.randomUUID()}/`;
    const pkgs = [{ name: "paged-pkg", version: "1.0.0" }];

    osv.pagesDown = true;

    try {
      expect(await lookup(root, pkgs)).toEqual([]);
    } finally {
      osv.pagesDown = false;
    }

    expect(await lookup(root, pkgs)).toEqual([{ name: "paged-pkg", version: "1.0.0", ids: ["MAL-2026-0006"] }]);
  });

  // review of a02bd4b, finding 1: a page that could not be read dropped the batch's other hits
  test("a version whose next page cannot be read does not hide another version's hit in the same batch", async () => {
    const root = `${osvServer.url.href}${crypto.randomUUID()}/`;

    osv.pagesDown = true;

    try {
      expect(await lookup(root, [{ name: "evil-root", version: "1.0.0" }, { name: "paged-pkg", version: "1.0.0" }])).toEqual([{ name: "evil-root", version: "1.0.0", ids: ["MAL-2026-0001"] }]);
    } finally {
      osv.pagesDown = false;
    }

    expect(await lookup(root, [{ name: "paged-pkg", version: "1.0.0" }])).toEqual([{ name: "paged-pkg", version: "1.0.0", ids: ["MAL-2026-0006"] }]);
  });

  test("more versions than one batch holds are asked in batches, the last one's included", async () => {
    const root = `${osvServer.url.href}${crypto.randomUUID()}/`;
    const pkgs = [...Array.from({ length: OSV_BATCH }, (_, i) => ({ name: `filler-${i}`, version: "1.0.0" })), { name: "evil-root", version: "1.0.0" }];
    const before = osv.batches;

    expect(await lookup(root, pkgs)).toEqual([{ name: "evil-root", version: "1.0.0", ids: ["MAL-2026-0001"] }]);
    expect(osv.batches - before).toBe(2);
  });

  // review of bb6c5ae, finding 4: anything a scan sent was forwarded and kept
  test("a name or version that is not an npm coordinate is not asked about", async () => {
    const root = `${osvServer.url.href}${crypto.randomUUID()}/`;
    const before = osv.asked;

    expect(await lookup(root, [{ name: "../etc", version: "1.0.0" }, { name: "ok-name", version: "1.0.0 || x" }, { name: "ok-name", version: "x".repeat(300) }])).toEqual([]);
    expect(osv.asked).toBe(before);
  });
});
