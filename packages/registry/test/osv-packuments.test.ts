// The OSSF malicious-packages feed on the npm protocol routes (osv.ts advisoriesFor, apm.ts, fast-tarball.ts,
// degraded.ts). Found by the launch smoke on 2026-11-25 (HOME-351): registry.apmjs.dev served ugent_uws 10.9.9 to
// 10.9.11 with dist-tag latest = 10.9.11, and that tarball answered 200. It runs a wget exfil preinstall and OSSF lists
// it as MAL-2026-20430. #31 made resolve, scan and explain refuse it, but a stock `npm install ugent_uws` through the
// plain registry read only the packument and tarball routes, which did not ask the feed. Now a listed version is left out
// of every packument (dist-tags moved or dropped as for a confirmed version), its version document is a 404 and its
// tarball a 403, each citing the MAL- id, from one small OSV query per name. A feed that does not answer refuses nothing.
// npm and OSV are local stand-ins on 127.0.0.1; the database is a real Postgres.
import { afterAll, afterEach, beforeAll, describe, expect, setSystemTime, test } from "bun:test";
import { createHash } from "node:crypto";
import { Effect, Layer, Option } from "effect";
import { z } from "zod";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis } from "../src/analysis.ts";
import { Auth } from "../src/auth.ts";
import { apmRoute, upstreamRoute } from "../src/apm.ts";
import { Blobs } from "../src/blobs.ts";
import { BLOCKLIST_KEY, Blocklist, type BlocklistBody, type BlocklistReader } from "../src/blocklist.ts";
import { Clock } from "../src/clock.ts";
import { RegistryConfig } from "../src/config.ts";
import { Store } from "../src/db.ts";
import { degradedRoute } from "../src/degraded.ts";
import { EdgeChecks } from "../src/edge-checks.ts";
import { MemoryPool, RequestMemory } from "../src/memory.ts";
import { KnownMalicious, listedAmong, listedNotice, NAME_FRESH_MS, NAME_STALE_MS, osvFeed, REQUEST_BUDGET_MS, type Advisory } from "../src/osv.ts";
import { installStamp, Upstream } from "../src/upstream.ts";
import { summarize } from "../src/kept-package.ts";
import { digestLabel, digestOf } from "../src/digest.ts";
import { packument as localPackument } from "../src/server.ts";
import { Client } from "pg";

const POOL = new MemoryPool();
const NOW = Date.parse("2026-11-25T00:00:00Z");
const DAY = 86_400_000;
const INSTALL_ACCEPT = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*";
const NPM_CLIENT = "npm/11.6.0 node/v24.11.0 linux x64 workspaces/false";

/** npm's packages: versions oldest first, and dist-tags besides latest (the newest). */
type NpmPackage = { versions: string[]; tags?: Record<string, string> };

const NPM = new Map(Object.entries<NpmPackage>({
  // shaped like ugent_uws: an empty 9.0.0, then inflated versions that are all listed
  "evil-tagged": { versions: ["9.0.0", "10.9.9", "10.9.10", "10.9.11"], tags: { next: "10.9.11", old: "9.0.0" } },
  ranged: { versions: ["1.0.0", "1.5.0", "1.6.0", "2.0.0"] },
  "all-listed": { versions: ["1.0.0", "1.1.0"] },
  clean: { versions: ["1.0.0", "1.1.0"] },
  withdrawn: { versions: ["1.0.0"] },
  // an old npm name the proxy accepts (capitals): the feed is asked about it as written
  "Legacy-Name": { versions: ["1.0.0", "1.1.0"] },
  // a tag naming a version npm's packument does not list (its document unreadable or gone)
  "orphan-tag": { versions: ["1.0.0"], tags: { beta: "2.0.0" } },
  // two advisories, one of which OSV fails to send
  "half-read": { versions: ["1.0.0", "1.1.0", "1.2.0"] },
  // listed while a slower request about it is still out
  flip: { versions: ["1.0.0", "1.1.0"] },
  // its latest an apm reviewer confirmed malicious (the package page's answer test)
  "confirmed-latest": { versions: ["1.0.0", "2.0.0"] },
  // more versions than a kept summary holds: a stable 1.0.0 published first, 201 nightlies, then a listed 9.0.0
  truncated: { versions: ["1.0.0", ...Array.from({ length: 201 }, (_, i) => `8.0.0-nightly.${i}`), "9.0.0"] },
} satisfies Record<string, NpmPackage>));

/** OSV's advisories per name: ids only in the batch answer, then each one read whole. */
type Vuln = { id: string; withdrawn?: string; affected?: unknown[] };

const VULNS = new Map(Object.entries<Vuln[]>({
  "evil-tagged": [
    { id: "MAL-2026-1000", affected: [{ package: { name: "evil-tagged", ecosystem: "npm" }, versions: ["10.9.9", "10.9.10", "10.9.11", "10.9.8"] }] },
    { id: "GHSA-aaaa-bbbb-cccc", affected: [{ package: { name: "evil-tagged", ecosystem: "npm" }, versions: ["9.0.0"] }] },
  ],
  // 1.5.0 up to and including 1.6.0; a GIT range and another name's entry name nothing here
  ranged: [
    {
      id: "MAL-2026-1001",
      affected: [
        { package: { name: "ranged", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "1.5.0" }, { last_affected: "1.6.0" }] }, { type: "GIT", events: [{ introduced: "0" }] }] },
        { package: { name: "other", ecosystem: "npm" }, versions: ["1.0.0"] },
      ],
    },
  ],
  "all-listed": [{ id: "MAL-2026-1002", affected: [{ package: { name: "all-listed", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }] }] }],
  clean: [{ id: "GHSA-xxxx-yyyy-zzzz", affected: [{ package: { name: "clean", ecosystem: "npm" }, versions: ["1.0.0"] }] }],
  withdrawn: [{ id: "MAL-2026-1003", withdrawn: "2026-11-24T00:00:00Z", affected: [{ package: { name: "withdrawn", ecosystem: "npm" }, versions: ["1.0.0"] }] }],
  "Legacy-Name": [{ id: "MAL-2026-1004", affected: [{ package: { name: "Legacy-Name", ecosystem: "npm" }, versions: ["1.1.0"] }] }],
  "orphan-tag": [{ id: "MAL-2026-1005", affected: [{ package: { name: "orphan-tag", ecosystem: "npm" }, versions: ["2.0.0"] }] }],
  truncated: [{ id: "MAL-2026-1009", affected: [{ package: { name: "truncated", ecosystem: "npm" }, versions: ["9.0.0"] }] }],
  flip: [],
  "half-read": [
    { id: "MAL-2026-1006", affected: [{ package: { name: "half-read", ecosystem: "npm" }, versions: ["1.2.0"] }] },
    { id: "MAL-2026-1007", affected: [{ package: { name: "half-read", ecosystem: "npm" }, versions: ["1.1.0"] }] },
  ],
} satisfies Record<string, Vuln[]>));

const tgz = (name: string, v: string): Uint8Array => new TextEncoder().encode(`tarball of ${name}@${v}`);
const integrity = (name: string, v: string): string => `sha512-${createHash("sha512").update(tgz(name, v)).digest("base64")}`;
const shasum = (name: string, v: string): string => createHash("sha1").update(tgz(name, v)).digest("hex");

const npm = Bun.serve({
  port: 0,
  hostname: "127.0.0.1",
  fetch(req): Response {
    const parts = decodeURIComponent(new URL(req.url).pathname.slice(1)).split("/");
    const name = parts[0] ?? "";
    const pkg = NPM.get(name);

    if (!pkg) return Response.json({ error: "Not found" }, { status: 404 });
    const doc = (v: string) => ({ name, version: v, dist: { tarball: `${npm.url.href}${name}/-/${name}-${v}.tgz`, shasum: shasum(name, v), integrity: integrity(name, v) } });

    if (parts[1] === "-") {
      const v = (parts[2] ?? "").slice(name.length + 1, -".tgz".length);

      return pkg.versions.includes(v) ? new Response(tgz(name, v)) : new Response("missing", { status: 404 });
    }

    if (parts[1] !== undefined) return pkg.versions.includes(parts[1]) ? Response.json(doc(parts[1])) : Response.json({ error: "Not found" }, { status: 404 });
    const versions = Object.fromEntries(pkg.versions.map((v) => [v, doc(v)]));
    // a long list a minute apart, oldest first, so a kept summary's publish-time window leaves the first ones out
    const time = Object.fromEntries(pkg.versions.map((v, i) => [v, new Date(NOW - 30 * DAY + (pkg.versions.length > 200 ? i * 60_000 : 0)).toISOString()]));

    return Response.json({ name, "dist-tags": { latest: pkg.versions.at(-1), ...pkg.tags }, versions, time });
  },
});

/** A query for every version of one name: no version in it. */
const NameQuery = z.object({ queries: z.array(z.strictObject({ package: z.object({ name: z.string(), ecosystem: z.literal("npm") }) })).length(1) });

/** OSV, standing in: counts the name queries and advisory reads, fails while `down`, answers late while `stallMs`. */
const osv = { attempts: 0, names: 0, reads: 0, down: false, stallMs: 0, unreadable: new Set<string>() };

const osvServer = Bun.serve({
  port: 0,
  hostname: "127.0.0.1",
  async fetch(req): Promise<Response> {
    osv.attempts++;
    // the answer is what OSV listed when it was asked; a stall delays it, as a slow network would
    const stall = osv.stallMs;
    const res = await respond(req);

    if (stall > 0) await Bun.sleep(stall);

    return res;
  },
});

/** What the OSV stand-in answers `req` with, from what it lists now. */
async function respond(req: Request): Promise<Response> {
    if (osv.down) return new Response("unavailable", { status: 503 });
    const path = new URL(req.url).pathname;
    const read = /\/v1\/vulns\/(.+)$/.exec(path);

    if (read?.[1]) {
      osv.reads++;
      const id = decodeURIComponent(read[1]);

      if (osv.unreadable.has(id)) return new Response("unavailable", { status: 503 });
      const vuln = [...VULNS.values()].flat().find((v) => v.id === id);

      return vuln ? Response.json(vuln) : Response.json({ code: 5, message: "Bug not found." }, { status: 404 });
    }

    const q = NameQuery.safeParse(await req.json());

    if (!q.success) return new Response("bad query", { status: 400 });
    osv.names++;

    return Response.json({ results: q.data.queries.map((one) => ({ vulns: (VULNS.get(one.package.name) ?? []).map((v) => ({ id: v.id, modified: "2026-11-24T00:00:00Z" })) })) });
}

let db: Awaited<ReturnType<typeof freshDatabase>>;

beforeAll(async () => {
  db = await freshDatabase();
});

afterAll(async () => {
  npm.stop(true);
  osvServer.stop(true);
  await db.drop();
});

afterEach(() => {
  osv.unreadable.clear();
  osv.down = false;
  osv.stallMs = 0;
  setSystemTime();
});

const SYNCED: BlocklistBody = { format: 1, syncedAt: NOW, local: [], confirmed: [] };

const blocklist = Layer.succeed(
  Blocklist,
  Blocklist.of({ read: Effect.succeed({ kind: "ok" as const, list: SYNCED, etag: "e" }), recent: Effect.succeed({ kind: "ok" as const, list: SYNCED, etag: "e" }), block: () => Effect.void, sync: () => Effect.die("not used") }),
);

const noBlobs = Layer.succeed(
  Blobs,
  Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }),
);

/** The edge checks (APM_INSTALL_CHECKS=edge) over a synced list that refuses nothing. */
const edgeLayer = () => {
  const bucket: BlocklistReader = { get: async (key) => (key === BLOCKLIST_KEY ? { body: new Blob([JSON.stringify(SYNCED)]).stream(), etag: "e" } : null) };

  return EdgeChecks.layer({ bucket, cache: null, cacheKey: "http://registry.test/-/apm/internal/edge-view", now: () => Date.now(), background: null, report: null }, () => Promise.resolve("asked"));
};

type Options = { accept?: string; safe?: boolean; edge?: boolean; root?: string; route?: "upstream" | "apm" | "degraded" };

type Got = { status: number; headers: Headers; text: string } | null;

/** A fresh OSV root: the feed's answers are kept per root, so a test that needs OSV asked again takes a new one. */
const freshRoot = (): string => `${osvServer.url.href}${crypto.randomUUID()}/`;

/** One root for the tests that may share what the feed answered. */
const SHARED_ROOT = freshRoot();

/** The route a test sends its request through. */
function routeFor(route: NonNullable<Options["route"]>, req: Request, safe: boolean) {
  switch (route) {
    case "apm":
      return apmRoute(req, new URL(req.url), { kind: "anon" });
    case "degraded":
      return degradedRoute(req);
    case "upstream":
      return upstreamRoute(req, new URL(req.url), safe);
    default: {
      const _exhaustive: never = route;

      return _exhaustive;
    }
  }
}

/** One request through the route the test names (upstreamRoute by default), with the feed at `root`. */
async function get(path: string, options: Options = {}): Promise<Got> {
  const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: npm.url.href, legacyAuth: false, namePolicy: "open", admins: [], tarballRedirects: "upstream" } as const;
  const edge = options.edge === true ? edgeLayer() : Layer.empty;
  const base = Layer.mergeAll(Store.postgres(db.url), Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs, blocklist, edge, Layer.succeed(RegistryConfig, settings), RequestMemory.layer(POOL));
  const auth = Auth.layer({ databaseUrl: db.url, options: { secret: "test-secret-that-is-long-enough-for-better-auth" }, baseURL: "http://web.test/" });
  const layers = Layer.provideMerge(auth, Layer.provideMerge(Upstream.layer(npm.url.href, 1, null), Layer.provideMerge(osvFeed(options.root ?? SHARED_ROOT), base)));
  const req = new Request(`http://registry.test${path}`, { headers: { accept: options.accept ?? "application/json", "user-agent": NPM_CLIENT } });
  const route = routeFor(options.route ?? "upstream", req, options.safe ?? false);
  const program = Effect.flatMap(route, (res) => Effect.promise(async () => (res ? { status: res.status, headers: res.headers, text: await res.text() } : null)));

  return Effect.runPromise(program.pipe(Effect.provide(layers), Effect.scoped));
}

const Packument = z.object({ "dist-tags": z.record(z.string(), z.string()), versions: z.record(z.string(), z.looseObject({ version: z.string() })) });
const ErrorBody = z.object({ error: z.string(), knownMalicious: z.object({ name: z.string(), version: z.string(), ids: z.array(z.string()) }).optional() });

async function packument(name: string, options: Options = {}) {
  const got = await get(`/${name}`, { accept: INSTALL_ACCEPT, ...options });

  expect(got?.status).toBe(200);

  return { headers: got?.headers ?? new Headers(), body: Packument.parse(JSON.parse(got?.text ?? "")) };
}

describe("packuments leave out what the feed lists", () => {
  test("the install packument drops listed versions, moves latest to the newest left, drops a tag left with none, and says why", async () => {
    const { headers, body } = await packument("evil-tagged");

    expect(Object.keys(body.versions)).toEqual(["9.0.0"]);
    expect(body["dist-tags"]).toEqual({ latest: "9.0.0", old: "9.0.0" });
    expect(headers.get("npm-notice")).toBe("apm withholds evil-tagged versions the OSSF malicious-packages feed lists as malicious (MAL-2026-1000: 10.9.9, 10.9.10, 10.9.11, 10.9.8)");
    // npm prints a notice only from an answer it did not keep
    expect(headers.get("cache-control")).toBe("no-store");
  });

  test("the full packument and its ~safe view drop them too", async () => {
    for (const safe of [false, true]) {
      const { body } = await packument("evil-tagged", { accept: "application/json", safe });

      expect(Object.keys(body.versions).filter((v) => v.startsWith("10."))).toEqual([]);
      expect(body["dist-tags"].latest).not.toStartWith("10.");
    }
  });

  test("a range is matched by OSV's rule, last_affected included, and another name's entry is not read as this one's", async () => {
    const { body } = await packument("ranged");

    expect(Object.keys(body.versions)).toEqual(["1.0.0", "2.0.0"]);
    expect(body["dist-tags"]).toEqual({ latest: "2.0.0" });
  });

  test("a name every version of which is listed is served with none and no latest", async () => {
    const { body } = await packument("all-listed");

    expect(body).toEqual({ "dist-tags": {}, versions: {} });
  });

  test("an advisory that is not a MAL- id, or a withdrawn one, withholds nothing, and the answer is unchanged", async () => {
    for (const name of ["clean", "withdrawn"]) {
      const { headers, body } = await packument(name);

      expect(Object.keys(body.versions)).toEqual(name === "clean" ? ["1.0.0", "1.1.0"] : ["1.0.0"]);
      expect(headers.get("npm-notice")).toBeNull();
      expect(headers.get("cache-control")).toBe("no-cache");
    }
  });

  test("the version document and dist-tags routes agree, and the version asked for says why it is missing", async () => {
    const listed = await get("/evil-tagged/10.9.11");

    expect(listed?.status).toBe(404);
    expect(ErrorBody.parse(JSON.parse(listed?.text ?? "")).knownMalicious).toEqual({ name: "evil-tagged", version: "10.9.11", ids: ["MAL-2026-1000"] });
    // the tag that named a listed version names it no longer
    expect(ErrorBody.parse(JSON.parse((await get("/evil-tagged/next"))?.text ?? "")).error).toContain("MAL-2026-1000");
    expect(JSON.parse((await get("/evil-tagged/latest"))?.text ?? "")).toMatchObject({ version: "9.0.0" });
    expect(JSON.parse((await get("/-/package/evil-tagged/dist-tags", { route: "apm" }))?.text ?? "")).toEqual({ latest: "9.0.0", old: "9.0.0" });
  });

  test("one name query per name, and each MAL- advisory read once, however many requests and versions", async () => {
    const root = freshRoot();
    const before = { ...osv };

    await packument("evil-tagged", { root });
    await packument("evil-tagged", { root, accept: "application/json" });
    await get("/evil-tagged/-/evil-tagged-10.9.11.tgz", { root });
    await get("/evil-tagged/9.0.0", { root });
    await packument("clean", { root });

    expect(osv.names - before.names).toBe(2);
    // MAL-2026-1000 once; the GHSA ids are never read
    expect(osv.reads - before.reads).toBe(1);
  });
});

describe("what the review of 34ccf92 found", () => {
  test("an old npm name with capitals is asked about as written", async () => {
    expect(Object.keys((await packument("Legacy-Name")).body.versions)).toEqual(["1.0.0"]);
  });

  test("a tag naming a listed version npm's packument does not list is dropped", async () => {
    expect((await packument("orphan-tag")).body["dist-tags"]).toEqual({ latest: "1.0.0" });
  });

  test("an advisory OSV fails to send does not hide the one it sent, and the partial answer is not kept", async () => {
    const root = freshRoot();

    osv.unreadable.add("MAL-2026-1007");
    expect(Object.keys((await packument("half-read", { root })).body.versions)).toEqual(["1.0.0", "1.1.0"]);
    // a partial answer is not kept: the next request asks again, finds the same, and withholds it too
    const attempts = osv.attempts;

    expect(Object.keys((await packument("half-read", { root })).body.versions)).toEqual(["1.0.0", "1.1.0"]);
    expect(osv.attempts).toBeGreaterThan(attempts);
    // another name is still asked about, and once OSV sends everything the whole answer is kept
    expect(Object.keys((await packument("evil-tagged", { root })).body.versions)).toEqual(["9.0.0"]);
    osv.unreadable.clear();
    expect(Object.keys((await packument("half-read", { root })).body.versions)).toEqual(["1.0.0"]);
  });

  test("a slower request's older answer does not replace a newer one the isolate kept", async () => {
    const root = freshRoot();
    const flipped = VULNS.get("flip") ?? [];

    osv.stallMs = 300;
    const slow = packument("flip", { root });

    await Bun.sleep(100);
    osv.stallMs = 0;
    flipped.push({ id: "MAL-2026-1008", affected: [{ package: { name: "flip", ecosystem: "npm" }, versions: ["1.1.0"] }] });

    try {
      expect(Object.keys((await packument("flip", { root })).body.versions)).toEqual(["1.0.0"]);
      // the slow request asked before the listing: the newer answer the isolate kept meanwhile wins, for it too
      expect(Object.keys((await slow).body.versions)).toEqual(["1.0.0"]);
      expect(Object.keys((await packument("flip", { root })).body.versions)).toEqual(["1.0.0"]);
    } finally {
      flipped.length = 0;
    }
  });

  test("a request that had a partial answer for a name gets the same on every later read of it, OSV not asked again", async () => {
    osv.unreadable.add("MAL-2026-1007");
    const feed = osvFeed(freshRoot());

    const twice = Effect.gen(function* () {
      const k = yield* KnownMalicious;
      const first = yield* k.advisoriesFor("half-read");
      const attempts = osv.attempts;
      const second = yield* k.advisoriesFor("half-read");

      return { first, second, askedAgain: osv.attempts > attempts };
    });

    const got = await Effect.runPromise(twice.pipe(Effect.provide(feed)));

    expect(got.first.map((a) => a.id)).toEqual(["MAL-2026-1006"]);
    expect(got.second).toEqual(got.first);
    expect(got.askedAgain).toBe(false);
  });

  test("a partial refresh after the kept answer expired keeps what both found, request after request", async () => {
    const root = freshRoot();

    expect(Object.keys((await packument("half-read", { root })).body.versions)).toEqual(["1.0.0"]);
    setSystemTime(new Date(Date.now() + NAME_FRESH_MS + 1_000));
    osv.unreadable.add("MAL-2026-1007");

    for (let i = 0; i < 2; i++) expect(Object.keys((await packument("half-read", { root })).body.versions)).toEqual(["1.0.0"]);
  });

  test("what a partial refresh read is OSV's word: an advisory it read as withdrawn is not taken back from the kept answer", async () => {
    const root = freshRoot();
    const advisory = VULNS.get("half-read")?.[0];

    expect(advisory?.id).toBe("MAL-2026-1006");
    await packument("half-read", { root });
    setSystemTime(new Date(Date.now() + NAME_FRESH_MS + 1_000));
    osv.unreadable.add("MAL-2026-1007");

    try {
      if (advisory) advisory.withdrawn = "2026-11-25T00:00:00Z";
      // 1.2.0 (MAL-2026-1006, now withdrawn) is served again; 1.1.0 (MAL-2026-1007, unread) stays withheld
      expect(Object.keys((await packument("half-read", { root })).body.versions)).toEqual(["1.0.0", "1.2.0"]);
    } finally {
      if (advisory) delete advisory.withdrawn;
    }
  });

  test("after a failure the isolate does not ask OSV again for a while, so an outage costs one wait, not one per request", async () => {
    const root = freshRoot();

    osv.down = true;
    const before = osv.attempts;

    await packument("clean", { root });
    await packument("evil-tagged", { root });
    expect(osv.attempts - before).toBe(1);
  });

  test("a range's limit bounds it, \"*\" bounding nothing", () => {
    const hit = (events: Advisory["ranges"][number]) => [...listedAmong("p", [{ id: "MAL-1", versions: [], ranges: [events] }], ["1.0.0", "2.0.0", "3.0.0"]).keys()];

    expect(hit([{ introduced: "0" }, { limit: "2.0.0" }])).toEqual(["1.0.0"]);
    expect(hit([{ introduced: "0" }, { limit: "*" }])).toEqual(["1.0.0", "2.0.0", "3.0.0"]);
  });
});

describe("tarballs of listed versions are refused", () => {
  const TarballBody = ErrorBody.required({ knownMalicious: true });

  test("403 citing the MAL- id on the database path, the edge path and ~safe; an unlisted version is still served", async () => {
    for (const options of [{}, { edge: true }, { safe: true }] satisfies Options[]) {
      const got = await get("/evil-tagged/-/evil-tagged-10.9.11.tgz", options);

      expect(got?.status).toBe(403);
      const body = TarballBody.parse(JSON.parse(got?.text ?? ""));

      expect(body.error).toBe("known malicious: the OSSF malicious-packages feed lists evil-tagged@10.9.11 (MAL-2026-1000), so apm does not serve it. See https://osv.dev/vulnerability/MAL-2026-1000");
      expect(body.knownMalicious.ids).toEqual(["MAL-2026-1000"]);
    }

    const clean = await get("/evil-tagged/-/evil-tagged-9.0.0.tgz");

    expect([200, 302]).toContain(clean?.status ?? 0);
  });

  test("a listed version npm no longer has is refused as listed, not as missing", async () => {
    const got = await get("/evil-tagged/-/evil-tagged-10.9.8.tgz");

    expect(got?.status).toBe(403);
    expect(got?.text).toContain("MAL-2026-1000");
  });
});

describe("while the database is down", () => {
  test("the degraded packument and tarball routes withhold listed versions too", async () => {
    const { body, headers } = await packument("evil-tagged", { route: "degraded" });

    expect(Object.keys(body.versions)).toEqual(["9.0.0"]);
    expect(headers.get("npm-notice")).toContain("MAL-2026-1000");
    expect((await get("/evil-tagged/-/evil-tagged-10.9.11.tgz", { route: "degraded" }))?.status).toBe(403);
  });
});

describe("a feed that does not answer", () => {
  test("fails open for a name it never answered: every version is served", async () => {
    osv.down = true;
    const { body, headers } = await packument("evil-tagged", { root: freshRoot() });

    expect(Object.keys(body.versions)).toEqual(["9.0.0", "10.9.9", "10.9.10", "10.9.11"]);
    expect(headers.get("npm-notice")).toBeNull();
  });

  test("uses the last answer for a name while it is under a day old, then fails open", async () => {
    const root = freshRoot();

    await packument("evil-tagged", { root });
    osv.down = true;
    setSystemTime(new Date(Date.now() + NAME_FRESH_MS + 1_000));
    expect(Object.keys((await packument("evil-tagged", { root })).body.versions)).toEqual(["9.0.0"]);
    setSystemTime(new Date(Date.now() + NAME_STALE_MS));
    expect(Object.keys((await packument("evil-tagged", { root })).body.versions)).toHaveLength(4);
  });

  test("a stalled feed costs a packument one budget at most, and it still answers", async () => {
    osv.stallMs = REQUEST_BUDGET_MS + 2_000;
    const t0 = performance.now();
    const { body } = await packument("evil-tagged", { root: freshRoot() });

    expect(performance.now() - t0).toBeLessThan(REQUEST_BUDGET_MS + 1_500);
    expect(Object.keys(body.versions)).toHaveLength(4);
  });
});

describe("advisories", () => {
  const a = (over: Partial<Advisory>): Advisory => ({ id: "MAL-1", versions: [], ranges: [], ...over });

  test("exact versions, introduced/fixed, introduced/last_affected and unsorted events", () => {
    const versions = ["0.9.0", "1.0.0", "1.2.0", "1.2.1", "2.0.0", "2.1.0", "not-semver"];
    const hit = (adv: Advisory) => [...listedAmong("p", [adv], versions).keys()];

    expect(hit(a({ versions: ["1.2.0", "not-semver"] }))).toEqual(["1.2.0", "not-semver"]);
    expect(hit(a({ ranges: [[{ introduced: "1.0.0" }, { fixed: "1.2.1" }]] }))).toEqual(["1.0.0", "1.2.0"]);
    expect(hit(a({ ranges: [[{ introduced: "1.2.1" }, { last_affected: "2.0.0" }]] }))).toEqual(["1.2.1", "2.0.0"]);
    expect(hit(a({ ranges: [[{ fixed: "2.0.0" }, { introduced: "0" }]] }))).toEqual(["0.9.0", "1.0.0", "1.2.0", "1.2.1"]);
    expect(hit(a({ ranges: [[{ introduced: "0" }]] }))).toEqual(["0.9.0", "1.0.0", "1.2.0", "1.2.1", "2.0.0", "2.1.0"]);
  });

  test("the notice names every advisory and stays a short ASCII header", () => {
    expect(listedNotice("p", [])).toBeNull();
    expect(listedNotice("p", [a({ ranges: [[{ introduced: "0" }]] })])).toBe("apm withholds p versions the OSSF malicious-packages feed lists as malicious (MAL-1: >=0)");
    const long = listedNotice("p", [a({ versions: Array.from({ length: 200 }, (_, i) => `1.0.${i}`) })]) ?? "";

    expect(long.length).toBeLessThanOrEqual(400);
    expect(long).toEndWith("...");
  });

  test("an install copy's stamp is the confirmed set's alone when the feed lists nothing, and changes when it lists something", async () => {
    const rows = [{ version: "1.0.0", digest: "sha512-x" }];

    expect(await installStamp(rows, [])).toBe(await installStamp(rows));
    expect(await installStamp(rows, ["osv x"])).not.toBe(await installStamp(rows));
  });
});

describe("the package page's answers", () => {
  const Row = z.object({ version: z.string(), refused: z.object({ kind: z.string(), ids: z.array(z.string()).optional() }).nullable() });
  const PackageAnswer = z.object({ latest: z.string().nullable(), distTags: z.record(z.string(), z.string()), versions: z.array(Row) });

  test("latest and the dist-tags are what the packuments serve, and each listed version names its advisory", async () => {
    const got = await get("/-/apm/v1/packages/evil-tagged", { route: "apm", root: freshRoot() });

    expect(got?.status).toBe(200);
    const body = PackageAnswer.parse(JSON.parse(got?.text ?? ""));

    expect(body.latest).toBe("9.0.0");
    expect(body.distTags).toEqual({ latest: "9.0.0", old: "9.0.0" });
    expect(body.versions.map((v) => [v.version, v.refused])).toEqual([
      ["10.9.11", { kind: "known-malicious", ids: ["MAL-2026-1000"] }],
      ["10.9.10", { kind: "known-malicious", ids: ["MAL-2026-1000"] }],
      ["10.9.9", { kind: "known-malicious", ids: ["MAL-2026-1000"] }],
      ["9.0.0", null],
    ]);
  });

  test("latest and the dist-tags match the packument's, a tag on a listed version outside the list and a confirmed latest included", async () => {
    const digest = digestOf({ integrity: integrity("confirmed-latest", "2.0.0"), shasum: shasum("confirmed-latest", "2.0.0") });
    const client = new Client({ connectionString: db.url });

    await client.connect();
    await client.query("INSERT INTO reviews (package, version, digest, outcome, result, reviewed_at, human_state) VALUES ($1, $2, $3, 'flagged', '{}', 0, 'confirmed')", ["confirmed-latest", "2.0.0", digest ? digestLabel(digest) : ""]);
    await client.end();
    const root = freshRoot();

    for (const name of ["evil-tagged", "ranged", "all-listed", "clean", "orphan-tag", "confirmed-latest"]) {
      const answer = PackageAnswer.parse(JSON.parse((await get(`/-/apm/v1/packages/${name}`, { route: "apm", root }))?.text ?? ""));
      const { body } = await packument(name, { root });

      expect([name, answer.distTags]).toEqual([name, body["dist-tags"]]);
      expect([name, answer.latest]).toEqual([name, body["dist-tags"].latest ?? null]);
    }

    const confirmed = PackageAnswer.parse(JSON.parse((await get("/-/apm/v1/packages/confirmed-latest", { route: "apm", root }))?.text ?? ""));

    expect(confirmed.versions.find((v) => v.version === "2.0.0")?.refused).toEqual({ kind: "confirmed-malicious" });
  });

  test("a package published here: latest and the dist-tags are its packument's when its latest is confirmed malicious and the one before is yanked", async () => {
    const name = "here-confirmed-latest";
    const client = new Client({ connectionString: db.url });
    const sum = (v: string) => createHash("sha1").update(`${name}@${v}`).digest("hex");
    const sri = (v: string) => `sha512-${createHash("sha512").update(`${name}@${v}`).digest("base64")}`;

    await client.connect();
    await client.query("INSERT INTO packages (name, created_at, modified_at, dist_tags, description, keywords, readme, readme_version) VALUES ($1, 1, 2, $2, '', '[]', '', NULL)", [name, JSON.stringify({ latest: "3.0.0", beta: "2.0.0" })]);

    for (const [i, [version, status]] of ([["1.0.0", "active"], ["2.0.0", "yanked"], ["3.0.0", "active"]] as const).entries()) {
      await client.query(
        `INSERT INTO versions (package, version, manifest, shasum, integrity, size, tarball_key, published_at, published_by, status, status_reason, status_at)
         VALUES ($1, $2, $3, $4, $5, 10, 'sha512/x', $6, 'alice', $7, NULL, NULL)`,
        [name, version, JSON.stringify({ name, version }), sum(version), sri(version), 1_000 + i, status],
      );
    }

    const digest = digestOf({ integrity: sri("3.0.0"), shasum: sum("3.0.0") });

    await client.query("INSERT INTO reviews (package, version, digest, outcome, result, reviewed_at, human_state) VALUES ($1, '3.0.0', $2, 'flagged', '{}', 0, 'confirmed')", [name, digest ? digestLabel(digest) : ""]);
    await client.end();

    const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: npm.url.href, legacyAuth: false, namePolicy: "open", admins: [], tarballRedirects: "upstream" } as const;

    const served = await Effect.runPromise(
      Effect.flatMap(Store, (s) => s.getPackage(name)).pipe(
        Effect.flatMap((pkg) => (pkg ? localPackument(pkg, true) : Effect.die("no package row"))),
        Effect.provide(Layer.mergeAll(Store.postgres(db.url), Clock.fixed({ now: NOW, wallNow: NOW }), Layer.succeed(RegistryConfig, settings))),
        Effect.scoped,
      ),
    );

    const answer = PackageAnswer.parse(JSON.parse((await get(`/-/apm/v1/packages/${name}`, { route: "apm", root: freshRoot() }))?.text ?? ""));

    expect(served["dist-tags"]).toEqual({ latest: "1.0.0" });
    expect(answer.distTags).toEqual(served["dist-tags"]);
    expect(answer.latest).toBe("1.0.0");
    expect(answer.versions.find((v) => v.version === "3.0.0")?.refused).toEqual({ kind: "confirmed-malicious" });
  });

  test("a kept summary that leaves out the stable version latest falls back to: the answer's latest is the packument's", async () => {
    const listing = await Effect.runPromise(
      Effect.flatMap(Upstream, (u) => Effect.flatMap(RequestMemory, (lease) => u.listing("truncated", lease))).pipe(
        Effect.provide(Layer.provideMerge(Upstream.layer(npm.url.href, 1, null), Layer.mergeAll(Store.postgres(db.url), noBlobs, Clock.fixed({ now: NOW, wallNow: NOW }), RequestMemory.layer(POOL)))),
        Effect.scoped,
      ),
    );

    if (listing.kind !== "found") throw new Error("no package");
    const summary = summarize(listing.pkg);

    expect(summary?.versions.some((v) => v.version === "1.0.0")).toBe(false);
    const client = new Client({ connectionString: db.url });

    await client.connect();
    await client.query("INSERT INTO kept_packages (package, summary, computed_at, asked_at) VALUES ($1, $2::jsonb, $3, $3)", ["truncated", JSON.stringify(summary), NOW]);
    await client.end();
    const root = freshRoot();
    const { body } = await packument("truncated", { root });
    const answer = PackageAnswer.parse(JSON.parse((await get("/-/apm/v1/packages/truncated", { route: "apm", root }))?.text ?? ""));

    expect(body["dist-tags"].latest).toBe("1.0.0");
    expect(answer.distTags).toEqual(body["dist-tags"]);
    expect(answer.latest).toBe("1.0.0");
  });

  test("the per-version answer says the same, and a clean package's answer is unchanged", async () => {
    const root = freshRoot();
    const listed = await get("/-/apm/v1/packages/evil-tagged/versions/10.9.11", { route: "apm", root });

    expect(listed?.status).toBe(200);
    expect(Row.parse(JSON.parse(listed?.text ?? "")).refused).toEqual({ kind: "known-malicious", ids: ["MAL-2026-1000"] });
    const clean = PackageAnswer.parse(JSON.parse((await get("/-/apm/v1/packages/clean", { route: "apm", root }))?.text ?? ""));

    expect(clean.latest).toBe("1.1.0");
    expect(clean.distTags).toEqual({ latest: "1.1.0" });
    expect(clean.versions.every((v) => v.refused === null)).toBe(true);
  });
});

