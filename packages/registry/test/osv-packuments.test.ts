// The OSSF malicious-packages feed on the npm protocol routes (osv.ts advisoriesFor, apm.ts, fast-tarball.ts,
// degraded.ts). Found by the launch smoke on 2026-11-25 (HOME-351): registry.apmjs.dev served ugent_uws 10.9.9 to
// 10.9.11 with dist-tag latest = 10.9.11, and that tarball answered 200. It runs a wget exfil preinstall and OSSF lists
// it as MAL-2026-20430. #31 made resolve, scan and explain refuse it, but a stock `npm install ugent_uws` through the
// plain registry read only the packument and tarball routes, which did not ask the feed. Now a listed version is left out
// of every packument (dist-tags moved or dropped as for a confirmed version), its version document is a 404 and its
// tarball a 403, each citing the MAL- id, from one small OSV query per name. A feed that does not answer refuses nothing.
// npm and OSV are local stand-ins on 127.0.0.1; the database is a real Postgres.
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, setSystemTime, test } from "bun:test";
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
    const time = Object.fromEntries(pkg.versions.map((v) => [v, new Date(NOW - 30 * DAY).toISOString()]));

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

  // Sol on #44, finding 1: an advisory a partial answer read was kept for that request alone, so an outage right after
  // it served the version it had withheld
  test("what a partial answer read stays withheld through an outage, until a complete answer replaces it or it is a day old", async () => {
    const root = freshRoot();
    const advisory = VULNS.get("half-read")?.[0];
    const tarball = async () => (await get("/half-read/-/half-read-1.2.0.tgz", { root }))?.status;
    const t0 = Date.now();

    expect(advisory?.id).toBe("MAL-2026-1006");
    osv.unreadable.add("MAL-2026-1007");
    expect(Object.keys((await packument("half-read", { root })).body.versions)).toEqual(["1.0.0", "1.1.0"]);
    osv.down = true;
    expect(Object.keys((await packument("half-read", { root })).body.versions)).toEqual(["1.0.0", "1.1.0"]);
    expect(await tarball()).toBe(403);
    // a day after it was read, an outage fails open again, as for a name never answered
    const aDayOn = t0 + NAME_STALE_MS + 60_000;

    setSystemTime(new Date(aDayOn));
    expect(Object.keys((await packument("half-read", { root })).body.versions)).toEqual(["1.0.0", "1.1.0", "1.2.0"]);
    // a complete answer replaces what partial answers read: once OSV withdraws the advisory, the version is served
    osv.down = false;
    osv.unreadable.clear();
    setSystemTime(new Date(aDayOn + 60_000));
    expect(Object.keys((await packument("half-read", { root })).body.versions)).toEqual(["1.0.0"]);

    try {
      if (advisory) advisory.withdrawn = "2026-11-25T00:00:00Z";
      setSystemTime(new Date(aDayOn + 60_000 + NAME_FRESH_MS + 1_000));
      expect(Object.keys((await packument("half-read", { root })).body.versions)).toEqual(["1.0.0", "1.2.0"]);
      osv.down = true;
      setSystemTime(new Date(aDayOn + 60_000 + 2 * NAME_FRESH_MS + 2_000));
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

// Sol on #59 (3e21a4f): what a partial answer read was kept beside the name's complete answer, as a whole, so an older
// complete answer could undo a newer partial one (an amended or withdrawn advisory), a slower request's answer could
// undo a newer one, and a newer copy from the data center's cache did not retire what it superseded. Each advisory is
// now decided by the newest answer that read it, complete or partial, from this isolate or the data center's cache.
describe("each advisory of a name is what the newest answer that read it says", () => {
  const X = "MAL-2026-1010";
  const Y = "MAL-2026-1011";
  const naming = (id: string, versions: string[], withdrawn?: string): Vuln => (withdrawn === undefined ? { id, affected: [{ package: { name: "observed", ecosystem: "npm" }, versions }] } : { id, withdrawn, affected: [{ package: { name: "observed", ecosystem: "npm" }, versions }] });

  /** One request's advisoriesFor("observed") at `root`, as the versions each advisory names. */
  const asked = async (root: string, fetcher: typeof fetch = fetch): Promise<Record<string, string[]>> => {
    const got = await Effect.runPromise(Effect.flatMap(KnownMalicious, (k) => k.advisoriesFor("observed")).pipe(Effect.provide(osvFeed(root, fetcher))));

    return Object.fromEntries(got.map((a) => [a.id, a.versions]));
  };

  /** fetch, with the answer to the first request whose URL has `part` held until `release` (`asked`: it was answered). */
  function held(part: string) {
    const answered = Promise.withResolvers<void>();
    const gate = Promise.withResolvers<void>();
    let holding = true;

    const fetcher = Object.assign(
      async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const res = await fetch(input, init);

        if (holding && String(input).includes(part)) {
          holding = false;
          answered.resolve();
          await gate.promise;
        }

        return res;
      },
      { preconnect: fetch.preconnect },
    );

    return { fetcher, asked: answered.promise, release: () => gate.resolve() };
  }

  let t = Date.now();

  const at = (ms: number): void => {
    t = ms;
    setSystemTime(new Date(t));
  };

  beforeEach(() => {
    VULNS.set("observed", [naming(X, ["1.0.0"]), naming(Y, ["1.1.0"])]);
    at(Date.now());
  });

  afterEach(() => {
    VULNS.delete("observed");
  });

  test("an advisory a partial answer read amended is kept as amended through an outage, the older complete answer notwithstanding", async () => {
    const root = freshRoot();

    expect(await asked(root)).toEqual({ [X]: ["1.0.0"], [Y]: ["1.1.0"] });
    at(t + NAME_FRESH_MS + 1_000);
    VULNS.set("observed", [naming(X, ["2.0.0"]), naming(Y, ["1.1.0"])]);
    osv.unreadable.add(Y);
    expect(await asked(root)).toEqual({ [X]: ["2.0.0"], [Y]: ["1.1.0"] });
    osv.down = true;
    at(t + 60_000);
    // on 3e21a4f: 1.0.0, the complete answer's, as X was in it
    expect(await asked(root)).toEqual({ [X]: ["2.0.0"], [Y]: ["1.1.0"] });
  });

  test("an advisory a partial answer read withdrawn stays withdrawn through an outage", async () => {
    const root = freshRoot();

    await asked(root);
    at(t + NAME_FRESH_MS + 1_000);
    VULNS.set("observed", [naming(X, ["1.0.0"], "2026-11-25T00:00:00Z"), naming(Y, ["1.1.0"])]);
    osv.unreadable.add(Y);
    expect(await asked(root)).toEqual({ [Y]: ["1.1.0"] });
    osv.down = true;
    at(t + 60_000);
    // on 3e21a4f: X again, from the stale complete answer
    expect(await asked(root)).toEqual({ [Y]: ["1.1.0"] });
  });

  test("a slower partial answer asked for before a withdrawal was read does not bring the advisory back", async () => {
    const root = freshRoot();

    await asked(root);
    at(t + NAME_FRESH_MS + 1_000);
    osv.unreadable.add(Y);
    // the slower request reads X while it is listed, and its answer lands only after the next request's
    const slow = held(`vulns/${X}`);
    const first = asked(root, slow.fetcher);

    await slow.asked;
    at(t + 1_000);
    VULNS.set("observed", [naming(X, ["1.0.0"], "2026-11-25T00:00:00Z"), naming(Y, ["1.1.0"])]);
    expect(await asked(root)).toEqual({ [Y]: ["1.1.0"] });
    slow.release();
    // what the slow request answers is read from what the isolate knows once its answer is in
    expect(await first).toEqual({ [Y]: ["1.1.0"] });
    osv.down = true;
    at(t + 60_000);
    expect(await asked(root)).toEqual({ [Y]: ["1.1.0"] });
  });

  test("a slower complete answer asked for before an advisory was listed does not leave out what a newer answer read", async () => {
    const root = freshRoot();

    VULNS.set("observed", []);
    const slow = held("querybatch");
    const first = asked(root, slow.fetcher);

    await slow.asked;
    at(t + 1_000);
    VULNS.set("observed", [naming(X, ["1.0.0"]), naming(Y, ["1.1.0"])]);
    osv.unreadable.add(Y);
    expect(await asked(root)).toEqual({ [X]: ["1.0.0"] });
    slow.release();
    // on 3e21a4f: {}, the complete answer as of when it was asked
    expect(await first).toEqual({ [X]: ["1.0.0"] });
    osv.down = true;
    at(t + 60_000);
    expect(await asked(root)).toEqual({ [X]: ["1.0.0"] });
  });

  test("a newer complete answer that leaves out an advisory a partial answer read retires it, before it is a day old", async () => {
    const root = freshRoot();

    osv.unreadable.add(Y);
    expect(await asked(root)).toEqual({ [X]: ["1.0.0"] });
    osv.unreadable.clear();
    VULNS.set("observed", [naming(Y, ["1.1.0"])]);
    at(t + 60_000);
    expect(await asked(root)).toEqual({ [Y]: ["1.1.0"] });
    osv.down = true;
    at(t + NAME_FRESH_MS + 1_000);
    expect(await asked(root)).toEqual({ [Y]: ["1.1.0"] });
  });

  test("a newer complete answer from the data center's cache retires what it leaves out, and a miss after it does not bring it back", async () => {
    const root = freshRoot();
    const copies = new Map<string, Response>();

    const cache = {
      match: async (key: Request) => copies.get(key.url)?.clone(),
      put: async (key: Request, res: Response) => {
        copies.set(key.url, res);
      },
    };

    Object.defineProperty(globalThis, "caches", { value: { default: cache }, configurable: true });

    try {
      osv.unreadable.add(Y);
      expect(await asked(root)).toEqual({ [X]: ["1.0.0"] });
      // another isolate's complete answer, asked for later: Y only
      copies.set(`https://osv-cache.apmjs.internal/v2/${encodeURIComponent(`${root} observed`)}`, Response.json({ fetchedAt: t + 1_000, advisories: [{ id: Y, versions: ["1.1.0"], ranges: [] }] }));
      osv.down = true;
      at(t + NAME_FRESH_MS + 2_000);
      // stale, while OSV is down: on 3e21a4f X still counted beside it
      expect(await asked(root)).toEqual({ [Y]: ["1.1.0"] });
      copies.clear();
      at(t + 1_000);
      expect(await asked(root)).toEqual({ [Y]: ["1.1.0"] });
    } finally {
      Reflect.deleteProperty(globalThis, "caches");
    }
  });

  /** The data center's cache, standing in: its copies by URL, and with `gated`, the first read held until `release`. */
  function sharedCache(gated = false) {
    const copies = new Map<string, Response>();
    const reading = Promise.withResolvers<void>();
    const gate = Promise.withResolvers<void>();
    let holding = gated;

    const cache = {
      match: async (key: Request) => {
        if (holding) {
          holding = false;
          reading.resolve();
          await gate.promise;
        }

        return copies.get(key.url)?.clone();
      },
      put: async (key: Request, res: Response) => {
        copies.set(key.url, res);
      },
    };

    Object.defineProperty(globalThis, "caches", { value: { default: cache }, configurable: true });

    return { copies, reading: reading.promise, release: () => gate.resolve(), restore: () => Reflect.deleteProperty(globalThis, "caches") };
  }

  // Sol on 6f206c5: the freshness check after the cache read, the backoff's and the answer used the time from before it
  test("a request whose cache read lands after another request's answer answers with that answer, in a backoff too", async () => {
    const root = freshRoot();
    const shared = sharedCache(true);

    try {
      const first = asked(root);

      await shared.reading;
      at(t + 1_000);
      expect(await asked(root)).toEqual({ [X]: ["1.0.0"], [Y]: ["1.1.0"] });
      // OSV goes down at the root: a name asked about next starts its backoff
      osv.down = true;
      await Effect.runPromise(Effect.flatMap(KnownMalicious, (k) => k.advisoriesFor("observed-other")).pipe(Effect.provide(osvFeed(root))));
      shared.release();
      // on 6f206c5: {}, the newer answer read as not yet asked for
      expect(await first).toEqual({ [X]: ["1.0.0"], [Y]: ["1.1.0"] });
    } finally {
      shared.restore();
    }
  });

  // Sol on 6f206c5: the data center's copy was written when an answer's time matched the newest complete one's, so an
  // older answer of the same millisecond, landing last, overwrote the newer one's copy
  test("of two complete answers asked for in one millisecond, the newer one's is the data center's copy", async () => {
    const root = freshRoot();
    const shared = sharedCache();

    try {
      VULNS.set("observed", []);
      const slow = held("querybatch");
      const first = asked(root, slow.fetcher);

      await slow.asked;
      VULNS.set("observed", [naming(X, ["1.0.0"])]);
      expect(await asked(root)).toEqual({ [X]: ["1.0.0"] });
      slow.release();
      expect(await first).toEqual({ [X]: ["1.0.0"] });
      await Bun.sleep(20);
      const copy = shared.copies.get(`https://osv-cache.apmjs.internal/v2/${encodeURIComponent(`${root} observed`)}`);

      // on 6f206c5: the empty answer's
      expect(await copy?.clone().json()).toEqual({ fetchedAt: t, advisories: [{ id: X, versions: ["1.0.0"], ranges: [] }] });
    } finally {
      shared.restore();
    }
  });

  // Sol on 6f206c5: a complete answer spoke only for the advisories the isolate had seen, so an older answer landing
  // after it could add one it left out
  test("an older answer that lands after a newer complete one does not bring back an advisory the newer one left out", async () => {
    const root = freshRoot();

    VULNS.set("observed", [naming(X, ["1.0.0"])]);
    const slow = held(`vulns/${X}`);
    const first = asked(root, slow.fetcher);

    await slow.asked;
    at(t + 1_000);
    VULNS.set("observed", []);
    expect(await asked(root)).toEqual({});
    slow.release();
    // on 6f206c5: X, from the listing the newer answer superseded
    expect(await first).toEqual({});
    osv.down = true;
    at(t + 60_000);
    expect(await asked(root)).toEqual({});
  });
});
