// The upstream tarball route without the packument (fast-tarball.ts): every request reads what can refuse it (the
// database, the block list, npm's document for the one version) before any byte goes out, and passes npm's bytes on
// unchanged, checked against the version's checksum on the way. These run upstreamRoute itself, so the route's order
// (installs, then this path, then the packument route) is what is tested. npm is a local stand-in on 127.0.0.1.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { gzipSync } from "node:zlib";
import { Duration, Effect, Layer, Option } from "effect";
import { Client } from "pg";
import { SCORER } from "@apm/core";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis, type JobOutcome } from "../src/analysis.ts";
import { upstreamRoute } from "../src/apm.ts";
import { Blobs } from "../src/blobs.ts";
import { BLOCKLIST_KEY, Blocklist, type BlocklistBody, type BlocklistReader } from "../src/blocklist.ts";
import { Clock } from "../src/clock.ts";
import { RegistryConfig } from "../src/config.ts";
import { Store } from "../src/db.ts";
import { EDGE_READ_DEADLINE_MS, EDGE_VIEW_MAX_AGE_MS, EdgeChecks } from "../src/edge-checks.ts";

/** What npm's own client sends for an install document. */
const INSTALL_ACCEPT = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*";

import { queueDownload, versionOfFile } from "../src/fast-tarball.ts";
import { type Lease, MemoryPool, RequestMemory } from "../src/memory.ts";
import { Upstream, type UpstreamApi } from "../src/upstream.ts";

const POOL = new MemoryPool();
const NOW = Date.parse("2026-11-17T00:00:00Z");

type Tarball = { bytes: Uint8Array; integrity: string; hex: string };

function tarball(size: number): Tarball {
  const bytes = new Uint8Array(randomBytes(size));
  const digest = createHash("sha512").update(bytes).digest();

  return { bytes, integrity: `sha512-${digest.toString("base64")}`, hex: digest.toString("hex") };
}

// big enough to arrive in several chunks, so a check that held nothing back would show
const FAST = tarball(300_000);
const FAST_NEXT = tarball(2_000);
const MOVED = tarball(5_000);
const SCOPED = tarball(4_000);
const TAMPERED = tarball(200_000);
const GZ = tarball(50_000);

// more than the 32 MiB analysis cap once decoded, about 33 KB as gzip: the declared length is the small one
const BIG_ZEROS = (() => {
  const bytes = new Uint8Array(33 * 1024 * 1024);
  const digest = createHash("sha512").update(bytes).digest();

  return { bytes, integrity: `sha512-${digest.toString("base64")}`, hex: digest.toString("hex") } satisfies Tarball;
})();

/** npm, standing in. `asked` lists every path it was sent, as sent (percent-encoding kept). */
function fakeNpm() {
  const asked: string[] = [];
  let url = "";

  const doc = (name: string, version: string, t: Tarball, tarballPath = `${name}/-/${name.split("/").at(-1) ?? name}-${version}.tgz`) => ({
    name,
    version,
    dist: { tarball: `${url}${tarballPath}`, integrity: t.integrity, shasum: createHash("sha1").update(t.bytes).digest("hex") },
  });

  const packument = (name: string, versions: Record<string, Tarball>) => ({
    name,
    "dist-tags": { latest: Object.keys(versions).at(-1) },
    versions: Object.fromEntries(Object.entries(versions).map(([v, t]) => [v, doc(name, v, t)])),
    time: Object.fromEntries(Object.keys(versions).map((v) => [v, "2026-10-01T00:00:00Z"])),
  });

  const routes = () => ({
    "/fast": () => Response.json(packument("fast", { "1.0.0": FAST, "1.1.0": FAST_NEXT })),
    "/fast/1.0.0": () => Response.json(doc("fast", "1.0.0", FAST)),
    "/fast/1.1.0": () => Response.json(doc("fast", "1.1.0", FAST_NEXT)),
    // npm answers a tag or a range with the version it resolves to: 2.0.0 is not a version of fast
    "/fast/2.0.0": () => Response.json(doc("fast", "1.1.0", FAST_NEXT)),
    "/fast/-/fast-1.0.0.tgz": () => new Response(FAST.bytes, { headers: { "content-type": "application/octet-stream" } }),
    "/fast/-/fast-1.1.0.tgz": () => new Response(FAST_NEXT.bytes),
    "/moved": () => Response.json({ ...packument("moved", {}), versions: { "1.0.0": doc("moved", "1.0.0", MOVED, "moved/-/elsewhere-1.0.0.tgz") } }),
    "/moved/1.0.0": () => Response.json(doc("moved", "1.0.0", MOVED, "moved/-/elsewhere-1.0.0.tgz")),
    "/moved/-/elsewhere-1.0.0.tgz": () => new Response(MOVED.bytes),
    "/@scope%2Fpkg": () => Response.json(packument("@scope/pkg", { "1.0.0": SCOPED })),
    "/@scope%2Fpkg/1.0.0": () => Response.json(doc("@scope/pkg", "1.0.0", SCOPED)),
    "/@scope/pkg/-/pkg-1.0.0.tgz": () => new Response(SCOPED.bytes),
    "/tampered": () => Response.json(packument("tampered", { "1.0.0": TAMPERED })),
    "/tampered/1.0.0": () => Response.json(doc("tampered", "1.0.0", TAMPERED)),
    // the right length, other bytes
    "/tampered/-/tampered-1.0.0.tgz": () => new Response(new Uint8Array(randomBytes(TAMPERED.bytes.length))),
    "/gz": () => Response.json(packument("gz", { "1.0.0": GZ })),
    "/gz/1.0.0": () => Response.json(doc("gz", "1.0.0", GZ)),
    // sent compressed: the Content-Length counts the gzip bytes, and fetch hands over the decoded ones
    "/gz/-/gz-1.0.0.tgz": () => new Response(gzipSync(GZ.bytes), { headers: { "content-encoding": "gzip" } }),
    "/gzbig": () => Response.json(packument("gzbig", { "1.0.0": BIG_ZEROS })),
    "/gzbig/1.0.0": () => Response.json(doc("gzbig", "1.0.0", BIG_ZEROS)),
    "/gzbig/-/gzbig-1.0.0.tgz": () => new Response(gzipSync(BIG_ZEROS.bytes), { headers: { "content-encoding": "gzip" } }),
    "/mine": () => Response.json(packument("mine", { "1.0.0": FAST })),
    "/mine/1.0.0": () => Response.json(doc("mine", "1.0.0", FAST)),
    "/mine/-/mine-1.0.0.tgz": () => new Response(FAST.bytes),
    // asked only by the edge tests whose clock jumps while npm answers (onNpmAsk)
    "/aging": () => Response.json(packument("aging", { "1.0.0": FAST })),
    "/aging/1.0.0": () => Response.json(doc("aging", "1.0.0", FAST)),
    "/aging/-/aging-1.0.0.tgz": () => new Response(FAST.bytes),
    "/agingdoc": () => Response.json(packument("agingdoc", { "1.0.0": FAST })),
  }) satisfies Record<string, () => Response>;

  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const path = new URL(req.url).pathname;

      asked.push(path);
      onNpmAsk(path);
      const answer = Object.entries(routes()).find(([p]) => p === path)?.[1];

      return answer ? answer() : Response.json({ error: "Not found" }, { status: 404 });
    },
  });

  url = server.url.href;

  return { url, asked, stop: () => server.stop(true) };
}

let db: Awaited<ReturnType<typeof freshDatabase>>;
let npm: ReturnType<typeof fakeNpm>;
let list: BlocklistBody | null;

/** How long the database path's read of the block list (Blocklist.recent) takes. */
let listDelayMs = 0;
let enqueued: string[];

/** Whether the analysis queue refuses what it is sent (Analysis.enqueue answers false). */
let refuseQueue = false;
let stored: string[];

const sql = async (text: string, params: readonly unknown[] = []): Promise<void> => {
  const c = new Client({ connectionString: db.url });

  await c.connect();

  try {
    await c.query(text, [...params]);
  } finally {
    await c.end();
  }
};

beforeAll(async () => {
  db = await freshDatabase();
  npm = fakeNpm();
});

afterAll(async () => {
  npm.stop();
  await db.drop();
});

beforeEach(() => {
  npm.asked.length = 0;
  edgeQueued = [];
  edgeShift = 0;
  onNpmAsk = () => undefined;
  list = { format: 1, syncedAt: NOW, local: [], confirmed: [] };
  listDelayMs = 0;
  enqueued = [];
  refuseQueue = false;
  stored = [];
});

const blocklist = Layer.succeed(
  Blocklist,
  Blocklist.of({
    read: Effect.sync(() => (list === null ? { kind: "missing" as const } : { kind: "ok" as const, list, etag: "e" })),
    recent: Effect.andThen(
      Effect.suspend(() => Effect.sleep(Duration.millis(listDelayMs))),
      Effect.sync(() => (list === null ? { kind: "missing" as const } : { kind: "ok" as const, list, etag: "e" })),
    ),
    block: () => Effect.void,
    sync: () => Effect.die("not used"),
  }),
);

const blobs = Layer.succeed(
  Blobs,
  Blobs.of({
    put: (key) => Effect.sync(() => void stored.push(key)),
    stream: () => Effect.succeed(Option.none()),
    bytes: () => Effect.succeed(Option.none()),
    exists: () => Effect.succeed(false),
    remove: () => Effect.void,
  }),
);

const analysis = Layer.succeed(
  Analysis,
  Analysis.of({
    ensure: (_pkg, v) => Effect.succeed(v),
    enqueue: (name, version) => Effect.sync(() => {
      enqueued.push(`${name}@${version}`);

      return !refuseQueue;
    }),
    runJob: () => Effect.succeed<JobOutcome>("missing"),
    recover: Effect.succeed(0),
  }),
);

/** `failed`: the body ended in an error; `bytes` are the ones read before it. */
const NPM_CLIENT = "npm/10.9.0 node/v24.11.0 linux x64 workspaces/false";

type Got = { status: number; headers: Headers; bytes: Uint8Array; failed: boolean } | null;

/** Reads a body chunk by chunk, keeping what arrived before any error. */
async function readAll(body: ReadableStream<Uint8Array> | null): Promise<{ bytes: Uint8Array; failed: boolean }> {
  if (body === null) return { bytes: new Uint8Array(), failed: false };
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];

  try {
    for (;;) {
      const next = await reader.read();

      if (next.done) break;
      chunks.push(next.value);
    }

    return { bytes: Buffer.concat(chunks), failed: false };
  } catch {
    return { bytes: Buffer.concat(chunks), failed: true };
  }
}

/**
 * One request through upstreamRoute; null when it does not answer (the protocol route does). The upstream TTL is an
 * hour, so npm's document for a version stays in this isolate between requests, as a hot one does in production.
 */
/**
 * Edge checks for one request (edge-checks.ts, APM_INSTALL_CHECKS=edge): the list its view reads (null: none was
 * written; "fail": R2 throws), and whether the database is one nothing can reach, so any statement fails the request.
 */
type Edge = { list: BlocklistBody | null | "fail"; deadDatabase?: boolean; delayMs?: number };

/** A database no request can reach: port 9 refuses connections. */
const DEAD_DATABASE = "postgres://apm:apm@127.0.0.1:9/none";

/** Downloads the edge path answered, queued for analysis after the answer. */
let edgeQueued: string[] = [];

/** How far the edge views' clock is ahead of Date.now; a test moves it while npm answers, through onNpmAsk. */
let edgeShift = 0;

/** Called with each path npm is asked for, before it answers. */
let onNpmAsk: (path: string) => void = () => undefined;

/** A new bucket object per request, so no view outlives the request that read it. */
const edgeLayer = (edge: Edge) => {
  const bucket: BlocklistReader = {
    get: async (key) => {
      if (edge.delayMs !== undefined) await Bun.sleep(edge.delayMs);

      if (edge.list === "fail") throw new Error("R2 is down");
      const text = JSON.stringify(edge.list);

      return key === BLOCKLIST_KEY && edge.list !== null ? { text: () => Promise.resolve(text), etag: "e" } : null;
    },
  };

  return EdgeChecks.layer({ bucket, cache: null, cacheKey: "http://registry.test/-/apm/internal/edge-view", now: () => Date.now() + edgeShift, background: null, report: null }, (input) => {
    edgeQueued.push(`${input.name}@${input.version}`);

    return Promise.resolve("asked");
  });
};

async function get(path: string, options: { method?: string; headers?: Record<string, string>; safe?: boolean ; redirects?: "npm" | "upstream"; edge?: Edge } = {}): Promise<Got> {
  const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: npm.url, legacyAuth: false, namePolicy: "open", admins: [], tarballRedirects: options.redirects ?? "upstream" } as const;
  const store = Store.postgres(options.edge?.deadDatabase === true ? DEAD_DATABASE : db.url);
  const edge = options.edge === undefined ? Layer.empty : edgeLayer(options.edge);
  const base = Layer.mergeAll(store, Clock.fixed({ now: NOW, wallNow: NOW }), analysis, blobs, blocklist, edge, Layer.succeed(RegistryConfig, settings), RequestMemory.layer(POOL));
  const layers = Layer.provideMerge(Upstream.layer(npm.url, 3_600_000, null), base);
  // npm's own client unless a test says otherwise: one of the clients that checks a tarball's integrity itself
  const req = new Request(`http://registry.test${path}`, { method: options.method ?? "GET", headers: { "user-agent": NPM_CLIENT, ...options.headers } });

  const program = Effect.flatMap(upstreamRoute(req, new URL(req.url), options.safe ?? false), (res) =>
    Effect.promise(async () => (res ? { status: res.status, headers: res.headers, ...(await readAll(res.body)) } : null)),
  );

  return Effect.runPromise(program.pipe(Effect.provide(layers), Effect.scoped));
}

const sha512 = (bytes: Uint8Array): string => `sha512-${createHash("sha512").update(bytes).digest("base64")}`;

const confirm = (name: string, version: string, t: Tarball) =>
  sql(
    `INSERT INTO reviews (package, version, digest, outcome, result, reviewed_at, human_state) VALUES ($1, $2, $3, 'flagged', '{}', 0, 'confirmed')
     ON CONFLICT (package, version, digest) DO UPDATE SET human_state = 'confirmed'`,
    [name, version, `sha512-${t.hex}`],
  );

/** A request with credentials: answered with npm's bytes through the Worker, never sent to npm. */
const AUTH = { headers: { authorization: "Bearer someone" } } as const;

const dismiss = (name: string, version: string) => sql("UPDATE reviews SET human_state = 'dismissed' WHERE package = $1 AND version = $2", [name, version]);

describe("versionOfFile", () => {
  test("takes only the file apm's packuments link: the package's own name, a valid version, .tgz", () => {
    expect(versionOfFile("react", "react-19.2.0.tgz")).toBe("19.2.0");
    expect(versionOfFile("@types/node", "node-20.1.0-rc.1.tgz")).toBe("20.1.0-rc.1");
    expect(versionOfFile("react", "evil-19.2.0.tgz")).toBeNull();
    expect(versionOfFile("react", "react-^19.0.0.tgz")).toBeNull();
    expect(versionOfFile("react", "react-latest.tgz")).toBeNull();
    expect(versionOfFile("react", "react-1.0.0 || 2.0.0.tgz")).toBeNull();
    expect(versionOfFile("react", "react-19.2.0.tar")).toBeNull();
  });
});

describe("the upstream tarball fast path", () => {
  test("sends a request without credentials to npm's own tarball URL once nothing refuses it, and opens nothing itself", async () => {
    const got = await get("/fast/-/fast-1.0.0.tgz");

    expect(got?.status).toBe(302);
    expect(got?.headers.get("location")).toBe(`${npm.url}fast/-/fast-1.0.0.tgz`);
    expect(got?.headers.get("cache-control")).toBe("no-store");
    expect(got?.bytes.length).toBe(0);
    expect(npm.asked).toContain("/fast/1.0.0");
    expect(npm.asked.filter((p) => p.endsWith(".tgz"))).toEqual([]);
    expect(npm.asked).not.toContain("/fast");
    expect(stored).toEqual([]);
  });

  test("serves npm's bytes unchanged to a request with credentials, without reading the packument, and keeps no copy", async () => {
    const got = await get("/fast/-/fast-1.0.0.tgz", AUTH);

    expect(got?.status).toBe(200);
    expect(got?.headers.get("content-type")).toBe("application/octet-stream");
    expect(got?.headers.get("content-length")).toBe(String(FAST.bytes.length));
    expect(sha512(got?.bytes ?? new Uint8Array())).toBe(FAST.integrity);
    expect(npm.asked).toContain("/fast/-/fast-1.0.0.tgz");
    expect(npm.asked).not.toContain("/fast");
    expect(stored).toEqual([]);
  });

  test("HEAD answers the length and sends no body", async () => {
    expect((await get("/fast/-/fast-1.0.0.tgz", { method: "HEAD" }))?.status).toBe(302);
    const got = await get("/fast/-/fast-1.0.0.tgz", { method: "HEAD", ...AUTH });

    expect(got?.status).toBe(200);
    expect(got?.headers.get("content-length")).toBe(String(FAST.bytes.length));
    expect(got?.bytes.length).toBe(0);
  });

  test("a version confirmed malicious is 410 on the very next request after it was served, and served again once dismissed", async () => {
    expect((await get("/fast/-/fast-1.0.0.tgz"))?.status).toBe(302);
    await confirm("fast", "1.0.0", FAST);
    npm.asked.length = 0;

    try {
      const refused = await get("/fast/-/fast-1.0.0.tgz");

      // refused before any byte is sent or anyone is sent to npm, and nothing was opened for it
      expect(refused?.status).toBe(410);
      expect(new TextDecoder().decode(refused?.bytes)).toContain("confirmed malicious");
      expect(npm.asked.filter((p) => p.endsWith(".tgz"))).toEqual([]);

      // with credentials too. Only the database knows here (review.ts puts a confirmation on the block list before it
      // commits, and a version on the list is never asked for: the next test), so npm's tarball may have been opened
      // while the statement ran, and is let go unread
      const private410 = await get("/fast/-/fast-1.0.0.tgz", AUTH);

      expect(private410?.status).toBe(410);
      expect(private410?.headers.get("content-type")).not.toBe("application/octet-stream");
      // the other version is not touched
      expect((await get("/fast/-/fast-1.1.0.tgz"))?.status).toBe(302);
    } finally {
      await dismiss("fast", "1.0.0");
    }

    const back = await get("/fast/-/fast-1.0.0.tgz", AUTH);

    expect(back?.status).toBe(200);
    expect(sha512(back?.bytes ?? new Uint8Array())).toBe(FAST.integrity);
    expect((await get("/fast/-/fast-1.0.0.tgz"))?.status).toBe(302);
  });

  test("a version on the install block list is 410 even when the database has no confirmation", async () => {
    expect((await get("/fast/-/fast-1.0.0.tgz"))?.status).toBe(302);
    list = { format: 1, syncedAt: NOW, local: [], confirmed: [{ name: "fast", version: "1.0.0", digest: `sha512-${FAST.hex}`, addedAt: NOW }] };

    npm.asked.length = 0;
    expect((await get("/fast/-/fast-1.0.0.tgz"))?.status).toBe(410);
    expect((await get("/fast/-/fast-1.0.0.tgz", { method: "HEAD" }))?.status).toBe(410);
    // nor with credentials, whose tarball is opened early only when the block list does not refuse it
    expect((await get("/fast/-/fast-1.0.0.tgz", AUTH))?.status).toBe(410);
    expect(npm.asked.filter((p) => p.endsWith(".tgz"))).toEqual([]);
    expect((await get("/fast/-/fast-1.1.0.tgz"))?.status).toBe(302);
  });

  test("a block list read that misses its deadline leaves the database to decide alone: what it confirms is refused, the rest served", async () => {
    expect((await get("/fast/-/fast-1.0.0.tgz"))?.status).toBe(302);
    listDelayMs = 2_000;
    // on the list alone: not seen once the list is late, as on the install document's database path
    list = { format: 1, syncedAt: NOW, local: [], confirmed: [{ name: "fast", version: "1.1.0", digest: `sha512-${FAST_NEXT.hex}`, addedAt: NOW }] };
    await confirm("fast", "1.0.0", FAST);

    try {
      for (const options of [{}, AUTH]) {
        const start = performance.now();

        expect((await get("/fast/-/fast-1.0.0.tgz", options))?.status).toBe(410);
        expect(performance.now() - start).toBeLessThan(EDGE_READ_DEADLINE_MS + 300);
      }

      const start = performance.now();

      expect((await get("/fast/-/fast-1.1.0.tgz"))?.status).toBe(302);
      expect((await get("/fast/-/fast-1.1.0.tgz", AUTH))?.status).toBe(200);
      expect(performance.now() - start).toBeLessThan(2 * (EDGE_READ_DEADLINE_MS + 300));
    } finally {
      await dismiss("fast", "1.0.0");
    }
  });

  test("a block list that was never written adds nothing; the database still refuses", async () => {
    list = null;

    expect((await get("/fast/-/fast-1.0.0.tgz"))?.status).toBe(302);
    await confirm("fast", "1.0.0", FAST);

    try {
      expect((await get("/fast/-/fast-1.0.0.tgz"))?.status).toBe(410);
      expect((await get("/fast/-/fast-1.0.0.tgz", AUTH))?.status).toBe(410);
    } finally {
      await dismiss("fast", "1.0.0");
    }
  });

  test("a package published on apm is left to the protocol route, never served from npm", async () => {
    await sql(`INSERT INTO packages (name, created_at, modified_at, dist_tags) VALUES ('mine', 0, 0, '{"latest":"1.0.0"}'::jsonb)`);

    try {
      expect(await get("/mine/-/mine-1.0.0.tgz")).toBeNull();
      expect(await get("/mine/-/mine-1.0.0.tgz", { method: "HEAD" })).toBeNull();
      expect(await get("/mine/-/mine-1.0.0.tgz", AUTH)).toBeNull();
    } finally {
      await sql("DELETE FROM packages WHERE name = 'mine'");
    }
  });

  test("a name the block list says is published here goes to the packument route", async () => {
    list = { format: 1, syncedAt: NOW, local: [{ name: "fast", addedAt: NOW }], confirmed: [] };
    const got = await get("/fast/-/fast-1.0.0.tgz");

    // the packument route answers it as it did before this path, keeping the bytes it downloaded whole in R2
    expect(got?.status).toBe(200);
    expect(stored).toEqual([`sha512/${FAST.hex}`]);
  });

  test("~safe keeps its own route: the packument and its policy", async () => {
    const got = await get("/fast/-/fast-1.0.0.tgz", { safe: true });

    // nothing here is scored, so the view does not serve it, and nothing is fetched for it
    expect(got?.status).toBe(404);
    expect(new TextDecoder().decode(got?.bytes)).toContain("is not in this view");
    expect(npm.asked.filter((p) => p.endsWith(".tgz"))).toEqual([]);
  });

  test("a request with credentials is served the same bytes, and no copy is kept", async () => {
    const got = await get("/fast/-/fast-1.0.0.tgz", { headers: { authorization: "Bearer someone" } });

    expect(got?.status).toBe(200);
    expect(sha512(got?.bytes ?? new Uint8Array())).toBe(FAST.integrity);
    expect(got?.headers.get("cache-control")).toBe("private, no-store");
    expect(got?.headers.get("vary")).toBe("Authorization, Cookie");
    expect((await get("/fast/-/fast-1.0.0.tgz", { headers: { cookie: "s=1" } }))?.headers.get("cache-control")).toBe("private, no-store");
    expect(npm.asked).not.toContain("/fast");
    expect(stored).toEqual([]);
  });

  test("a confirmed version's refusal to a request with credentials is not kept by a shared cache either", async () => {
    await confirm("fast", "1.0.0", FAST);

    try {
      const got = await get("/fast/-/fast-1.0.0.tgz", { headers: { cookie: "s=1" } });

      expect(got?.status).toBe(410);
      expect(got?.headers.get("cache-control")).toBe("private, no-store");
      expect(got?.headers.get("vary")).toBe("Authorization, Cookie");
    } finally {
      await dismiss("fast", "1.0.0");
    }
  });

  test("a version npm does not have is not served", async () => {
    const missing = await get("/fast/-/fast-9.9.9.tgz");

    expect(missing?.status).toBe(404);
    expect(npm.asked.filter((p) => p.endsWith(".tgz") && p !== "/fast/-/fast-9.9.9.tgz")).toEqual([]);
  });

  test("a version npm's document resolves to another (a tag or range) is not served as that one", async () => {
    const got = await get("/fast/-/fast-2.0.0.tgz");

    expect(got?.status).toBe(404);
    expect(npm.asked).not.toContain("/fast/-/fast-1.1.0.tgz");
  });

  test("a file name that is not the package's goes to the packument route, as before", async () => {
    await get("/fast/-/other-1.0.0.tgz");

    // the packument route keeps what it downloads whole in R2; this path keeps nothing
    expect(stored).toEqual([`sha512/${FAST.hex}`]);
  });

  test("a tarball npm links from another URL is fetched from there and checked, never redirected to", async () => {
    // only the upstream's own URL for exactly this version is redirected to: past it, the client follows any further
    // hops with none of apm's checks
    for (const options of [{}, AUTH]) {
      const got = await get("/moved/-/moved-1.0.0.tgz", options);

      expect(got?.status).toBe(200);
      expect(got?.headers.get("location")).toBeNull();
      expect(sha512(got?.bytes ?? new Uint8Array())).toBe(MOVED.integrity);
    }

    const got = await get("/moved/-/moved-1.0.0.tgz", AUTH);

    expect(got?.status).toBe(200);
    expect(sha512(got?.bytes ?? new Uint8Array())).toBe(MOVED.integrity);
    expect(npm.asked).toContain("/moved/-/elsewhere-1.0.0.tgz");
    expect(npm.asked).not.toContain("/moved");
  });

  test("scoped packages take the same path", async () => {
    expect((await get("/@scope/pkg/-/pkg-1.0.0.tgz"))?.headers.get("location")).toBe(`${npm.url}@scope/pkg/-/pkg-1.0.0.tgz`);
    const got = await get("/@scope/pkg/-/pkg-1.0.0.tgz", AUTH);

    expect(got?.status).toBe(200);
    expect(sha512(got?.bytes ?? new Uint8Array())).toBe(SCOPED.integrity);
    expect(npm.asked).toContain("/@scope%2Fpkg/1.0.0");
    expect(npm.asked).not.toContain("/@scope%2Fpkg");
  });

  test("bytes that do not match the version's checksum never reach the end of the answer", async () => {
    const got = await get("/tampered/-/tampered-1.0.0.tgz", AUTH);

    // the answer errors, and the last bytes are held back, so the client never has the whole tampered body
    expect(got?.failed).toBe(true);
    expect(got?.bytes.length ?? 0).toBeLessThan(TAMPERED.bytes.length);
  });

  test("a tarball npm sends compressed is served decoded, with no Content-Length counting the compressed bytes", async () => {
    const got = await get("/gz/-/gz-1.0.0.tgz", AUTH);

    expect(got?.status).toBe(200);
    expect(got?.failed).toBe(false);
    expect(sha512(got?.bytes ?? new Uint8Array())).toBe(GZ.integrity);
    expect(got?.headers.get("content-length")).toBeNull();

    const head = await get("/gz/-/gz-1.0.0.tgz", { method: "HEAD", ...AUTH });

    expect(head?.status).toBe(200);
    expect(head?.headers.get("content-length")).toBeNull();
  });

  test("a download queues the version for analysis unless it is scored, decided or queued already", async () => {
    await get("/fast/-/fast-1.1.0.tgz");
    expect(enqueued).toEqual(["fast@1.1.0"]);

    enqueued = [];
    await sql("INSERT INTO analysis_jobs (package, version, queued_at, scorer) VALUES ('fast', '1.1.0', $1, $2)", [NOW - 60_000, SCORER]);
    await get("/fast/-/fast-1.1.0.tgz");
    expect(enqueued).toEqual([]);

    // a reservation older than the requeue window does not count
    await sql("UPDATE analysis_jobs SET queued_at = $1 WHERE package = 'fast' AND version = '1.1.0'", [NOW - 11 * 60_000]);
    await get("/fast/-/fast-1.1.0.tgz");
    expect(enqueued).toEqual(["fast@1.1.0"]);

    enqueued = [];
    await sql("INSERT INTO analysis_outcomes (package, version, scorer, starts, outcome, decided_at) VALUES ('fast', '1.1.0', $1, 1, 'unreadable', 0)", [SCORER]);
    await get("/fast/-/fast-1.1.0.tgz");
    expect(enqueued).toEqual([]);
  });
});

describe("a download answered from the edge view, asked about after its answer (queueDownload)", () => {
  const ask = (name: string, version: string) =>
    Effect.runPromise(queueDownload({ name, version }).pipe(Effect.provide(Layer.mergeAll(Store.postgres(db.url), Clock.fixed({ now: NOW, wallNow: NOW }), analysis)), Effect.scoped));

  test("is \"asked\" when the queue took the version, \"failed\" when it refused it, so the edge asks again in seconds and counts the failure", async () => {
    expect(await ask("qd", "1.0.0")).toBe("asked");
    refuseQueue = true;
    expect(await ask("qd", "1.0.1")).toBe("failed");
    expect(enqueued).toEqual(["qd@1.0.0", "qd@1.0.1"]);
  });

  test("is \"asked\" with nothing sent when the version is queued already", async () => {
    await sql("INSERT INTO analysis_jobs (package, version, queued_at, scorer) VALUES ('qd', '2.0.0', $1, $2)", [NOW - 60_000, SCORER]);
    refuseQueue = true;
    expect(await ask("qd", "2.0.0")).toBe("asked");
    expect(enqueued).toEqual([]);
  });
});

describe("compressed upstream answers on the older tarball paths", () => {
  // fetch decodes a gzip answer, so its Content-Length (the compressed size) is not the body's: a check against it
  // failed a valid download over the cap (serve, the packument route) and the analysis reader (openTarball)
  const upstreamDo = <A>(f: (u: UpstreamApi, lease: Lease) => Effect.Effect<A, unknown, never>) => {
    const base = Layer.mergeAll(Store.postgres(db.url), Clock.fixed({ now: NOW, wallNow: NOW }), blobs, RequestMemory.layer(POOL));
    const layers = Layer.provideMerge(Upstream.layer(npm.url, 3_600_000, null), base);

    return Effect.runPromise(Effect.gen(function* () {
      return yield* f(yield* Upstream, yield* RequestMemory);
    }).pipe(Effect.provide(layers), Effect.scoped));
  };

  for (const path of ["serve", "openTarball"] as const) {
    test(`${path} passes on a big compressed tarball whole and checked`, async () => {
      const got = await upstreamDo((u, lease) =>
        Effect.gen(function* () {
          const pkg = yield* u.get("gzbig", lease);

          if (pkg === null) return yield* Effect.die("npm stand-in has gzbig");
          const served = yield* u[path](pkg, "1.0.0");

          if (served.kind !== "stream") return { kind: served.kind, bytes: null, length: null };

          return { kind: served.kind, length: served.length, bytes: yield* Effect.promise(() => readAll(served.body)) };
        }),
      );

      expect(got.kind).toBe("stream");
      expect(got.length).toBeNull();
      expect(got.bytes?.failed).toBe(false);
      expect(sha512(got.bytes?.bytes ?? new Uint8Array())).toBe(BIG_ZEROS.integrity);
    }, 60_000);
  }
});

describe("which requests are redirected to npm", () => {
  const plain = async (headers: Record<string, string>, redirects: "npm" | "upstream" = "upstream") => {
    const got = await get("/fast/-/fast-1.0.0.tgz", { headers, redirects });

    return { status: got?.status, location: got?.headers.get("location") ?? null, intact: sha512(got?.bytes ?? new Uint8Array()) === FAST.integrity };
  };

  test("npm, pnpm, bun and yarn 1 are redirected: each checks the tarball against the install document's integrity", async () => {
    for (const ua of [NPM_CLIENT, "pnpm/9.15.0 npm/? node/v22.11.0 linux x64", "Bun/1.4.4", "yarn/1.22.22 npm/? node/v22.11.0 linux x64"]) {
      expect(await plain({ "user-agent": ua }), ua).toEqual({ status: 302, location: `${npm.url}fast/-/fast-1.0.0.tgz`, intact: false });
    }
  });

  test("yarn 2 and later, and any client apm does not know, get npm's bytes checked here", async () => {
    // Yarn Berry trusts its own cache checksum, which a first install does not have yet
    for (const ua of ["yarn/4.6.0 npm/? node/v22.11.0 linux x64", "curl/8.5.0", ""]) {
      expect(await plain({ "user-agent": ua }), ua).toEqual({ status: 200, location: null, intact: true });
    }
  });

  test("by default only npm's own https URL is redirected to, so this stand-in's tarball is streamed", async () => {
    expect(await plain({ "user-agent": NPM_CLIENT }, "npm")).toEqual({ status: 200, location: null, intact: true });
  });
});

describe("with edge checks (APM_INSTALL_CHECKS=edge)", () => {
  // synced just now by the edge views' clock (Date.now): a list not synced for 15 minutes decides nothing
  const synced = (input: { local?: string[]; confirmed?: { name: string; version: string; t: Tarball }[] } = {}): BlocklistBody => ({
    format: 1,
    syncedAt: Date.now(),
    local: (input.local ?? []).map((name) => ({ name, addedAt: NOW })),
    confirmed: (input.confirmed ?? []).map((c) => ({ name: c.name, version: c.version, digest: `sha512-${c.t.hex}`, addedAt: NOW })),
  });

  test("a name the view clears is redirected to npm with no database statement, and queued for analysis after the answer", async () => {
    // the database cannot be reached: any statement would fail this request
    const got = await get("/fast/-/fast-1.0.0.tgz", { edge: { list: synced(), deadDatabase: true } });

    expect(got?.status).toBe(302);
    expect(got?.headers.get("location")).toBe(`${npm.url}fast/-/fast-1.0.0.tgz`);
    expect(got?.headers.get("cache-control")).toBe("no-store");
    expect(npm.asked.filter((p) => p.endsWith(".tgz"))).toEqual([]);
    expect(edgeQueued).toEqual(["fast@1.0.0"]);
    // HEAD the same
    expect((await get("/fast/-/fast-1.0.0.tgz", { method: "HEAD", edge: { list: synced(), deadDatabase: true } }))?.status).toBe(302);
  });

  test("a name the view lists as published here, or with any confirmed version, takes the database path", async () => {
    for (const list of [synced({ local: ["fast"] }), synced({ confirmed: [{ name: "fast", version: "1.1.0", t: FAST_NEXT }] })]) {
      await expect(get("/fast/-/fast-1.0.0.tgz", { edge: { list, deadDatabase: true } })).rejects.toThrow();
    }

    // and the database path answers as it always has, reading the same list: the confirmed version is refused, the
    // other one served
    const flagged = synced({ confirmed: [{ name: "fast", version: "1.1.0", t: FAST_NEXT }] });

    list = flagged;

    expect((await get("/fast/-/fast-1.1.0.tgz", { edge: { list: flagged } }))?.status).toBe(410);
    expect((await get("/fast/-/fast-1.0.0.tgz", { edge: { list: flagged } }))?.status).toBe(302);
    expect(edgeQueued).toEqual([]);
  });

  test("a name published here in the database but not yet in the view is the publish's hold to cover; with it in the view the protocol route answers", async () => {
    await sql(`INSERT INTO packages (name, created_at, modified_at, dist_tags) VALUES ('mine', 0, 0, '{"latest":"1.0.0"}'::jsonb)`);

    try {
      expect(await get("/mine/-/mine-1.0.0.tgz", { edge: { list: synced({ local: ["mine"] }) } })).toBeNull();
    } finally {
      await sql("DELETE FROM packages WHERE name = 'mine'");
    }
  });

  test("a list never synced, never written, or unreadable from R2 takes the database path, never answers open", async () => {
    for (const list of [{ ...synced(), syncedAt: null }, null, "fail" as const]) {
      await expect(get("/fast/-/fast-1.0.0.tgz", { edge: { list, deadDatabase: true } })).rejects.toThrow();
      expect((await get("/fast/-/fast-1.0.0.tgz", { edge: { list } }))?.status).toBe(302);
    }

    // the database path queued it, inline, as before
    expect(edgeQueued).toEqual([]);
  });

  test("requests with credentials, ~safe, and clients that do not check tarballs keep the database path", async () => {
    const edge = { list: synced(), deadDatabase: true };

    await expect(get("/fast/-/fast-1.0.0.tgz", { ...AUTH, edge })).rejects.toThrow();
    await expect(get("/fast/-/fast-1.0.0.tgz", { headers: { cookie: "s=1" }, edge })).rejects.toThrow();
    await expect(get("/fast/-/fast-1.0.0.tgz", { safe: true, edge })).rejects.toThrow();
    await expect(get("/fast/-/fast-1.0.0.tgz", { headers: { "user-agent": "yarn/4.6.0 npm/? node/v22.11.0 linux x64" }, edge })).rejects.toThrow();

    const live = { list: synced() };

    expect((await get("/fast/-/fast-1.0.0.tgz", { ...AUTH, edge: live }))?.status).toBe(200);
    expect((await get("/fast/-/fast-1.0.0.tgz", { safe: true, edge: live }))?.status).toBe(404);
    expect(edgeQueued).toEqual([]);
  });

  test("a clearance that ages past the view's window while npm answers is not used: the tarball and install document take the database path", async () => {
    // the view clears the name, then npm's answer takes the view's whole window (the clock jumps while npm answers)
    onNpmAsk = (path) => {
      if (path.startsWith("/aging")) edgeShift = EDGE_VIEW_MAX_AGE_MS;
    };
    // with no database to reach, the database path fails the request: so the edge's clearance did not answer it

    await expect(get("/aging/-/aging-1.0.0.tgz", { edge: { list: synced(), deadDatabase: true } })).rejects.toThrow();
    expect(npm.asked).toContain("/aging/1.0.0");
    edgeShift = 0;
    await expect(get("/agingdoc", { headers: { accept: INSTALL_ACCEPT }, edge: { list: synced(), deadDatabase: true } })).rejects.toThrow();
    expect(npm.asked).toContain("/agingdoc");
    // npm has no such package: that answer too is made from the clearance only while it is young
    onNpmAsk = (path) => {
      if (path.startsWith("/agingmissing")) edgeShift = EDGE_VIEW_MAX_AGE_MS;
    };

    edgeShift = 0;
    await expect(get("/agingmissing", { headers: { accept: INSTALL_ACCEPT }, edge: { list: synced(), deadDatabase: true } })).rejects.toThrow();
    edgeShift = 0;
    onNpmAsk = () => undefined;
    expect(await get("/agingmissing2", { headers: { accept: INSTALL_ACCEPT }, edge: { list: synced(), deadDatabase: true } })).toBeNull();

    expect(edgeQueued).toEqual([]);

    // a clearance still young when npm has answered (npm's documents are in this isolate now) is used, with no statement
    onNpmAsk = () => undefined;
    edgeShift = 0;
    expect((await get("/aging/-/aging-1.0.0.tgz", { edge: { list: synced(), deadDatabase: true } }))?.status).toBe(302);
    expect((await get("/agingdoc", { headers: { accept: INSTALL_ACCEPT }, edge: { list: synced(), deadDatabase: true } }))?.status).toBe(200);
  });

  test("a version npm's document does not confirm, or one linked from another URL, takes the database path", async () => {
    await expect(get("/fast/-/fast-2.0.0.tgz", { edge: { list: synced(), deadDatabase: true } })).rejects.toThrow();
    await expect(get("/moved/-/moved-1.0.0.tgz", { edge: { list: synced(), deadDatabase: true } })).rejects.toThrow();
  });

  test("a slow R2 holds neither read past its deadline: the view's read and then the database path's list read each give up at EDGE_READ_DEADLINE_MS", async () => {
    // warm npm's document, so only the two R2 reads and the statement are timed
    expect((await get("/fast/-/fast-1.0.0.tgz"))?.status).toBe(302);
    listDelayMs = 1_000;
    const start = performance.now();
    const got = await get("/fast/-/fast-1.0.0.tgz", { edge: { list: synced(), delayMs: 1_000 } });
    const took = performance.now() - start;

    expect(got?.status).toBe(302);
    // the view's 300 ms, then the list's 300 ms beside the statement: not the 1.3 s the second R2 read used to add
    expect(took).toBeGreaterThanOrEqual(2 * EDGE_READ_DEADLINE_MS - 20);
    expect(took).toBeLessThan(2 * EDGE_READ_DEADLINE_MS + 300);
    expect(edgeQueued).toEqual([]);
  });
});
