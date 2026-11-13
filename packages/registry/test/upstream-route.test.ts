// The npm protocol's packument route for packages only npm has (apm.ts, upstreamRoute). Review of 89441a9:
// - finding 4: the registry keeps npm's packument without devDependencies, so `npm view <pkg> devDependencies` had
//   nothing to show. The full packument now adds them back from a read of their own; the abbreviated one, which installs
//   read, stays without them, and licenseText is left out of both.
// - finding 7: an upstream that could not be asked, or a packument the reader refused, answered 404 "Not found", which
//   npm reports as a package that does not exist. It is now a 503 with Retry-After.
// - review of f0e533a, finding 1: the full packument's devDependencies were read with no budget beside the packument
//   the request already held. Both now share the request's budget (REQUEST_METADATA_WEIGHT).
// npm is a local stand-in on 127.0.0.1; no real host is contacted.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { Effect, Layer, Option } from "effect";
import { z } from "zod";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis } from "../src/analysis.ts";
import { UPSTREAM_RETRY_AFTER_S, upstreamRoute } from "../src/apm.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { RegistryConfig } from "../src/config.ts";
import { Store } from "../src/db.ts";
import { DEV_DEPENDENCIES, readPackument } from "../src/packument-read.ts";
import { Upstream } from "../src/upstream.ts";
import { MemoryPool, RequestMemory } from "../src/memory.ts";

/** This file's memory pool: every request it runs takes a lease of it, as a Worker isolate's do. */
const POOL = new MemoryPool();

const NOW = Date.parse("2026-11-12T00:00:00Z");

const noBlobs = Layer.succeed(
  Blobs,
  Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }),
);

const dist = (name: string, v: string) => ({ tarball: `https://npm.invalid/${name}/-/${name}-${v}.tgz`, shasum: "1".repeat(40), integrity: `sha512-${createHash("sha512").update(`${name}${v}`).digest("base64")}` });

/** npm's packument for `viewed`: two versions, each with devDependencies and a licenseText. */
const VIEWED = {
  _id: "viewed",
  name: "viewed",
  "dist-tags": { latest: "1.1.0" },
  versions: {
    "1.0.0": { name: "viewed", version: "1.0.0", license: "MIT", dependencies: { dep: "^1.0.0" }, devDependencies: { tap: "^16.0.0" }, licenseText: "MIT License\n".repeat(100), dist: dist("viewed", "1.0.0") },
    "1.1.0": { name: "viewed", version: "1.1.0", license: "MIT", devDependencies: { vitest: "^3.0.0", typescript: "^5.0.0" }, licenseText: "MIT License\n".repeat(100), dist: dist("viewed", "1.1.0") },
  },
  time: { "1.0.0": "2026-10-01T00:00:00Z", "1.1.0": "2026-10-02T00:00:00Z" },
};

/**
 * `heavy`: 2,000 versions, each with 11.5 KB of a kept field and 340 devDependencies. Alone, each read fits every
 * per-read limit (24 MB weight cached and scored; 45 MB weight, 1.4 million nodes, of devDependencies); together they
 * pass REQUEST_METADATA_WEIGHT.
 */
const HEAVY = JSON.stringify({
  name: "heavy",
  "dist-tags": { latest: "1.0.1999" },
  versions: Object.fromEntries(
    Array.from({ length: 2_000 }, (_, i) => [
      `1.0.${i}`,
      { name: "heavy", version: `1.0.${i}`, notes: "n".repeat(11_500), devDependencies: Object.fromEntries(Array.from({ length: 340 }, (_, j) => [`dev${j}`, {}])), dist: dist("heavy", `1.0.${i}`) },
    ]),
  ),
});

/** npm, standing in: `viewed`; `heavy`; `down`, which fails with a 500; `broken`, whose packument is not JSON; nothing else. */
function fakeNpm() {
  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const path = new URL(req.url).pathname;

      if (path === "/viewed") return Response.json(VIEWED);

      if (path === "/heavy") return new Response(HEAVY, { headers: { "content-type": "application/json" } });

      if (path === "/down") return new Response("upstream trouble", { status: 500 });

      // a trailing comma in a field nobody reads: JSON.parse refuses it, and so does the reader now
      if (path === "/broken") return new Response('{"name":"broken","users":{"a":true,},"versions":{}}', { headers: { "content-type": "application/json" } });

      return Response.json({ error: "Not found" }, { status: 404 });
    },
  });

  return { url: server.url.href, stop: () => server.stop(true) };
}

let db: Awaited<ReturnType<typeof freshDatabase>>;
let npm: ReturnType<typeof fakeNpm>;

beforeAll(async () => {
  db = await freshDatabase();
  npm = fakeNpm();
});

afterAll(async () => {
  npm.stop();
  await db.drop();
});

/** One request through upstreamRoute; null when the route does not answer it (the protocol route then says 404). */
async function get(path: string, accept = "application/json"): Promise<{ status: number; headers: Headers; text: string } | null> {
  const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: npm.url, legacyAuth: false, namePolicy: "open", admins: [] } as const;
  const base = Layer.mergeAll(Store.postgres(db.url), Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs, Layer.succeed(RegistryConfig, settings), RequestMemory.layer(POOL));
  // a TTL under a second, so each request asks the stand-in again
  const layers = Layer.provideMerge(Upstream.layer(npm.url, 1, null), base);
  const req = new Request(`http://registry.test${path}`, { headers: { accept } });

  const program = Effect.flatMap(upstreamRoute(req, new URL(req.url), false), (res) =>
    Effect.promise(async () => (res ? { status: res.status, headers: res.headers, text: await res.text() } : null)),
  );

  return Effect.runPromise(program.pipe(Effect.provide(layers), Effect.scoped));
}

const Served = z.object({ versions: z.record(z.string(), z.looseObject({ version: z.string() })) });

describe("the npm packument route", () => {
  test("the full packument carries each version's devDependencies; the abbreviated one and licenseText do not", async () => {
    const full = await get("/viewed");

    expect(full?.status).toBe(200);
    const fullBody = Served.parse(JSON.parse(full?.text ?? ""));

    // on 89441a9 both were left out
    expect(fullBody.versions["1.0.0"]?.devDependencies).toEqual({ tap: "^16.0.0" });
    expect(fullBody.versions["1.1.0"]?.devDependencies).toEqual({ vitest: "^3.0.0", typescript: "^5.0.0" });
    expect(fullBody.versions["1.1.0"]?.license).toBe("MIT");
    expect(Object.values(fullBody.versions).some((v) => "licenseText" in v)).toBe(false);

    const abbreviated = await get("/viewed", "application/vnd.npm.install-v1+json");

    expect(abbreviated?.status).toBe(200);
    const abbreviatedBody = Served.parse(JSON.parse(abbreviated?.text ?? ""));

    expect(Object.values(abbreviatedBody.versions).some((v) => "devDependencies" in v || "licenseText" in v)).toBe(false);
  });

  test("devDependencies that do not fit beside the packument in the request's budget are left out, not held", async () => {
    // each read on its own is within every limit
    for (const profile of [undefined, DEV_DEPENDENCIES]) expect((await readPackument(new Blob([HEAVY]).stream(), { profile, lease: new MemoryPool().request() })).kind).toBe("ok");
    // the two together (about 68 MiB) fit one request's 72 MiB, but not while the isolate's pool holds 20 MiB for others
    const others = POOL.request();
    expect(others.take(20 * 1024 * 1024)).toBe(true);
    const full = await get("/heavy").finally(() => others.release());

    expect(full?.status).toBe(200);
    const body = Served.parse(JSON.parse(full?.text ?? ""));

    expect(Object.keys(body.versions)).toHaveLength(2_000);
    expect(body.versions["1.0.7"]?.notes).toBe("n".repeat(11_500));
    // on f0e533a the second read had no budget: all of them were read and held beside the packument
    expect(Object.values(body.versions).some((v) => "devDependencies" in v)).toBe(false);
  }, 60_000);

  test("an upstream that fails is a 503 with Retry-After, not a missing package", async () => {
    // on 89441a9 the route did not answer, and the protocol route said 404 Not found
    const r = await get("/down");

    expect(r?.status).toBe(503);
    expect(r?.headers.get("retry-after")).toBe(String(UPSTREAM_RETRY_AFTER_S));
  });

  test("a packument the reader refuses is a 503 too", async () => {
    const r = await get("/broken");

    expect(r?.status).toBe(503);
    expect(r?.headers.get("retry-after")).toBe(String(UPSTREAM_RETRY_AFTER_S));
  });

  test("a package npm does not have is still not found", async () => {
    // the route leaves it to the protocol route, which answers 404
    expect(await get("/nobody-has-this")).toBeNull();
  });
});
