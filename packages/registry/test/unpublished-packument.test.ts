// A package whose every version was unpublished is still a 200 from npm: no versions or dist-tags, and the unpublish
// recorded as an object under `time.unpublished`. upstream.ts read `time` as a record of strings, so the whole
// packument was refused and the registry answered 503 "The upstream registry could not be read ... Try again shortly"
// on every request for that name, which clients retry. It is now read, and served as npm serves it: a package with no
// versions. npm is a local stand-in on 127.0.0.1; no real host is contacted.
import { describe, expect, test } from "bun:test";
import { Effect, Layer, Option } from "effect";
import { z } from "zod";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis } from "../src/analysis.ts";
import { upstreamRoute } from "../src/apm.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { RegistryConfig } from "../src/config.ts";
import { Store } from "../src/db.ts";
import { MemoryPool, RequestMemory } from "../src/memory.ts";
import { cachedPackage, Upstream } from "../src/upstream.ts";

/** This file's memory pool: every request it runs takes a lease of it, as a Worker isolate's do. */
const POOL = new MemoryPool();

const NOW = Date.parse("2026-11-22T00:00:00Z");

/** npm's answer for a package whose two versions were both unpublished (the shape registry.npmjs.org sends). */
const UNPUBLISHED = {
  _id: "gone-pkg",
  name: "gone-pkg",
  time: {
    created: "2025-08-24T23:54:56.459Z",
    modified: "2025-11-21T20:20:02.492Z",
    "1.0.0": "2025-08-24T23:54:56.649Z",
    "1.0.1": "2025-08-25T00:00:11.719Z",
    unpublished: { time: "2025-11-21T20:20:02.492Z", versions: ["1.0.0", "1.0.1"] },
  },
  _rev: "3-0123456789abcdef0123456789abcdef",
};

const noBlobs = Layer.succeed(
  Blobs,
  Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }),
);

function fakeNpm() {
  const body = JSON.stringify(UNPUBLISHED);

  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch: (req) => (new URL(req.url).pathname === "/gone-pkg" ? new Response(body, { headers: { "content-type": "application/json" } }) : Response.json({ error: "Not found" }, { status: 404 })),
  });

  return { url: server.url.href, stop: () => server.stop(true) };
}

const Served = z.object({ name: z.string(), "dist-tags": z.record(z.string(), z.string()), versions: z.record(z.string(), z.unknown()) });

describe("a package npm lists as unpublished", () => {
  test("is read as a package with no versions, not refused", () => {
    const pkg = cachedPackage("gone-pkg", UNPUBLISHED, { versionDocs: 0, maxPieceChars: 0 }, null);

    // before the fix: null, which the registry turns into its 503
    expect(pkg).not.toBeNull();
    expect(pkg?.versions).toEqual([]);
    expect(pkg?.distTags).toEqual({});
  });

  test("a version's own time is still read when another entry of `time` is not a string", () => {
    const body = {
      name: "half-gone",
      "dist-tags": { latest: "2.0.0" },
      versions: { "2.0.0": { name: "half-gone", version: "2.0.0", dist: { tarball: "https://npm.invalid/half-gone/-/half-gone-2.0.0.tgz", shasum: "1".repeat(40) } } },
      time: { "2.0.0": "2026-10-02T00:00:00.000Z", odd: { not: "a string" } },
    };

    const pkg = cachedPackage("half-gone", body, { versionDocs: 0, maxPieceChars: 0 }, null);

    expect(pkg?.versions.map((v) => [v.version, v.published_at])).toEqual([["2.0.0", Date.parse("2026-10-02T00:00:00.000Z")]]);
  });

  // npm install's own document first: it is answered on its own path (installPackument, Upstream.installCopy), and
  // TTL 0 expires entries immediately, so each request reads the stand-in independently of wall-clock timing
  test("its install document and its full packument are served 200 with no versions, never a 503 the client retries", async () => {
    const db = await freshDatabase();
    const npm = fakeNpm();

    const get = async (accept: string) => {
      const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: npm.url, legacyAuth: false, namePolicy: "open", admins: [] } as const;
      const base = Layer.mergeAll(Store.postgres(db.url), Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs, Layer.succeed(RegistryConfig, settings), RequestMemory.layer(POOL));
      const layers = Layer.provideMerge(Upstream.layer(npm.url, 0, null), base);
      const req = new Request("http://registry.test/gone-pkg", { headers: { accept } });
      const program = Effect.flatMap(upstreamRoute(req, new URL(req.url), false), (res) => Effect.promise(async () => ({ status: res?.status, type: res?.headers.get("content-type") ?? null, text: (await res?.text()) ?? "" })));

      return Effect.runPromise(program.pipe(Effect.provide(layers), Effect.scoped));
    };

    try {
      // before the fix, both: 503 {"error":"The upstream registry could not be read for gone-pkg. Try again shortly."}
      const install = await get("application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*");

      expect(install.status).toBe(200);
      expect(install.type).toBe("application/vnd.npm.install-v1+json; charset=utf-8");
      const slim = Served.parse(JSON.parse(install.text));

      expect(slim.name).toBe("gone-pkg");
      expect(slim.versions).toEqual({});
      expect(slim["dist-tags"]).toEqual({});

      const full = await get("application/json");

      expect(full.status).toBe(200);
      const served = Served.parse(JSON.parse(full.text));

      expect(served.name).toBe("gone-pkg");
      expect(served.versions).toEqual({});
      expect(served["dist-tags"]).toEqual({});
    } finally {
      npm.stop();
      await db.drop();
    }
  });
});
