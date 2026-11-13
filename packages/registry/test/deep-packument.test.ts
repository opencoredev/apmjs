// Review of 9913a74, finding 4: an upstream version whose `exports` nests 50,000 levels deep was listed, but serving
// the package's packument threw RangeError in JSON.stringify, so the request failed for every version of the package.
// A manifest past the limits apm reads is now served without the fields past them, and says which it left out. npm is
// a local stand-in on 127.0.0.1; no real host is contacted.
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { Effect, Layer, Option } from "effect";
import { z } from "zod";
import { TRIMMED_FIELD } from "@apm/core";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis } from "../src/analysis.ts";
import { upstreamRoute } from "../src/apm.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { RegistryConfig } from "../src/config.ts";
import { Store } from "../src/db.ts";
import { Upstream } from "../src/upstream.ts";

const NOW = Date.parse("2026-11-12T00:00:00Z");
const DEPTH = 50_000;

const noBlobs = Layer.succeed(
  Blobs,
  Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }),
);

/** npm, standing in: one package with a shallow 1.0.0 and a 2.0.0 whose exports nest DEPTH levels deep. */
function fakeNpm() {
  const dist = (v: string) => JSON.stringify({ tarball: `https://npm.invalid/deep-review/-/deep-review-${v}.tgz`, shasum: "1".repeat(40), integrity: `sha512-${createHash("sha512").update(v).digest("base64")}` });
  const deep = `${'{"node":'.repeat(DEPTH)}"./index.js"${"}".repeat(DEPTH)}`;
  const shallow = `{"name":"deep-review","version":"1.0.0","main":"index.js","license":"MIT","dist":${dist("1.0.0")}}`;
  const deepVersion = `{"name":"deep-review","version":"2.0.0","main":"index.js","license":"MIT","dependencies":{"left-pad":"^1.0.0"},"exports":${deep},"dist":${dist("2.0.0")}}`;
  const body = `{"name":"deep-review","dist-tags":{"latest":"2.0.0"},"versions":{"1.0.0":${shallow},"2.0.0":${deepVersion}},"time":{"1.0.0":"2026-10-01T00:00:00Z","2.0.0":"2026-10-02T00:00:00Z"}}`;

  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch: (req) => (new URL(req.url).pathname === "/deep-review" ? new Response(body, { headers: { "content-type": "application/json" } }) : Response.json({ error: "Not found" }, { status: 404 })),
  });

  return { url: server.url.href, stop: () => server.stop(true) };
}

const Packument = z.object({ versions: z.record(z.string(), z.looseObject({ version: z.string(), dist: z.object({ tarball: z.string() }) })) });

describe("a packument with a manifest past the limits apm reads", () => {
  test("is served, with the deep field left out and named, and every other version whole", async () => {
    const db = await freshDatabase();
    const npm = fakeNpm();

    try {
      const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: npm.url, legacyAuth: false, namePolicy: "open", admins: [] } as const;
      const base = Layer.mergeAll(Store.postgres(db.url), Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs, Layer.succeed(RegistryConfig, settings));
      const layers = Layer.provideMerge(Upstream.layer(npm.url, 60_000, null), base);
      const req = new Request("http://registry.test/deep-review");
      const program = Effect.flatMap(upstreamRoute(req, new URL(req.url), false), (res) => Effect.promise(async () => ({ status: res?.status, text: (await res?.text()) ?? "" })));
      // on 9913a74: the effect died with RangeError (Maximum call stack size exceeded)
      const r = await Effect.runPromise(program.pipe(Effect.provide(layers), Effect.scoped));

      expect(r.status).toBe(200);
      const versions = Packument.parse(JSON.parse(r.text)).versions;
      const deep = versions["2.0.0"];

      expect(deep?.exports).toBeUndefined();
      expect(deep?.dependencies).toEqual({ "left-pad": "^1.0.0" });
      expect(deep?.dist.tarball).toBe("http://registry.test/deep-review/-/deep-review-2.0.0.tgz");
      expect(String(deep?.[TRIMMED_FIELD])).toBe("package.json nests deeper than 64 levels, past what apm serves; left out: exports");
      expect(versions["1.0.0"]?.[TRIMMED_FIELD]).toBeUndefined();
      expect(versions["1.0.0"]?.main).toBe("index.js");
    } finally {
      npm.stop();
      await db.drop();
    }
  }, 60_000);
});
