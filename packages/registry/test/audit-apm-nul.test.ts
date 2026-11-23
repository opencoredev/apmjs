// A NUL in a package name (%00 in the path or a query) reaches Postgres, which refuses it: the request ends as
// StoreError and the Worker answers 500 "Internal error" and reports an infra failure. It is bad input: 400.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { Effect, Layer, Option } from "effect";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis } from "../src/analysis.ts";
import { apmRoute } from "../src/apm.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { RegistryConfig } from "../src/config.ts";
import { Store } from "../src/db.ts";
import { MemoryPool, RequestMemory } from "../src/memory.ts";

const POOL = new MemoryPool();
const NOW = Date.parse("2026-11-12T00:00:00Z");
let db: Awaited<ReturnType<typeof freshDatabase>>;

beforeAll(async () => {
  db = await freshDatabase();
});
afterAll(async () => {
  await db.drop();
});

const noBlobs = Layer.succeed(Blobs, Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }));

async function get(path: string): Promise<number | string> {
  const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: null, legacyAuth: false, namePolicy: "open", admins: [] } as const;
  const layers = Layer.mergeAll(Store.postgres(db.url), Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs, Layer.succeed(RegistryConfig, settings), RequestMemory.layer(POOL));
  const req = new Request(`http://registry.test${path}`);

  try {
    const res = await Effect.runPromise(apmRoute(req, new URL(req.url), { kind: "anon" } as never).pipe(Effect.provide(layers), Effect.scoped));

    return res?.status ?? 0;
  } catch (e) {
    return `threw ${String(e).slice(0, 40)}`;
  }
}

describe("a NUL in a name is a 400, not a database error", () => {
  for (const path of [
    "/-/apm/v1/resolve?name=%00",
    "/-/apm/v1/packages/%00",
    "/-/apm/v1/packages/p%00/versions/1.0.0",
    "/-/apm/v1/score/%00",
    "/-/apm/v1/popular-scores?names=%00,p",
  ]) {
    test(path, async () => {
      expect(await get(path)).toBe(400);
    });
  }
});
