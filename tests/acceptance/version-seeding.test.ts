// A package's versions besides `latest` are queued once someone looks at it: each version a dist-tag names and each
// published in the last week (analysis.ts, versionsToSeed). Before this only `latest` was queued, by the package page
// and by the cron's refresh, so typescript's daily 7.1.0-dev builds (dist-tag `next`) showed "n/a" on the package page
// for days, until someone asked for that exact version (18 Nov 2026). npm is a local stand-in; no real host is contacted.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { z } from "zod";
import { SEED_INTAKE_MAX } from "../../packages/registry/src/seeding.ts";
import { getJson, pkgTgz, startRegistry, type Registry } from "./harness";

const DAY = 86_400_000;
const clock = Date.parse("2026-11-18T12:00:00Z");

const sha512 = (b: Uint8Array): string => `sha512-${createHash("sha512").update(b).digest("base64")}`;

/** Each version: when it was published, and the dist-tag naming it, if any. */
type Line = Record<string, { ago: number; tag?: string }>;

const LINES = {
  // the package page's case: typescript's shape, a stable latest and a nightly line under `next`
  "dev-line": {
    "0.5.0": { ago: 300 * DAY },
    "0.9.0-beta": { ago: 200 * DAY, tag: "beta" },
    "1.0.0": { ago: 30 * DAY, tag: "latest" },
    "2.0.0-dev.1": { ago: 3 * DAY },
    "2.0.0-dev.2": { ago: 2 * DAY },
    "2.0.0-dev.3": { ago: 1 * DAY, tag: "next" },
  },
  // the cron's case: a package the home page asks about, never opened
  "dev-cron": {
    "1.0.0": { ago: 30 * DAY, tag: "latest" },
    "1.1.0-rc.1": { ago: 2 * DAY, tag: "rc" },
  },
  // the busy queue's case: a page opened while the queue took its fill, so the cron reaches the rest
  "dev-busy": {
    "1.0.0": { ago: 30 * DAY, tag: "latest" },
    "2.0.0-dev.1": { ago: 1 * DAY, tag: "next" },
  },
} satisfies Record<string, Line>;

const lineOf = (name: string): Line | undefined => (name === "dev-line" || name === "dev-cron" || name === "dev-busy" ? LINES[name] : undefined);

const Page = z.object({ versions: z.array(z.object({ version: z.string(), score: z.number().nullable() })) }).loose();

describe("versions besides latest are queued when someone looks at the package", () => {
  const tarballs = new Map<string, Uint8Array>();
  let npm: ReturnType<typeof Bun.serve>;
  let reg: Registry;

  const jobs = async (name: string): Promise<string[]> =>
    z
      .array(z.object({ version: z.string() }))
      .parse(await reg.query("SELECT version FROM analysis_jobs WHERE package = $1 ORDER BY version", [name]))
      .map((r) => r.version);

  beforeAll(async () => {
    for (const [name, line] of Object.entries(LINES)) {
      for (const version of Object.keys(line)) tarballs.set(`${name}-${version}.tgz`, pkgTgz({ name, version, license: "MIT", main: "index.js" }, { "index.js": "module.exports = 1;\n" }));
    }

    npm = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        const path = decodeURIComponent(new URL(req.url).pathname.slice(1));
        const tar = /^([^/]+)\/-\/(.+\.tgz)$/.exec(path);

        if (tar) {
          const bytes = tarballs.get(tar[2] ?? "");

          return bytes ? new Response(bytes) : new Response("not found", { status: 404 });
        }

        const line = lineOf(path);

        if (!line) return Response.json({ error: "Not found" }, { status: 404 });
        const entries = Object.entries(line);

        return Response.json({
          name: path,
          "dist-tags": Object.fromEntries(entries.flatMap(([v, x]) => (x.tag ? [[x.tag, v]] : []))),
          versions: Object.fromEntries(entries.map(([v]) => [v, { name: path, version: v, main: "index.js", license: "MIT", dist: { tarball: `${npm.url.toString()}${path}/-/${path}-${v}.tgz`, integrity: sha512(tarballs.get(`${path}-${v}.tgz`) ?? new Uint8Array()) } }])),
          time: Object.fromEntries(entries.map(([v, x]) => [v, new Date(clock - x.ago).toISOString()])),
        });
      },
    });
    reg = await startRegistry({ now: () => clock, upstream: npm.url.toString(), upstreamTtlMs: 0 });
  }, 60_000);

  afterAll(async () => {
    await reg?.stop();
    await npm?.stop(true);
  });

  /** The package's reservations once a page's seeding (after its answer) has had time to land. */
  const jobsSettled = async (name: string, want: number): Promise<string[]> => {
    let got = await jobs(name);

    for (let i = 0; i < 40 && got.length < want; i++) {
      await Bun.sleep(100);
      got = await jobs(name);
    }

    return got;
  };

  test("the package page queues latest, every dist-tagged version and the last week's, not an old untagged one", async () => {
    const first = await getJson(`${reg.url}-/apm/v1/packages/dev-line`);

    expect(first.status).toBe(200);
    // on main, only 1.0.0 was queued; the others are queued after the answer (seeding.ts), not before it
    expect(await jobsSettled("dev-line", 5)).toEqual(["0.9.0-beta", "1.0.0", "2.0.0-dev.1", "2.0.0-dev.2", "2.0.0-dev.3"]);

    // the queue scores them, and the page shows each with its score
    let page = Page.parse(first.body);

    for (let i = 0; i < 60 && page.versions.some((v) => v.version !== "0.5.0" && v.score === null); i++) {
      await Bun.sleep(500);
      page = Page.parse((await getJson(`${reg.url}-/apm/v1/packages/dev-line`)).body);
    }

    expect(page.versions.map((v) => [v.version, v.score])).toEqual([
      ["2.0.0-dev.3", 100],
      ["2.0.0-dev.2", 100],
      ["2.0.0-dev.1", 100],
      ["1.0.0", 100],
      ["0.9.0-beta", 100],
      ["0.5.0", null],
    ]);
    // and nothing is queued again once they are scored
    await reg.query("DELETE FROM analysis_jobs WHERE package = 'dev-line'");
    await getJson(`${reg.url}-/apm/v1/packages/dev-line`);
    await Bun.sleep(500);
    expect(await jobs("dev-line")).toEqual([]);
  }, 120_000);

  // review of 2022f3d, P2: a crawler's page views added eight jobs a package, across any number of names
  test("a page seeds nothing while the queue is busy, and the cron reaches those versions", async () => {
    // the queue took its fill in the last ten minutes (SEED_INTAKE_MAX), from other callers
    await reg.query("INSERT INTO analysis_jobs (package, version, queued_at, scorer) SELECT 'filler', g::text, $1, 'x' FROM generate_series(1, $2::int) g", [clock - 60_000, SEED_INTAKE_MAX]);

    // the first view queues latest (which the answer needs, as before) and seeds nothing past the bound
    expect((await getJson(`${reg.url}-/apm/v1/packages/dev-busy`)).status).toBe(200);
    await Bun.sleep(500);
    expect(await jobs("dev-busy")).toEqual(["1.0.0"]);

    // once latest is scored, a second view keeps the package's summary (kept_packages), still seeding nothing
    for (let i = 0; i < 60 && (await reg.query("SELECT 1 FROM kept_packages WHERE package = 'dev-busy'")).length === 0; i++) {
      await Bun.sleep(250);
      await getJson(`${reg.url}-/apm/v1/packages/dev-busy`);
    }

    expect(await jobs("dev-busy")).toEqual(["1.0.0"]);
    // the cron's seeding is not held by the bound: it queues the rest
    await reg.sweep();
    expect(await jobs("dev-busy")).toEqual(["1.0.0", "2.0.0-dev.1"]);
    await reg.query("DELETE FROM analysis_jobs WHERE package = 'filler'");
  }, 120_000);

  test("the cron's refresh of a package the home page asks about queues its dist-tagged and recent versions too", async () => {
    // the home page's kept answer for dev-cron (an earlier scorer's), worked out an hour ago and asked about since
    await reg.query("INSERT INTO latest_scores (package, version, score, grade, computed_at, asked_at) VALUES ('dev-cron', '1.0.0', 100, 'A', $1, $1)", [clock - 60 * 60_000]);
    await reg.sweep();

    expect(await jobs("dev-cron")).toEqual(["1.0.0", "1.1.0-rc.1"]);
  }, 120_000);
});
