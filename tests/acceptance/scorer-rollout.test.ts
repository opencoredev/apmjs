// apm-score-v11 ships over a database of apm-score-v10 results (review of e8616ca, finding 2). A scorer change used to
// make every stored analysis invisible, so every page read "queued" and the cron re-queued what was already analysed,
// and the queue (one analysis at a time) took hours. Now v11 reads a v10 analysis it would store the same as its own,
// keeps the v10 decisions it would make the same, analyses again only what v11 scores differently, keeps the home page's
// popular scores while those wait, and seeds them a few at a time. npm is a local stand-in; no real host is contacted.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { z } from "zod";
import { analyze, type Analysis } from "../../packages/core/src/index.ts";
import { getJson, pkgTgz, startRegistry, type Registry } from "./harness";

const clock = Date.parse("2026-11-01T00:00:00Z");
const PUBLISHED = "2026-10-01T00:00:00Z";

type Served = { bytes: Uint8Array; downloads: number };

const sha512hex = (b: Uint8Array): string => createHash("sha512").update(b).digest("hex");

const Popular = z.object({ packages: z.array(z.object({ name: z.string(), version: z.string().nullable(), score: z.number().nullable(), grade: z.string().nullable() })) });
const Score = z.object({ score: z.number(), grade: z.string(), scorer: z.string().optional(), coverage: z.object({ kind: z.string() }).nullish() }).loose();

/** What apm-score-v10 stored for `bytes`: the analysis as v11 makes it, under v10's name and without v11's coverage. */
function v10Of(name: string, files: Record<string, string>, change: (a: Analysis) => Analysis = (a) => a): Analysis {
  const manifest = { name, version: "1.0.0", license: "MIT", main: "index.js" };
  const entries = [["package.json", JSON.stringify(manifest)], ...Object.entries(files)].map(([path, text]) => ({ path: path ?? "", size: (text ?? "").length, mode: 0o644, data: new TextEncoder().encode(text ?? "") }));
  const { coverage: _coverage, ...a } = analyze({ name, manifest, files: entries, publisher: "someone", previousPublishers: [] });

  return change({ ...a, scorer: "apm-score-v10" });
}

describe("rolling out apm-score-v11 over apm-score-v10's results", () => {
  const files = { "index.js": "module.exports = 1;\n" };
  const served = new Map<string, Served>();
  let npm: ReturnType<typeof Bun.serve>;
  let reg: Registry;

  const insertAnalysis = (name: string, analysis: Analysis) =>
    reg.query("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ($1, '1.0.0', $2, 'apm-score-v10', $3::jsonb, $4)", [name, `sha512-${sha512hex(served.get(name)?.bytes ?? new Uint8Array())}`, JSON.stringify(analysis), clock - 86_400_000]);

  beforeAll(async () => {
    for (const name of ["kept-clean", "kept-incomplete", "kept-refused", "kept-pending"]) served.set(name, { bytes: pkgTgz({ name, version: "1.0.0", license: "MIT", main: "index.js" }, files), downloads: 0 });

    npm = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        const u = new URL(req.url);
        const tar = /^\/([^/]+)\/-\/[^/]+\.tgz$/.exec(u.pathname);
        const name = tar?.[1] ?? decodeURIComponent(u.pathname.slice(1));
        const one = served.get(name);

        if (!one) return Response.json({ error: "Not found" }, { status: 404 });

        if (tar) {
          one.downloads++;

          return new Response(one.bytes);
        }

        const dist = { tarball: `${npm.url.toString()}${name}/-/${name}-1.0.0.tgz`, integrity: `sha512-${Buffer.from(sha512hex(one.bytes), "hex").toString("base64")}` };

        return Response.json({ name, "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": { name, version: "1.0.0", main: "index.js", license: "MIT", dist } }, time: { "1.0.0": PUBLISHED } });
      },
    });
    reg = await startRegistry({ now: () => clock, upstream: npm.url.toString(), upstreamTtlMs: 0 });

    // what production holds after apm-score-v10: a clean analysis, one incomplete for a file over 32 MB, a version
    // v10 refused as too large to download, and reservations an older Worker made (no scorer recorded)
    await insertAnalysis("kept-clean", v10Of("kept-clean", files));
    await insertAnalysis(
      "kept-incomplete",
      v10Of("kept-incomplete", files, (a) => ({
        ...a,
        skipped: [{ path: "big.js", size: 34 * 1024 * 1024, reason: "too-large" }],
        signals: [...a.signals, { id: "incomplete", label: "Analysis incomplete", points: -61, evidence: ["not analyzed: big.js (34.0 MB, over the 32 MB limit)"], confidence: "confirmed" }],
      })),
    );
    await reg.query("INSERT INTO analysis_outcomes (package, version, scorer, outcome, detail, decided_at) VALUES ('kept-refused', '1.0.0', 'apm-score-v10', 'too-large', 'the tarball (43.7 MB) is larger than the 32 MiB apm downloads', $1)", [clock - 86_400_000]);
    // an older Worker's reservations, long past: one for a version v10 analysed, one for a version that never ran

    for (const name of ["kept-clean", "kept-pending"]) await reg.query("INSERT INTO analysis_jobs (package, version, queued_at) VALUES ($1, '1.0.0', $2)", [name, clock - 86_400_000]);
    // the home page's kept scores, worked out from v10's analyses, an hour ago

    for (const [name, score, grade] of [["kept-clean", 100, "A"], ["kept-incomplete", 39, "F"]] as const) {
      await reg.query("INSERT INTO latest_scores (package, version, score, grade, computed_at, asked_at) VALUES ($1, '1.0.0', $2, $3, $4, $4)", [name, score, grade, clock - 60 * 60_000]);
    }
  }, 60_000);

  afterAll(async () => {
    await reg?.stop();
    await npm?.stop(true);
  });

  test("a clean apm-score-v10 analysis is v11's own: scored at once, complete, nothing queued or downloaded", async () => {
    const s = await getJson(`${reg.url}-/apm/v1/score/kept-clean/1.0.0`);

    // on e8616ca: 503, queued again; every page of every package scored before the deploy said so
    expect(s.status, JSON.stringify(s.body)).toBe(200);
    expect(Score.parse(s.body)).toMatchObject({ score: 100, grade: "A", coverage: { kind: "complete" } });
    expect(served.get("kept-clean")?.downloads).toBe(0);
    expect(await reg.query("SELECT scorer FROM analysis_outcomes WHERE package = 'kept-clean'")).toEqual([]);
  }, 60_000);

  test("the sweep re-sends an older Worker's reservation only for a version that never ran, and keeps popular scores", async () => {
    await reg.sweep();

    // kept-pending never ran under any scorer: the sweep sends it again, claiming it for the current scorer; kept-clean,
    // which v10 analysed and v11 reads as its own, keeps the older Worker's reservation and is not sent or run
    expect(await reg.query("SELECT package, scorer FROM analysis_jobs WHERE package IN ('kept-clean', 'kept-pending') ORDER BY package")).toEqual([
      { package: "kept-clean", scorer: null },
      { package: "kept-pending", scorer: "apm-score-v11" },
    ]);
    expect(await reg.query("SELECT package FROM analysis_outcomes WHERE scorer = 'apm-score-v11' ORDER BY package")).not.toContainEqual({ package: "kept-clean" });
    expect(served.get("kept-clean")?.downloads).toBe(0);

    // on e8616ca the refresh nulled kept-incomplete's score (no v11 analysis) and the home page showed it unscored
    const popular = Popular.parse((await getJson(`${reg.url}-/apm/v1/popular-scores?names=kept-clean,kept-incomplete`)).body).packages;

    expect(popular).toEqual([
      { name: "kept-clean", version: "1.0.0", score: 100, grade: "A" },
      { name: "kept-incomplete", version: "1.0.0", score: 39, grade: "F" },
    ]);
    // and kept-incomplete, which v11 scores differently, was seeded for the queue under the current scorer
    expect(await reg.query("SELECT package, scorer FROM analysis_jobs WHERE package = 'kept-incomplete'")).toEqual([{ package: "kept-incomplete", scorer: "apm-score-v11" }]);
  }, 120_000);

  test("what v11 scores differently is analysed again: a v10 result with a file left unread, and a v10 size refusal", async () => {
    for (const name of ["kept-incomplete", "kept-refused"]) {
      expect(await reg.analysisJob({ name, version: "1.0.0" })).toBe("ack");
      const s = await getJson(`${reg.url}-/apm/v1/score/${name}/1.0.0`);

      expect(s.status, JSON.stringify(s.body)).toBe(200);
      expect(Score.parse(s.body)).toMatchObject({ score: 100, coverage: { kind: "complete" } });
      expect(served.get(name)?.downloads).toBeGreaterThan(0);
    }
  }, 120_000);
});
