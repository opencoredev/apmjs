// A version apm did not read in full: the package answer and the score answer say where the unread files are (the
// biggest folders, from the analysis's skipped list), so the page can name them instead of only counting them. A
// revoked version's paths are withheld, so it names none. npm is a local stand-in; no real host is contacted.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { z } from "zod";
import { analyze, SCORER, type Analysis } from "../../packages/core/src/index.ts";
import { getJson, pkgTgz, startRegistry, type Registry } from "./harness";

const clock = Date.parse("2026-11-01T00:00:00Z");
const PUBLISHED = "2026-10-01T00:00:00Z";
const NAME = "big-bundles";

const sha512hex = (b: Uint8Array): string => createHash("sha512").update(b).digest("hex");

const Folders = z.array(z.object({ path: z.string(), files: z.number(), bytes: z.number() }));
const PackageAnswer = z.object({ score: z.object({ grade: z.string(), coverage: z.object({ kind: z.string() }).nullable(), omittedFolders: Folders }).nullable() }).loose();
const ScoreAnswer = z.object({ grade: z.string(), omittedFolders: Folders }).loose();

/** The analysis as the current scorer stores one that left files past the byte budget unread, next's shape. */
function partialAnalysis(files: Record<string, string>): Analysis {
  const manifest = { name: NAME, version: "1.0.0", license: "MIT", main: "index.js" };
  const entries = [["package.json", JSON.stringify(manifest)], ...Object.entries(files)].map(([path, text]) => ({ path: path ?? "", size: (text ?? "").length, mode: 0o644, data: new TextEncoder().encode(text ?? "") }));
  const a = analyze({ name: NAME, manifest, files: entries, publisher: "someone", previousPublishers: [] });

  const skipped = [
    ...Array.from({ length: 6 }, (_, i) => ({ path: `dist/compiled/webpack/chunk${i}.js`, size: 9_000_000, reason: "over-budget" as const })),
    ...Array.from({ length: 30 }, (_, i) => ({ path: `dist/esm/server/f${i}.js`, size: 250_000, reason: "over-budget" as const })),
    { path: "dist/bundle-analyzer/report.js", size: 100_000, reason: "over-budget" as const },
    { path: "README.md", size: 10_000, reason: "over-budget" as const },
  ];

  return { ...a, skipped, coverage: { kind: "partial", omittedFiles: skipped.length, omittedBytes: skipped.reduce((n, s) => n + s.size, 0), reasons: ["over-budget"], notes: [] } };
}

describe("where the files apm did not read are", () => {
  const files = { "index.js": "module.exports = 1;\n" };
  const bytes = pkgTgz({ name: NAME, version: "1.0.0", license: "MIT", main: "index.js" }, files);
  let npm: ReturnType<typeof Bun.serve>;
  let reg: Registry;

  beforeAll(async () => {
    npm = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        const u = new URL(req.url);

        if (u.pathname.endsWith(".tgz")) return new Response(bytes);

        if (decodeURIComponent(u.pathname.slice(1)) !== NAME) return Response.json({ error: "Not found" }, { status: 404 });
        const dist = { tarball: `${npm.url.toString()}${NAME}/-/${NAME}-1.0.0.tgz`, integrity: `sha512-${Buffer.from(sha512hex(bytes), "hex").toString("base64")}` };

        return Response.json({ name: NAME, "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": { name: NAME, version: "1.0.0", main: "index.js", license: "MIT", dist } }, time: { "1.0.0": PUBLISHED } });
      },
    });
    reg = await startRegistry({ now: () => clock, upstream: npm.url.toString(), upstreamTtlMs: 0 });
    await reg.query("INSERT INTO upstream_analysis (package, version, digest, scorer, analysis, analyzed_at) VALUES ($1, '1.0.0', $2, $3, $4::jsonb, $5)", [
      NAME,
      `sha512-${sha512hex(bytes)}`,
      SCORER,
      JSON.stringify(partialAnalysis(files)),
      clock - 86_400_000,
    ]);
  }, 60_000);

  afterAll(async () => {
    await reg?.stop();
    await npm?.stop(true);
  });

  const expected = [
    { path: "dist/compiled", files: 6, bytes: 54_000_000 },
    { path: "dist/esm", files: 30, bytes: 7_500_000 },
    // dist/bundle-analyzer is not a common layout name, so it is never named (review of c93d72e, finding 1): the
    // package root's README is the third
    { path: ".", files: 1, bytes: 10_000 },
  ];

  test("the package answer names the three biggest folders of unread files, beside the coverage", async () => {
    const r = await getJson(`${reg.url}-/apm/v1/packages/${NAME}`);

    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const score = PackageAnswer.parse(r.body).score;

    expect(score?.grade).toBe("P");
    expect(score?.coverage?.kind).toBe("partial");
    expect(score?.omittedFolders).toEqual(expected);
  }, 60_000);

  test("the score answer names them too", async () => {
    const r = await getJson(`${reg.url}-/apm/v1/score/${NAME}/1.0.0`);

    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(ScoreAnswer.parse(r.body).omittedFolders).toEqual(expected);
  }, 60_000);
});
