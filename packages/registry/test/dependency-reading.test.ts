// Review of 120efc2, finding 1: scoreWarning checked only the `incomplete` signal, partial coverage and the floor, so
// two reports core readingOf calls incomplete got no warning: a stored apm-score-v10 report with unanalyzed-files
// (-20, scoring 80) and an apm-score-v11 report with no coverage record (scoring 100). Asked for by name, each was
// review-first (the verdict reads the report itself); as a dependency the resolve sent no warning and no risk, so every
// verdict said install, and the scan API gave no advisory. Each case below asks the real resolve route for the version
// directly and as a dependency, and the real scan route, on the real Postgres store, then reads each resolve answer
// through the CLI's own parser and verdict (the website's copy answers the same: tests/fixtures/explain-verdicts.json).
import { describe, expect, test } from "bun:test";
import { Effect, Layer, Option } from "effect";
import { Client } from "pg";
import { z } from "zod";
import { analyze, PREVIOUS_SCORER, SCORER, type Analysis as Scored, type AnalyzeInput, type TarEntry } from "@apm/core";
import { freshDatabase } from "../../../tests/acceptance/postgres.ts";
import { ResolveOk } from "../../cli/src/api.ts";
import { explain } from "../../cli/src/explain.ts";
import { Analysis } from "../src/analysis.ts";
import { DEFAULT_POLICY, policyBlock, resolveResponse, ResolveWait, scanResponse } from "../src/apm.ts";
import { Blobs } from "../src/blobs.ts";
import { Clock } from "../src/clock.ts";
import { RegistryConfig } from "../src/config.ts";
import { Store, type VersionRecord } from "../src/db.ts";
import { MemoryPool, RequestMemory } from "../src/memory.ts";
import { Upstream } from "../src/upstream.ts";

const POOL = new MemoryPool();
const NOW = Date.parse("2026-11-16T00:00:00Z");
const PUBLISHED = NOW - 10 * 86_400_000;
const enc = new TextEncoder();
const file = (path: string, text: string): TarEntry => ({ path, size: enc.encode(text).length, mode: 0o644, data: enc.encode(text) });

type Manifest = { name: string; version: string; main: string; license: string; dependencies?: Record<string, string> };

function manifestOf(name: string, dependencies?: Record<string, string>): Manifest {
  const m: Manifest = { name, version: "1.0.0", main: "index.js", license: "MIT" };

  if (dependencies) m.dependencies = dependencies;

  return m;
}

function analysisOf(m: Manifest, files: { path: string; text: string }[] = [{ path: "index.js", text: "module.exports = 1;\n" }], maxScannedBytes?: number): Scored {
  const input: AnalyzeInput = { name: m.name, manifest: m, files: [file("package.json", JSON.stringify(m)), ...files.map((f) => file(f.path, f.text))], publisher: "u", previousPublishers: [] };

  if (maxScannedBytes !== undefined) input.maxScannedBytes = maxScannedBytes;

  return analyze(input);
}

/** A stored analysis by apm-score-v10 that left files unread: no coverage (v10 stored none) and unanalyzed-files at -20. */
function legacyGap(m: Manifest): Scored {
  const { coverage: _coverage, ...rest } = analysisOf(m);

  return { ...rest, scorer: PREVIOUS_SCORER, signals: [{ id: "unanalyzed-files", label: "Some files were not analyzed: the package is larger than the analysis reads", points: -20, evidence: ["not analyzed: dist/big.js (40.0 MB)"], confidence: "confirmed" }] };
}

/** The current scorer's analysis with its coverage record missing, and nothing else lost: it scores 100. */
function missingCoverage(m: Manifest): Scored {
  const { coverage: _coverage, ...rest } = analysisOf(m);

  return { ...rest, scorer: SCORER };
}

/** The current scorer's partial reading whose one gap is a file past the byte budget: the allowlisted kind. */
const sizeOnly = (m: Manifest): Scored => analysisOf(m, [{ path: "index.js", text: "module.exports = require('./big.js');\n" }, { path: "big.js", text: `module.exports = '${"x".repeat(5000)}';\n` }], 1000);

/** The current scorer's analysis stopped by a parser limit: `incomplete` at -61. */
const parserLimit = (m: Manifest): Scored => analysisOf(m, [{ path: "index.js", text: "0;".repeat(240_001) }]);

type Case = { name: string; analysis: (m: Manifest) => Scored; verdict: "install" | "review-first"; text: string };

const CASES: Case[] = [
  { name: "legacy-gap", analysis: legacyGap, verdict: "review-first", text: "apm did not analyse every file in it (scores 80/100, B)" },
  { name: "missing-coverage", analysis: missingCoverage, verdict: "review-first", text: "apm could not fully analyse it: its analysis does not record how much of it was read (scores 100/100, A)" },
  { name: "size-only", analysis: sizeOnly, verdict: "install", text: "apm read only part of it: 1 file (0.0 MB) not read (scores 100/100 on what it read)" },
  { name: "parser-limit", analysis: parserLimit, verdict: "review-first", text: "apm could not fully analyse it (scores 39/100, F)" },
];

const noBlobs = Layer.succeed(
  Blobs,
  Blobs.of({ put: () => Effect.void, stream: () => Effect.succeed(Option.none()), bytes: () => Effect.succeed(Option.none()), exists: () => Effect.succeed(false), remove: () => Effect.void }),
);

// nothing is fetched upstream: every package here is local
const SETTINGS = { baseUrl: "http://registry.test/", webUrl: "http://web.test/", upstreamUrl: "http://127.0.0.1:9/", legacyAuth: false, namePolicy: "open", admins: [] } as const;

function layersFor(url: string) {
  const base = Layer.mergeAll(Store.postgres(url), Clock.fixed({ now: NOW, wallNow: NOW }), Analysis.none, noBlobs, Layer.succeed(ResolveWait, { maxMs: 0, pollMs: 1 }), Layer.succeed(RegistryConfig, SETTINGS), RequestMemory.layer(POOL));

  return Layer.provideMerge(Upstream.layer(SETTINGS.upstreamUrl, 60_000, null), base);
}

async function resolve(url: string, name: string, strict = false): Promise<{ status: number; body: unknown }> {
  const params = new URLSearchParams({ name, range: "latest" });

  if (strict) params.set("strict", "1");
  const program = Effect.flatMap(resolveResponse(new URL(`http://registry.test/-/apm/v1/resolve?${params}`)), (res) => Effect.promise(async () => ({ status: res.status, body: await res.json() })));

  return Effect.runPromise(program.pipe(Effect.provide(layersFor(url)), Effect.scoped));
}

const ScanBody = z.object({ advisories: z.array(z.object({ package: z.string(), level: z.string(), description: z.string() })), warnings: z.array(z.object({ name: z.string(), kind: z.string(), text: z.string() })) });

async function scan(url: string, name: string, strict = false) {
  const req = new Request("http://registry.test/-/apm/v1/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ packages: [{ name, version: "1.0.0" }], strict }) });
  const program = Effect.flatMap(scanResponse(req, { kind: "anon" }), (res) => Effect.promise(async () => ScanBody.parse(await res.json())));

  return Effect.runPromise(program.pipe(Effect.provide(layersFor(url)), Effect.scoped));
}

/** The CLI's verdict on a resolve answer, read through the CLI's own parser, as `apm explain` reads it. */
function cliVerdict(name: string, answer: { status: number; body: unknown }) {
  expect(answer.status).toBe(200);
  const ok = ResolveOk.parse(answer.body);
  const tree = ok.tree;

  return explain({
    name,
    range: null,
    resolved: { kind: "ok", version: ok.version, report: ok.report, skipped: ok.skipped, deps: { unchecked: tree?.unchecked ?? 0, uncheckedDeps: tree?.uncheckedDeps ?? [], reviews: { kind: "off" }, warnings: ok.warnings, risks: (tree?.risks ?? []).map((d) => ({ ...d, scorer: d.scorer ?? null })) } },
    review: { kind: "off" },
    older: { kind: "not-needed" },
  });
}

const Warnings = z.object({ warnings: z.array(z.object({ name: z.string(), kind: z.string(), text: z.string(), via: z.array(z.string()) })).default([]) });

async function withRig(c: Case, fn: (url: string) => Promise<void>): Promise<void> {
  const db = await freshDatabase();
  const client = new Client({ connectionString: db.url });

  await client.connect();

  try {
    const insert = async (m: Manifest, analysis: Scored): Promise<void> => {
      await client.query(`INSERT INTO packages (name, created_at, modified_at, dist_tags) VALUES ($1, 0, 0, '{"latest":"1.0.0"}'::jsonb)`, [m.name]);
      await client.query(
        `INSERT INTO versions (package, version, manifest, shasum, integrity, size, tarball_key, published_at, published_by, score)
         VALUES ($1, '1.0.0', $2::jsonb, $3, 'sha1-x', 10, 'sha512/x', $4, 'u', $5::jsonb)`,
        [m.name, JSON.stringify(m), "0".repeat(40), PUBLISHED, JSON.stringify(analysis)],
      );
    };

    await client.query(`INSERT INTO users (name, password_hash, email, created_at) VALUES ('u', 'x', 'u@example.test', 0)`);
    const dep = manifestOf(c.name);
    const root = manifestOf("app", { [c.name]: "^1.0.0" });

    await insert(dep, c.analysis(dep));
    await insert(root, analysisOf(root));
    await fn(db.url);
  } finally {
    await client.end();
    await db.drop();
  }
}

describe("a version's reading answers the same asked for directly, as a dependency and in a scan", () => {
  for (const c of CASES) {
    test(`${c.name}: ${c.verdict}`, () =>
      withRig(c, async (url) => {
        const direct = await resolve(url, c.name);
        const asDep = await resolve(url, "app");
        const scanned = await scan(url, c.name);

        // the registry's own answers: an incomplete warning for the version, wherever it sits in the tree
        expect(Warnings.parse(direct.body).warnings.map((w) => [w.name, w.kind, w.text, w.via])).toEqual([[c.name, "incomplete", c.text, []]]);
        expect(Warnings.parse(asDep.body).warnings.map((w) => [w.name, w.kind, w.text, w.via])).toEqual([[c.name, "incomplete", c.text, ["app@1.0.0"]]]);
        expect(scanned.advisories.map((a) => [a.package, a.level])).toEqual([[c.name, "warn"]]);
        expect(scanned.warnings.map((w) => [w.name, w.kind, w.text])).toEqual([[c.name, "incomplete", c.text]]);

        // the install verdict on each resolve answer
        expect(cliVerdict(c.name, direct).verdict).toBe(c.verdict);
        expect(cliVerdict("app", asDep).verdict).toBe(c.verdict);
      }));
  }

  for (const c of CASES) {
    test(`${c.name}: strict mode, the ~safe view and scan's policy refuse it`, () =>
      withRig(c, async (url) => {
        const dep = manifestOf(c.name);
        const record: VersionRecord = { package: c.name, version: "1.0.0", manifest: dep, shasum: "", integrity: "", size: 0, tarball_key: "", published_at: PUBLISHED, seq: 0, published_by: "u", deprecated: null, status: "active", status_reason: null, status_at: null, status_by: null, score: c.analysis(dep) };
        const strictScan = await scan(url, c.name, true);
        const strictDep = await resolve(url, "app", true);

        expect(policyBlock(record, DEFAULT_POLICY, NOW)).not.toBeNull();
        expect(strictScan.advisories.map((a) => [a.package, a.level])).toEqual([[c.name, "fatal"]]);
        expect(strictDep.status).toBe(422);
      }));
  }

  test("a clean version has no warning anywhere, and installs", () =>
    withRig({ name: "clean", analysis: (m) => analysisOf(m), verdict: "install", text: "" }, async (url) => {
      const asDep = await resolve(url, "app");

      expect(Warnings.parse(asDep.body).warnings).toEqual([]);
      expect((await scan(url, "clean")).advisories).toEqual([]);
      expect(cliVerdict("app", asDep).verdict).toBe("install");
    }));
});
