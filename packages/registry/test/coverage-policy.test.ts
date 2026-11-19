// apm-score-v11: files left unread for their size or the byte budget cost no points, so a partial reading can score
// 98. Every install path checks coverage apart from the score: the install warning (resolve, scan, the Bun scanner,
// apm add), strict mode, ~safe and scan's policy (policyBlock), and a staged publish's approval.
import { describe, expect, test } from "bun:test";
import { analyze, finalize, PREVIOUS_SCORER, readingOf, unfinishedAnalysis, type Analysis, type TarEntry } from "@apm/core";
import { machO } from "../../core/test/executables.ts";
import { keptLatestScore, policyBlock, DEFAULT_POLICY } from "../src/apm.ts";
import { typedConfirmationReason } from "../src/approval.ts";
import type { VersionRecord } from "../src/db.ts";
import { scoreWarning } from "../src/warnings.ts";

const enc = new TextEncoder();
const entry = (path: string, text: string): TarEntry => ({ path, size: text.length, mode: 0o644, data: enc.encode(text) });
const manifest = { name: "big", version: "1.0.0", license: "MIT", main: "index.js" };

/** A clean package whose second file is past a small byte budget: partial coverage and nothing found. */
function partial(): Analysis {
  return analyze({ name: "big", manifest, files: [entry("package.json", JSON.stringify(manifest)), entry("index.js", "module.exports = require('./big.js');\n"), entry("big.js", `module.exports = '${"x".repeat(5000)}';\n`)], publisher: "a", previousPublishers: [], maxScannedBytes: 1000 });
}

function complete(): Analysis {
  return analyze({ name: "big", manifest, files: [entry("package.json", JSON.stringify(manifest)), entry("index.js", "module.exports = 1;\n")], publisher: "a", previousPublishers: [] });
}

const AT = Date.parse("2026-11-16T00:00:00Z");

function version(score: Analysis): VersionRecord {
  return { package: "big", version: "1.0.0", manifest, shasum: "", integrity: "", size: 0, tarball_key: "", published_at: AT - 30 * 86_400_000, seq: 0, published_by: "a", deprecated: null, status: "active", status_reason: null, status_at: null, status_by: null, score };
}

const report = (a: Analysis) => finalize(a, { publishedAt: 0, now: AT, deprecated: null, status: "active", statusReason: null });

describe("a partial reading that scores well is still not a pass", () => {
  test("it scores what was read, and is graded P", () => {
    const r = report(partial());

    expect(r.score).toBe(100);
    expect(r.grade).toBe("P");
    expect(r.coverage).toMatchObject({ kind: "partial", omittedFiles: 1 });
  });

  test("installs warn, as for an incomplete analysis, naming what was not read", () => {
    const w = scoreWarning({ name: "big", version: "1.0.0", report: report(partial()), floor: 40, url: "", via: [] });

    expect(w?.kind).toBe("incomplete");
    expect(w?.text).toBe("apm read only part of it: 1 file (0.0 MB) not read (scores 100/100 on what it read)");
    expect(scoreWarning({ name: "big", version: "1.0.0", report: report(complete()), floor: 40, url: "", via: [] })).toBeNull();
  });

  test("strict mode, ~safe and scan's policy refuse it, whatever its score", () => {
    expect(policyBlock(version(partial()), DEFAULT_POLICY, AT)).toBe("apm read only part of it: 1 file (0.0 MB) not read");
    expect(policyBlock(version(complete()), DEFAULT_POLICY, AT)).toBeNull();
  });

  test("a staged publish of it asks for the typed confirmation", () => {
    expect(typedConfirmationReason({ report: report(partial()), filesListed: true })).toBe("apm read only part of this version (1 file (0.0 MB) not read), so what it did not read was not checked.");
    expect(typedConfirmationReason({ report: report(complete()), filesListed: true })).toBeNull();
  });
});

describe("a stopped analysis is said to have stopped, not counted", () => {
  test("strict mode's reason names no count of files", () => {
    const stopped = unfinishedAnalysis({ name: "big", manifest, files: [], phase: "parse", limit: 1 });

    // on e8616ca: "apm read only part of it: 0 files (0.0 MB) not read"
    expect(policyBlock(version(stopped), DEFAULT_POLICY, AT)).toBe("apm read only part of it: its analysis stopped before it finished, so nothing in it was cleared");
  });
});

describe("a package published on apm keeps the analysis made at its publish", () => {
  test("a v10 analysis incomplete for a file's size keeps v10's -61 and is refused, as v10 refused it", () => {
    const { coverage: _coverage, ...rest } = complete();
    const v10: Analysis = { ...rest, scorer: PREVIOUS_SCORER, signals: [{ id: "incomplete" as const, label: "Analysis incomplete", points: -61, evidence: ["not analyzed: big.js (34.0 MB, over the 32 MB limit)"], confidence: "confirmed" as const }] };

    expect(policyBlock(version(v10), DEFAULT_POLICY, AT)).toContain("score 39/100 is below 40");
    // and a clean one reads as v11's own: complete, passing
    expect(policyBlock(version({ ...rest, scorer: PREVIOUS_SCORER }), DEFAULT_POLICY, AT)).toBeNull();
  });
});

describe("the home page's kept scores while the current scorer catches up", () => {
  const kept = { name: "prettier", version: "3.10.1", score: 39, grade: "F" };
  const none = { name: "prettier", version: null, score: null, grade: null };

  test("a latest version waiting for the current scorer keeps the score kept for it", () => {
    expect(keptLatestScore(kept, none, "3.10.1")).toEqual(kept);
  });

  test("a new score, a newer latest version, or a version nobody can score replaces it", () => {
    const fresh = { name: "prettier", version: "3.10.1", score: 100, grade: "A" };

    expect(keptLatestScore(kept, fresh, null)).toEqual(fresh);
    expect(keptLatestScore(kept, none, "3.10.2")).toEqual(none);
    expect(keptLatestScore(kept, none, null)).toEqual(none);
  });
});

// Round 12 review of 7cd0b2b, P2: a binary's reading that passed what it may keep was reported as a file left unread for
// the budget, its findings dropped: 100 (P), which a partial reading's policy lets through. It keeps what it found and
// is incomplete: every install path holds it.
describe("a binary's reading that stopped at what it may hold is incomplete, not a budget omission", () => {
  const dense = (): Analysis => {
    const m = { name: "big", version: "1.0.0", license: "MIT" };
    const data = machO({ size: 256, tail: enc.encode(`\n${"'child_'+'process';\n".repeat(60_000)}`) });

    return analyze({ name: "big", manifest: m, files: [entry("package.json", JSON.stringify(m)), { path: "lib/b000000", size: data.length, mode: 0o755, data }], publisher: "a", previousPublishers: [] });
  };

  test("its findings count, it reads as incomplete, and scan's policy, strict mode and ~safe refuse it", () => {
    const a = dense();
    const r = report(a);

    // production (274d284): 65 (C), complete. A reading stopped for its resources scores 0 (round 13 review of d594415)
    expect(r.score).toBe(0);
    expect(r.coverage).toEqual({ kind: "complete" });
    expect(readingOf(a)).toEqual({ kind: "incomplete", why: "signal" });
    expect(policyBlock(version(a), DEFAULT_POLICY, AT)).toMatch(/^score 0\/100 is below 40 \(incomplete/);
    expect(scoreWarning({ name: "big", version: "1.0.0", report: r, floor: 40, url: "", via: [] })?.kind).toBe("incomplete");
  }, 60_000);
});
