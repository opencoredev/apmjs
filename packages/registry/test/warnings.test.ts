// The install warnings resolve and scan send: a scored version's warning carries every signal that cost it points (id
// and points only), so the website's and the CLI's install verdict can tell a risk from apm's own gap.
import { describe, expect, test } from "bun:test";
import type { ScoreReport, SignalId } from "@apm/core";
import { cooldownWarning, lostSignals, scoreWarning, stateWarning, versionUrl } from "../src/warnings.ts";

const report = (score: number, signals: { id: SignalId; points: number }[]): Pick<ScoreReport, "score" | "grade" | "signals" | "scorer"> => ({
  scorer: "apm-score-v10",
  score,
  grade: score >= 40 ? "C" : "F",
  signals: signals.map((s) => ({ ...s, label: s.id, evidence: [`index.js:1: ${s.id}`], confidence: "confirmed" as const })),
});

const where = { url: "https://apmjs.dev/package/dep?v=1.0.0", via: ["app@1.0.0"] };

describe("warnings carry the lost signals of a scored version", () => {
  test("lostSignals: what cost points, heaviest first, with no evidence", () => {
    expect(lostSignals(report(9, [{ id: "new-publisher", points: -10 }, { id: "dynamic-require", points: 0 }, { id: "incomplete", points: -61 }, { id: "unanalyzed-files", points: -20 }]))).toEqual([
      { id: "incomplete", points: -61 },
      { id: "unanalyzed-files", points: -20 },
      { id: "new-publisher", points: -10 },
    ]);
  });

  test("an incomplete or low score warning has them", () => {
    const incomplete = scoreWarning({ name: "dep", version: "1.0.0", report: report(9, [{ id: "incomplete", points: -61 }, { id: "unanalyzed-files", points: -20 }, { id: "new-publisher", points: -10 }]), floor: 40, ...where });

    expect(incomplete?.kind).toBe("incomplete");
    expect(incomplete?.signals).toEqual([{ id: "incomplete", points: -61 }, { id: "unanalyzed-files", points: -20 }, { id: "new-publisher", points: -10 }]);
    expect(scoreWarning({ name: "dep", version: "1.0.0", report: report(39, [{ id: "remote-shell", points: -61 }]), floor: 40, ...where })?.signals).toEqual([{ id: "remote-shell", points: -61 }]);
  });

  test("a cooldown warning has them when the version is scored, and none when it is not", () => {
    const fresh = { name: "dep", version: "1.0.0", ageMs: 2 * 3_600_000, cooldownMs: 24 * 3_600_000, ...where };

    expect(cooldownWarning({ ...fresh, report: report(65, [{ id: "obfuscated", points: -20 }, { id: "suspicious-combination", points: -15 }]) })?.signals).toEqual([{ id: "obfuscated", points: -20 }, { id: "suspicious-combination", points: -15 }]);
    expect(cooldownWarning({ ...fresh, report: report(100, []) })?.signals).toEqual([]);
    expect(cooldownWarning({ ...fresh, report: null })).not.toHaveProperty("signals");
    expect(cooldownWarning(fresh)).not.toHaveProperty("signals");
    expect(cooldownWarning({ ...fresh, ageMs: 25 * 3_600_000 })).toBeNull();
  });

  test("a warning about a version with no score has none", () => {
    expect(stateWarning({ kind: "pending", name: "dep", version: "1.0.0", text: "not scored yet", ...where })).not.toHaveProperty("signals");
  });
});

// review of c456c92: the install verdict lets a dependency's partial reading install only on the warning's own record
// of it, and holds a version apm will never score unless the reason is its size
describe("warnings carry what the verdict needs to fail closed", () => {
  const partial = { kind: "partial" as const, omittedFiles: 2656, omittedBytes: 74_038_961, reasons: ["too-large" as const], notes: [] };

  test("a scored version's warning carries its coverage as stored, and none when it stored none", () => {
    const w = scoreWarning({ name: "dep", version: "1.0.0", report: { ...report(98, []), scorer: "apm-score-v11", grade: "P", coverage: partial }, floor: 40, ...where });

    expect(w?.kind).toBe("incomplete");
    expect(w?.coverage).toEqual(partial);
    expect(scoreWarning({ name: "dep", version: "1.0.0", report: report(9, [{ id: "incomplete", points: -61 }]), floor: 40, ...where })).not.toHaveProperty("coverage");
    expect(cooldownWarning({ name: "dep", version: "1.0.0", ageMs: 1, cooldownMs: 10, ...where, report: { ...report(98, []), coverage: { kind: "complete" } } })?.coverage).toEqual({ kind: "complete" });
  });

  test("an unscorable warning names why, when the registry decided it", () => {
    expect(stateWarning({ kind: "unscorable", name: "dep", version: "1.0.0", text: "apm cannot score this version", unscorable: "analysis-limit", ...where }).unscorable).toBe("analysis-limit");
    expect(stateWarning({ kind: "unscorable", name: "dep", version: "1.0.0", text: "could not be analyzed", ...where })).not.toHaveProperty("unscorable");
  });
});

describe("versionUrl", () => {
  test("the version's page on the website: /package/<name>?v=<version>, the version encoded", () => {
    expect(versionUrl("https://apmjs.dev/", "express", "5.3.0")).toBe("https://apmjs.dev/package/express?v=5.3.0");
    expect(versionUrl("https://apmjs.dev/", "@types/node", "1.0.0+build.5")).toBe("https://apmjs.dev/package/@types/node?v=1.0.0%2Bbuild.5");
  });

  test("a name ending in .md keeps its page, not the Markdown view of another name", () => {
    expect(versionUrl("https://apmjs.dev/", "@acme/readme.md", "1.0.0")).toBe("https://apmjs.dev/package/@acme/readme%2Emd?v=1.0.0");
  });
});
