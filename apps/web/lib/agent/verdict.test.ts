// The install verdict: the registry's policy answer and the AI review in, one word and its reasons out.
import { describe, expect, test } from "bun:test";
import { parsePackageSpec } from "./explain";
import { parseResolve, type ResolveOutcome } from "./source";
import { INSTALL, NETWORK } from "./testing";
import { explainInstall, reviewInput, verdictText } from "./verdict";

const ok = (score: number, over: Partial<Extract<ResolveOutcome, { kind: "ok" }>> = {}): ResolveOutcome => ({
  kind: "ok",
  version: "1.3.0",
  source: "upstream",
  report: { score, grade: score >= 90 ? "A" : score >= 75 ? "B" : "C", signals: score < 100 ? [NETWORK] : [], notChecked: [] },
  skipped: [],
  uncheckedDeps: [],
  ...over,
});

const clean = { kind: "reviewed", state: "found-nothing", findings: 0 } as const;

describe("explainInstall", () => {
  test("a clean, scored version past the policy: install, with the exact commands", () => {
    const v = explainInstall({ name: "zod", range: null, resolve: ok(92), review: clean });

    expect(v.verdict).toBe("install");
    expect(v.summary).toBe("zod@1.3.0 passes apm's checks: it scores 92/100 (A), is past the 24-hour cooldown, and nothing in its dependency tree was refused.");
    expect(v.commands).toEqual({ apm: "apm add zod@1.3.0", bun: "bun add zod@1.3.0", npm: "npm install zod@1.3.0", pnpm: "pnpm add zod@1.3.0" });
    expect(v.summary).not.toMatch(/\bsafe\b/);
  });

  test("a score under 75: review first, naming the biggest loss", () => {
    const v = explainInstall({ name: "x", range: "^1", resolve: ok(60, { report: { score: 60, grade: "C", signals: [NETWORK, INSTALL], notChecked: [] } }), review: { kind: "none" } });

    expect(v.verdict).toBe("review-first");
    expect(v.summary).toContain("it lost points: Runs a script at install time (postinstall)");
    expect(v.reasons[0]).toBe("Runs a script at install time (postinstall) (-15 points).");
    expect(v.reasons).toContain("No AI review of this version.");
  });

  test("an open AI flag: review first, and the flag is the first reason", () => {
    const v = explainInstall({ name: "x", range: null, resolve: ok(95), review: { kind: "reviewed", state: "under-review", findings: 2 } });

    expect(v.verdict).toBe("review-first");
    expect(v.reasons[0]).toBe("The AI review flagged this version (2 findings); a person at apm is checking it.");
  });

  test("a confirmed malicious version: do not install, no commands", () => {
    const v = explainInstall({ name: "x", range: null, resolve: ok(95), review: { kind: "reviewed", state: "confirmed", findings: 1 } });

    expect(v).toMatchObject({ verdict: "do-not-install", commands: null });
  });

  test("the policy refused the range: do not install, with the registry's reason and what it skipped", () => {
    const v = explainInstall({ name: "x", range: "2.0.0", resolve: { kind: "refused", reason: "x@2.0.0: published 3h ago (cooldown 24h)", newest: "2.0.0", skipped: [{ version: "2.0.0", reason: "published 3h ago (cooldown 24h)" }] }, review: { kind: "none" } });

    expect(v.verdict).toBe("do-not-install");
    expect(v.summary).toBe("Do not install x@2.0.0: x@2.0.0: published 3h ago (cooldown 24h)");
    expect(v.reasons).toContain("Skipped 2.0.0: published 3h ago (cooldown 24h).");
  });

  test("an unknown name says it may be a typosquat; a down registry says nothing was checked", () => {
    expect(explainInstall({ name: "reakt", range: null, resolve: { kind: "missing", reason: "No package named reakt." }, review: { kind: "none" } }).verdict).toBe("not-found");
    const down = explainInstall({ name: "x", range: null, resolve: { kind: "unavailable" }, review: { kind: "none" } });

    expect(down.verdict).toBe("unknown");
    expect(down.summary).toContain("Nothing was checked");
  });

  test("unscored: review first", () => {
    expect(explainInstall({ name: "x", range: null, resolve: ok(90, { report: null }), review: clean }).verdict).toBe("review-first");
  });

  test("verdictText is the summary, reasons and the command", () => {
    const text = verdictText(explainInstall({ name: "zod", range: null, resolve: ok(92), review: clean }));

    expect(text.split("\n")[0]).toBe("Verdict: install");
    expect(text).toContain("Run: apm add zod@1.3.0");
  });
});

describe("parseResolve", () => {
  test("reads 200, 422 and 404 answers; anything else is unavailable", () => {
    expect(parseResolve(200, { name: "zod", version: "4.1.0", report: null, skipped: [], tree: { uncheckedDeps: [{ dependency: "a@1", reason: "r", via: [] }] } })).toMatchObject({ kind: "ok", version: "4.1.0", uncheckedDeps: [{ dependency: "a@1" }] });
    expect(parseResolve(422, { error: "too new", name: "zod", version: null, skipped: [], newest: { version: "5.0.0", report: {} } })).toEqual({ kind: "refused", reason: "too new", newest: "5.0.0", skipped: [] });
    expect(parseResolve(404, { error: "No package named q." })).toEqual({ kind: "missing", reason: "No package named q." });
    expect(parseResolve(500, {})).toEqual({ kind: "unavailable" });
    expect(parseResolve(200, { nope: true })).toEqual({ kind: "unavailable" });
  });
});

describe("reviewInput and parsePackageSpec", () => {
  test("reviewInput", () => {
    expect(reviewInput(null)).toEqual({ kind: "none" });
    expect(reviewInput({ status: "queued", review: null })).toEqual({ kind: "queued" });
  });

  test("parsePackageSpec splits name and range, scoped names included", () => {
    expect(parsePackageSpec("zod")).toEqual({ name: "zod", range: null });
    expect(parsePackageSpec("zod@^4")).toEqual({ name: "zod", range: "^4" });
    expect(parsePackageSpec("@scope/Name@1.2.3")).toEqual({ name: "@scope/name", range: "1.2.3" });
    expect(parsePackageSpec("@scope/name")).toEqual({ name: "@scope/name", range: null });
    expect(parsePackageSpec("")).toBeNull();
    expect(parsePackageSpec("../etc")).toBeNull();
  });
});
