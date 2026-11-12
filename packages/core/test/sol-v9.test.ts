// The independent v9 review's two exceptions to the findings superset (fixtures/sol-v9.json, inert sources):
//
// 1. Two entries at one path (`a.js` with code, then an empty `a.js`). The modern walk reached the empty one through
//    `imports` and cached its read by path; the v3 walk then skipped the first entry's different bytes, so the library
//    scored 100 where v3 scores 40 (literal module name) or 30 (joined). `analyze` now refuses such a list, as the
//    registry does at publish, and the cache is keyed by entry.
// 2. 101 network findings: v9 ranked 100 tree findings first and kept only those, so `index.js` (the one file v3
//    cites first) was counted, not named. The signal now keeps every cited source past the cap, and the property
//    helper compares them instead of skipping the check.
import { describe, expect, test } from "bun:test";
import { z } from "zod";
import { AmbiguousPathsError, analyze, finalize, type TarEntry, findingsOf } from "../src/index.ts";
import fixtureData from "./fixtures/sol-v9.json";
import { scoreOfV3, supersetGaps, type SupersetInput } from "./superset.ts";

const Fixture = z.object({
  name: z.string(),
  v3: z.number(),
  manifest: z.record(z.string(), z.unknown()),
  files: z.array(z.object({ path: z.string(), text: z.string() })),
});

type Fixture = z.infer<typeof Fixture>;

const fixtures = z.array(Fixture).parse(fixtureData);

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function inputOf(f: Fixture, files = f.files): SupersetInput {
  return { name: "probe-pkg", manifest: f.manifest, files: files.map((x) => entry(x.path, x.text)), publisher: "a", previousPublishers: [] };
}

function fixture(name: string): Fixture {
  const f = fixtures.find((x) => x.name === name);

  if (!f) throw new Error(`no fixture ${name}`);

  return f;
}

describe("duplicate paths", () => {
  for (const name of ["duplicate-path-literal", "duplicate-path-joined"]) {
    const f = fixture(name);

    test(`${name}: v3 scores ${f.v3}, and analyze refuses the list with a typed error`, () => {
      expect(scoreOfV3(inputOf(f))).toBe(f.v3);

      let thrown: unknown;

      try {
        analyze(inputOf(f));
      } catch (e) {
        thrown = e;
      }

      expect(thrown).toBeInstanceOf(AmbiguousPathsError);
      expect(thrown instanceof AmbiguousPathsError ? thrown.paths : []).toEqual(["a.js"]);
    });

    test(`${name}: each a.js alone keeps the superset`, () => {
      const [code, empty] = f.files.filter((x) => x.path === "a.js");
      const others = f.files.filter((x) => x.path !== "a.js");

      for (const only of [code, empty]) {
        if (!only) throw new Error("fixture has two a.js entries");
        const input = inputOf(f, [...others, only]);

        expect(supersetGaps(input, analyze(input))).toEqual([]);
      }
    });
  }

  test("a path that differs only by ./ or an empty segment is the same path", () => {
    const f = fixture("duplicate-path-literal");

    for (const alias of ["./a.js", "a.js/", ".//a.js"]) {
      const files = [...f.files.filter((x) => x.path !== "a.js" || x.text !== ""), { path: alias, text: "" }];

      expect(() => analyze(inputOf(f, files))).toThrow(AmbiguousPathsError);
    }
  });

  test("a path that escapes the package folder is refused", () => {
    const f = fixture("duplicate-path-literal");
    const files = [...f.files.filter((x) => x.path !== "a.js" || x.text === ""), { path: "../a.js", text: "" }];

    expect(() => analyze(inputOf(f, files))).toThrow(AmbiguousPathsError);
  });
});

describe("evidence past the kept cap", () => {
  const f = fixture("evidence-overflow");

  test("v3 scores 90, v10 100 (network is a capability), and the network finding still names index.js", () => {
    const analysis = analyze(inputOf(f));
    const network = findingsOf(analysis).find((s) => s.id === "network");

    expect(finalize(analysis, STATE).score).toBe(100);
    expect(scoreOfV3(inputOf(f))).toBe(f.v3);
    expect(network?.uncounted).toBe(1);
    expect([...(network?.evidence ?? []), ...(network?.more ?? [])].some((e) => e.startsWith("index.js:"))).toBe(false);
    expect(network?.sources).toContain("index.js");
    expect(network?.sources).toHaveLength(101);
  });

  test("the property helper compares sources on overflow", () => {
    const analysis = analyze(inputOf(f));

    expect(supersetGaps(inputOf(f), analysis)).toEqual([]);

    // without the kept sources the helper must report the file v3 cites, not skip the check
    const stripped = { ...analysis, signals: analysis.signals.map(({ sources: _sources, ...s }) => s), capabilities: analysis.capabilities.map(({ sources: _sources, ...c }) => c) };

    expect(supersetGaps(inputOf(f), stripped)).toEqual([expect.stringContaining("network: v3 cites index.js")]);
  });

  test("evidence within the cap carries no sources list", () => {
    const input = inputOf(f, f.files.slice(0, 50));

    for (const s of analyze(input).signals) expect(s.sources).toBeUndefined();
  });
});
