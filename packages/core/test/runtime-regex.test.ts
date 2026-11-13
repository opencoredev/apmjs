// Every regex @apm/core builds at runtime is linear in the text it reads. regex-linear.test.ts times the literals; a
// pattern built from strings (`new RegExp(String.raw`…${ENV_OBJECT}`)`) is not a literal, and one of them,
// `\bfor\s*\(\s*(?:const|let|var)?\s*[\w$]+…`, split a run of blanks among two adjacent quantifiers from one `for (`:
// `for (` + 64K blanks + `!` took 2.4 s while the meter charged it as one linear pass (review of d49bf6e, finding 1).
//
// This greps src/ for every `RegExp(` call, runs src/ in a process that records each regex it builds at runtime and
// the line that built it (fixtures/regex-record.ts), checks that every grepped call was recorded, so none is missed,
// and times each recorded regex on the adversarial inputs, including one start followed by one long run.
import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { safeRegexCost } from "../src/decode.ts";
import { factsOf } from "../src/facts.ts";
import { prefixRuns, repeats, slowOn } from "./fixtures/regex-timing.ts";

const SRC = join(import.meta.dir, "..", "src");

/** A `RegExp(` call on a line that is not a comment, as "file.ts:line". */
function grepped(): string[] {
  const out: string[] = [];

  for (const f of readdirSync(SRC).filter((x) => x.endsWith(".ts"))) {
    readFileSync(join(SRC, f), "utf8")
      .split("\n")
      .forEach((line, i) => {
        if (/^\s*(?:\/\/|\/?\*)/.test(line)) return;

        if (/(?<![\w$.])(?:new\s+)?RegExp\s*\(/.test(line)) out.push(`${f}:${i + 1}`);
      });
  }

  return out;
}

/**
 * The one call that builds a package's own regex: the decoder runs a regex literal from the code it decodes, and only
 * one safeRegexCost proves fixed-width (no `*`, `+`, groups or alternation), charged per character it reads. Its
 * patterns come from packages, so the test checks the guard instead of timing a list.
 */
const PACKAGE_PATTERNS = new Set(["decode.ts"]);

const Recorded = z.array(z.object({ source: z.string(), flags: z.string(), site: z.string().nullable() }));

const recorded = Recorded.parse(JSON.parse(Bun.spawnSync(["bun", join(import.meta.dir, "fixtures", "regex-record.ts")], { stderr: "inherit" }).stdout.toString()));

describe("every regex built at runtime is linear", () => {
  test("every `RegExp(` call in src/ is one the recorder saw build a regex", () => {
    const sites = new Set(recorded.flatMap((r) => (r.site ? [r.site] : [])));
    const calls = grepped();

    expect(calls.length).toBeGreaterThanOrEqual(15);
    expect(calls.filter((c) => !sites.has(c))).toEqual([]);
  });

  test("a package's own regex runs only when it is fixed-width", () => {
    const fromPackages = recorded.filter((r) => r.site && PACKAGE_PATTERNS.has(r.site.split(":")[0] ?? ""));

    expect(fromPackages.length).toBeGreaterThan(0);
    expect(fromPackages.filter((r) => safeRegexCost(r.source, r.flags) === null)).toEqual([]);

    for (const quadratic of [String.raw`\s*\s*x`, String.raw`(a+)+$`, String.raw`for\s*\(\s*(?:const)?\s*\w+`, String.raw`a*a*b`]) expect(safeRegexCost(quadratic, "g")).toBeNull();
  });

  test(
    `the ${recorded.length} regexes built at runtime (src/ and the parser it loads): none grows faster than its input`,
    () => {
      const ours = recorded.filter((r) => !(r.site && PACKAGE_PATTERNS.has(r.site.split(":")[0] ?? "")));
      const unique = [...new Map(ours.map((r) => [`${r.flags}/${r.source}`, r])).values()];

      expect(unique.length).toBeGreaterThan(20);

      const slow = unique.flatMap((r) => {
        const re = new RegExp(r.source, r.flags.replace("y", ""));
        const where = `${r.site ?? "a library"}: /${r.source.slice(0, 60)}/`;

        return [...slowOn(where, re, repeats), ...slowOn(where, re, prefixRuns)];
      });

      expect(slow).toEqual([]);
    },
    240_000,
  );

  test("`for (` and a long run of blanks: the facts read it in linear time", () => {
    const at = (n: number): string => `for (${" ".repeat(n)}!`;

    factsOf(at(1000));
    const a = Math.min(...[0, 1].map(() => timed(() => factsOf(at(32_000)))));
    const b = Math.min(...[0, 1].map(() => timed(() => factsOf(at(64_000)))));

    // quadratic, this took 600 ms then 2.4 s; linear, a few milliseconds each
    expect(b).toBeLessThan(Math.max(50, 3 * a));
  });
});

function timed(fn: () => void): number {
  const t = performance.now();

  fn();

  return performance.now() - t;
}
