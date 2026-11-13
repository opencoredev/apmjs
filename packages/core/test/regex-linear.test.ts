// Every regex the analysis runs over a package's text is linear in that text, so a text pass charged by its length
// (src/meter.ts, chargeText) costs what it is charged. A backtracking engine makes some shapes quadratic or worse: an
// unanchored `\d+ path=` on repeated digits (the PAX header, review at 90b3072), `\b[\w$]+\.` on `a$a$…` (importsOf),
// `\S*\/` from every `$(` (the net-tool command match), `\/\/[^\s:]+` from every `//` and `^\s*` across blank lines
// (the secret scan). This finds every regex literal in src/ and the rule patterns built at runtime, runs each on inputs
// made of the characters such shapes need, and fails on any whose time grows faster than its input.
import { describe, expect, test } from "bun:test";
import { parse, type AnyNode } from "acorn";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { RULES } from "../src/rules.ts";

type Found = { where: string; re: RegExp };

function isNode(v: unknown): v is AnyNode {
  return v instanceof Object && "type" in v && "start" in v;
}

/** Every regex literal in the module's source (types stripped), with where it is. */
function literalsIn(file: string): Found[] {
  const src = readFileSync(file, "utf8");
  const js = new Bun.Transpiler({ loader: "ts" }).transformSync(src);
  const out: Found[] = [];
  const stack: unknown[] = [parse(js, { ecmaVersion: "latest", sourceType: "module" })];

  for (let n = stack.pop(); n !== undefined; n = stack.pop()) {
    if (!isNode(n)) continue;

    if (n.type === "Literal" && "regex" in n && n.regex) {
      try {
        out.push({ where: `${file.split("/").at(-1) ?? file}: /${n.regex.pattern.slice(0, 60)}/`, re: new RegExp(n.regex.pattern, n.regex.flags.replace("y", "")) });
      } catch {
        // a flag this runtime lacks: not a regex the analysis can run here either
      }
    }

    for (const v of Object.values(n)) {
      if (Array.isArray(v)) stack.push(...v);
      else if (isNode(v)) stack.push(v);
    }
  }

  return out;
}

const SRC = join(import.meta.dir, "..", "src");

const REGEXES: Found[] = [
  ...readdirSync(SRC)
    .filter((f) => f.endsWith(".ts"))
    .flatMap((f) => literalsIn(join(SRC, f))),
  ...RULES.flatMap((r) => r.patterns.map((p) => ({ where: `RULES ${r.id}: /${p.re.source.slice(0, 60)}/`, re: p.re }))),
];

/** Characters the shapes above need: word characters, `$`, digits, blanks, quotes, slashes and brackets. */
const ALPHABET = ["a", "$", "9", " ", "\n", "'", '"', "`", ".", "(", ",", "=", "\\", "/", "_", ":", "[", "x", "+", "-"];

function inputs(re: RegExp, n: number): string[] {
  const out: string[] = [];

  for (const a of ALPHABET) out.push(a.repeat(n));

  for (let i = 0; i < ALPHABET.length; i++) for (let j = i + 1; j < ALPHABET.length; j++) out.push(`${ALPHABET[i] ?? ""}${ALPHABET[j] ?? ""}`.repeat(n / 2));

  // the words the pattern itself names, repeated with what may follow them
  for (const w of new Set((re.source.match(/[A-Za-z_]{3,}/g) ?? []).slice(0, 4))) {
    for (const tail of [" ", "(", ".", "a$", "  ", "\\x41"]) out.push(`${w}${tail}`.repeat(Math.floor(n / (w.length + tail.length))));
  }

  return out;
}

function ms(re: RegExp, s: string): number {
  const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
  const t = performance.now();
  let k = 0;

  for (const _ of s.matchAll(g)) if (++k > 100_000) break;

  return performance.now() - t;
}

describe("every regex over package text is linear", () => {
  test(
    `${REGEXES.length} regexes on generated inputs: none grows faster than its input`,
    () => {
      expect(REGEXES.length).toBeGreaterThan(150);
      const N = 16_000;
      const slow: string[] = [];

      for (const r of REGEXES) {
        inputs(r.re, N).forEach((s, i) => {
          // a linear pattern reads 16,000 characters in well under a millisecond; only a slow one is timed again
          if (ms(r.re, s) < 8) return;
          const twice = inputs(r.re, N * 2)[i] ?? "";
          const a = Math.min(ms(r.re, s), ms(r.re, s));
          const b = Math.min(ms(r.re, twice), ms(r.re, twice));

          // twice the input: about twice the time when linear, four times when quadratic
          if (b > 3 * a && b > 8) slow.push(`${r.where} on ${JSON.stringify(s.slice(0, 8))}…: ${a.toFixed(1)} ms, then ${b.toFixed(1)} ms at twice the length`);
        });
      }

      expect(slow).toEqual([]);
    },
    120_000,
  );
});
