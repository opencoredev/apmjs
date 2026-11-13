// Every regex the analysis runs over a package's text is linear in that text, so a text pass charged by its length
// (src/meter.ts, chargeText) costs what it is charged. A backtracking engine makes some shapes quadratic or worse: an
// unanchored `\d+ path=` on repeated digits (the PAX header, review at 90b3072), `\b[\w$]+\.` on `a$a$…` (importsOf),
// `\S*\/` from every `$(` (the net-tool command match), `\/\/[^\s:]+` from every `//` and `^\s*` across blank lines
// (the secret scan). This finds every regex literal in src/ and the rule patterns built at runtime, runs each on inputs
// made of the characters such shapes need (fixtures/regex-timing.ts), and fails on any whose time grows faster than
// its input. runtime-regex.test.ts does the same for every pattern src/ builds with `new RegExp`.
import { describe, expect, test } from "bun:test";
import { parse, type AnyNode } from "acorn";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { RULES } from "../src/rules.ts";
import { repeats, slowOn } from "./fixtures/regex-timing.ts";

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

describe("every regex over package text is linear", () => {
  test(
    `${REGEXES.length} regexes on generated inputs: none grows faster than its input`,
    () => {
      expect(REGEXES.length).toBeGreaterThan(150);
      const slow = REGEXES.flatMap((r) => slowOn(r.where, r.re, repeats));

      expect(slow).toEqual([]);
    },
    120_000,
  );
});
