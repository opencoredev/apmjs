// Writes `v10` and `v10why` into the stored review fixtures from a recording (see v10-record.ts): for each fixture whose
// apm-score-v10 score differs from what its file expected before, the score and the reason, read off the signals.
// Usage: APM_RECORD_V10=/tmp/rec.jsonl bun test <fixture tests>; bun packages/core/test/v10-merge.ts /tmp/rec.jsonl
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { SCORE_FLOOR } from "../src/index.ts";
import { ABOVE_FLOOR } from "./v10-record.ts";

const Line = z.object({ set: z.string(), name: z.string(), score: z.number(), risks: z.array(z.tuple([z.string(), z.number()])), capabilities: z.array(z.string()) });

const lines = readFileSync(process.argv[2] ?? "", "utf8")
  .split("\n")
  .filter((l) => l.trim())
  .map((l) => Line.parse(JSON.parse(l)));

const Stored = z.looseObject({ name: z.string(), v3: z.number(), kind: z.string().optional() });

/** What each set's tests expected before v10, in the order they read it. */
const PREVIOUS = {
  "sol-lexer": ["v9", "v8", "v7", "v5"],
  "sol-parser-v5": ["v9", "v8", "v6"],
  "sol-parser-v6": ["v7"],
  "sol-v7": ["v8"],
  "sol-v8": ["v9"],
} as const satisfies Record<string, readonly string[]>;

const Score = z.number();

function reason(l: z.infer<typeof Line>, v3: number, detection: boolean): string {
  const caps = l.capabilities.length > 0 ? `lists ${l.capabilities.join(", ")} as capabilities at no cost` : "finds no capability";
  const risks = l.risks.length > 0 ? `; risk signals: ${l.risks.map(([id, p]) => `${id} ${p}`).join(", ")}` : "; no risk signal";
  const above = detection && v3 < SCORE_FLOOR && l.score >= SCORE_FLOOR ? `${ABOVE_FLOOR} ` : "";

  return `${above}apm-score-v10 ${caps}${risks}`;
}

for (const [set, keys] of Object.entries(PREVIOUS)) {
  const path = join(import.meta.dir, "fixtures", `${set}.json`);
  const raw = readFileSync(path, "utf8");
  const indent = /^\[\n( +)/.exec(raw)?.[1]?.length ?? 2;
  const data: unknown = JSON.parse(raw);
  const fixtures = z.array(Stored).parse(data);
  let changed = 0;

  for (const f of fixtures) {
    const got = lines.find((l) => l.set === set && l.name === f.name);

    if (!got) continue;
    const before = keys.map((k) => Score.safeParse(f[k])).find((r) => r.success)?.data;

    delete f.v10;
    delete f.v10why;

    if (got.score === before) continue;
    f.v10 = got.score;
    f.v10why = reason(got, f.v3, f.kind !== "precision");
    changed++;
  }

  writeFileSync(path, `${JSON.stringify(fixtures, null, indent)}\n`);
  console.log(`${set}: ${changed} of ${fixtures.length} changed`);
}
