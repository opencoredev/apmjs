// Scores every review probe (packages/core/test/fixtures/review-r3-probes.ts) with one or more scorers, as written and
// with `postinstall: node index.js`, and prints one row per probe. Bytes only: nothing is installed or run.
// Usage, from the repo root (each scorer is a `label=<core src dir>`, e.g. a worktree of the commit that was live):
//   bun tools/score-eval/probes.ts v9=/path/to/v9/packages/core/src now=packages/core/src [--json out.json]
// It exits 1 when a probe v9 refused (under 40) is passed by the last scorer given, as written or at install.
import { resolve } from "node:path";
import { z } from "zod";
import { BENIGN_EXTRA, PROBES, type Probe } from "../../packages/core/test/fixtures/review-r3-probes.ts";

type Core = Pick<typeof import("../../packages/core/src/score.ts"), "analyze" | "finalize">;

const args = process.argv.slice(2);
const jsonAt = args.indexOf("--json");
const jsonOut = jsonAt >= 0 ? args[jsonAt + 1] : undefined;

const scorers = args.filter((a, i) => a.includes("=") && (jsonAt < 0 || i !== jsonAt + 1)).map((a) => {
  const [label = "", dir = ""] = a.split("=");

  return { label, dir };
});

if (scorers.length === 0) {
  console.error("usage: bun tools/score-eval/probes.ts <label>=<core src dir> ... [--json out.json]");
  process.exit(2);
}

const Report = z.object({ score: z.number(), signals: z.array(z.object({ id: z.string(), points: z.number() })) });
const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

function entry(path: string, text: string) {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

type Cell = { score: number; ms: number; risks: string };

function score(core: Core, p: Probe, install: boolean): Cell {
  const scripts: Record<string, string> = install ? { postinstall: "node index.js" } : {};
  const manifest = { name: "probe-pkg", version: "1.0.0", license: "MIT", main: "index.js", scripts };
  const files = [entry("package.json", JSON.stringify(manifest)), ...Object.entries(p.files).map(([path, text]) => entry(path, text))];
  const t = performance.now();

  try {
    const r = Report.parse(core.finalize(core.analyze({ name: manifest.name, manifest, files, publisher: "a", previousPublishers: [] }), STATE));

    return { score: r.score, ms: performance.now() - t, risks: r.signals.filter((s) => s.points < 0).map((s) => `${s.id}${s.points}`).join(" ") };
  } catch (e) {
    return { score: -1, ms: performance.now() - t, risks: `error: ${String(e).slice(0, 80)}` };
  }
}

const loaded: { label: string; core: Core }[] = [];

for (const s of scorers) loaded.push({ label: s.label, core: await import(resolve(s.dir, "score.ts")) });

const rows: { id: string; expect: string; finding: number | null; cells: Record<string, { normal: Cell; install: Cell }> }[] = [];

for (const p of [...PROBES, ...BENIGN_EXTRA]) {
  const cells: Record<string, { normal: Cell; install: Cell }> = {};

  for (const { label, core } of loaded) cells[label] = { normal: score(core, p, false), install: score(core, p, true) };
  rows.push({ id: p.id, expect: p.expect, finding: p.finding ?? null, cells });
  const line = loaded.map(({ label }) => `${label} ${String(cells[label]?.normal.score).padStart(3)}/${String(cells[label]?.install.score).padStart(3)}`).join("  ");
  const last = cells[loaded.at(-1)?.label ?? ""];

  console.log(`${p.id.padEnd(30)} ${p.expect.padEnd(6)} ${line}  ${last?.normal.risks ?? ""}`);
}

if (jsonOut) await Bun.write(jsonOut, JSON.stringify(rows, null, 1));

// refused by the first scorer (v9), passed by the last: as written, or at install
const first = loaded[0]?.label ?? "";
const last = loaded.at(-1)?.label ?? "";

const regressions = rows.flatMap((r) => (["normal", "install"] as const).flatMap((mode) => {
  const before = r.cells[first]?.[mode].score ?? -1;
  const after = r.cells[last]?.[mode].score ?? -1;

  return before >= 0 && before < 40 && after >= 40 ? [`${r.id} (${mode}): ${first} ${before}, ${last} ${after}`] : [];
}));

console.log(`\nrefused by ${first}, passed by ${last}: ${regressions.length === 0 ? "none" : `\n  ${regressions.join("\n  ")}`}`);

const slowest = rows.flatMap((r) => Object.entries(r.cells).map(([label, c]) => ({ id: r.id, label, ms: Math.max(c.normal.ms, c.install.ms) }))).sort((a, b) => b.ms - a.ms)[0];

if (slowest) console.log(`slowest: ${slowest.id} with ${slowest.label}, ${slowest.ms.toFixed(0)} ms`);

if (loaded.length > 1 && regressions.length > 0) process.exit(1);
