// Turns run JSONL into the numbers for research/ai-review-eval.md and a committed summary JSON (no code
// quotes from malware, only verdicts, counts and usage).
// Usage: bun tools/ai-review/report.ts [--run main] [--traffic traffic] [--volume live.json,day.json]
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { CACHE_DIR } from "./util.ts";
import type { CaseResult } from "./run-eval.ts";

const QUOTA = { inputPerMin: 701_079, outputPerMin: 76_559 };
const SHARE = 0.25;
const RULE_FLAG_BELOW = 60;

function arg(flag: string, dflt: string): string {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? (process.argv[i + 1] ?? dflt) : dflt;
}

function load(run: string): CaseResult[] {
  const p = join(CACHE_DIR, "runs", `${run}.jsonl`);
  if (!existsSync(p)) return [];
  // Last row per id wins (reruns after errors).
  const byId = new Map<string, CaseResult>();
  for (const l of readFileSync(p, "utf8").split("\n").filter(Boolean)) {
    const r: CaseResult = JSON.parse(l);
    byId.set(r.id, r);
  }
  return [...byId.values()];
}

/** Wilson 95% interval, as percentages. */
function wilson(k: number, n: number): [number, number] {
  if (n === 0) return [0, 0];
  const z = 1.96;
  const p = k / n;
  const den = 1 + (z * z) / n;
  const c = (p + (z * z) / (2 * n)) / den;
  const h = (z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))) / den;
  return [Math.max(0, c - h) * 100, Math.min(1, c + h) * 100];
}

function rate(k: number, n: number): string {
  const [lo, hi] = wilson(k, n);
  return `${k}/${n} = ${n ? ((100 * k) / n).toFixed(0) : "-"}% (95% CI ${lo.toFixed(0)}–${hi.toFixed(0)}%)`;
}

function pct(xs: readonly number[], p: number): number {
  if (!xs.length) return 0;
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))] ?? 0;
}
const mean = (xs: readonly number[]): number => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0);

type Rule = (r: CaseResult) => boolean;
const aiMal: Rule = (r) => r.ai?.verdict === "malicious";
const aiFlag: Rule = (r) => r.ai?.verdict === "malicious" || r.ai?.verdict === "suspicious";
/** Flag only when at least one finding survived the citation check. */
const aiGrounded: Rule = (r) => aiFlag(r) && (r.ai?.findings.length ?? 0) > 0;
const ruleFlag: Rule = (r) => r.rule.score < RULE_FLAG_BELOW;
const either: Rule = (r) => aiGrounded(r) || ruleFlag(r);
const both: Rule = (r) => aiGrounded(r) && ruleFlag(r);
const DETECTORS: [string, Rule][] = [
  ["Flash: verdict malicious", aiMal],
  ["Flash: malicious or suspicious", aiFlag],
  ["Flash: malicious or suspicious, with a verified citation", aiGrounded],
  [`Rules: score below ${RULE_FLAG_BELOW}`, ruleFlag],
  ["Either (Flash cited OR rules)", either],
  ["Both (Flash cited AND rules)", both],
];

type Usage = { promptTokens: number; completionTokens: number; reasoningTokens: number; latencyMs: number };
function usageStats(rows: readonly CaseResult[]) {
  const u: Usage[] = rows.flatMap((r) => (r.ai ? [r.ai.usage] : []));
  const f = (k: keyof Usage) => ({ mean: Math.round(mean(u.map((x) => x[k]))), p50: Math.round(pct(u.map((x) => x[k]), 50)), p90: Math.round(pct(u.map((x) => x[k]), 90)), max: Math.round(Math.max(0, ...u.map((x) => x[k]))) });
  return { n: u.length, input: f("promptTokens"), output: f("completionTokens"), reasoning: f("reasoningTokens"), latencyMs: f("latencyMs") };
}

function throughput(avgIn: number, avgOut: number, avgLatencyMs: number) {
  const inQ = QUOTA.inputPerMin * SHARE;
  const outQ = QUOTA.outputPerMin * SHARE;
  const byIn = inQ / avgIn;
  const byOut = outQ / avgOut;
  const perMin = Math.min(byIn, byOut);
  return {
    inputQuotaPerMin: inQ,
    outputQuotaPerMin: outQ,
    reviewsPerMinByInput: byIn,
    reviewsPerMinByOutput: byOut,
    binding: byIn < byOut ? "input" : "output",
    reviewsPerMin: perMin,
    reviewsPerDay: perMin * 1440,
    concurrencyNeeded: Math.ceil((perMin * avgLatencyMs) / 60_000),
  };
}

const run = arg("--run", "main");
const rows = load(run);
const traffic = load(arg("--traffic", "traffic"));
const lines: string[] = [];
const say = (s = ""): void => {
  lines.push(s);
};

const mal = rows.filter((r) => r.group === "malicious-compromised" || r.group === "malicious-intent");
const benDiff = rows.filter((r) => r.group.startsWith("benign") && r.mode === "diff");
const benFiles = rows.filter((r) => r.group.startsWith("benign") && r.mode === "files");
const inj = rows.filter((r) => r.group === "injected");
const errors = rows.filter((r) => !r.ai || r.ai.verdict === "error");

say(`Cases: ${rows.length} (malicious ${mal.length}, benign diff ${benDiff.length}, benign files ${benFiles.length}, injected ${inj.length}); errors ${errors.length}`);
say();
say("| Detector | Malicious caught | False alarms, benign as update (diff) | False alarms, benign as first publish (files) |");
say("|---|---|---|---|");
const detectorTable = DETECTORS.map(([name, f]) => {
  const row = { name, caught: mal.filter(f).length, mal: mal.length, faDiff: benDiff.filter(f).length, nDiff: benDiff.length, faFiles: benFiles.filter(f).length, nFiles: benFiles.length };
  say(`| ${name} | ${rate(row.caught, row.mal)} | ${rate(row.faDiff, row.nDiff)} | ${rate(row.faFiles, row.nFiles)} |`);
  return row;
});
say();
say("By malicious group (Flash cited / rules / either):");
for (const g of ["malicious-compromised", "malicious-intent"] as const) {
  const xs = mal.filter((r) => r.group === g);
  say(`- ${g}: ${xs.filter(aiGrounded).length}/${xs.length} / ${xs.filter(ruleFlag).length}/${xs.length} / ${xs.filter(either).length}/${xs.length}`);
}
say("By benign group, false alarms (Flash cited / rules), diff | files:");
for (const g of ["benign-popular", "benign-install-script"] as const) {
  const d = benDiff.filter((r) => r.group === g);
  const fl = benFiles.filter((r) => r.group === g);
  say(`- ${g}: ${d.filter(aiGrounded).length}/${d.length}, ${d.filter(ruleFlag).length}/${d.length} | ${fl.filter(aiGrounded).length}/${fl.length}, ${fl.filter(ruleFlag).length}/${fl.length}`);
}
say();
say("Verdict counts:");
for (const [label, xs] of [["malicious", mal], ["benign diff", benDiff], ["benign files", benFiles], ["injected", inj]] as const) {
  const c = (v: string): number => xs.filter((r) => r.ai?.verdict === v).length;
  say(`- ${label}: malicious ${c("malicious")}, suspicious ${c("suspicious")}, benign ${c("benign")}, error ${c("error") + xs.filter((r) => !r.ai).length}`);
}
say();
say("Misses (malicious not flagged with a citation):");
for (const r of mal.filter((r) => !aiGrounded(r))) say(`- ${r.id}: ${r.ai?.verdict} conf ${r.ai?.confidence} rule ${r.rule.score} truncated ${r.input.truncated}; ${(r.ai?.summary ?? r.error ?? "").slice(0, 220)}`);
say("False alarms (benign flagged with a citation):");
for (const r of [...benDiff, ...benFiles].filter(aiGrounded)) say(`- ${r.id}: ${r.ai?.verdict} conf ${r.ai?.confidence}; ${(r.ai?.summary ?? "").slice(0, 220)}`);
say();
say("Prompt injection:");
for (const p of ["hardened", "naive"] as const) {
  const xs = inj.filter((r) => r.prompt === p);
  say(`- ${p} prompt: benign ${xs.filter((r) => r.ai?.verdict === "benign").length}/${xs.length}, suspicious ${xs.filter((r) => r.ai?.verdict === "suspicious").length}, malicious ${xs.filter((r) => r.ai?.verdict === "malicious").length}; injection comment cited as a finding in ${xs.filter((r) => r.ai?.findings.some((f) => /AI CODE REVIEWERS|NPM-SEC-2291|correct verdict/i.test(f.quote))).length}`);
}
say();
const allFindings = rows.flatMap((r) => r.ai?.findings ?? []);
const allDropped = rows.flatMap((r) => r.ai?.dropped ?? []);
const whys = new Map<string, number>();
for (const d of allDropped) whys.set(d.why, (whys.get(d.why) ?? 0) + 1);
const flaggedNoCite = rows.filter((r) => aiFlag(r) && (r.ai?.findings.length ?? 0) === 0);
say(`Citations: ${allFindings.length + allDropped.length} findings returned, ${allFindings.length} kept, ${allDropped.length} dropped (${[...whys].map(([k, v]) => `${k} ${v}`).join(", ")}); flagged with no surviving citation: ${flaggedNoCite.length} (${flaggedNoCite.map((r) => r.id).join(", ")})`);
say();
const evalUsage = usageStats(rows.filter((r) => r.ai && r.ai.verdict !== "error"));
const diffUsage = usageStats(rows.filter((r) => r.mode === "diff" && r.ai));
const filesUsage = usageStats(rows.filter((r) => r.mode === "files" && r.ai));
const trafficUsage = usageStats(traffic.filter((r) => r.ai && r.ai.verdict !== "error"));
say("| Set | n | Input tokens mean / p50 / p90 | Output tokens mean / p50 / p90 (reasoning mean) | Latency s mean / p50 / p90 |");
say("|---|---|---|---|---|");
for (const [label, u] of [["All eval cases", evalUsage], ["Diff mode", diffUsage], ["Files mode", filesUsage], ["Random new npm versions", trafficUsage]] as const) {
  if (!u.n) continue;
  say(`| ${label} | ${u.n} | ${u.input.mean} / ${u.input.p50} / ${u.input.p90} | ${u.output.mean} / ${u.output.p50} / ${u.output.p90} (${u.reasoning.mean}) | ${(u.latencyMs.mean / 1000).toFixed(1)} / ${(u.latencyMs.p50 / 1000).toFixed(1)} / ${(u.latencyMs.p90 / 1000).toFixed(1)} |`);
}
say();
const basis = trafficUsage.n >= 20 ? trafficUsage : evalUsage;
const tp = throughput(basis.input.mean, basis.output.mean, basis.latencyMs.mean);
const tpEval = throughput(evalUsage.input.mean, evalUsage.output.mean, evalUsage.latencyMs.mean);
say(`Throughput at a quarter of the quota (${tp.inputQuotaPerMin} input, ${tp.outputQuotaPerMin} output tokens/min), using ${basis === trafficUsage ? "random new npm versions" : "eval cases"} as the per-review cost: ${tp.reviewsPerMinByInput.toFixed(1)}/min by input, ${tp.reviewsPerMinByOutput.toFixed(1)}/min by output -> ${tp.reviewsPerMin.toFixed(1)}/min, ${Math.round(tp.reviewsPerDay)}/day (binding: ${tp.binding}; ~${tp.concurrencyNeeded} requests in flight)`);
say(`Same with eval-set costs: ${tpEval.reviewsPerMin.toFixed(1)}/min, ${Math.round(tpEval.reviewsPerDay)}/day (binding ${tpEval.binding})`);

// Volume and coverage.
const volDir = join(CACHE_DIR, "volume");
const volFiles = existsSync(volDir) ? readdirSync(volDir).filter((f) => f.endsWith(".json")).sort() : [];
type Vol = { mode: string; estimatedVersionsPerDay: number; shareOfVersionsFromPackagesWithWeeklyDownloadsAtLeast: Record<string, number> } & Record<string, unknown>;
const vols: Vol[] = volFiles.map((f) => JSON.parse(readFileSync(join(volDir, f), "utf8")));
const coverage: Record<string, unknown>[] = [];
for (const v of vols) {
  say();
  say(`Volume (${v.mode}): ~${v.estimatedVersionsPerDay} new versions/day; share from packages with >=1k / >=10k / >=100k weekly downloads: ${Object.values(v.shareOfVersionsFromPackagesWithWeeklyDownloadsAtLeast).map((x) => `${(x * 100).toFixed(1)}%`).join(" / ")}`);
  const policies: [string, number][] = [
    ["all new versions", v.estimatedVersionsPerDay],
    ...Object.entries(v.shareOfVersionsFromPackagesWithWeeklyDownloadsAtLeast).map(([k, s]): [string, number] => [`packages with >=${k} weekly downloads`, v.estimatedVersionsPerDay * s]),
  ];
  say("| Policy | Versions/day | Capacity/day | Reviewed same day | Backlog growth/day |");
  say("|---|---|---|---|---|");
  for (const [label, perDay] of policies) {
    const share = Math.min(1, tp.reviewsPerDay / Math.max(1, perDay));
    const backlog = Math.max(0, perDay - tp.reviewsPerDay);
    coverage.push({ volume: v.mode, policy: label, versionsPerDay: Math.round(perDay), capacityPerDay: Math.round(tp.reviewsPerDay), sameDayShare: share, backlogGrowthPerDay: Math.round(backlog) });
    say(`| ${label} | ${Math.round(perDay)} | ${Math.round(tp.reviewsPerDay)} | ${(share * 100).toFixed(0)}% | ${backlog ? `+${Math.round(backlog)}` : "none"} |`);
  }
}

if (traffic.length) {
  say();
  const t = traffic.filter((r) => r.ai);
  const c = (v: string): number => t.filter((r) => r.ai?.verdict === v).length;
  say(`Random new npm versions (${t.length}): Flash malicious ${c("malicious")}, suspicious ${c("suspicious")}, benign ${c("benign")}, errors ${c("error")}; flagged with citation ${t.filter(aiGrounded).length}; rules below ${RULE_FLAG_BELOW}: ${t.filter(ruleFlag).length}`);
  for (const r of t.filter(aiFlag)) say(`- ${r.id}: ${r.ai?.verdict} conf ${r.ai?.confidence} cited ${r.ai?.findings.length}; ${(r.ai?.summary ?? "").slice(0, 200)}`);
}

// Errors on first attempt (the JSONL keeps every attempt; `load` keeps only the last).
const attempts = (r: string): CaseResult[] => {
  const p = join(CACHE_DIR, "runs", `${r}.jsonl`);
  return existsSync(p) ? readFileSync(p, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
};
const allAttempts = [...attempts(run), ...attempts("repeat"), ...attempts(arg("--traffic", "traffic"))];
const failed = allAttempts.filter((r) => !r.ai || r.ai.verdict === "error");
say();
say(`Attempts: ${allAttempts.length} requests, ${failed.length} returned no usable JSON (${failed.map((r) => `${r.id} out=${r.ai?.usage.completionTokens ?? 0}`).join(", ")})`);

// Stability: the same request twice.
const repeat = load("repeat");
const stability: Record<string, unknown> = {};
if (repeat.length) {
  const first = new Map(rows.map((r) => [r.id, r]));
  const pairs = repeat.flatMap((r) => {
    const a = first.get(r.id);
    return a ? [[a, r] as const] : [];
  });
  const sameVerdict = pairs.filter(([a, b]) => a.ai?.verdict === b.ai?.verdict).length;
  const sameFlag = pairs.filter(([a, b]) => aiGrounded(a) === aiGrounded(b)).length;
  const malPairs = pairs.filter(([a]) => a.group.startsWith("malicious"));
  const benPairs = pairs.filter(([a]) => a.group.startsWith("benign"));
  say();
  say(`Stability over ${pairs.length} repeated requests: same verdict ${sameVerdict}/${pairs.length}, same flag decision ${sameFlag}/${pairs.length}`);
  say(`- repeat run alone: malicious caught ${malPairs.filter(([, b]) => aiGrounded(b)).length}/${malPairs.length}, benign first-publish false alarms ${benPairs.filter(([, b]) => aiGrounded(b)).length}/${benPairs.length}`);
  say(`- flagged in either run: malicious ${malPairs.filter(([a, b]) => aiGrounded(a) || aiGrounded(b)).length}/${malPairs.length}, benign ${benPairs.filter(([a, b]) => aiGrounded(a) || aiGrounded(b)).length}/${benPairs.length}`);
  for (const [a, b] of pairs.filter(([a, b]) => a.ai?.verdict !== b.ai?.verdict)) say(`  - ${a.id}: ${a.ai?.verdict} -> ${b.ai?.verdict}`);
  Object.assign(stability, { pairs: pairs.length, sameVerdict, sameFlag });
}

// Bootstrap interval on the day estimate (versions per changed package is heavy-tailed).
for (const f of volFiles.filter((x) => x.startsWith("day-"))) {
  const d: { distinctPackagesChanged: number; packages: { versionsInWindow: number }[] } = JSON.parse(readFileSync(join(volDir, f), "utf8"));
  const xs = d.packages.map((p) => p.versionsInWindow);
  let seed = 7;
  const rand = (): number => {
    seed = (seed * 1103515245 + 12345) % 2147483648;
    return seed / 2147483648;
  };
  const means: number[] = [];
  for (let i = 0; i < 2000; i++) {
    let sum = 0;
    for (let j = 0; j < xs.length; j++) sum += xs[Math.floor(rand() * xs.length)] ?? 0;
    means.push(sum / xs.length);
  }
  say(`Day estimate 95% bootstrap interval: ${Math.round(pct(means, 2.5) * d.distinctPackagesChanged)}–${Math.round(pct(means, 97.5) * d.distinctPackagesChanged)} versions/day`);
}

process.stdout.write(`${lines.join("\n")}\n`);
const summary = {
  generatedAt: new Date().toISOString(),
  run,
  quota: QUOTA,
  share: SHARE,
  ruleFlagBelow: RULE_FLAG_BELOW,
  detectors: detectorTable,
  usage: { eval: evalUsage, diff: diffUsage, files: filesUsage, traffic: trafficUsage },
  throughput: tp,
  stability,
  coverage,
  cases: [...rows, ...traffic].map((r) => ({
    id: r.id,
    group: r.group,
    mode: r.mode,
    prompt: r.prompt,
    verdict: r.ai?.verdict ?? "error",
    confidence: r.ai?.confidence ?? 0,
    citedFindings: r.ai?.findings.length ?? 0,
    droppedFindings: r.ai?.dropped.length ?? 0,
    ruleScore: r.rule.score,
    ruleSignals: r.rule.signals,
    estTokens: r.input.estTokens,
    truncated: r.input.truncated,
    promptTokens: r.ai?.usage.promptTokens ?? 0,
    completionTokens: r.ai?.usage.completionTokens ?? 0,
    latencyMs: Math.round(r.ai?.usage.latencyMs ?? 0),
  })),
};
const outPath = join(dirname(new URL(import.meta.url).pathname), "results", "summary.json");
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, `${JSON.stringify(summary, null, 2)}\n`);
