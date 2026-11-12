// Reviews a random sample of versions that were really published during the live volume window, to get
// real per-review token costs and see what Flash and the rules say about ordinary npm traffic.
// These tarballs are untrusted too: downloaded to the cache and read as bytes only.
// Usage: bun tools/ai-review/traffic.ts <sampleSize> [--dry]
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fetchNpmTarball } from "./fetch-malicious.ts";
import { inputFor, runCases, type Case } from "./run-eval.ts";
import { loadTgz } from "./samples.ts";
import { CACHE_DIR, mapLimit, rng, shuffle } from "./util.ts";

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

type LivePackage = { id: string; versionsInWindow: number; weeklyDownloads: number | null };
type LiveFile = { startedAt: string; endedAt: string; packages: LivePackage[] };

const volDir = join(CACHE_DIR, "volume");
const liveFile = readdirSync(volDir).filter((f) => f.startsWith("live-")).sort().at(-1);
if (!liveFile) throw new Error("run npm-volume.ts live first");
const live: LiveFile = JSON.parse(readFileSync(join(volDir, liveFile), "utf8"));
const from = Date.parse(live.startedAt) - 60_000;
const to = Date.parse(live.endedAt);
const size = Number(process.argv[2] ?? 40);
const picked = shuffle(live.packages.filter((p) => p.versionsInWindow > 0), rng(42)).slice(0, size);

const cases = (
  await mapLimit(picked, 4, async (p): Promise<Case | null> => {
    try {
      const res = await fetch(`https://registry.npmjs.org/${p.id.replace("/", "%2f")}`, { headers: { "user-agent": "apm-research/0.1" } });
      if (!res.ok) return null;
      const doc: unknown = await res.json();
      if (!isRecord(doc) || !isRecord(doc.time) || !isRecord(doc.versions)) return null;
      const time = doc.time;
      const versions = Object.keys(doc.versions);
      const inWindow = versions.filter((v) => typeof time[v] === "string" && Date.parse(String(time[v])) >= from && Date.parse(String(time[v])) <= to);
      const version = inWindow.sort((a, b) => Date.parse(String(time[b])) - Date.parse(String(time[a])))[0];
      if (!version) return null;
      const lower = versions.filter((v) => v !== version && Bun.semver.order(v, version) < 0 && Date.parse(String(time[v] ?? "")) < Date.parse(String(time[version])));
      const previous = lower.sort((a, b) => Bun.semver.order(b, a))[0] ?? null;
      const sample = loadTgz(await fetchNpmTarball(p.id, version));
      const prev = previous ? loadTgz(await fetchNpmTarball(p.id, previous)) : null;
      return { id: `${p.id}@${version}#${prev ? "diff" : "files"}`, group: "traffic", name: p.id, version, mode: prev ? "diff" : "files", prompt: "hardened", sample, prev, previous };
    } catch (e) {
      process.stdout.write(`skip ${p.id}: ${String(e).slice(0, 100)}\n`);
      return null;
    }
  })
).filter((c): c is Case => c !== null);

const est = cases.map((c) => inputFor(c).estTokens).sort((a, b) => a - b);
process.stdout.write(
  `${cases.length} traffic cases (${cases.filter((c) => c.mode === "diff").length} diff, ${cases.filter((c) => c.mode === "files").length} first publish); est input tokens p50 ${est[Math.floor(est.length / 2)]} p90 ${est[Math.floor(est.length * 0.9)]}\n`,
);
await runCases(cases, "traffic", process.argv.includes("--dry"));
