// Measures how many new npm versions are published per day, two ways.
//
//   live:  poll replicate.npmjs.com/_changes for N minutes, then read each changed package's
//          packument and count versions whose publish time falls inside the window.
//   day:   find the change sequence number from 24 hours ago by binary search (the feed lists each
//          package once, at its latest change, so the package at a sequence was last modified then),
//          page the feed from there to now, and read a random sample of the changed packages to
//          count versions published in the last 24 hours.
//
// Both also look up weekly downloads so the "popular packages only" share can be computed.
// Usage: bun tools/ai-review/npm-volume.ts live <minutes> [cap] | resume <changes-*.raw> [cap] | day <sampleSize>
// Output: JSON in ~/.cache/apm-ai-review-samples/volume/.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { CACHE_DIR, mapLimit, rng, shuffle } from "./util.ts";

const FEED = "https://replicate.npmjs.com/registry/_changes";
const REGISTRY = "https://registry.npmjs.org/";
const UA = { "user-agent": "apm-research-volume/0.1" };
const OUT = join(CACHE_DIR, "volume");

type Change = { seq: number; id: string };

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

async function getJson(url: string, tries = 4): Promise<unknown> {
  for (let i = 0; ; i++) {
    try {
      const res = await fetch(url, { headers: UA, signal: AbortSignal.timeout(60_000) });
      if (res.status === 404) return null;
      if (res.status === 429) {
        const after = Number(res.headers.get("retry-after") ?? "");
        await res.body?.cancel();
        if (i >= tries + 4) throw new Error("HTTP 429");
        await Bun.sleep(Number.isFinite(after) && after > 0 ? after * 1000 : 5000 * 2 ** Math.min(i, 4));
        continue;
      }
      if (res.status >= 500) throw new Error(`HTTP ${res.status}`);
      if (!res.ok) return null;
      return await res.json();
    } catch (e) {
      if (i >= tries) throw e;
      await Bun.sleep(1000 * 2 ** i);
    }
  }
}

/** Like getJson, but a lookup that keeps failing counts as unknown instead of ending the run. */
async function tryJson(url: string): Promise<unknown> {
  try {
    return await getJson(url);
  } catch {
    return null;
  }
}

function parseChanges(v: unknown): { results: Change[]; lastSeq: number } {
  if (!isRecord(v) || !Array.isArray(v.results)) throw new Error("bad _changes response");
  const results: Change[] = [];
  for (const r of v.results) {
    if (isRecord(r) && typeof r.seq === "number" && typeof r.id === "string") results.push({ seq: r.seq, id: r.id });
  }
  const lastSeq = typeof v.last_seq === "number" ? v.last_seq : (results.at(-1)?.seq ?? 0);
  return { results, lastSeq };
}

async function changesSince(since: number, limit: number): Promise<{ results: Change[]; lastSeq: number }> {
  return parseChanges(await getJson(`${FEED}?since=${since}&limit=${limit}`));
}

async function headSeq(): Promise<number> {
  const v = await getJson("https://replicate.npmjs.com/registry/");
  if (!isRecord(v) || typeof v.update_seq !== "number") throw new Error("bad registry info");
  return v.update_seq;
}

type PackumentTimes = { modified: number | null; versions: { version: string; at: number }[] };

/** Publish times from the full packument. Skips "created" and "modified". */
async function packumentTimes(name: string): Promise<PackumentTimes | null> {
  const v = await getJson(REGISTRY + name.replace("/", "%2f"));
  if (!isRecord(v) || !isRecord(v.time)) return null;
  const versions: { version: string; at: number }[] = [];
  let modified: number | null = null;
  for (const [k, t] of Object.entries(v.time)) {
    if (typeof t !== "string") continue;
    const at = Date.parse(t);
    if (Number.isNaN(at)) continue;
    if (k === "modified") modified = at;
    else if (k !== "created") versions.push({ version: k, at });
  }
  return { modified, versions };
}

/** Weekly downloads; the bulk endpoint takes up to 128 unscoped names, scoped names go one by one. */
async function weeklyDownloads(names: readonly string[]): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  const unscoped = names.filter((n) => !n.startsWith("@"));
  const scoped = names.filter((n) => n.startsWith("@"));
  for (let i = 0; i < unscoped.length; i += 128) {
    const batch = unscoped.slice(i, i + 128);
    const v = await tryJson(`https://api.npmjs.org/downloads/point/last-week/${batch.join(",")}`);
    if (batch.length === 1) {
      if (isRecord(v) && typeof v.downloads === "number" && batch[0]) out.set(batch[0], v.downloads);
    } else if (isRecord(v)) {
      for (const [k, d] of Object.entries(v)) if (isRecord(d) && typeof d.downloads === "number") out.set(k, d.downloads);
    }
  }
  // The downloads API rate-limits single-name lookups hard; go one at a time.
  for (const n of scoped) {
    const v = await tryJson(`https://api.npmjs.org/downloads/point/last-week/${n}`);
    if (isRecord(v) && typeof v.downloads === "number") out.set(n, v.downloads);
    await Bun.sleep(250);
  }
  return out;
}

type SampledPackage = { id: string; versionsInWindow: number; weeklyDownloads: number | null; gone: boolean };

async function samplePackages(ids: readonly string[], from: number, to: number): Promise<SampledPackage[]> {
  const counted = await mapLimit(ids, 4, async (id) => {
    const p = await packumentTimes(id).catch(() => null);
    if (!p) return { id, versionsInWindow: 0, weeklyDownloads: null, gone: true };
    return { id, versionsInWindow: p.versions.filter((x) => x.at >= from && x.at <= to).length, weeklyDownloads: null, gone: false };
  });
  const dl = await weeklyDownloads(counted.filter((c) => c.versionsInWindow > 0).map((c) => c.id));
  return counted.map((c) => ({ ...c, weeklyDownloads: dl.get(c.id) ?? null }));
}

function summarize(sample: readonly SampledPackage[], populationChanges: number, windowMs: number) {
  const versions = sample.reduce((n, s) => n + s.versionsInWindow, 0);
  const perChange = sample.length ? versions / sample.length : 0;
  const perDay = (populationChanges * perChange * 86_400_000) / windowMs;
  // Shares are over versions whose package's downloads are known.
  const known = sample.filter((s) => s.versionsInWindow > 0 && s.weeklyDownloads !== null);
  const knownVersions = known.reduce((n, s) => n + s.versionsInWindow, 0);
  const popular = (min: number): number => {
    const v = known.filter((s) => (s.weeklyDownloads ?? 0) >= min).reduce((n, s) => n + s.versionsInWindow, 0);
    return knownVersions ? v / knownVersions : 0;
  };
  return {
    sampledPackages: sample.length,
    goneOrUnreadable: sample.filter((s) => s.gone).length,
    packagesWithNewVersions: sample.filter((s) => s.versionsInWindow > 0).length,
    versionsInSample: versions,
    versionsWithKnownDownloads: knownVersions,
    versionsPerChangedPackage: perChange,
    estimatedVersionsPerDay: Math.round(perDay),
    shareOfVersionsFromPackagesWithWeeklyDownloadsAtLeast: { "1000": popular(1000), "10000": popular(10_000), "100000": popular(100_000) },
  };
}

async function live(minutes: number, cap: number): Promise<void> {
  const start = Date.now();
  let since = await headSeq();
  const changes: (Change & { seenAt: number })[] = [];
  while (Date.now() - start < minutes * 60_000) {
    const { results, lastSeq } = await changesSince(since, 10_000);
    const now = Date.now();
    for (const r of results) changes.push({ ...r, seenAt: now });
    since = Math.max(since, lastSeq);
    await Bun.sleep(10_000);
  }
  const end = Date.now();
  write(`changes-${new Date(start).toISOString().replace(/[:.]/g, "-")}.raw`, { start, end, changes });
  await finishLive(start, end, changes, cap);
}

async function finishLive(start: number, end: number, changes: readonly (Change & { seenAt: number })[], cap: number): Promise<void> {
  // A package can appear several times; count each package once and let the packument say how many
  // versions it published in the window.
  const ids = [...new Set(changes.map((c) => c.id))];
  // Reading every packument can take long for busy windows; a random sample of `cap` is enough.
  const sampleIds = shuffle(ids, rng(start)).slice(0, cap);
  // Allow for feed lag at the start: count versions published in the window widened by a minute.
  const sample = await samplePackages(sampleIds, start - 60_000, end);
  const windowMs = end - start + 60_000;
  const result = {
    mode: "live",
    startedAt: new Date(start).toISOString(),
    endedAt: new Date(end).toISOString(),
    changeEvents: changes.length,
    distinctPackages: ids.length,
    ...summarize(sample, ids.length, windowMs),
    packages: sample,
  };
  write(`live-${new Date(start).toISOString().replace(/[:.]/g, "-")}.json`, result);
}

/** Time of the latest change of the package listed right after `seq`. */
async function timeAtSeq(seq: number): Promise<{ seq: number; at: number } | null> {
  const { results } = await changesSince(seq, 5);
  for (const r of results) {
    const p = await packumentTimes(r.id);
    if (p?.modified) return { seq: r.seq, at: p.modified };
  }
  return null;
}

async function day(sampleSize: number): Promise<void> {
  const now = Date.now();
  const target = now - 86_400_000;
  const head = await headSeq();
  let lo = Math.max(0, head - 3_000_000);
  let hi = head;
  const probes: { seq: number; at: number }[] = [];
  for (let i = 0; i < 24 && hi - lo > 2000; i++) {
    const mid = Math.floor((lo + hi) / 2);
    const t = await timeAtSeq(mid);
    if (!t) break;
    probes.push(t);
    if (t.at < target) lo = mid;
    else hi = mid;
  }
  const startSeq = lo;
  const ids: string[] = [];
  let since = startSeq;
  for (;;) {
    const { results, lastSeq } = await changesSince(since, 10_000);
    for (const r of results) ids.push(r.id);
    if (results.length < 10_000 || lastSeq <= since) break;
    since = lastSeq;
  }
  const distinct = [...new Set(ids)];
  const sampleIds = shuffle(distinct, rng(20261112)).slice(0, sampleSize);
  const sample = await samplePackages(sampleIds, target, now);
  const result = {
    mode: "day",
    windowStart: new Date(target).toISOString(),
    windowEnd: new Date(now).toISOString(),
    startSeq,
    headSeq: head,
    probes: probes.map((p) => ({ seq: p.seq, at: new Date(p.at).toISOString() })),
    distinctPackagesChanged: distinct.length,
    ...summarize(sample, distinct.length, 86_400_000),
    packages: sample,
  };
  write(`day-${new Date(now).toISOString().replace(/[:.]/g, "-")}.json`, result);
}

function write(file: string, data: unknown): void {
  mkdirSync(OUT, { recursive: true });
  const path = join(OUT, file);
  writeFileSync(path, JSON.stringify(data, null, 2));
  const { packages: _omit, changes: _changes, ...head } = isRecord(data) ? data : {};
  process.stdout.write(`${path}\n${JSON.stringify(head, null, 2)}\n`);
}

const [mode, arg, arg2] = process.argv.slice(2);
if (mode === "live") await live(Number(arg ?? 10), Number(arg2 ?? 600));
else if (mode === "resume" && arg) {
  const raw: { start: number; end: number; changes: (Change & { seenAt: number })[] } = JSON.parse(readFileSync(arg, "utf8"));
  await finishLive(raw.start, raw.end, raw.changes, Number(arg2 ?? 600));
}
else if (mode === "day") await day(Number(arg ?? 400));
else process.stdout.write("usage: npm-volume.ts live <minutes> [sampleCap] | day <sampleSize>\n");
