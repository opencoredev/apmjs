// A tarball too large to hold, scored inside workerd the way the queue scores it (streamed-analysis.ts), with what it
// costs: the isolate's memory before each pass and after the run (workerd-heap.ts: JS heap, embedder heap and
// ArrayBuffer bytes after a full GC), the V8 heap the collections during the run saw (--trace-gc, since the isolate
// cannot be measured while the analysis runs), and the CPU the workerd process spent on the request.
//
// workerd runs under a V8 heap cap of HEAP_CAP_MB of old space and small semi-spaces, so a run whose live memory does
// not fit beside what it holds outside the heap ends workerd (an out-of-memory crash) and fails, as the platform would
// end it. Measured with a 20 MB cap, next's run does end workerd: the cap is enforced.
//
// A generated tarball over the 32 MiB download cap, one native binary and a little code, always runs. The real ones run
// when their tarballs are on this machine: next 16.4.6 and the 70-package corpus in ~/.cache/apm-corpus/tgz (the
// corpus docs/SCORE.md measures), and @next/swc-linux-x64-gnu 16.4.6 in ~/.cache/apm-big/tgz.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { MAX_UPSTREAM_TARBALL_BYTES } from "../src/upstream.ts";
import { WORKER_CPU_MS } from "../src/analysis.ts";
import { ENTRY } from "./streamed-analysis-entry.ts";
import { startWorkerdHeap, type WorkerdHeap } from "./workerd-heap.ts";

const MB = 1024 * 1024;

/** A Worker spends about this many times this machine's CPU per unit of work (scripts/compat.ts: vite 8.3.8 on staging). */
const WORKER_CPU_FACTOR = 4.7;

/** What a run may cost here: WORKER_CPU_MS on a Worker at WORKER_CPU_FACTOR. */
const CPU_MS_HERE = WORKER_CPU_MS / WORKER_CPU_FACTOR;

/**
 * The CPU a run measured here costs depends on what else this machine runs, so the margin is checked against a run
 * production already makes inside the limit: prettier 3.10.1 read whole (28 to 35 s of CPU on staging, scripts/compat.ts),
 * measured in the same isolate just before. A streamed run must cost less.
 */
let reference: number | null = null;

/**
 * The old space V8 may use here, with 4 MB semi-spaces (three of them, about 12 MB): with the held files and stream
 * buffers outside the heap, under the 128 MB a Worker isolate has.
 */
const HEAP_CAP_MB = 96;

/** The most live memory any full collection may find during a run: half the cap, the rest left to garbage and the runtime. */
const LIVE_LIMIT = (HEAP_CAP_MB / 2) * MB;

const DIRS = [join(homedir(), ".cache", "apm-corpus", "tgz"), join(homedir(), ".cache", "apm-big", "tgz")];

function tarballAt(file: string): string | null {
  for (const dir of DIRS) if (existsSync(join(dir, file))) return join(dir, file);

  return null;
}

/** Generated tarballs, served by name beside the files on disk. */
const generated = new Map<string, Uint8Array>();

function served(name: string): Uint8Array | null {
  const g = generated.get(name);

  if (g) return g;
  const path = tarballAt(name);

  return path ? new Uint8Array(readFileSync(path)) : null;
}

/** A ustar archive of `files` under package/, gzip'd. */
function tgz(files: Record<string, Uint8Array | string>): Uint8Array {
  const blocks: Uint8Array[] = [];

  for (const [name, content] of Object.entries(files)) {
    const data = content instanceof Uint8Array ? content : new TextEncoder().encode(content);
    const header = new Uint8Array(512);
    const put = (s: string, at: number): void => header.set(new TextEncoder().encode(s), at);
    put(`package/${name}`, 0);
    put("0000644\0", 100);
    put("0000000\0", 108);
    put("0000000\0", 116);
    put(`${data.length.toString(8).padStart(11, "0")}\0`, 124);
    put("00000000000\0", 136);
    put("        ", 148);
    put("0", 156);
    put("ustar\0", 257);
    put("00", 263);
    put(`${header.reduce((n, b) => n + b, 0).toString(8).padStart(6, "0")}\0 `, 148);
    blocks.push(header, data, new Uint8Array((512 - (data.length % 512)) % 512));
  }

  blocks.push(new Uint8Array(1024));
  const tar = new Uint8Array(blocks.reduce((n, b) => n + b.length, 0));
  let at = 0;

  for (const b of blocks) {
    tar.set(b, at);
    at += b.length;
  }

  return Bun.gzipSync(tar);
}

/** Every workerd process below this one, by pid, with the CPU it has spent in clock ticks of 10 ms (from /proc). */
function workerdTicks(): Map<number, number> {
  const procs = new Map<number, { ppid: number; comm: string; ticks: number }>();

  for (const d of readdirSync("/proc")) {
    if (!/^\d+$/.test(d)) continue;
    let stat: string;

    try {
      stat = readFileSync(`/proc/${d}/stat`, "utf8");
    } catch {
      continue;
    }

    const close = stat.lastIndexOf(")");
    const fields = stat.slice(close + 2).split(" ");
    procs.set(Number(d), { comm: stat.slice(stat.indexOf("(") + 1, close), ppid: Number(fields[1]), ticks: Number(fields[11]) + Number(fields[12]) });
  }

  const below = (pid: number): boolean => {
    for (let p = procs.get(pid)?.ppid; p !== undefined && p > 1; p = procs.get(p)?.ppid) if (p === process.pid) return true;

    return false;
  };

  const out = new Map<number, number>();

  for (const [pid, p] of procs) if (p.comm.startsWith("workerd") && below(pid)) out.set(pid, p.ticks);

  return out;
}

/** The workerd processes this file started: not those other test files in this process left running. */
let ours = new Set<number>();

/** CPU milliseconds this file's workerd has spent. */
function workerdCpuMs(): number {
  let ticks = 0;

  for (const [pid, t] of workerdTicks()) if (ours.has(pid)) ticks += t;

  return ticks * 10;
}

const Signal = z.object({ id: z.string(), evidence: z.array(z.string()), count: z.number() });
const Coverage = z.discriminatedUnion("kind", [z.object({ kind: z.literal("complete") }), z.object({ kind: z.literal("partial"), omittedFiles: z.number(), omittedBytes: z.number(), reasons: z.array(z.string()), notes: z.array(z.string()) })]);
const Scored = z.object({ kind: z.literal("scored"), spent: z.boolean(), score: z.number(), grade: z.string(), coverage: Coverage.nullable(), signals: z.array(Signal), skipped: z.number(), notChecked: z.array(z.string()), files: z.number(), analysis: z.string() });
const Other = z.object({ kind: z.enum(["unscorable", "failed", "fetch-failed", "absent", "stream"]) }).loose();
const Answer = z.object({ result: z.union([Scored, Other]), before: z.array(z.number()), after: z.number(), leased: z.number().optional() });

/** A GC trace line's heap before the collection, in MB: `Mark-Compact 45.3 (52.1) -> 30.1 (50.0) MB`. */
const GC_LINE = /(?:Scavenge|Mark-Compact|Mark-sweep|Minor Mark-Sweep)[^\d]*([\d.]+) \(([\d.]+)\) -> ([\d.]+) \(([\d.]+)\) MB/;

let heap: WorkerdHeap;
const gcLines: string[] = [];

beforeAll(async () => {
  const before = new Set(workerdTicks().keys());

  heap = await startWorkerdHeap(ENTRY, {
    v8Flags: ["--trace-gc", `--max-old-space-size=${HEAP_CAP_MB}`, "--max-semi-space-size=4"],
    onStdout: (line) => {
      if (GC_LINE.test(line)) gcLines.push(line);
    },
    serviceBindings: {
      NPM: async (req) => {
        const name = decodeURIComponent(new URL(req.url).pathname.slice(1));
        const bytes = served(name);

        return bytes ? new Response(bytes, { headers: { "content-length": String(bytes.length) } }) : new Response("not found", { status: 404 });
      },
    },
  });
  ours = new Set([...workerdTicks().keys()].filter((pid) => !before.has(pid)));
}, 60_000);

afterAll(async () => {
  await heap.dispose();
});

const mb = (n: number): string => `${(n / MB).toFixed(1)} MiB`;

/** `peakHeap`: the largest heap any collection began with, garbage included; `liveHeap`: the most a full collection left. */
type Measured = { answer: z.infer<typeof Answer>; cpuMs: number; wallMs: number; base: number; peakHeap: number; liveHeap: number };

async function run(route: "stream" | "held", file: string, name: string, sha512: string, query = ""): Promise<Measured> {
  // warm: the code a first request compiles is not counted against the run
  await heap.dispatch("/measure");
  const base = Number(await (await heap.dispatch("/measure")).text());
  gcLines.length = 0;
  const cpu = workerdCpuMs();
  const t = performance.now();
  const res = await heap.dispatch(`/${route}?file=${encodeURIComponent(file)}&name=${encodeURIComponent(name)}&sha512=${sha512}${query}`);
  const answer = Answer.parse(await res.json());
  const wallMs = performance.now() - t;
  const cpuMs = workerdCpuMs() - cpu;
  const peakHeap = Math.max(0, ...gcLines.map((l) => Number(GC_LINE.exec(l)?.[1] ?? 0) * MB));
  const liveHeap = Math.max(0, ...gcLines.flatMap((l) => (/Mark-Compact|Mark-sweep/.test(l) && !/Minor/.test(l) ? [Number(GC_LINE.exec(l)?.[3] ?? 0) * MB] : [])));
  const r = answer.result;
  const what = r.kind === "scored" ? `score ${r.score} (${r.grade})${r.coverage?.kind === "partial" ? `, partial: ${r.coverage.omittedFiles} files not read` : ""}${r.spent ? " (meter spent)" : ""}, ${r.files} files, ${r.skipped} skipped, signals ${r.signals.map((s) => `${s.id}:${s.count}`).join(" ")}` : r.kind;

  process.stdout.write(
    `[${route}] ${name}: ${what}; CPU ${(cpuMs / 1000).toFixed(2)} s here (about ${((cpuMs * WORKER_CPU_FACTOR) / 1000).toFixed(0)} s on a Worker), wall ${(wallMs / 1000).toFixed(2)} s; ` +
      `held over a base of ${mb(base)}: before each pass ${answer.before.map((b) => `+${mb(b - base)}`).join(", ")}, after +${mb(answer.after - base)}; V8 heap at most ${mb(peakHeap)} with garbage, ${mb(liveHeap)} live after a full collection${answer.leased === undefined ? "" : `; the run's lease peaked at ${mb(answer.leased)}`}\n`,
  );

  return { answer, cpuMs, wallMs, base, peakHeap, liveHeap };
}

const sha512 = (bytes: Uint8Array): string => createHash("sha512").update(bytes).digest("hex");

function scored(m: Measured): z.infer<typeof Scored> {
  const r = m.answer.result;

  if (r.kind !== "scored") throw new Error(`not scored: ${JSON.stringify(r)}`);

  return r;
}

describe("a tarball too large to hold is scored as a stream", () => {
  test("a generated 36 MiB tarball (one native binary, a little code) reads in one pass to the analysis it gets held whole", async () => {
    const bytes = tgz({
      "package.json": JSON.stringify({ name: "big-native", version: "1.0.0", license: "MIT", main: "index.js" }),
      "index.js": "module.exports = require('./lib/a.js');\n",
      "lib/a.js": "module.exports = 2;\n",
      "prebuilt/addon.node": new Uint8Array(randomBytes(36 * MB)),
    });

    generated.set("big-native.tgz", bytes);
    expect(bytes.length).toBeGreaterThan(MAX_UPSTREAM_TARBALL_BYTES);
    const m = await run("stream", "big-native.tgz", "big-native", sha512(bytes));
    const r = scored(m);
    // 36 MiB unpacks under the 48 MiB cap, so the held path reads it whole: the same scorer, given every byte
    const whole = scored(await run("held", "big-native.tgz", "big-native", sha512(bytes)));

    // read exactly as a tarball held whole is: the binary is listed, not read, and nothing was left out
    expect(r.analysis).toBe(whole.analysis);
    expect(r.signals.find((s) => s.id === "incomplete")).toBeUndefined();
    expect(r.files).toBe(4);
    // one pass: the first held package.json and the two code files, all the plan wanted
    expect(m.answer.before).toHaveLength(1);

    for (const b of [...m.answer.before, m.answer.after]) expect(b - m.base).toBeLessThan(8 * MB);
  }, 120_000);

  test("bytes that do not match their sha512 store nothing", async () => {
    const bytes = generated.get("big-native.tgz") ?? new Uint8Array();
    const wrong = createHash("sha512").update("other bytes").digest("hex");
    const m = await run("stream", "big-native.tgz", "big-native", wrong);

    expect(m.answer.result).toEqual({ kind: "fetch-failed", reason: "the upstream tarball failed its integrity check", retryable: true });
    expect(bytes.length).toBeGreaterThan(0);
  }, 120_000);

  test.skipIf(tarballAt("prettier-3.10.1.tgz") === null)("prettier 3.10.1, read whole as production reads it: the CPU a run inside the limit costs here", async () => {
    const bytes = served("prettier-3.10.1.tgz") ?? new Uint8Array();
    const m = await run("held", "prettier-3.10.1.tgz", "prettier", sha512(bytes));

    expect(scored(m).kind).toBe("scored");
    reference = m.cpuMs;
  }, 300_000);

  for (const [file, name] of [
    ["next-16.4.6.tgz", "next"],
    ["swc-linux-x64-gnu-16.4.6.tgz", "@next/swc-linux-x64-gnu"],
    ["prisma-client-7.10.1.tgz", "@prisma/client"],
  ] as const) {
    test.skipIf(tarballAt(file) === null)(`${name}: scored inside the CPU limit with margin, and in memory`, async () => {
      const bytes = served(file) ?? new Uint8Array();
      const m = await run("stream", file, name, sha512(bytes));
      const r = scored(m);

      expect(m.cpuMs).toBeLessThan(CPU_MS_HERE);

      if (reference !== null) expect(m.cpuMs).toBeLessThan(reference);
      // it finished under the heap cap (workerd would have crashed), with live memory well inside it
      expect(m.liveHeap).toBeLessThan(LIVE_LIMIT);

      for (const b of [...m.answer.before, m.answer.after]) expect(b - m.base).toBeLessThan(32 * MB);

      // a partial reading is never a pass (apm-score-v11): what it could not read makes its coverage partial and its
      // grade P, whatever it scored on what it read
      if (r.skipped > 0) {
        expect(r.coverage).toMatchObject({ kind: "partial", omittedFiles: r.skipped });
        expect(r.grade).toBe("P");
      } else expect(r.coverage).toEqual({ kind: "complete" });
    }, 300_000);
  }

  test.skipIf(tarballAt("next-16.4.6.tgz") === null)("next, beside 27 MiB of live objects (the queue run holds next's packument), still fits the heap cap", async () => {
    const bytes = served("next-16.4.6.tgz") ?? new Uint8Array();
    const m = await run("stream", "next-16.4.6.tgz", "next (with a packument's weight held)", sha512(bytes), "&ballastMiB=27");

    expect(scored(m).grade).toBe("P");
    // the ballast is live throughout: what a full collection leaves is the run's and the ballast's
    expect(m.liveHeap).toBeLessThan(LIVE_LIMIT + 32 * MB);
  }, 300_000);

  for (const [file, name] of [
    ["express-5.3.0.tgz", "express"],
    ["better-sqlite3-13.1.1.tgz", "better-sqlite3"],
  ] as const) {
    test.skipIf(tarballAt(file) === null)(`${name}, under the caps, read whole as before: for comparison`, async () => {
      const bytes = served(file) ?? new Uint8Array();
      const m = await run("held", file, name, sha512(bytes));

      expect(scored(m).kind).toBe("scored");
    }, 300_000);
  }
});
