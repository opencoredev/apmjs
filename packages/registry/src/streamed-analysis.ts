// Scoring an upstream tarball too large to hold. A Worker has 128 MB; next 16.4.6 is 43.7 MB compressed and 192 MB
// unpacked, and @next/swc-linux-x64-gnu 16.4.6 holds one 101 MB native binary. Neither can be buffered and unpacked
// whole, so they are read as a stream, twice:
//
// 1. The first pass inflates and reads every entry as it arrives (@apm/core's TarballInflater). It keeps package.json
//    and the other files the analysis reads by name, the first bytes of every file, and the paths each code file imports
//    (each file gathered on its own and let go once read). It hashes every byte it is sent.
// 2. With the manifest and that import graph, planReading picks the files `analyze` would read first, in its order, up
//    to READ.holdBytes. When the first pass already holds them all (a package of one native binary and a package.json),
//    that is the reading. Otherwise a second pass reads the tarball again and keeps those files whole.
// 3. `analyze` runs over every entry, told which ones it holds only the first bytes of (`notHeld`): a file it reaches
//    and does not have is reported as not read, which makes the analysis's coverage partial, as a file past the byte
//    budget of a tarball read whole does. Native binaries and the other files `analyze` only ever looks at the first
//    bytes of are read exactly as they would be from a tarball held whole.
//
// Integrity: every pass hashes every byte it reads with sha512 and compares it with the version's dist.integrity, and
// the length with the one its source declared, before anything it read is used. A pass that fails either uses nothing
// it read; the run stores nothing and is handed back like a download that failed its checksum. A size verdict is
// stored only for bytes that matched. The second pass is held to the first, verified one: each entry it reads must be
// the one the first listed at that place (path, size, mode), checked before anything is allocated for it.
//
// Memory: everything the read keeps (each entry and its path, held files, a file gathered to read its imports, the
// import graph, the inflate's buffers) is charged to the run's memory lease (memory.ts) before it is kept; a refused
// charge stops the run, to be tried again. The file names and the import graph also have limits of their own
// (MAX_STREAMED_NAMES_BYTES, IMPORT_GRAPH_BYTES and IMPORT_GRAPH_EDGES in @apm/core). The analysis's own working memory
// (its trees) is not leased, as for a tarball read whole.
//
// CPU (measured in workerd, packages/registry/test/streamed-analysis.workerd.test.ts, and in docs/SCORE.md): the passes
// inflate natively and read headers in a few hundred milliseconds; the import paths of next's 80 MB of JavaScript take
// about a second; the passes, the path check and the plan charge one stream meter (READ.streamWork), and the analysis
// is held to READ.work units, a fifth of the meter a tarball read whole gets, and READ.holdBytes of files.
import { createHash } from "node:crypto";
import {
  ambiguousPaths,
  analyze,
  ENTRY_BYTES,
  firstPass,
  HEAD_BYTES,
  MAX_ANALYSIS_WORK,
  Meter,
  MeterExhausted,
  metered,
  planReading,
  TarballInflater,
  unfinishedAnalysis,
  type Analysis,
  type HoldRule,
  type ListedEntry,
  type LookAt,
  type StreamedTarball,
  type StreamMemory,
  type TarEntry,
} from "@apm/core";
import { Manifest, type Unscorable, type VersionRecord } from "./db.ts";
import type { Digest } from "./digest.ts";
import type { OpenedTarball, UpstreamPackage } from "./upstream.ts";

/** What a streamed read may cost, and what it may hold. */
export type ReadLimits = {
  /** Bytes of files the analysis holds whole, and so reads: its byte budget. */
  readonly holdBytes: number;
  /** Work the analysis may spend (@apm/core's meter). */
  readonly work: number;
  /** Work both passes, the path check and the plan may spend together: inflating, reading headers, import paths, planning. */
  readonly streamWork: number;
  /** The largest compressed tarball read. */
  readonly maxTarballBytes: number;
  /**
   * The most a pass hashes to establish that a tarball is over maxTarballBytes: past maxTarballBytes it stops inflating
   * and only hashes, so a size verdict is stored only for bytes that matched. Past this it cannot check, and asks again.
   */
  readonly maxVerifiedBytes: number;
  /** The most one pass inflates. */
  readonly maxUnpackedBytes: number;
  /** The largest file the first pass gathers to read its imports, and how much it gathers in all. */
  readonly lookFileBytes: number;
  readonly lookTotalBytes: number;
  /** How long a pass may take in all, and may wait for its next chunk. */
  readonly totalMs: number;
  readonly idleMs: number;
};

const MiB = 1024 * 1024;

/**
 * The limits a queued run reads with. holdBytes and work keep a streamed run near half of the Worker's 60 s CPU limit
 * (WORKER_CPU_MS) with both passes. Measured in workerd (streamed-analysis.workerd.test.ts): next 16.4.6 at 6 MiB costs
 * 0.5 to 0.7 of prettier 3.10.1 read whole (28 to 35 s on staging), against 8.6 s here at 8 MiB, which read 30 more
 * files of 8,711 and came to the same signals. A fifth of the meter is 64 million units; a run of a tarball held whole
 * may spend 320 million.
 */
export const READ: ReadLimits = {
  holdBytes: 6 * MiB,
  work: MAX_ANALYSIS_WORK / 5,
  streamWork: MAX_ANALYSIS_WORK / 2,
  maxTarballBytes: 256 * MiB,
  maxVerifiedBytes: 1024 * MiB,
  maxUnpackedBytes: 512 * MiB,
  lookFileBytes: 4 * MiB,
  lookTotalBytes: 160 * MiB,
  totalMs: 5 * 60_000,
  idleMs: 60_000,
};

/** How the run reads, from the runs before it (analysis.ts's planFor): its meter, and a smaller budget for a re-run. */
export type ReadPlan = { readonly maxWork: number; readonly maxScannedBytes?: number; readonly incompleteBecause?: readonly string[] };

/**
 * What a streamed run came to. `scored`, `unscorable` and `failed` are what a run of a tarball held whole comes to.
 * `fetch-failed`: the bytes could not be read or checked, did not match their checksum, or the registry had no memory
 * for them, so nothing was used; `retryable` when asking again may work. `absent`: the upstream no longer lists the
 * version.
 */
export type StreamedAnalysis =
  | { kind: "scored"; analysis: Analysis; spent: boolean }
  | { kind: "unscorable"; unscorable: Unscorable }
  | { kind: "failed"; errorClass: string }
  | { kind: "fetch-failed"; reason: string; retryable: boolean }
  | { kind: "absent" };

/** One pass over the tarball: what it read, once its bytes passed their checksum, or why it read nothing usable. */
type Pass =
  | { kind: "read"; tarball: StreamedTarball }
  | Extract<StreamedAnalysis, { kind: "unscorable" | "fetch-failed" | "absent" }>
  // the archive is one apm does not read, or a pass ran its meter out: known only once its bytes passed their checksum
  | { kind: "refused"; message: string; tooLarge: boolean }
  | { kind: "spent" };

/** Why a second pass is not used: it listed entries the first, verified one did not. */
export const CHANGED_TEXT = "the tarball's second read listed other files than the first";

/** Why a run stopped for the registry's memory, not the package's: it is tried again. */
export const NO_MEMORY_TEXT = "the registry had no memory to spare for this tarball's read";

/** A pass that stopped before its bytes were verified, or for a reason that is not the package's: tried again. */
const retry = (reason: string): Pass => ({ kind: "fetch-failed", reason, retryable: true });

/** "a 43.7 MB tarball", for what a refusal says. */
function sizeText(bytes: number): string {
  return `${(bytes / 1_000_000).toFixed(1)} MB`;
}

const tooLarge = (what: string): Pass => ({ kind: "unscorable", unscorable: { reason: "too-large", detail: what } });

/** `p`, or a fetch failure once `ms` pass without it settling. */
async function within<T>(p: Promise<T>, ms: number, onTimeout: () => void): Promise<{ kind: "ok"; value: T } | { kind: "timeout" }> {
  let timer: ReturnType<typeof setTimeout> | null = null;

  const timeout = new Promise<{ kind: "timeout" }>((resolve) => {
    timer = setTimeout(() => resolve({ kind: "timeout" }), ms);
  });

  try {
    const got = await Promise.race([p.then((value) => ({ kind: "ok", value }) as const), timeout]);

    if (got.kind === "timeout") onTimeout();

    return got;
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
}

/**
 * Reads the tarball once: every byte hashed and counted, and pushed to the inflater until it stops (an archive apm does
 * not read, a spent meter, a refused memory charge, an entry the verified read it is held to did not list), after which
 * the rest is still hashed, so a refusal of bytes that did not match their checksum is a fetch failure, never a verdict
 * on the package. Past maxTarballBytes it stops inflating and only hashes, up to maxVerifiedBytes, so "too large" is
 * stored only for bytes that matched. `expect`: the entries a second pass must find, in order (the first pass's).
 */
async function readPass(args: { open: () => Promise<OpenedTarball>; digest: Digest; hold: HoldRule; look?: LookAt; meter: Meter; memory: StreamMemory; limits: ReadLimits; expect?: readonly ListedEntry[] }): Promise<Pass> {
  const { limits } = args;
  const opened = await args.open();

  switch (opened.kind) {
    case "absent":
      return opened;
    case "unavailable":
      return { kind: "fetch-failed", reason: opened.reason, retryable: opened.retryable };
    case "stream":
      break;
    default: {
      const _exhaustive: never = opened;

      return _exhaustive;
    }
  }

  // the same digest the opener was given: a source that answered for other bytes is refused below like a mismatch
  if (opened.digest.algo !== args.digest.algo || opened.digest.hex !== args.digest.hex) {
    await opened.body.cancel().catch(() => undefined);

    return retry("the tarball was opened for another checksum");
  }

  const declared = opened.length;

  // a length apm cannot check: no verdict, so it is asked again (after the fetch failures analysis.ts allows, the
  // version is recorded unavailable)
  if (declared !== null && declared > limits.maxVerifiedBytes) {
    await opened.body.cancel().catch(() => undefined);

    return retry(`the upstream declares the tarball at ${sizeText(declared)}, more than the ${limits.maxVerifiedBytes / MiB} MiB apm checks`);
  }

  const reader = opened.body.getReader();
  const hash = createHash(args.digest.algo);
  const inflater = new TarballInflater({ hold: args.hold, look: args.look, maxUnpackedBytes: limits.maxUnpackedBytes, meter: args.meter, memory: args.memory, expect: args.expect });
  const deadline = Date.now() + limits.totalMs;
  let seen = 0;
  // past maxTarballBytes nothing more is inflated, only hashed
  let inflating = declared === null || declared <= limits.maxTarballBytes;

  if (!inflating) await inflater.abandon();

  const stop = (): void => {
    reader.cancel().catch(() => undefined);
  };

  for (;;) {
    const wait = Math.min(limits.idleMs, Math.max(0, deadline - Date.now()));
    let next: Awaited<ReturnType<typeof reader.read>>;

    try {
      const got = await within(reader.read(), wait, stop);

      if (got.kind === "timeout") {
        await inflater.abandon();

        return retry("the tarball download stalled or took too long");
      }

      next = got.value;
    } catch {
      await inflater.abandon();

      return retry("the tarball download failed");
    }

    if (next.done) break;
    const chunk = next.value;

    if (chunk.byteLength === 0) continue;
    seen += chunk.byteLength;

    if ((declared !== null && seen > declared) || seen > limits.maxVerifiedBytes) {
      stop();
      await inflater.abandon();

      return retry(seen > limits.maxVerifiedBytes ? `the tarball is larger than the ${limits.maxVerifiedBytes / MiB} MiB apm checks` : "the upstream sent more bytes than it declared");
    }

    hash.update(chunk);

    if (inflating && seen > limits.maxTarballBytes) {
      inflating = false;
      await inflater.abandon();
    }

    if (inflating) await inflater.push(chunk.buffer instanceof ArrayBuffer ? new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength) : chunk.slice());
  }

  const result = inflating ? await inflater.end() : null;
  const verified = (declared === null || seen === declared) && hash.digest("hex") === args.digest.hex;

  // a second read that listed other entries is not used, whatever its hash: it stopped before allocating them
  if (result?.kind === "changed") return retry(CHANGED_TEXT);

  // nothing read is used until every byte has matched: a truncated or tampered stream stores nothing
  if (!verified) return retry("the upstream tarball failed its integrity check");

  // verified bytes over what apm reads: that is a verdict
  if (result === null) return tooLarge(`the tarball (${sizeText(seen)}) is larger than the ${limits.maxTarballBytes / MiB} MiB apm reads`);

  switch (result.kind) {
    case "read":
      return { kind: "read", tarball: result.tarball };
    case "refused":
      return { kind: "refused", message: result.error.message, tooLarge: result.error.kind === "too-large" };
    case "spent":
      return { kind: "spent" };
    case "memory":
      return retry(NO_MEMORY_TEXT);
    default: {
      const _exhaustive: never = result;

      return _exhaustive;
    }
  }
}

/** The tarball's own package.json when it parses as a manifest, else the packument's (as a run of a held tarball does). */
function manifestOf(files: readonly TarEntry[], notHeld: ReadonlySet<TarEntry>, fallback: VersionRecord["manifest"]): VersionRecord["manifest"] {
  const pj = files.find((f) => f.path === "package.json");

  if (!pj || notHeld.has(pj)) return fallback;

  try {
    const parsed = Manifest.safeParse(JSON.parse(new TextDecoder().decode(pj.data)));

    return parsed.success ? parsed.data : fallback;
  } catch {
    return fallback;
  }
}

/** What a read charged for one entry it kept (TarStream: the entry, its path, its kept bytes). */
const chargeOf = (f: TarEntry): number => ENTRY_BYTES + 2 * f.path.length + f.data.length;

/**
 * The read with only `keep` held: every other file it held is cut to its first bytes and counted as not held, and what
 * that lets go is given back to `memory`.
 */
function keepOnly(t: StreamedTarball, keep: ReadonlySet<string>, memory: StreamMemory): StreamedTarball {
  let freed = 0;

  const files = t.files.map((f) => {
    if (t.notHeld.has(f) || keep.has(f.path)) return f;
    const cut = { ...f, data: f.data.slice(0, HEAD_BYTES) };
    freed += f.data.length - cut.data.length;

    return cut;
  });

  memory.give(freed);

  return { files, notHeld: new Set(files.filter((f, i) => f !== t.files[i] || t.notHeld.has(f))), unpackedBytes: t.unpackedBytes, charged: t.charged - freed };
}

/** What a pass that read nothing usable comes to for the run. */
function failedPass(pass: Exclude<Pass, { kind: "read" }>, what: string): StreamedAnalysis {
  switch (pass.kind) {
    case "refused":
      return pass.tooLarge
        ? { kind: "unscorable", unscorable: { reason: "too-large", detail: `the tarball ${pass.message}, the most apm reads as a stream` } }
        : { kind: "unscorable", unscorable: { reason: "unreadable", detail: `the tarball is not one apm can read (${pass.message})` } };
    case "spent":
      return { kind: "unscorable", unscorable: { reason: "too-large", detail: `the tarball is too large for apm to read: ${what} ran past the work it may spend` } };
    case "unscorable":
    case "fetch-failed":
    case "absent":
      return pass;
    default: {
      const _exhaustive: never = pass;

      return _exhaustive;
    }
  }
}

/** What coverage says of a plan made from a cut import graph. */
export const IMPORTS_CUT_TEXT = "this tarball's import graph was larger than apm keeps, so the reading plan may have missed files its code loads";

/**
 * Analyzes a version's tarball as a stream (the file's opening comment says how). `open` opens it again for each pass.
 * Everything the read keeps is charged to `memory` (the run's lease) first. Never throws: an error (a bug, a stack
 * overflow) comes back as `failed` with its class, as for a held tarball.
 */
export async function analyzeStreamedTarball(args: { pkg: UpstreamPackage; v: VersionRecord; digest: Digest; open: () => Promise<OpenedTarball>; plan: ReadPlan; memory: StreamMemory; limits?: ReadLimits }): Promise<StreamedAnalysis> {
  try {
    return await analyzeOrFail(args);
  } catch (e) {
    // the error's class, never its message: a message may quote the package it came from
    return { kind: "failed", errorClass: e instanceof Error ? e.name : "a thrown value that is not an Error" };
  }
}

async function analyzeOrFail({ pkg, v, digest, open, plan, memory, limits = READ }: Parameters<typeof analyzeStreamedTarball>[0]): Promise<StreamedAnalysis> {
  // every analyzed byte is checked against the sha512 dist.integrity; a version with only the legacy sha1 is not read
  if (digest.algo !== "sha512") return { kind: "unscorable", unscorable: { reason: "unavailable", detail: "the upstream publishes no sha512 integrity for this version, which apm needs to read a tarball this large as a stream" } };
  const budget = Math.min(limits.holdBytes, plan.maxScannedBytes ?? limits.holdBytes);
  const streamMeter = new Meter(limits.streamWork);
  const first = firstPass({ holdBytes: budget, lookFileBytes: limits.lookFileBytes, lookTotalBytes: limits.lookTotalBytes, memory });
  const one = await readPass({ open, digest, hold: first.hold, look: first.look, meter: streamMeter, memory, limits });

  if (one.kind !== "read") return failedPass(one, "reading it");
  let tarball = one.tarball;
  const manifest = manifestOf(tarball.files, tarball.notHeld, v.manifest);
  let planned: Set<string> | null;

  // the path check and the plan charge the stream's meter, as the passes do: a package whose exports cost more than
  // the meter has left is an analysis that stopped, and says so
  try {
    const files = tarball.files;

    planned = metered(streamMeter, () => (ambiguousPaths(files).length > 0 ? null : planReading({ manifest, files, imports: first.imports, budget })));
  } catch (e) {
    if (!(e instanceof MeterExhausted)) throw e;

    return { kind: "scored", analysis: unfinishedAnalysis({ name: pkg.name, manifest, files: tarball.files, phase: e.phase, limit: e.limit, because: plan.incompleteBecause }), spent: true };
  }

  // a path twice, or one escaping the folder: tools disagree on what it holds, so it is not scored (as for a held tarball)
  if (planned === null) return { kind: "unscorable", unscorable: { reason: "unreadable", detail: "the tarball holds a path twice or one outside the package folder, so tools disagree on what it installs" } };
  // the tarball's own package.json, which the first pass holds whenever apm reads a manifest that large, is what the
  // plan and the analysis read: it stays held whatever the plan's budget, so it is never reported as not read
  const wanted = new Set([...planned, "package.json"]);
  const importsCut = first.importsCut;
  first.imports.clear();
  // what the first pass held and the plan does not want is let go before anything else is read
  tarball = keepOnly(tarball, wanted, memory);

  // the plan wants files the first pass did not hold: a second pass reads only those, beside what the first kept, held
  // to the first pass's verified entries and to what is left of the budget
  if (tarball.files.some((f) => wanted.has(f.path) && tarball.notHeld.has(f))) {
    const one = tarball;
    const kept = new Map(one.files.filter((f) => !one.notHeld.has(f)).map((f) => [f.path, f]));
    let allowance = budget - [...kept.values()].reduce((n, f) => n + f.size, 0);

    const hold: HoldRule = ({ path, size }) => {
      if (!wanted.has(path) || kept.has(path) || size > allowance) return "head";
      allowance -= size;

      return "hold";
    };

    const two = await readPass({ open, digest, hold, meter: streamMeter, memory, limits, expect: one.files.map((f) => ({ path: f.path, size: f.size, mode: f.mode })) });

    if (two.kind !== "read") return failedPass(two, "reading it again");
    const files = two.tarball.files.map((f) => kept.get(f.path) ?? f);
    // the first pass's entries the merge does not use, and the second's it replaced, are let go
    memory.give(one.files.reduce((n, f) => n + (kept.has(f.path) ? 0 : chargeOf(f)), 0) + two.tarball.files.reduce((n, f) => n + (kept.has(f.path) ? chargeOf(f) : 0), 0));
    tarball = { files, notHeld: new Set(files.filter((f) => two.tarball.notHeld.has(f))), unpackedBytes: two.tarball.unpackedBytes, charged: 0 };
  }

  const earlier = pkg.versions.filter((x) => x.published_at < v.published_at);
  const meter = new Meter(Math.min(plan.maxWork, limits.work));

  const analysis = analyze({
    name: pkg.name,
    manifest,
    files: tarball.files,
    notHeld: tarball.notHeld,
    publisher: v.published_by,
    previousPublishers: [...new Set(earlier.map((x) => x.published_by))],
    maxScannedBytes: budget,
    incompleteBecause: plan.incompleteBecause,
    coverageNotes: importsCut ? [IMPORTS_CUT_TEXT] : [],
    meter,
  });

  return { kind: "scored", analysis, spent: meter.exhausted !== null };
}

/** The most of one file a read for the file view holds from a tarball too large to hold whole. */
export const MAX_STREAMED_FILE_BYTES = 8 * MiB;

/**
 * What a verified streamed read for the file view came to: the entries (only `want` held, when it is within
 * MAX_STREAMED_FILE_BYTES), or the status and words the route answers with.
 */
export type VerifiedRead = { kind: "read"; tarball: StreamedTarball } | { kind: "failed"; status: 404 | 422 | 502; reason: string };

/**
 * One streamed read of a version's tarball that holds only the file at `want`, for the file view: every byte hashed
 * against the sha512 dist.integrity before anything is used, the same pass a streamed analysis makes. Never throws.
 */
export async function readOneFile(args: { open: () => Promise<OpenedTarball>; digest: Digest; want: string | null; memory: StreamMemory; limits?: ReadLimits }): Promise<VerifiedRead> {
  const limits = args.limits ?? READ;

  if (args.digest.algo !== "sha512") return { kind: "failed", status: 422, reason: "this version has no sha512 integrity, which apm needs to read a tarball this large" };

  try {
    const hold: HoldRule = ({ path, size }) => (path === args.want && size <= MAX_STREAMED_FILE_BYTES ? "hold" : "head");
    const pass = await readPass({ open: args.open, digest: args.digest, hold, meter: new Meter(limits.streamWork), memory: args.memory, limits });

    switch (pass.kind) {
      case "read":
        return pass;
      case "absent":
        return { kind: "failed", status: 404, reason: "the upstream registry no longer serves this version's tarball" };
      case "fetch-failed":
        return { kind: "failed", status: 502, reason: pass.reason };
      case "unscorable":
        return { kind: "failed", status: 422, reason: pass.unscorable.detail };
      case "refused":
        return { kind: "failed", status: 422, reason: `apm can't read this version's tarball (${pass.message})` };
      case "spent":
        return { kind: "failed", status: 422, reason: "the tarball is too large for apm to read" };
      default: {
        const _exhaustive: never = pass;

        return _exhaustive;
      }
    }
  } catch (e) {
    return { kind: "failed", status: 502, reason: `the read failed (${e instanceof Error ? e.name : "an error"})` };
  }
}
