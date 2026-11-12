// Scoring upstream versions. A request analyzes a few small tarballs itself, within a per-request budget, and
// sends everything else to the analysis queue, whose consumer does the heavy work one message at a time.
//
// The platform stops a Worker that runs past its CPU limit (limits.cpu_ms, packages/infra), and a stopped run stores
// nothing. In a deployed Worker the clock does not move while code runs, so the analyser's own deadline cannot catch
// that: a run is counted as begun before it starts (startAnalysis), and the next run learns that the one before it never
// finished. That run reads less and is incomplete; the one after it records that the version cannot be scored. A
// version is never left looking queued forever, and never scored clean on a reading that stopped short.
import { Context, Effect, Layer, Ref, Semaphore } from "effect";
import { ambiguousPaths, analyze, ArchiveError, parseAnalysis, readTarball, type Analysis as Scored, type TarEntry } from "@apm/core";
import type { Queue } from "@cloudflare/workers-types";
import { Clock } from "./clock.ts";
import { Manifest, Store, type Unscorable, type VersionRecord } from "./db.ts";
import { QueueError, type BlobError, type StoreError } from "./errors.ts";
import { digestLabel, tooLargeText, Upstream, type Digest, type UpstreamPackage } from "./upstream.ts";
import { timed, timingOrNull } from "./timing.ts";

export type AnalysisJob = { readonly name: string; readonly version: string };

/**
 * What a queued job came to. "stored": scored (now or before). "unscorable": recorded as a version this scorer can
 * never score, and why. "missing": the upstream does not list the version. "retry": the upstream could not be asked,
 * or failed in a way that may pass, so the queue should deliver the job again. "busy": another run of it began less
 * than RUN_WINDOW_MS ago and may still be going, so the job comes back once that run must have ended.
 */
export type JobOutcome = "stored" | "unscorable" | "missing" | "retry" | "busy";

/** Per request: analyze at most this many upstream tarballs inline. */
export const INLINE_ANALYSES = 8;

/** Tarballs larger than this (compressed) always go to the queue. */
export const INLINE_MAX_BYTES = 4 * 1024 * 1024;

/**
 * The most a tarball may inflate to on a Worker. A Worker has 128 MB, and the parser keeps the inflated archive
 * and each entry's bytes, so this stays well under half of it. Larger archives are refused (publish) or recorded as
 * unscorable (upstream), never passed.
 */
export const WORKER_MAX_UNPACKED_BYTES = 48 * 1024 * 1024;

/**
 * The Worker's CPU limit, as packages/infra sets it (limits.cpu_ms): the most Cloudflare allows on the paid plan. One
 * queue message is handled per invocation, so one analysis has all of it.
 */
export const WORKER_CPU_MS = 300_000;

/**
 * The analyser's deadline for a queued version: under a third of the CPU limit, leaving the rest for the download,
 * the unpack (0.07 s for 26 MB), the database writes and a platform CPU slower than the one it was measured on. The
 * slowest corpus package under the caps (three, 20 MB unpacked) takes 5.9 s in workerd.
 */
export const QUEUE_ANALYSIS_MS = 90_000;

/** Per inline analysis: a request runs at most INLINE_ANALYSES of them, 120 s together, under the CPU limit. */
export const INLINE_ANALYSIS_MS = 15_000;

/** A run begun less than this long ago may still be going: the CPU limit, plus the download and the writes. */
export const RUN_WINDOW_MS = 6 * 60_000;

/** A re-run after a stopped one reads at most this much, and says so. */
export const RERUN_SCANNED_BYTES = 4 * 1024 * 1024;

/** The run that records analysis-limit instead of analysing: two runs began and neither stored anything. */
const GIVE_UP_AT_START = 3;

/** A queued version is sent again only after this long without a result. */
const REQUEUE_AFTER_MS = 10 * 60_000;

/** How one analysis run reads: the whole package within a deadline, or a smaller re-run that is marked incomplete. */
export type RunPlan = { maxAnalysisMs: number; maxScannedBytes?: number; incompleteBecause?: readonly string[] };

const RERUN: RunPlan = {
  maxAnalysisMs: QUEUE_ANALYSIS_MS / 3,
  maxScannedBytes: RERUN_SCANNED_BYTES,
  incompleteBecause: [`an earlier analysis of this version was stopped by the platform's CPU limit before it stored anything, so this one read at most ${RERUN_SCANNED_BYTES / (1024 * 1024)} MB`],
};

const LIMIT_HIT: Unscorable = { reason: "analysis-limit", detail: `two analyses of it ran past the registry's ${WORKER_CPU_MS / 60_000}-minute CPU limit and were stopped` };

export type TarballAnalysis = { kind: "scored"; analysis: Scored } | { kind: "unscorable"; unscorable: Unscorable };

/** Runs the scorer over an upstream tarball, or says why these bytes can never be scored. */
export function analyzeUpstreamTarball(pkg: UpstreamPackage, v: VersionRecord, bytes: Uint8Array, plan: RunPlan): TarballAnalysis {
  let files: TarEntry[];

  try {
    files = readTarball(bytes, WORKER_MAX_UNPACKED_BYTES);
  } catch (e) {
    if (e instanceof ArchiveError && e.kind === "too-large") return { kind: "unscorable", unscorable: { reason: "too-large", detail: `the tarball ${e.message}, the most apm unpacks` } };

    return { kind: "unscorable", unscorable: { reason: "unreadable", detail: `the tarball is not one apm can read (${e instanceof Error ? e.message : String(e)})` } };
  }

  // a path twice, or one escaping the folder: tools disagree on what it holds, so it is not scored (analyze refuses it)
  if (ambiguousPaths(files).length > 0) return { kind: "unscorable", unscorable: { reason: "unreadable", detail: "the tarball holds a path twice or one outside the package folder, so tools disagree on what it installs" } };

  const pj = files.find((f) => f.path === "package.json");
  let manifest = v.manifest;

  if (pj) {
    try {
      const parsed = Manifest.safeParse(JSON.parse(new TextDecoder().decode(pj.data)));

      if (parsed.success) manifest = parsed.data;
    } catch {
      // keep the packument manifest
    }
  }

  const earlier = pkg.versions.filter((x) => x.published_at < v.published_at);
  const previousPublishers = [...new Set(earlier.map((x) => x.published_by))];

  return { kind: "scored", analysis: analyze({ name: pkg.name, manifest, files, publisher: v.published_by, previousPublishers, ...plan }) };
}

export type AnalysisApi = {
  /**
   * Makes sure an upstream version has a stored analysis and returns the version with it. Small tarballs are
   * analyzed now while this request's budget lasts; the rest are queued and come back unscored. A version that can
   * never be scored comes back with `unscorable`.
   */
  readonly ensure: (pkg: UpstreamPackage, v: VersionRecord) => Effect.Effect<VersionRecord, StoreError | BlobError>;
  /** Queues a version for analysis unless it is already scored or queued. */
  readonly enqueue: (name: string, version: string) => Effect.Effect<void, StoreError>;
  /** The consumer's work: fetch, verify, analyze and store one version, or record why it cannot be. */
  readonly runJob: (job: AnalysisJob) => Effect.Effect<JobOutcome, StoreError | BlobError>;
};

export class Analysis extends Context.Service<Analysis, AnalysisApi>()("@apm/registry/Analysis") {
  /** No upstream, nothing to score: local versions are scored when they are published. */
  static readonly none = Layer.succeed(
    Analysis,
    Analysis.of({ ensure: (_pkg, v) => Effect.succeed(v), enqueue: () => Effect.void, runJob: () => Effect.succeed<JobOutcome>("missing") }),
  );

  static layer(queue: Queue<AnalysisJob> | null): Layer.Layer<Analysis, never, Store | Upstream | Clock> {
    return Layer.effect(
      Analysis,
      Effect.gen(function* () {
        const store = yield* Store;
        const upstream = yield* Upstream;
        const clock = yield* Clock;
        const budget = yield* Ref.make(INLINE_ANALYSES);
        // One inline download and analysis at a time: a request may look up many packages at once (scan), and
        // each analysis holds a tarball and its inflated files in the Worker's 128 MB.
        const inline = yield* Semaphore.make(1);
        const timeAnalysis = timed(yield* timingOrNull, "analysis");

        const enqueue = (name: string, version: string): Effect.Effect<void, StoreError> =>
          Effect.gen(function* () {
            if (queue === null) return;
            const now = yield* clock.now;
            const claimed = yield* store.claimAnalysisJob(name, version, now, REQUEUE_AFTER_MS);

            if (!claimed) return;
            const job: AnalysisJob = { name, version };
            // a job the queue refused is not on it, so its reservation goes too and the next request queues it again
            yield* Effect.tryPromise({ try: () => queue.send(job), catch: (cause) => new QueueError({ operation: "send", cause }) }).pipe(
              Effect.catchTag("QueueError", (e) =>
                Effect.logWarning("analysis queue send failed", { name, version, cause: String(e.cause) }).pipe(Effect.andThen(store.releaseAnalysisJob(name, version, now))),
              ),
            );
          });

        const markUnscorable = (pkg: UpstreamPackage, v: VersionRecord, unscorable: Unscorable): Effect.Effect<VersionRecord, StoreError> =>
          Effect.gen(function* () {
            yield* store.setUnscorable({ name: pkg.name, version: v.version, unscorable, at: yield* clock.now });
            v.unscorable = unscorable;

            return v;
          });

        /** Analyzes bytes and stores what it came to. A run that fails with an error it reports takes its start back. */
        const analyzeAndStore = (pkg: UpstreamPackage, v: VersionRecord, got: { bytes: Uint8Array; digest: Digest }, plan: RunPlan): Effect.Effect<VersionRecord, StoreError> =>
          Effect.gen(function* () {
            const result = analyzeUpstreamTarball(pkg, v, got.bytes, plan);

            switch (result.kind) {
              case "unscorable":
                return yield* markUnscorable(pkg, v, result.unscorable);
              case "scored":
                yield* store.setUpstreamAnalysis({ name: pkg.name, version: v.version, digest: digestLabel(got.digest), analysis: result.analysis, at: yield* clock.now });
                v.score = result.analysis;

                return v;
              default: {
                const _exhaustive: never = result;

                return _exhaustive;
              }
            }
          }).pipe(Effect.onError(() => store.abandonAnalysis(pkg.name, v.version).pipe(Effect.ignore)));

        /** What a tarball the upstream will never serve in a checkable form, or one too large to fetch, is: recorded. */
        const refused = (got: { kind: "too-large"; bytes: number | null } | { kind: "unavailable"; reason: string }): Unscorable =>
          got.kind === "too-large" ? { reason: "too-large", detail: tooLargeText(got.bytes) } : { reason: "unavailable", detail: got.reason };

        const api: AnalysisApi = {
          ensure: (pkg, v) =>
            Effect.gen(function* () {
              if (parseAnalysis(v.score) || v.unscorable) return v;
              const left = yield* Ref.getAndUpdate(budget, (n) => Math.max(0, n - 1));

              if (left <= 0) {
                yield* enqueue(pkg.name, v.version);

                return v;
              }

              return yield* inline.withPermits(1)(
                timeAnalysis(Effect.gen(function* () {
                  const got = yield* upstream.tarball(pkg, v.version);

                  switch (got.kind) {
                    case "absent":
                      return v;
                    case "too-large":
                      return yield* markUnscorable(pkg, v, refused(got));
                    case "unavailable":
                      return got.retryable ? v : yield* markUnscorable(pkg, v, refused(got));
                    case "ok":
                      break;
                    default: {
                      const _exhaustive: never = got;

                      return _exhaustive;
                    }
                  }

                  if (got.bytes.length > INLINE_MAX_BYTES) {
                    yield* enqueue(pkg.name, v.version);

                    return v;
                  }

                  const starts = yield* store.startAnalysis({ name: pkg.name, version: v.version, now: yield* clock.now, runMs: RUN_WINDOW_MS });

                  // another run may be going, or an earlier one was stopped: the queue's run decides, on its own budget
                  if (starts !== 1) {
                    if (starts !== null) yield* store.abandonAnalysis(pkg.name, v.version);
                    yield* enqueue(pkg.name, v.version);

                    return v;
                  }

                  return yield* analyzeAndStore(pkg, v, got, { maxAnalysisMs: INLINE_ANALYSIS_MS });
                })),
              );
            }),
          enqueue,
          runJob: (job) =>
            Effect.gen(function* (): Effect.fn.Return<JobOutcome, StoreError | BlobError> {
              const probe = yield* upstream.probe(job.name);

              switch (probe.kind) {
                case "unknown":
                  return "retry";
                case "absent":
                  return "missing";
                case "found":
                  break;
                default: {
                  const _exhaustive: never = probe;

                  return _exhaustive;
                }
              }

              const pkg = probe.pkg;
              const v = pkg.versions.find((x) => x.version === job.version);

              if (!v) return "missing";

              if (parseAnalysis(v.score)) return "stored";

              if (v.unscorable) return "unscorable";
              const got = yield* upstream.tarball(pkg, v.version);

              switch (got.kind) {
                case "absent":
                  return "missing";
                case "too-large":
                  yield* markUnscorable(pkg, v, refused(got));

                  return "unscorable";
                case "unavailable":
                  if (got.retryable) return "retry";
                  yield* markUnscorable(pkg, v, refused(got));

                  return "unscorable";
                case "ok":
                  break;
                default: {
                  const _exhaustive: never = got;

                  return _exhaustive;
                }
              }

              const starts = yield* store.startAnalysis({ name: pkg.name, version: v.version, now: yield* clock.now, runMs: RUN_WINDOW_MS });

              if (starts === null) return "busy";

              if (starts >= GIVE_UP_AT_START) {
                yield* markUnscorable(pkg, v, LIMIT_HIT);

                return "unscorable";
              }

              const stored = yield* analyzeAndStore(pkg, v, got, starts === 1 ? { maxAnalysisMs: QUEUE_ANALYSIS_MS } : RERUN);

              return stored.unscorable ? "unscorable" : "stored";
            }),
        };

        return Analysis.of(api);
      }),
    );
  }
}
