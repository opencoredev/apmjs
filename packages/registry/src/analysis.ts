// Scoring upstream versions. An anonymous request never analyses anything: a version with no stored analysis is queued,
// and the answer says so. A signed-in or token caller's request analyses at most INLINE_ANALYSES small tarballs
// itself, each under a quarter of the work meter; everything else goes to the analysis queue, whose consumer runs one
// analysis per invocation under the whole meter.
//
// Every analysis is bounded by counted work (the meter in @apm/core), not by time: in a deployed Worker the clock does
// not move while code runs. The meter is sized so a full one stays under 25 s of CPU, inside the default 30 s limit.
// Should the platform stop a run anyway, a record of it exists before it starts (startAnalysis), and the cron sweep
// (recover) requeues every run that began and never ended. The next run reads less and is incomplete; the one after it
// records that the version cannot be scored. A version is never left looking queued forever, and never scored clean
// on a reading that stopped short.
import { Context, Effect, Layer, Ref, Semaphore } from "effect";
import { ambiguousPaths, analyze, ArchiveError, MAX_ANALYSIS_WORK, Meter, MeterExhausted, parseAnalysis, readTarball, unfinishedAnalysis, type Analysis as Scored, type TarEntry } from "@apm/core";
import { Clock } from "./clock.ts";
import { Manifest, Store, type Unscorable, type VersionRecord } from "./db.ts";
import { QueueError, type BlobError, type StoreError } from "./errors.ts";
import { digestLabel, tooLargeText, Upstream, type Digest, type UpstreamPackage } from "./upstream.ts";
import { timed, timingOrNull } from "./timing.ts";

export type AnalysisJob = { readonly name: string; readonly version: string };

/** What the analysis needs of the queue's producer binding: sending one job. A `Queue<AnalysisJob>` is one. */
export type AnalysisQueue = { readonly send: (job: AnalysisJob) => Promise<object | void> };

/**
 * What a queued job came to. "stored": scored (now or before). "unscorable": recorded as a version this scorer can
 * never score, and why. "missing": the upstream does not list the version. "retry": the upstream could not be asked,
 * or failed in a way that may pass, so the queue should deliver the job again. "busy": another run of it began less
 * than RUN_WINDOW_MS ago and may still be going, so the job comes back once that run must have ended.
 */
export type JobOutcome = "stored" | "unscorable" | "missing" | "retry" | "busy";

/** Per request from a signed-in or token caller: analyze at most this many upstream tarballs inline. Anonymous: none. */
export const INLINE_ANALYSES = 2;

/** Tarballs larger than this (compressed) always go to the queue. */
export const INLINE_MAX_BYTES = 4 * 1024 * 1024;

/**
 * The most a tarball may inflate to on a Worker. A Worker has 128 MB, and the parser keeps the inflated archive
 * and each entry's bytes, so this stays well under half of it. Larger archives are refused (publish) or recorded as
 * unscorable (upstream), never passed.
 */
export const WORKER_MAX_UNPACKED_BYTES = 48 * 1024 * 1024;

/**
 * The CPU limit the analysis is sized for: Cloudflare's default per invocation. packages/infra may set a higher one
 * (limits.cpu_ms); nothing here depends on it. One queue message is handled per invocation.
 */
export const WORKER_CPU_MS = 30_000;

/**
 * Work one queued analysis may spend, the unpack included: the whole meter. A full meter is about 17 s of CPU at the
 * most expensive unit measured (docs/SCORE.md), under the 25 s that leaves room for the download and the writes.
 */
export const QUEUE_WORK = MAX_ANALYSIS_WORK;

/** Per inline analysis: a quarter of the meter, so the INLINE_ANALYSES a request may run stay under half of it. */
export const INLINE_WORK = MAX_ANALYSIS_WORK / 4;

/** A run begun less than this long ago may still be going: a full meter's CPU, plus the download and the writes. */
export const RUN_WINDOW_MS = 6 * 60_000;

/** At most this many unfinished runs are requeued per sweep; the rest wait for the next one. */
const RECOVER_PER_SWEEP = 200;

/** A re-run after a stopped one reads at most this much, and says so. */
export const RERUN_SCANNED_BYTES = 4 * 1024 * 1024;

/** The run that records analysis-limit instead of analysing: two runs began and neither stored anything. */
const GIVE_UP_AT_START = 3;

/** A queued version is sent again only after this long without a result. */
const REQUEUE_AFTER_MS = 10 * 60_000;

/** How one analysis run reads: the whole package under a meter, or a smaller re-run that is marked incomplete. */
export type RunPlan = { maxWork: number; maxScannedBytes?: number; incompleteBecause?: readonly string[] };

const RERUN: RunPlan = {
  maxWork: MAX_ANALYSIS_WORK / 4,
  maxScannedBytes: RERUN_SCANNED_BYTES,
  incompleteBecause: [`an earlier analysis of this version was stopped by the platform's CPU limit before it stored anything, so this one read at most ${RERUN_SCANNED_BYTES / (1024 * 1024)} MB`],
};

const LIMIT_HIT: Unscorable = { reason: "analysis-limit", detail: "two analyses of it were stopped by the platform before they finished, so the registry stopped trying" };

/**
 * What one run came to. `scored` with `spent` when the meter ran out, the unpack or the analysis: the analysis is then
 * `incomplete`, naming the phase. An inline run that spends its quarter of the meter is not stored; the queue's run,
 * with the whole meter, decides.
 */
export type TarballAnalysis = { kind: "scored"; analysis: Scored; spent: boolean } | { kind: "unscorable"; unscorable: Unscorable };

/** Runs the scorer over an upstream tarball under one meter, unpack included, or says why these bytes can never be scored. */
export function analyzeUpstreamTarball(pkg: UpstreamPackage, v: VersionRecord, bytes: Uint8Array, plan: RunPlan): TarballAnalysis {
  const meter = new Meter(plan.maxWork);
  let files: TarEntry[];

  try {
    files = readTarball(bytes, WORKER_MAX_UNPACKED_BYTES, meter);
  } catch (e) {
    if (e instanceof MeterExhausted) {
      return { kind: "scored", analysis: unfinishedAnalysis({ name: pkg.name, manifest: v.manifest, files: [], phase: e.phase, limit: e.limit, because: plan.incompleteBecause }), spent: true };
    }

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

  const analysis = analyze({ name: pkg.name, manifest, files, publisher: v.published_by, previousPublishers, maxScannedBytes: plan.maxScannedBytes, incompleteBecause: plan.incompleteBecause, meter });

  return { kind: "scored", analysis, spent: meter.exhausted !== null };
}

export type AnalysisApi = {
  /**
   * Makes sure an upstream version has a stored analysis and returns the version with it. For a caller this request
   * let analyse inline (`allowInline`), small tarballs are analyzed now while its budget lasts; everything else is
   * queued and comes back unscored. A version that can never be scored comes back with `unscorable`.
   */
  readonly ensure: (pkg: UpstreamPackage, v: VersionRecord) => Effect.Effect<VersionRecord, StoreError | BlobError>;
  /**
   * Lets this request analyse up to INLINE_ANALYSES versions inline, when `signedIn` says the caller is signed in or
   * sent a token. It is asked only when an analysis would run. Without this call, every analysis is queued.
   */
  readonly allowInline: (signedIn: Effect.Effect<boolean>) => Effect.Effect<void>;
  /**
   * The cron sweep's half: requeues every run that began at least RUN_WINDOW_MS ago and never stored anything (the
   * platform stopped it). The queue's next run of it reads less and is incomplete, and the one after records the
   * version as one that cannot be scored. Returns how many it requeued.
   */
  readonly recover: Effect.Effect<number, StoreError | BlobError>;
  /** Queues a version for analysis unless it is already scored or queued. */
  readonly enqueue: (name: string, version: string) => Effect.Effect<void, StoreError>;
  /** The consumer's work: fetch, verify, analyze and store one version, or record why it cannot be. */
  readonly runJob: (job: AnalysisJob) => Effect.Effect<JobOutcome, StoreError | BlobError>;
};

export class Analysis extends Context.Service<Analysis, AnalysisApi>()("@apm/registry/Analysis") {
  /** No upstream, nothing to score: local versions are scored when they are published. */
  static readonly none = Layer.succeed(
    Analysis,
    Analysis.of({ ensure: (_pkg, v) => Effect.succeed(v), allowInline: () => Effect.void, enqueue: () => Effect.void, runJob: () => Effect.succeed<JobOutcome>("missing"), recover: Effect.succeed(0) }),
  );

  /** `queue`: the analysis queue's producer, or null for a registry with none. */
  static layer(queue: AnalysisQueue | null): Layer.Layer<Analysis, never, Store | Upstream | Clock> {
    return Layer.effect(
      Analysis,
      Effect.gen(function* () {
        const store = yield* Store;
        const upstream = yield* Upstream;
        const clock = yield* Clock;
        // nothing inline until the request says its caller is signed in; then up to INLINE_ANALYSES
        const budget = yield* Ref.make(0);
        const signedIn = yield* Ref.make<Effect.Effect<boolean> | null>(null);
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

        /**
         * Analyzes bytes and stores what it came to. A run that fails with an error it reports takes its start back. An
         * inline run that spends its share of the meter stores nothing: it takes its start back and queues the version,
         * whose queued run has the whole meter.
         */
        const analyzeAndStore = (pkg: UpstreamPackage, v: VersionRecord, got: { bytes: Uint8Array; digest: Digest }, plan: RunPlan, run: "inline" | "queued"): Effect.Effect<VersionRecord, StoreError> =>
          Effect.gen(function* () {
            const result = analyzeUpstreamTarball(pkg, v, got.bytes, plan);

            switch (result.kind) {
              case "unscorable":
                return yield* markUnscorable(pkg, v, result.unscorable);
              case "scored":
                if (result.spent && run === "inline") {
                  yield* store.abandonAnalysis(pkg.name, v.version);
                  yield* enqueue(pkg.name, v.version);

                  return v;
                }

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

        /** Whether this request may analyse one more version inline: its caller is signed in and its budget lasts. */
        const mayInline = Effect.gen(function* () {
          const check = yield* Ref.get(signedIn);

          if (check === null) return false;
          // asked once per request, when the first analysis would run
          const ok = yield* check;

          yield* Ref.set(signedIn, Effect.succeed(ok));

          if (!ok) return false;

          return (yield* Ref.getAndUpdate(budget, (n) => Math.max(0, n - 1))) > 0;
        });

        const runJob = (job: AnalysisJob): Effect.Effect<JobOutcome, StoreError | BlobError> =>
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

            // the record of this run, before anything is analysed: a run the platform stops leaves it for the sweep
            const starts = yield* store.startAnalysis({ name: pkg.name, version: v.version, now: yield* clock.now, runMs: RUN_WINDOW_MS });

            if (starts === null) return "busy";

            if (starts >= GIVE_UP_AT_START) {
              yield* markUnscorable(pkg, v, LIMIT_HIT);

              return "unscorable";
            }

            const stored = yield* analyzeAndStore(pkg, v, got, starts === 1 ? { maxWork: QUEUE_WORK } : RERUN, "queued");

            return stored.unscorable ? "unscorable" : "stored";
          });

        const api: AnalysisApi = {
          allowInline: (check) => Ref.set(signedIn, check).pipe(Effect.andThen(Ref.set(budget, INLINE_ANALYSES))),
          recover: Effect.gen(function* () {
            const now = yield* clock.now;
            const runs = yield* store.unfinishedAnalyses({ before: now - RUN_WINDOW_MS, limit: RECOVER_PER_SWEEP });

            // with no queue (a local registry), the sweep runs the job itself, under the same meter
            for (const r of runs) {
              if (queue === null) yield* runJob(r);
              else yield* enqueue(r.name, r.version);
            }

            return runs.length;
          }),
          ensure: (pkg, v) =>
            Effect.gen(function* () {
              if (parseAnalysis(v.score) || v.unscorable) return v;

              // anonymous, or past this request's budget: queued, and the answer says so
              if (!(yield* mayInline)) {
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

                  // the record of this run, before anything is analysed: a run the platform stops leaves it for the sweep
                  const starts = yield* store.startAnalysis({ name: pkg.name, version: v.version, now: yield* clock.now, runMs: RUN_WINDOW_MS });

                  // another run may be going, or an earlier one was stopped: the queue's run decides, on its own budget
                  if (starts !== 1) {
                    if (starts !== null) yield* store.abandonAnalysis(pkg.name, v.version);
                    yield* enqueue(pkg.name, v.version);

                    return v;
                  }

                  return yield* analyzeAndStore(pkg, v, got, { maxWork: INLINE_WORK }, "inline");
                })),
              );
            }),
          enqueue,
          runJob,
        };

        return Analysis.of(api);
      }),
    );
  }
}
