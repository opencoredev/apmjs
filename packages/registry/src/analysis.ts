// Scoring upstream versions. A request never analyses anything, whoever sends it: a version with no stored analysis is
// queued, and the answer says so (callers that wait, such as resolve, poll the store). The analysis queue's consumer
// runs one analysis per invocation under the whole meter, and records each run before it asks the upstream anything,
// so every attempt leaves a record (review of 5b5b492, finding 3: an inline run downloaded first and recorded later,
// so a run stopped inside the download left nothing behind). A registry with no queue records the job all the same,
// and its cron sweep runs it.
//
// Every analysis is metered by counted work (the meter in @apm/core), not by time: in a deployed Worker the clock does
// not move while code runs. The meter is not a proof: work it misses is stopped by the Worker's CPU limit
// (WORKER_CPU_MS, which packages/infra sets), and what follows makes every way a run can end store an outcome. A queued run records its start before it does
// anything, the upstream included (startAnalysis), and decides whether to stop trying before it downloads anything. The
// cron sweep (recover) requeues every run that began and never ended, and every job the queue accepted that never began
// one. Why the platform ended such a run (its CPU limit, its memory limit, a deploy) is not something the run can
// know, so recovery does not ask: a run that began and stored nothing is run again in full, and only after
// STOPS_BEFORE_RERUN of them does the next read less and store an incomplete analysis; if that one is stopped too the
// version is recorded as one that cannot be scored (planFor). On production, 13 Nov, seven runs sharing one isolate
// were ended by its memory limit, and the next delivery of each was the smaller re-run: five versions that need a
// second or less of CPU stored 39. The queue consumer now runs one invocation at a time (packages/infra,
// maxConcurrency 1), so analyses no longer share an isolate's memory. A run that fails with an error (a stack overflow, say) keeps its start counted too, and after MAX_FAILED_RUNS
// such runs the version is stored as incomplete, naming the error's class. A run that cannot fetch the version keeps
// its start and counts a fetch failure, and after MAX_FETCH_FAILURES of them the version is settled as unavailable, as
// is one the upstream no longer lists. A version is never left looking queued forever, and never scored clean on a
// reading that stopped short.
//
// A tarball too large to download or unpack whole (MAX_UPSTREAM_TARBALL_BYTES, WORKER_MAX_UNPACKED_BYTES) is read as a
// stream in the same run (streamed-analysis.ts), which checks every byte against the version's sha512 before it uses
// any. What a registry before apm-score-v11 refused for those caps decides nothing for this scorer: outcomes, like
// analyses, are kept per scorer.
import { RequestMemory } from "./memory.ts";
import { Context, Duration, Effect, Layer } from "effect";
import { ambiguousPaths, analyze, ArchiveError, failedAnalysis, MAX_ANALYSIS_WORK, Meter, MeterExhausted, parseAnalysis, readTarball, unfinishedAnalysis, type Analysis as Scored, type TarEntry } from "@apm/core";
import { Clock } from "./clock.ts";
import { Manifest, Store, type AnalysisStart, type RunHistory, type Unscorable, type VersionRecord } from "./db.ts";
import { isWithheld } from "./withheld.ts";
import { SEED_INTAKE_MAX, SEED_INTAKE_WINDOW_MS } from "./seeding.ts";
import { QueueError, type BlobError, type StoreError } from "./errors.ts";
import { digestLabel, digestOf, Upstream, type Digest, type UpstreamPackage } from "./upstream.ts";
import { timed, timingOrNull } from "./timing.ts";
import { analyzeStreamedTarball, type StreamedAnalysis } from "./streamed-analysis.ts";
import { WORKER_CPU_MS } from "../scripts/compat.ts";

export type AnalysisJob = { readonly name: string; readonly version: string };

/** What the analysis needs of the queue's producer binding: sending one job. A `Queue<AnalysisJob>` is one. */
export type AnalysisQueue = { readonly send: (job: AnalysisJob) => Promise<object | void> };

/**
 * What a queued job came to. "stored": scored (now or before), or stored as incomplete after MAX_FAILED_RUNS failed
 * runs. "unscorable": recorded as a version this scorer can never score, and why. "missing": the upstream does not
 * list the version, which is settled as unavailable. "retry": the upstream could not be asked, failed in a way that may
 * pass, or the run failed with an error it has retries left for, so the queue should deliver the job again. "busy": another run of it began less
 * than RUN_WINDOW_MS ago and may still be going, so the job comes back once that run must have ended.
 */
export type JobOutcome = "stored" | "unscorable" | "missing" | "retry" | "busy";

/** What analyzeAndStore came to: stored (scored, or failed past its retries), unscorable, or to be run again. */
type Stored = { kind: "stored" | "unscorable" | "retry"; v: VersionRecord };

/**
 * The most a tarball may inflate to when it is read whole on a Worker. A Worker has 128 MB, and the parser keeps the
 * inflated archive and each entry's bytes, so this stays well under half of it. Larger archives are refused (publish)
 * or read as a stream (upstream, streamed-analysis.ts), never passed.
 */
export const WORKER_MAX_UNPACKED_BYTES = 48 * 1024 * 1024;

/** The CPU limit per invocation, which packages/infra sets on the Worker. One queue message is handled per invocation. */
export { WORKER_CPU_MS };

/**
 * Work one queued analysis may spend, the unpack included: the whole meter, about 60 to 70 s of a Worker's CPU at the
 * units measured on staging (prettier 3.9.10: 160 million units, 31 s), past WORKER_CPU_MS (docs/SCORE.md). A run that
 * costs more is stopped by the platform, and the sweep recovers it.
 */
export const QUEUE_WORK = MAX_ANALYSIS_WORK;

/** A run begun less than this long ago may still be going: the Worker's whole CPU limit, plus the download and the writes. */
export const RUN_WINDOW_MS = WORKER_CPU_MS + 2 * 60_000;

/** At most this many jobs are requeued per sweep, unfinished runs and accepted jobs together; the rest wait for the next one. */
export const RECOVER_PER_SWEEP = 200;

/**
 * Work a sweep queues that nobody is waiting for (enqueueBackground): the cron's seeding. The queue runs one analysis
 * at a time; on production (18 Nov, read-only) a run took 1.0 s on average (p99 4.9 s, the longest 17.8 s), and the
 * queue stored 622 to 1,217 an hour when it had a backlog. So a sweep sends at most BACKGROUND_PER_SWEEP of them, about
 * a minute of the queue's work, each at once: a delay recorded apart from its claim let a user's ask in between find
 * the job reserved and send nothing (review of 8f4ced8, P2), and a user's ask is always sent at once.
 */
export const BACKGROUND_PER_SWEEP = 48;

/**
 * Of a sweep's RECOVER_PER_SWEEP, the room kept for accepted jobs that never began a run; the rest is for runs that
 * began and never ended. Either kind takes what the other leaves unused.
 */
export const RECOVER_ACCEPTED_SHARE = RECOVER_PER_SWEEP / 2;

/** The smaller re-run, after STOPS_BEFORE_RERUN stopped runs, reads at most this much, and says so. */
export const RERUN_SCANNED_BYTES = 4 * 1024 * 1024;

/**
 * Runs of a version that began and stored nothing before the next one reads less: the first run and one full re-run.
 * A stop is not always the package's cost (a deploy, or before maxConcurrency 1 the memory limit of an isolate it
 * shared), so one stop alone does not reduce the reading. After this many the next run reads less, and if that one is
 * stopped too the version is recorded as one that cannot be scored.
 */
export const STOPS_BEFORE_RERUN = 2;

/**
 * A version is settled as unavailable once at least MAX_FETCH_FAILURES runs ended unable to fetch it (the upstream
 * could not be asked, or would not serve the tarball yet) and FETCH_GIVE_UP_MS have passed since the first did: both,
 * so neither a burst of quick queue retries nor one slow retry ends it, and an outage shorter than an hour never does.
 */
export const MAX_FETCH_FAILURES = 10;

export const FETCH_GIVE_UP_MS = 60 * 60_000;

/** Times a result's write is tried again after a store error before the run is handed back. */
export const STORE_RETRIES = 2;

/** Runs that may fail with an error before the version is stored as incomplete, naming the error's class. */
export const MAX_FAILED_RUNS = 2;

/** A queued version is sent again only after this long without a result. */
export const REQUEUE_AFTER_MS = 10 * 60_000;

/**
 * How long a caller waits for a queue send. A send with no answer by then may still land, so its reservation stays: the
 * cron sweep (recover) sends the version again once REQUEUE_AFTER_MS pass with no run begun. A send that did land
 * leaves the job on the queue twice, and the second delivery finds the run taken (startAnalysis) and stores nothing.
 */
export const QUEUE_SEND_TIMEOUT_MS = 4_000;

/**
 * Versions published this recently are queued once someone looks at their package, whichever dist-tag names them: a
 * prerelease line (typescript's daily 7.1.0-dev builds under `next`, next's canaries) is never `latest`, and before
 * this nothing queued it until someone asked for that exact version, so the package page showed a week of them as
 * "n/a" (18 Nov 2026).
 */
export const RECENT_SEED_MS = 7 * 24 * 60 * 60_000;

/** At most this many versions besides `latest` are queued for one look at a package (versionsToSeed). */
export const SEED_PER_PACKAGE = 8;

/** A version as versionsToSeed reads it. */
export type SeedCandidate = Pick<VersionRecord, "version" | "published_at" | "status">;

/**
 * The versions of an upstream package to queue when someone looks at it, besides `latest` (which ensure queues): each
 * version a dist-tag names and each published in the last RECENT_SEED_MS, newest first, at most `limit`
 * (SEED_PER_PACKAGE), and only those not withheld that `done` says have no result yet (a score, or a decision that it
 * cannot be scored). Pure.
 */
export function versionsToSeed<V extends SeedCandidate>(input: { versions: readonly V[]; distTags: Readonly<Record<string, string>>; now: number; done: (v: V) => boolean; limit?: number }): string[] {
  const tagged = new Set(Object.values(input.distTags));
  const latest = input.distTags.latest;

  return input.versions
    .filter((v) => v.version !== latest && (tagged.has(v.version) || v.published_at >= input.now - RECENT_SEED_MS))
    .filter((v) => !isWithheld(v.status) && !input.done(v))
    .toSorted((a, b) => b.published_at - a.published_at)
    .slice(0, input.limit ?? SEED_PER_PACKAGE)
    .map((v) => v.version);
}

/** Whether a version as a read carries it has a result: a score (any scorer's the store returned) or an outcome. */
export const hasResult = (v: Pick<VersionRecord, "score" | "unscorable">): boolean => v.unscorable !== undefined || parseAnalysis(v.score) !== null;

/** What a queue send came to: taken, refused by the queue, or no answer in QUEUE_SEND_TIMEOUT_MS (it may yet land). */
type SendOutcome = { readonly kind: "sent" } | { readonly kind: "refused"; readonly cause: unknown } | { readonly kind: "unanswered" };

/** How one analysis run reads: the whole package under a meter, or a smaller re-run that is marked incomplete. */
export type RunPlan = { maxWork: number; maxScannedBytes?: number; incompleteBecause?: readonly string[] };

const FULL: RunPlan = { maxWork: QUEUE_WORK };

const rerun = (because: string): RunPlan => ({ maxWork: MAX_ANALYSIS_WORK / 4, maxScannedBytes: RERUN_SCANNED_BYTES, incompleteBecause: [`${because}, so this one read at most ${RERUN_SCANNED_BYTES / (1024 * 1024)} MB`] });

/** What the next run of a version does, from the runs before it: analyse in full, read less, or record that it cannot be scored. */
export type NextRun = { kind: "analyse"; plan: RunPlan } | { kind: "give-up"; unscorable: Unscorable };

/**
 * The next run's plan, from the runs before it. A run that could not fetch the version or failed with an error it
 * reported ended: it is not a stop. So the run just after one that reported runs in full, whatever stopped the runs
 * before that (MAX_FAILED_RUNS and MAX_FETCH_FAILURES decide what follows those). After a stop, the next runs in full
 * until STOPS_BEFORE_RERUN runs have stopped, then reads less; and past that many stops in all the version is
 * recorded as one that cannot be scored, which bounds the stops whatever came between them.
 */
export function planFor(history: RunHistory): NextRun {
  // the runs begun before this one that never ended: no result, no reported error, no fetch failure
  const stopped = Math.max(0, history.starts - 1 - history.fetchFailures - history.failures);

  if (stopped > STOPS_BEFORE_RERUN) {
    return { kind: "give-up", unscorable: { reason: "analysis-limit", detail: `${stopped} analyses of it were stopped by the platform before they finished, so the registry stopped trying` } };
  }

  // the run just before this one reported how it ended (review of 89441a9, finding 5)
  if (history.reportedStart !== null && history.reportedStart === history.starts - 1) return { kind: "analyse", plan: FULL };

  if (stopped === STOPS_BEFORE_RERUN) return { kind: "analyse", plan: rerun(`${stopped} earlier analyses of this version were stopped by the platform before they stored anything`) };

  return { kind: "analyse", plan: FULL };
}

const FETCH_GAVE_UP: Unscorable = { reason: "unavailable", detail: `the upstream registry could not be asked for it, would not serve its tarball, or the registry could not store the result, in ${MAX_FETCH_FAILURES} or more tries over an hour, so the registry stopped trying` };

/** What a queued version the upstream no longer serves is settled as, so the sweep never picks it again. */
const GONE: Record<"package" | "version" | "tarball", Unscorable> = {
  package: { reason: "unavailable", detail: "the upstream registry no longer has this package" },
  version: { reason: "unavailable", detail: "the upstream registry no longer lists this version" },
  tarball: { reason: "unavailable", detail: "the upstream registry no longer serves this version's tarball" },
};

/**
 * What one run came to. `scored` with `spent` when the meter ran out, the unpack or the analysis: the analysis is then
 * `incomplete`, naming the phase. `stream`: the tarball inflates past WORKER_MAX_UNPACKED_BYTES, so it is read again as
 * a stream (streamed-analysis.ts) instead of whole.
 */
export type TarballAnalysis = { kind: "scored"; analysis: Scored; spent: boolean } | { kind: "unscorable"; unscorable: Unscorable } | { kind: "failed"; errorClass: string } | { kind: "stream" };

/**
 * Runs the scorer over an upstream tarball under one meter, unpack included, or says why these bytes can never be
 * scored. Any other throw (a stack overflow, a bug) comes back as `failed` with the error's class, never as a pass.
 */
export function analyzeUpstreamTarball(pkg: UpstreamPackage, v: VersionRecord, bytes: Uint8Array, plan: RunPlan): TarballAnalysis {
  try {
    return analyzeOrThrow(pkg, v, bytes, plan);
  } catch (e) {
    // the error's class, never its message: a message may quote the package it came from
    return { kind: "failed", errorClass: e instanceof Error ? e.name : "a thrown value that is not an Error" };
  }
}

function analyzeOrThrow(pkg: UpstreamPackage, v: VersionRecord, bytes: Uint8Array, plan: RunPlan): TarballAnalysis {
  const meter = new Meter(plan.maxWork);
  let files: TarEntry[];

  try {
    files = readTarball(bytes, WORKER_MAX_UNPACKED_BYTES, meter);
  } catch (e) {
    if (e instanceof MeterExhausted) {
      return { kind: "scored", analysis: unfinishedAnalysis({ name: pkg.name, manifest: v.manifest, files: [], phase: e.phase, limit: e.limit, because: plan.incompleteBecause }), spent: true };
    }

    // too large to unpack whole (the gzip trailer says so before anything is inflated): read as a stream instead
    if (e instanceof ArchiveError && e.kind === "too-large") return { kind: "stream" };

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
   * The version as stored: with its analysis, or `unscorable` for one this scorer can never score. One with neither is
   * queued (unless it was queued less than REQUEUE_AFTER_MS ago) and comes back unscored; nothing is analysed here.
   */
  readonly ensure: (pkg: Pick<UpstreamPackage, "name">, v: VersionRecord) => Effect.Effect<VersionRecord, StoreError | BlobError>;
  /**
   * The cron sweep's half: requeues every run that began at least RUN_WINDOW_MS ago and never stored anything (the
   * platform stopped it). How the queue's next run of it reads depends on how many runs before it stored nothing (planFor). Returns how many
   * it requeued.
   */
  readonly recover: Effect.Effect<number, StoreError | BlobError, RequestMemory>;
  /**
   * Queues a version for analysis unless it is already scored or queued. True when it is on the queue now (or recorded
   * for the sweep, with no queue); false when the queue refused it (its reservation goes) or did not answer in
   * QUEUE_SEND_TIMEOUT_MS (its reservation stays, for the sweep).
   */
  readonly enqueue: (name: string, version: string) => Effect.Effect<boolean, StoreError>;
  /**
   * Several versions of one package queued for a page's seeding, claimed in one statement under the global bound (SEED_INTAKE_MAX in SEED_INTAKE_WINDOW_MS): claims and sends
   * nothing when the queue took that many jobs lately. How many it sent.
   */
  readonly admitSeeds: (name: string, versions: readonly string[]) => Effect.Effect<number, StoreError>;
  /**
   * Several versions of one package queued as work nobody waits for (a sweep's): within this service's
   * BACKGROUND_PER_SWEEP (the sweep builds this service once), each claimed version sent at once. How many it claimed;
   * none once the sweep's room is spent.
   */
  readonly enqueueBackground: (name: string, versions: readonly string[]) => Effect.Effect<number, StoreError>;
  /**
   * The consumer's work: fetch, verify, analyze and store one version, or record why it cannot be. The packument is
   * read under the run's lease (RequestMemory).
   */
  readonly runJob: (job: AnalysisJob) => Effect.Effect<JobOutcome, StoreError | BlobError, RequestMemory>;
};

export class Analysis extends Context.Service<Analysis, AnalysisApi>()("@apm/registry/Analysis") {
  /** No upstream, nothing to score: local versions are scored when they are published. */
  static readonly none = Layer.succeed(
    Analysis,
    Analysis.of({ ensure: (_pkg, v) => Effect.succeed(v), enqueue: () => Effect.succeed(true), admitSeeds: () => Effect.succeed(0), enqueueBackground: () => Effect.succeed(0), runJob: () => Effect.succeed<JobOutcome>("missing"), recover: Effect.succeed(0) }),
  );

  /** `queue`: the analysis queue's producer, or null for a registry with none. */
  static layer(queue: AnalysisQueue | null): Layer.Layer<Analysis, never, Store | Upstream | Clock> {
    return Layer.effect(
      Analysis,
      Effect.gen(function* () {
        const store = yield* Store;
        const upstream = yield* Upstream;
        const clock = yield* Clock;
        const timeAnalysis = timed(yield* timingOrNull, "analysis");

        /**
         * Sends a job this request claimed (claimAnalysisJob) at `claimedAt`. True when it is on the queue now. A refusal
         * drops the reservation, so the next request queues it again; no answer keeps it, for the sweep.
         */
        const send = (q: AnalysisQueue, name: string, version: string, claimedAt: number): Effect.Effect<boolean, StoreError> =>
          Effect.gen(function* () {
            const job: AnalysisJob = { name, version };

            const sent = yield* Effect.tryPromise({ try: () => q.send(job), catch: (cause) => new QueueError({ operation: "send", cause }) }).pipe(
              Effect.as<SendOutcome>({ kind: "sent" }),
              Effect.catchTag("QueueError", (e) => Effect.succeed<SendOutcome>({ kind: "refused", cause: e.cause })),
              Effect.timeoutOrElse({ duration: Duration.millis(QUEUE_SEND_TIMEOUT_MS), orElse: () => Effect.succeed<SendOutcome>({ kind: "unanswered" }) }),
            );

            switch (sent.kind) {
              case "sent":
                return true;
              // the queue said no: the job is not on it, so its reservation goes and the next request queues it again
              case "refused":
                yield* Effect.logWarning("analysis queue send refused", { name, version, cause: String(sent.cause) });
                yield* store.releaseAnalysisJob(name, version, claimedAt);

                return false;
              // no answer: the job may be on the queue or not, so the reservation stays and the sweep sends it again
              // if no run begins (a second delivery of a job that was on it finds its run taken)
              case "unanswered":
                yield* Effect.logWarning("analysis queue send unanswered", { name, version, waitedMs: QUEUE_SEND_TIMEOUT_MS });

                return false;
              default: {
                const _exhaustive: never = sent;

                return _exhaustive;
              }
            }
          });

        /**
         * Queues a version unless it was queued less than REQUEUE_AFTER_MS ago. True when it is on the queue now. With no
         * queue the job is recorded all the same (analysis_jobs), and the cron sweep runs it once REQUEUE_AFTER_MS pass.
         */
        const enqueue = (name: string, version: string): Effect.Effect<boolean, StoreError> =>
          Effect.gen(function* () {
            const now = yield* clock.now;
            const claimed = yield* store.claimAnalysisJob(name, version, now, REQUEUE_AFTER_MS);

            // claimed by an earlier request, whose job is on the queue
            if (!claimed || queue === null) return true;

            return yield* send(queue, name, version, now);
          });

        // how many background jobs this sweep has queued
        let background = 0;

        const enqueueBackground = (name: string, versions: readonly string[]): Effect.Effect<number, StoreError> =>
          Effect.gen(function* () {
            const room = Math.max(0, BACKGROUND_PER_SWEEP - background);

            if (room === 0 || versions.length === 0) return 0;
            const now = yield* clock.now;
            const claimed = yield* store.claimAnalysisJobs({ name, versions: [...new Set(versions)].slice(0, room), now, staleMs: REQUEUE_AFTER_MS });

            background += claimed.length;

            if (queue !== null) yield* Effect.forEach(claimed, (version) => send(queue, name, version, now), { concurrency: "unbounded" });

            return claimed.length;
          });

        const admitSeeds = (name: string, versions: readonly string[]): Effect.Effect<number, StoreError> =>
          Effect.gen(function* () {
            const now = yield* clock.now;
            const claimed = yield* store.admitSeedJobs({ name, versions: versions.slice(0, SEED_PER_PACKAGE), now, staleMs: REQUEUE_AFTER_MS, since: now - SEED_INTAKE_WINDOW_MS, max: SEED_INTAKE_MAX });

            if (queue === null) return claimed.length;
            const sent = yield* Effect.forEach(claimed, (version) => send(queue, name, version, now), { concurrency: "unbounded" });

            return sent.filter(Boolean).length;
          });

        // bound to the tarball the packument names for the version: the bytes this run fetched, or would have
        const markUnscorable = (pkg: UpstreamPackage, v: VersionRecord, unscorable: Unscorable): Effect.Effect<VersionRecord, StoreError> =>
          Effect.gen(function* () {
            const d = digestOf(v);
            const digest = d ? digestLabel(d) : null;

            yield* store.setUnscorable({ name: pkg.name, version: v.version, unscorable, digest, at: yield* clock.now });
            v.unscorable = { ...unscorable, digest };

            return v;
          });

        /**
         * A result's write, tried again on a store error: the pool opens a new connection for each try. On staging a
         * Hyperdrive connection closed under vite 8.3.8's finished analysis, and without a retry that lost the run.
         */
        const durable = <A>(write: Effect.Effect<A, StoreError>): Effect.Effect<A, StoreError> => write.pipe(Effect.retry({ times: STORE_RETRIES }));

        /**
         * Stores what an analysis came to. A run that fails with an error keeps its start counted (failAnalysis); after
         * MAX_FAILED_RUNS failed runs the version is stored as incomplete, naming the error's class. A run that fails in
         * a way it cannot report (a store error, a platform stop) leaves its start for the sweep.
         */
        const storeResult = (pkg: UpstreamPackage, v: VersionRecord, digest: Digest, result: Exclude<TarballAnalysis, { kind: "stream" }>): Effect.Effect<Stored, StoreError> =>
          Effect.gen(function* (): Effect.fn.Return<Stored, StoreError> {
            switch (result.kind) {
              case "unscorable":
                return { kind: "unscorable", v: yield* markUnscorable(pkg, v, result.unscorable) };
              case "failed": {
                const failures = yield* store.failAnalysis({ name: pkg.name, version: v.version, errorClass: result.errorClass, now: yield* clock.now, runMs: RUN_WINDOW_MS });

                yield* Effect.logWarning("analysis failed", { name: pkg.name, version: v.version, errorClass: result.errorClass, failures });

                if (failures !== null && failures >= MAX_FAILED_RUNS) {
                  // nothing of the version is read again, its manifest included: reading it may be what failed
                  const analysis = failedAnalysis({ manifest: {}, files: [], errorClass: result.errorClass, attempts: failures });

                  yield* durable(store.setUpstreamAnalysis({ name: pkg.name, version: v.version, digest: digestLabel(digest), analysis, at: yield* clock.now }));
                  v.score = analysis;

                  return { kind: "stored", v };
                }

                // the next delivery runs it again
                return { kind: "retry", v };
              }

              case "scored":
                yield* durable(store.setUpstreamAnalysis({ name: pkg.name, version: v.version, digest: digestLabel(digest), analysis: result.analysis, at: yield* clock.now }));
                v.score = result.analysis;

                return { kind: "stored", v };
              default: {
                const _exhaustive: never = result;

                return _exhaustive;
              }
            }
          });

        /**
         * Analyzes a tarball's bytes and stores what that came to, or says it is to be read as a stream. The bytes live
         * only as long as this does, so a streamed read that follows never holds them beside its own.
         */
        const analyzeAndStore = (pkg: UpstreamPackage, v: VersionRecord, got: { bytes: Uint8Array; digest: Digest }, plan: RunPlan): Effect.Effect<Stored | { kind: "stream" }, StoreError> =>
          timeAnalysis(Effect.gen(function* (): Effect.fn.Return<Stored | { kind: "stream" }, StoreError> {
            const result = analyzeUpstreamTarball(pkg, v, got.bytes, plan);

            if (result.kind === "stream") return result;

            return yield* storeResult(pkg, v, got.digest, result);
          }));

        /** What a tarball the upstream will never serve in a checkable form, or one too large to fetch, is: recorded. */
        const refused = (got: { kind: "unavailable"; reason: string }): Unscorable => ({ reason: "unavailable", detail: got.reason });

        /**
         * A tarball too large to hold, read as a stream (streamed-analysis.ts): each pass opens it again, and nothing it
         * read is used unless every byte matched the version's sha512. A read that could not get or check the bytes, or
         * found no room in the run's memory lease, counts a fetch failure and is handed back, as a download that failed
         * its checksum is. What it keeps is charged to a child of the run's lease (RequestMemory), given back when it ends.
         */
        const streamAndStore = (pkg: UpstreamPackage, v: VersionRecord, plan: RunPlan, fetchFailed: (errorClass: string) => Effect.Effect<JobOutcome, StoreError>): Effect.Effect<JobOutcome, StoreError, RequestMemory> =>
          timeAnalysis(Effect.gen(function* (): Effect.fn.Return<JobOutcome, StoreError, RequestMemory> {
            const digest = digestOf(v);

            if (!digest) {
              yield* markUnscorable(pkg, v, { reason: "unavailable", detail: "the upstream publishes no checksum for this version" });

              return "unscorable";
            }

            const open = () =>
              Effect.runPromise(upstream.openTarball(pkg, v.version).pipe(Effect.catchTag("BlobError", () => Effect.succeed({ kind: "unavailable", reason: "the blob store could not be read", retryable: true } as const))));

            const memory = (yield* RequestMemory).child();
            const result: StreamedAnalysis = yield* Effect.promise(() => analyzeStreamedTarball({ pkg, v, digest, open, plan, memory })).pipe(Effect.ensuring(Effect.sync(() => memory.release())));

            switch (result.kind) {
              case "absent":
                yield* settleGone({ name: pkg.name, version: v.version }, GONE.tarball);

                return "missing";
              case "fetch-failed":
                if (result.retryable) return yield* fetchFailed(result.reason);
                yield* markUnscorable(pkg, v, { reason: "unavailable", detail: result.reason });

                return "unscorable";
              case "scored":
              case "unscorable":
              case "failed":
                return (yield* storeResult(pkg, v, digest, result)).kind;
              default: {
                const _exhaustive: never = result;

                return _exhaustive;
              }
            }
          }));

        /** A queued version the upstream no longer serves: settled, so neither the queue nor the sweep tries it again. */
        const settleGone = (job: AnalysisJob, unscorable: Unscorable): Effect.Effect<void, StoreError> =>
          Effect.gen(function* () {
            // decided for no tarball: npm no longer lists one
            yield* store.setUnscorable({ name: job.name, version: job.version, unscorable, digest: null, at: yield* clock.now });
          });

        /**
         * The queue's run of one job. Its start is recorded before anything else, the upstream included, so every
         * delivery leaves a record the sweep finds, and the decision to stop trying comes before any download: after
         * the stops planFor allows the version is analysis-limit, and after MAX_FETCH_FAILURES runs that
         * could not fetch it over FETCH_GIVE_UP_MS, unavailable. A fetch that fails in a way that may pass keeps its
         * start, counts as a fetch failure and ends the run, so the queue's retry may run it again at once.
         */
        const runJob = (job: AnalysisJob): Effect.Effect<JobOutcome, StoreError | BlobError, RequestMemory> =>
          Effect.gen(function* (): Effect.fn.Return<JobOutcome, StoreError | BlobError, RequestMemory> {
            const begun = yield* store.startAnalysis({ name: job.name, version: job.version, now: yield* clock.now, runMs: RUN_WINDOW_MS });

            switch (begun.kind) {
              case "decided":
                return "unscorable";
              case "running":
                return "busy";
              case "started":
                break;
              default: {
                const _exhaustive: never = begun;

                return _exhaustive;
              }
            }

            // a run the store failed after it began is the registry's failure, not the package's: it is counted like a
            // fetch failure and handed back, so the queue's retry runs it again in full at once. Left as a begun run, it
            // read as busy for RUN_WINDOW_MS and then as one the platform stopped, so vite 8.3.8 waited 7 minutes and
            // stored the re-run's incomplete score. The count is bounded as fetch failures are (MAX_FETCH_FAILURES).
            const now = yield* clock.now;

            return yield* runStarted(job, begun, now).pipe(
              Effect.catchTag("StoreError", (e) =>
                Effect.logWarning("analysis run lost its store", { name: job.name, version: job.version, operation: e.operation }).pipe(
                  Effect.andThen(durable(store.failFetch({ name: job.name, version: job.version, errorClass: `store unavailable (${e.operation})`, now, runMs: RUN_WINDOW_MS }))),
                  Effect.as<JobOutcome>("retry"),
                  // the store is gone altogether: the start stays, and the sweep finds it once RUN_WINDOW_MS pass
                  Effect.catchTag("StoreError", () => Effect.fail(e)),
                ),
              ),
            );
          });

        /** The rest of a run once its start is recorded: give up, fetch, analyze and store. */
        const runStarted = (job: AnalysisJob, begun: Extract<AnalysisStart, { kind: "started" }>, now: number): Effect.Effect<JobOutcome, StoreError | BlobError, RequestMemory> =>
          Effect.gen(function* (): Effect.fn.Return<JobOutcome, StoreError | BlobError, RequestMemory> {
            if (begun.fetchFailures >= MAX_FETCH_FAILURES && begun.fetchFailedSince !== null && now - begun.fetchFailedSince >= FETCH_GIVE_UP_MS) {
              yield* settleGone(job, FETCH_GAVE_UP);

              return "unscorable";
            }

            // the runs before this one decide how it reads: two that stored nothing, and this one reads less
            const next = planFor(begun);

            if (next.kind === "give-up") {
              yield* settleGone(job, next.unscorable);

              return "unscorable";
            }

            const fetchFailed = (errorClass: string): Effect.Effect<JobOutcome, StoreError> => store.failFetch({ name: job.name, version: job.version, errorClass, now, runMs: RUN_WINDOW_MS }).pipe(Effect.as("retry"));
            // the job's own lease (worker.ts opens one per queue message, and one for the sweep that runs jobs itself)
            const probe = yield* upstream.probe(job.name, yield* RequestMemory);

            switch (probe.kind) {
              case "unknown":
                return yield* fetchFailed("upstream packument unavailable");
              case "absent":
                yield* settleGone(job, GONE.package);

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

            if (!v) {
              yield* settleGone(job, GONE.version);

              return "missing";
            }

            if (parseAnalysis(v.score)) return "stored";

            if (v.unscorable) return "unscorable";
            const held = yield* fetchAndStore(job, pkg, v, next.plan, fetchFailed);

            // too large to download (MAX_UPSTREAM_TARBALL_BYTES) or to unpack whole: read as a stream
            return held === "stream" ? yield* streamAndStore(pkg, v, next.plan, fetchFailed) : held;
          });

        /**
         * Downloads a tarball up to MAX_UPSTREAM_TARBALL_BYTES, analyzes it whole and stores what that came to; "stream"
         * when it is too large to download or to unpack whole. Its bytes are let go when this ends.
         */
        const fetchAndStore = (job: AnalysisJob, pkg: UpstreamPackage, v: VersionRecord, plan: RunPlan, fetchFailed: (errorClass: string) => Effect.Effect<JobOutcome, StoreError>): Effect.Effect<JobOutcome | "stream", StoreError | BlobError> =>
          Effect.gen(function* (): Effect.fn.Return<JobOutcome | "stream", StoreError | BlobError> {
            const got = yield* upstream.tarball(pkg, v.version);

            switch (got.kind) {
              case "absent":
                yield* settleGone(job, GONE.tarball);

                return "missing";
              case "too-large":
                return "stream";
              case "unavailable":
                if (got.retryable) return yield* fetchFailed("upstream tarball unavailable");
                yield* markUnscorable(pkg, v, refused(got));

                return "unscorable";
              case "ok":
                break;
              default: {
                const _exhaustive: never = got;

                return _exhaustive;
              }
            }

            const stored = yield* analyzeAndStore(pkg, v, got, plan);

            return stored.kind === "stream" ? "stream" : stored.kind;
          });

        const api: AnalysisApi = {
          recover: Effect.gen(function* () {
            const now = yield* clock.now;
            // jobs the queue accepted that never began a run (it gave up on them first, or never delivered them), past
            // the time a requeue may claim them again, so each is sent once more. Read first, and only read: each kind
            // has RECOVER_ACCEPTED_SHARE of the sweep, and what one leaves unused the other may take. Before this (review
            // of 89441a9, finding 6) unfinished runs were taken first, so 200 of them left no room for the others.
            const waiting = yield* store.acceptedAnalyses({ before: now - REQUEUE_AFTER_MS, limit: RECOVER_PER_SWEEP });
            // runs that began and never ended: picking them marks them swept, so only as many as there is room for
            const runs = yield* store.unfinishedAnalyses({ before: now - RUN_WINDOW_MS, limit: RECOVER_PER_SWEEP - Math.min(waiting.length, RECOVER_ACCEPTED_SHARE), now });
            const accepted = waiting.slice(0, RECOVER_PER_SWEEP - runs.length);

            // with no queue (a local registry), the sweep runs the job itself, under the same meter
            for (const r of [...runs, ...accepted]) {
              if (queue === null) {
                // each job's packument under a child of the sweep's lease, given back when the job ends
                const child = (yield* RequestMemory).child();
                yield* runJob(r).pipe(Effect.provideService(RequestMemory, child), Effect.ensuring(Effect.sync(() => child.release())));
              }
              else yield* enqueue(r.name, r.version);
            }

            return runs.length + accepted.length;
          }),
          // every cache miss goes to the queue, which records each run before it fetches anything
          ensure: (pkg, v) =>
            Effect.gen(function* () {
              if (parseAnalysis(v.score) || v.unscorable) return v;
              yield* enqueue(pkg.name, v.version);

              return v;
            }),
          enqueue,
          admitSeeds,
          enqueueBackground,
          runJob,
        };

        return Analysis.of(api);
      }),
    );
  }
}
