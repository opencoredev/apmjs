// Scoring upstream versions. A request analyzes a few small tarballs itself, within a per-request budget, and
// sends everything else to the analysis queue, whose consumer does the heavy work outside any request's CPU limit.
import { Context, Effect, Layer, Ref, Semaphore } from "effect";
import { analyze, parseAnalysis, readTarball, type Analysis as Scored, type TarEntry } from "@apm/core";
import type { Queue } from "@cloudflare/workers-types";
import { Clock } from "./clock.ts";
import { Manifest, Store, type VersionRecord } from "./db.ts";
import { QueueError, type BlobError, type StoreError } from "./errors.ts";
import { digestLabel, Upstream, type Digest, type UpstreamPackage } from "./upstream.ts";

export type AnalysisJob = { readonly name: string; readonly version: string };

/**
 * What a queued job came to. "stored": scored (now or before). "missing": the upstream does not list the version,
 * or its tarball can never be read. "retry": the upstream could not be asked, or failed in a way that may pass,
 * so the queue should deliver the job again.
 */
export type JobOutcome = "stored" | "missing" | "retry";

/** Per request: analyze at most this many upstream tarballs inline. */
export const INLINE_ANALYSES = 8;

/** Tarballs larger than this (compressed) always go to the queue. */
export const INLINE_MAX_BYTES = 4 * 1024 * 1024;

/**
 * The most a tarball may inflate to on a Worker. A Worker has 128 MB, and the parser keeps the inflated archive
 * and each entry's bytes, so this stays well under half of it. Larger archives are refused (publish) or left
 * unscored (upstream), never passed.
 */
export const WORKER_MAX_UNPACKED_BYTES = 48 * 1024 * 1024;

/** A queued version is sent again only after this long without a result. */
const REQUEUE_AFTER_MS = 10 * 60_000;

/** Runs the scorer over an upstream tarball. Null when the bytes are not a package apm can read. */
export function analyzeUpstreamTarball(pkg: UpstreamPackage, v: VersionRecord, bytes: Uint8Array): Scored | null {
  let files: TarEntry[];

  try {
    files = readTarball(bytes, WORKER_MAX_UNPACKED_BYTES);
  } catch {
    return null;
  }

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

  return analyze({ name: pkg.name, manifest, files, publisher: v.published_by, previousPublishers });
}

export type AnalysisApi = {
  /**
   * Makes sure an upstream version has a stored analysis and returns the version with it. Small tarballs are
   * analyzed now while this request's budget lasts; the rest are queued and come back unscored.
   */
  readonly ensure: (pkg: UpstreamPackage, v: VersionRecord) => Effect.Effect<VersionRecord, StoreError | BlobError>;
  /** Queues a version for analysis unless it is already scored or queued. */
  readonly enqueue: (name: string, version: string) => Effect.Effect<void, StoreError>;
  /** The consumer's work: fetch, verify, analyze and store one version, without a budget. */
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

        const analyzeAndStore = (pkg: UpstreamPackage, v: VersionRecord, got: { bytes: Uint8Array; digest: Digest }): Effect.Effect<VersionRecord, StoreError> =>
          Effect.gen(function* () {
            const analysis = analyzeUpstreamTarball(pkg, v, got.bytes);

            if (analysis === null) return v;
            yield* store.setUpstreamAnalysis({ name: pkg.name, version: v.version, digest: digestLabel(got.digest), analysis, at: yield* clock.now });
            v.score = analysis;

            return v;
          });

        const api: AnalysisApi = {
          ensure: (pkg, v) =>
            Effect.gen(function* () {
              if (parseAnalysis(v.score)) return v;
              const left = yield* Ref.getAndUpdate(budget, (n) => Math.max(0, n - 1));

              if (left <= 0) {
                yield* enqueue(pkg.name, v.version);

                return v;
              }

              return yield* inline.withPermits(1)(
                Effect.gen(function* () {
                  const got = yield* upstream.tarball(pkg, v.version);

                  if (got.kind !== "ok") return v;

                  if (got.bytes.length > INLINE_MAX_BYTES) {
                    yield* enqueue(pkg.name, v.version);

                    return v;
                  }

                  return yield* analyzeAndStore(pkg, v, got);
                }),
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
              const got = yield* upstream.tarball(pkg, v.version);

              switch (got.kind) {
                case "absent":
                  return "missing";
                case "unavailable":
                  return got.retryable ? "retry" : "missing";
                case "ok":
                  yield* analyzeAndStore(pkg, v, got);

                  return "stored";
                default: {
                  const _exhaustive: never = got;

                  return _exhaustive;
                }
              }
            }),
        };

        return Analysis.of(api);
      }),
    );
  }
}
