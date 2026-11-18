// Where one request's time went, sent as a Server-Timing header (worker.ts). Each metric adds up the time its
// operations took and counts them: "db" is every Postgres query (the first one includes connecting through
// Hyperdrive), "npm" a packument fetched from npm, "npm-cache" one read from the data center's cache, "npm-head" a
// packument's ETag checked with no body read (a conditional read npm answered with a 304, or one that failed),
// "npm-version" one version's document from npm (a few KiB), "npm-open" npm's tarball answer up to its headers, "blocklist" the install block list (R2, or this
// isolate's copy of it), "install-copy" a lookup of the install document's copy in the data center's cache, "checks"
// the wall time of the fast tarball path's checks run at once (fast-tarball.ts), "analysis" an upstream version
// scored on read. A Worker's clock moves only on I/O, so these are waits, and CPU work (parsing a packument, scoring)
// shows only as the gap before `total`. Optional everywhere: tests and the queue consumer run without it.
//
// Who gets the header:
// - a request whose x-apm-debug header is the operator's debug token (worker.ts, APM_DEBUG_TOKEN_HASH), on the read
//   answers the website's package page makes (http.ts, TIMED_PATHS) and on every answer marked public;
// - anyone, on an answer a route marked public (`expose`): only the install document and the fast tarball answer of a
//   package only npm has. What those numbers can tell is whether this data center's caches held npm's documents for
//   that public package (someone here asked for it lately), which the answer's own total time already shows to anyone
//   who times it. They name nothing but the request's own package, and no answer about a package published here, nor
//   any other route, is ever marked.
// Elsewhere nobody else gets it: even the database's time against the total shows whether npm's answer was cached,
// which on the website's reads tells what others asked for.
import { Context, Effect, Option } from "effect";

export type TimingMetric = "db" | "npm" | "npm-cache" | "npm-head" | "npm-version" | "npm-open" | "blocklist" | "install-copy" | "checks" | "analysis" | "edge";

/** "none": no header. "full": every metric with its count. */
export type TimingDetail = "none" | "full";

type Entry = { ms: number; count: number };

export type TimingApi = {
  /** Adds one operation of `ms` to `metric`. */
  readonly add: (metric: TimingMetric, ms: number) => void;
  /** The Server-Timing header value, with `total` ms for the whole answer; null when none is sent. */
  readonly header: (input: { total: number; detail: TimingDetail }) => string | null;
  /** Marks this request's answer as one whose timing anyone may see (see the top of this file for which). */
  readonly expose: () => void;
  /** Whether a route marked the answer public. */
  readonly exposed: () => boolean;
};

export class Timing extends Context.Service<Timing, TimingApi>()("@apm/registry/Timing") {
  static make(): TimingApi {
    const entries = new Map<TimingMetric, Entry>();
    let open = false;

    return {
      expose: () => {
        open = true;
      },
      exposed: () => open,
      add: (metric, ms) => {
        const e = entries.get(metric) ?? { ms: 0, count: 0 };
        entries.set(metric, { ms: e.ms + ms, count: e.count + 1 });
      },
      header: ({ total, detail }) => {
        switch (detail) {
          case "none":
            return null;
          case "full":
            return [...[...entries].map(([metric, e]) => `${metric};dur=${e.ms.toFixed(1)};desc="${e.count}"`), `total;dur=${total.toFixed(1)}`].join(", ");
          default: {
            const _exhaustive: never = detail;

            return _exhaustive;
          }
        }
      },
    };
  }
}

/** The request's timing, or null when nothing collects it. */
export const timingOrNull = Effect.map(Effect.serviceOption(Timing), Option.getOrNull);

/** Runs `effect` and adds its wall time to `metric` when a request collects timing. */
export const timed =
  (timing: TimingApi | null, metric: TimingMetric) =>
  <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, E, R> => {
    if (timing === null) return effect;

    return Effect.suspend(() => {
      const start = performance.now();

      return Effect.ensuring(
        effect,
        Effect.sync(() => timing.add(metric, performance.now() - start)),
      );
    });
  };
