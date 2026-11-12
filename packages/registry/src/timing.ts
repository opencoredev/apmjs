// Where one request's time went, sent as a Server-Timing header on the read answers the website's package page makes
// (worker.ts). Each metric adds up the time its operations took and counts them: "db" is every Postgres query (the
// first one includes connecting through Hyperdrive), "npm" a packument fetched from npm, "npm-cache" one read from the
// data center's cache, "analysis" an upstream version scored on read. A Worker's clock moves only on I/O, so these are
// waits, and CPU work (parsing a packument, scoring) shows only as the gap before `total`. Optional everywhere: tests
// and the queue consumer run without it.
//
// Only a request whose x-apm-debug header is the operator's debug token (worker.ts, APM_DEBUG_TOKEN_HASH) gets the
// header. Anyone else gets none: even the database's time against the total shows whether npm's answer was cached,
// which tells what others asked for.
import { Context, Effect, Option } from "effect";

export type TimingMetric = "db" | "npm" | "npm-cache" | "analysis";

/** "none": no header. "full": every metric with its count. */
export type TimingDetail = "none" | "full";

type Entry = { ms: number; count: number };

export type TimingApi = {
  /** Adds one operation of `ms` to `metric`. */
  readonly add: (metric: TimingMetric, ms: number) => void;
  /** The Server-Timing header value, with `total` ms for the whole answer; null when none is sent. */
  readonly header: (input: { total: number; detail: TimingDetail }) => string | null;
};

export class Timing extends Context.Service<Timing, TimingApi>()("@apm/registry/Timing") {
  static make(): TimingApi {
    const entries = new Map<TimingMetric, Entry>();

    return {
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
