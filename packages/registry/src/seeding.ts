// A package page's seeding: the versions besides `latest` it would queue for analysis (analysis.ts, versionsToSeed),
// queued after the answer, never on its path (review of 2022f3d, P2: the page awaited eight claims and their sends, up
// to 8 s of database wait or 4 s of queue wait). A look hands its versions over and returns at once; the work runs in
// the waitUntil of the request that accepted it, on services of its own (worker.ts), and is aborted at SEED_DEADLINE_MS.
// It is bounded three ways: SEEDS_RUNNING_MAX at a time in an isolate (a look past it seeds nothing), each package once
// per SEED_AGAIN_MS in an isolate, and globally by the claim itself (Analysis.admitSeeds: nothing once the queue took
// SEED_INTAKE_MAX jobs in SEED_INTAKE_WINDOW_MS). What a look does not seed, the cron's seeding reaches
// (kept-package.ts, seedKeptPackages), so a page view is never the only way a version gets queued.
import { Context, Effect, Layer } from "effect";

/**
 * The global bound on a page's seeding (Analysis.admitSeeds): it claims nothing once SEED_INTAKE_MAX jobs, from any
 * caller, were claimed in the last SEED_INTAKE_WINDOW_MS. The queue runs one analysis at a time and stored 600 to 1,400
 * an hour at its busiest on production, so 60 in ten minutes leaves most of it to what installs and lookups ask for;
 * past it, a crawler's page views add nothing, and the cron's seeding (apm.ts, seedKeptPackages) reaches those versions.
 */
export const SEED_INTAKE_WINDOW_MS = 10 * 60_000;
export const SEED_INTAKE_MAX = 60;

/** How long one look's seeding may run after the answer: a claim, and the sends of what it claimed. */
export const SEED_DEADLINE_MS = 5_000;

/** Looks seeding at once in one isolate; a look past them seeds nothing. */
export const SEEDS_RUNNING_MAX = 2;

/** How long an isolate leaves a package it seeded (or tried to) before a look seeds it again. */
export const SEED_AGAIN_MS = 10 * 60_000;

/** Packages an isolate remembers seeding, oldest let go first. */
const SEEDED_MAX = 2_000;

/** One look's seeding, and the signal that aborts it at SEED_DEADLINE_MS. */
export type SeedInput = { readonly name: string; readonly versions: readonly string[]; readonly signal: AbortSignal };

/** What a look's seeding came to: sent, skipped for the isolate's bounds, or dropped at its deadline or on a failure. */
export type SeedOutcome = "seeded" | "skipped" | "failed";

export type SeedingApi = {
  /** Hands a look's versions over to be queued after the answer; returns at once, whatever comes of them. */
  readonly look: (input: { name: string; versions: readonly string[] }) => Effect.Effect<SeedOutcome>;
};

/** The isolate's state: looks running, and when each package may be seeded again. */
type Held = { running: number; readonly seeded: Map<string, number> };

const held: Held = { running: 0, seeded: new Map() };

export class Seeding extends Context.Service<Seeding, SeedingApi>()("@apm/registry/Seeding") {
  /** No seeding after the answer (outside a request, or with no upstream): the cron's seeding reaches those versions. */
  static readonly none = Layer.succeed(Seeding, Seeding.of({ look: () => Effect.succeed<SeedOutcome>("skipped") }));

  /**
   * `background` keeps work alive after the response (ExecutionContext.waitUntil); `run` queues one look's versions on
   * services of its own (worker.ts), until `signal` aborts it. `state` is the isolate's (tests pass their own).
   */
  static layer(o: { background: (work: Promise<void>) => void; run: (input: SeedInput) => Promise<void>; now: () => number; deadlineMs?: number; state?: Held }): Layer.Layer<Seeding> {
    const state = o.state ?? held;
    const deadlineMs = o.deadlineMs ?? SEED_DEADLINE_MS;

    const look = (input: { name: string; versions: readonly string[] }): Effect.Effect<SeedOutcome> =>
      Effect.sync((): SeedOutcome => {
        const at = o.now();
        const until = state.seeded.get(input.name);

        if (input.versions.length === 0 || (until !== undefined && at < until && until - at <= SEED_AGAIN_MS) || state.running >= SEEDS_RUNNING_MAX) return "skipped";
        state.seeded.delete(input.name);
        state.seeded.set(input.name, at + SEED_AGAIN_MS);

        if (state.seeded.size > SEEDED_MAX) {
          const oldest = state.seeded.keys().next();

          if (!oldest.done) state.seeded.delete(oldest.value);
        }

        state.running++;
        const abort = new AbortController();
        const timer = setTimeout(() => abort.abort(), deadlineMs);

        const work = o
          .run({ ...input, signal: abort.signal })
          .catch(() => undefined)
          .finally(() => {
            clearTimeout(timer);
            state.running--;
          });

        o.background(work);

        return "seeded";
      });

    return Layer.succeed(Seeding, Seeding.of({ look }));
  }
}

/** A fresh isolate state, for tests. */
export const freshSeedingState = (): Held => ({ running: 0, seeded: new Map() });
