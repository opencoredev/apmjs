// Things other modules want to hear about without the publish path or the upstream proxy knowing who listens:
// a version went live, and a package's packument was fetched from upstream. worker.ts provides the listeners
// (the AI review queue) when they are configured; without it nothing listens.
import { Context, Effect, Option } from "effect";
import type { BackgroundLease } from "./memory.ts";
import type { UpstreamPackage } from "./upstream.ts";

export type Committed = { name: string; version: string; firstPublish: boolean };

export class ReleaseHooks extends Context.Service<
  ReleaseHooks,
  {
    /** After a version goes live (direct publish or approval). */
    readonly afterCommit: (v: Committed) => Effect.Effect<void>;
    /**
     * After an upstream packument is fetched (not on cache hits). `held` is a background lease (memory.ts) that holds
     * `pkg`: the listener stops when `held.signal` aborts, and releases it once nothing it started refers to `pkg` any
     * more. Until then `pkg` stays charged, past the deadline too.
     */
    readonly upstreamFetched: (pkg: UpstreamPackage, held: BackgroundLease) => Effect.Effect<void>;
  }
>()("@apm/registry/ReleaseHooks") {}

/** Runs a listener if one is provided. */
export const notify = <A>(pick: (hooks: ReleaseHooks["Service"]) => (event: A) => Effect.Effect<void>, event: A): Effect.Effect<void> =>
  Effect.flatMap(Effect.serviceOption(ReleaseHooks), (hooks) => (Option.isSome(hooks) ? pick(hooks.value)(event) : Effect.void));
