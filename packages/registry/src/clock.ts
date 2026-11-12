// The registry's notion of "now". `now` drives cooldowns, staging deadlines, revoke windows and confirmation
// windows; `wallNow` is the wall clock authenticator codes and their attempt budget are checked against.
// Production reads the system clock for both; the acceptance suite drives each per request through the test entry.
import { Context, Effect, Layer } from "effect";

export class Clock extends Context.Service<Clock, { readonly now: Effect.Effect<number>; readonly wallNow: Effect.Effect<number> }>()("@apm/registry/Clock") {
  static readonly system = Layer.succeed(Clock, Clock.of({ now: Effect.sync(() => Date.now()), wallNow: Effect.sync(() => Date.now()) }));
  static fixed(input: { now: number; wallNow: number | null }): Layer.Layer<Clock> {
    const { now, wallNow } = input;

    return Layer.succeed(Clock, Clock.of({ now: Effect.succeed(now), wallNow: wallNow === null ? Effect.sync(() => Date.now()) : Effect.succeed(wallNow) }));
  }
}
