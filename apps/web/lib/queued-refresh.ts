// When the package page asks the registry again for a version whose analysis is queued. An anonymous view never
// analyses a version itself (the registry queues it), so the first view of an unscored package shows "queued" and the
// page refreshes itself until the score is there. Pure, so the unit tests can drive the clock.

/** A queued analysis is asked about every 8 seconds, for up to 5 minutes; most finish within a minute of queueing. */
export const REFRESH_EVERY_MS = 8_000;
export const REFRESH_FOR_MS = 5 * 60_000;

export type RefreshStep = { kind: "wait"; ms: number } | { kind: "stop" };

/** What to do next while the version shows as queued: wait and refresh, or stop once the page has waited long enough. */
export function refreshStep(input: { startedAt: number; now: number }): RefreshStep {
  const left = input.startedAt + REFRESH_FOR_MS - input.now;

  return left > 0 ? { kind: "wait", ms: Math.min(REFRESH_EVERY_MS, left) } : { kind: "stop" };
}
