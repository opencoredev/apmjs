// resolve for exactly the version a package view shows (lib/refusal.ts readPolicy), as the page, its Markdown view and
// check_package read it: kept for POLICY_TTL_MS so a reload does not make the registry walk the dependency tree again,
// with views of one name@version that arrive together sharing one read. An answer the registry did not give
// (unavailable) is dropped at once, so the next view asks again. /api/explain does not read through this: a verdict
// asks resolve on every call. No "server-only": the unit tests import it.
import type { ResolveOutcome } from "./source";

export const POLICY_TTL_MS = 60_000;

/** At most this many name@range answers are kept; the oldest goes first. */
const MAX_ENTRIES = 500;

export type PolicyStore = Map<string, { readonly at: number; readonly outcome: Promise<ResolveOutcome> }>;

type Resolve = (input: { name: string; range: string }) => Promise<ResolveOutcome>;

/** `resolve` behind `store`: a fresh entry, or one still in flight, answers instead of a new read. */
export function cachedResolve(input: { resolve: Resolve; store: PolicyStore; now?: () => number }): Resolve {
  const { resolve, store } = input;
  const now = input.now ?? Date.now;

  return ({ name, range }) => {
    const key = `${name}@${range}`;
    const at = now();
    const kept = store.get(key);

    if (kept && at - kept.at < POLICY_TTL_MS) return kept.outcome;
    store.delete(key);
    const outcome = resolve({ name, range });
    const entry = { at, outcome };

    const drop = () => {
      if (store.get(key) === entry) store.delete(key);
    };

    store.set(key, entry);
    outcome.then((o) => o.kind === "unavailable" && drop(), drop);

    // a Map iterates in insertion order, so the first key is the oldest
    for (const oldest of store.keys()) {
      if (store.size <= MAX_ENTRIES) break;
      store.delete(oldest);
    }

    return outcome;
  };
}
