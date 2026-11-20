"use client";

// Search as you type, shared by the home page and the header box.
// - Every query asks /api/search (same origin) after a short pause; a newer query aborts the older request.
// - Answers are kept per query for the life of the component, so backspacing and retyping is instant.
// - The last answer stays available until the next one arrives, so nothing flashes.

import { useEffect, useState, type RefObject } from "react";
import { cn } from "cn";
import { SearchAnswer } from "@/lib/search-schema";

const SEARCH_DEBOUNCE_MS = 30;

/** Errors and answers made without npm are only reused this long, so a retype after an outage asks again. */
const DEGRADED_TTL_MS = 5_000;

export type SearchDone = { kind: "ok"; answer: SearchAnswer } | { kind: "error" };

export type Stored<T> = { value: T; at: number; degraded: boolean };

export function isFresh<T>(entry: Stored<T> | undefined): boolean {
  return entry !== undefined && (!entry.degraded || Date.now() - entry.at < DEGRADED_TTL_MS);
}

export type LiveSearch = {
  /** The answer for `q` when there is one, else the last answer shown. Null before the first answer. */
  current: SearchDone | null;
  /** The query `current` answers. */
  shownQuery: string;
  /** A request for `q` is waiting or in flight. */
  pending: boolean;
  /** Forgets the answer for `q`, so it is asked again. */
  retry: () => void;
};

/** `q` must already be normalized. An empty `q` asks nothing. */
export function useLiveSearch(q: string): LiveSearch {
  const [done, setDone] = useState<ReadonlyMap<string, Stored<SearchDone>>>(() => new Map());
  const [shownQuery, setShownQuery] = useState("");
  const have = q === "" || isFresh(done.get(q));

  useEffect(() => {
    if (have) return;
    const ctrl = new AbortController();

    const timer = setTimeout(async () => {
      let result: SearchDone = { kind: "error" };

      try {
        const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`, { signal: ctrl.signal });
        const parsed = SearchAnswer.safeParse(await res.json());

        if (res.ok && parsed.success) result = { kind: "ok", answer: parsed.data };
      } catch {
        if (ctrl.signal.aborted) return;
      }

      const degraded = result.kind === "error" || result.answer.upstreamFailed;
      setDone((prev) => new Map(prev).set(q, { value: result, at: Date.now(), degraded }));
      setShownQuery(q);
    }, SEARCH_DEBOUNCE_MS);

    return () => {
      clearTimeout(timer);
      ctrl.abort();
    };
  }, [q, have]);

  const current = (done.get(q) ?? done.get(shownQuery))?.value ?? null;

  const retry = () =>
    setDone((prev) => {
      const next = new Map(prev);
      next.delete(q);

      return next;
    });

  return { current, shownQuery: done.has(q) ? q : shownQuery, pending: !have, retry };
}

/**
 * Text typed into a server-rendered input before React hydrated it. React keeps that text on screen but its state
 * still holds the server's empty value, so no search runs for it. Read it once after hydration and hand it to
 * `adopt`. Runs only on mount: `adopt` is read then, not tracked.
 */
export function useTypedBeforeHydration(input: RefObject<HTMLInputElement | null>, adopt: (typed: string, focused: boolean) => void): void {
  const [first] = useState(() => adopt);

  useEffect(() => {
    const el = input.current;

    if (el && el.value !== "") first(el.value, document.activeElement === el);
  }, [input, first]);
}

/** A package name with the part that matches the query in full color and the rest muted. */
export function Highlight({ name, q, className }: { name: string; q: string; className?: string }) {
  const i = q ? name.indexOf(q) : -1;

  if (i < 0) return <span className={cn("truncate font-mono", className)}>{name}</span>;

  return (
    <span className={cn("truncate font-mono text-muted-foreground", className)}>
      {name.slice(0, i)}
      <span className="text-foreground">{name.slice(i, i + q.length)}</span>
      {name.slice(i + q.length)}
    </span>
  );
}
