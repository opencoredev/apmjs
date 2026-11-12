"use client";

// The home page: one search box, results as you type.
// - Every keystroke asks /api/search (same origin); the previous request is aborted.
// - Answers are kept per query, so backspacing and retyping is instant.
// - The last answer stays on screen until the next one arrives, so nothing flashes.
// - The name check runs in three parts after a short pause and fills its slots on its own.

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { ArrowRightIcon, CheckIcon, ChevronDownIcon, CloudOffIcon, CornerDownLeftIcon, LoaderCircleIcon, SearchIcon, TriangleAlertIcon, XIcon } from "lucide-react";
import { cn } from "cn";
import { ScoreBadge } from "@/components/score-badge";
import {
  NAME_PART_SCHEMAS,
  SearchAnswer,
  alternativesView,
  looksLikePackageName,
  type AlternativesView,
  type NamePart,
  type NamePartAnswer,
  type SearchHit,
} from "@/lib/search-schema";

const SEARCH_DEBOUNCE_MS = 30;
const NAME_CHECK_DEBOUNCE_MS = 250;

/** Errors and answers made without npm are only reused this long, so a retype after an outage asks again. */
const DEGRADED_TTL_MS = 5_000;

function normalize(q: string): string {
  return q.trim().toLowerCase();
}

function urlFor(q: string): string {
  return q ? `/?q=${encodeURIComponent(q)}` : "/";
}

function packageHref(name: string): string {
  return `/package/${name}`;
}

// ---------- data ----------

type SearchDone = { kind: "ok"; answer: SearchAnswer } | { kind: "error" };

type Stored<T> = { value: T; at: number; degraded: boolean };

function fresh<T>(entry: Stored<T> | undefined): boolean {
  return entry !== undefined && (!entry.degraded || Date.now() - entry.at < DEGRADED_TTL_MS);
}

function useLiveSearch(q: string): { current: SearchDone | null; shownQuery: string; pending: boolean; retry: () => void } {
  const [done, setDone] = useState<ReadonlyMap<string, Stored<SearchDone>>>(() => new Map());
  const [shownQuery, setShownQuery] = useState("");
  const have = q === "" || fresh(done.get(q));

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

type PartState<P extends NamePart> = { kind: "loading" } | { kind: "ok"; data: NamePartAnswer[P] } | { kind: "error" };

function useNamePart<P extends NamePart>(q: string | null, part: P): PartState<P> {
  const [done, setDone] = useState<ReadonlyMap<string, Stored<PartState<P>>>>(() => new Map());
  const have = q === null || fresh(done.get(q));

  useEffect(() => {
    if (q === null || have) return;
    const ctrl = new AbortController();

    const timer = setTimeout(async () => {
      let result: PartState<P> = { kind: "error" };

      try {
        const res = await fetch(`/api/names?q=${encodeURIComponent(q)}&part=${part}`, { signal: ctrl.signal });
        const parsed = NAME_PART_SCHEMAS[part].safeParse(await res.json());

        if (res.ok && parsed.success) result = { kind: "ok", data: parsed.data };
      } catch {
        if (ctrl.signal.aborted) return;
      }

      setDone((prev) => new Map(prev).set(q, { value: result, at: Date.now(), degraded: result.kind === "error" }));
    }, NAME_CHECK_DEBOUNCE_MS);

    return () => {
      clearTimeout(timer);
      ctrl.abort();
    };
  }, [q, part, have]);

  return (q !== null && done.get(q)?.value) || { kind: "loading" };
}

// ---------- small pieces ----------

function Highlight({ name, q, className }: { name: string; q: string; className?: string }) {
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

function SourceTag({ source }: { source: SearchHit["source"] }) {
  return source === "local" ? (
    <span className="inline-flex h-5 shrink-0 items-center rounded-md bg-foreground px-1.5 font-mono text-[11px] font-medium text-background" title="Published to this registry">
      apm
    </span>
  ) : (
    <span className="inline-flex h-5 shrink-0 items-center rounded-md border px-1.5 font-mono text-[11px] text-muted-foreground" title="From the public npm registry">
      npm
    </span>
  );
}

const compact = new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 });

type StatusKind = "free" | "taken" | "warn" | "wait";

function Status({ kind, children }: { kind: StatusKind; children: ReactNode }) {
  const tone = kind === "free" ? "text-ok" : kind === "warn" ? "text-warn" : "text-muted-foreground";

  return (
    <span className={cn("inline-flex shrink-0 items-center gap-1.5 text-sm font-medium", tone)}>
      {kind === "wait" ? (
        <LoaderCircleIcon className="size-3.5 animate-spin" aria-hidden />
      ) : kind === "free" ? (
        <CheckIcon className="size-4" aria-hidden />
      ) : kind === "warn" ? (
        <TriangleAlertIcon className="size-4" aria-hidden />
      ) : (
        <XIcon className="size-4" aria-hidden />
      )}
      {children}
    </span>
  );
}

function Line({ className }: { className?: string }) {
  return <span className={cn("block h-4 animate-pulse rounded bg-muted", className)} aria-hidden />;
}

// ---------- name check: four slots, each filled on its own ----------

function Slot({ label, href, children }: { label: string; href?: string; children: ReactNode }) {
  const body = (
    <>
      <span className="flex items-center justify-between text-[13px] text-muted-foreground">
        {label}
        {href && <ArrowRightIcon className="size-3.5 transition-transform group-hover:translate-x-0.5" aria-hidden />}
      </span>
      <span className="mt-2 flex min-h-[3.25rem] min-w-0 flex-col gap-1.5">{children}</span>
    </>
  );

  const base = "flex min-w-0 flex-col px-4 py-3.5";

  return href ? (
    <Link href={href} prefetch={false} className={cn("group transition-colors hover:bg-surface focus-visible:bg-surface", base)}>
      {body}
    </Link>
  ) : (
    <div className={base}>{body}</div>
  );
}

function ExactStatus({ state }: { state: PartState<"exact"> }) {
  if (state.kind === "loading") return <Status kind="wait">checking</Status>;

  if (state.kind === "error") return <Status kind="warn">couldn&apos;t check</Status>;
  const data = state.data;

  if (data.taken) {
    return (
      <>
        <Status kind="taken">taken{data.owners.length ? ` by ${data.owners.slice(0, 2).join(", ")}` : ""}</Status>
        {data.latest?.score !== null && data.latest?.score !== undefined && <ScoreBadge score={data.latest.score} grade={data.latest.grade} className="h-6" />}
      </>
    );
  }

  if (data.unknown) return <Status kind="warn">couldn&apos;t check npm</Status>;

  if (data.available) return <Status kind="free">available</Status>;

  return <Status kind="warn">{data.valid ? "blocked: too close to a popular name" : "invalid"}</Status>;
}

function ExactSlot({ q, state }: { q: string; state: PartState<"exact"> }) {
  const data = state.kind === "ok" ? state.data : null;

  return (
    <Slot label="Exact name" href={data?.taken ? packageHref(q) : undefined}>
      <Highlight name={q} q="" className="text-lg font-medium" />
      <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <ExactStatus state={state} />
      </span>
      {data && !data.taken && data.conflicts[0] && <span className="text-sm text-pretty text-muted-foreground">{data.conflicts[0].reason}</span>}
    </Slot>
  );
}

function ScopeSlot({ q, state }: { q: string; state: PartState<"alternatives"> }) {
  const bare = q.startsWith("@") ? q.slice(q.indexOf("/") + 1) : q;
  const scope = state.kind === "ok" ? state.data.scope : null;

  return (
    <Slot label="Under your scope">
      <span className="truncate font-mono text-[15px] text-muted-foreground">
        @{scope ?? "you"}/{bare}
      </span>
      <span className="text-sm text-muted-foreground">
        {scope === null ? "A scoped name is always yours. Sign in with GitHub to claim your scope." : "A name under your GitHub login is always yours."}
      </span>
    </Slot>
  );
}

function LookalikeSlot({ state }: { state: PartState<"lookalike"> }) {
  const nearest = state.kind === "ok" ? (state.data.lookalikes[0] ?? state.data.similar[0]) : undefined;

  return (
    <Slot label="Look-alike" href={nearest ? packageHref(nearest.name) : undefined}>
      {state.kind === "loading" ? (
        <>
          <Line className="w-32" />
          <Line className="w-48" />
        </>
      ) : state.kind === "error" ? (
        <span className="text-sm text-muted-foreground">Couldn&apos;t check.</span>
      ) : nearest ? (
        <>
          <span className="flex items-center gap-2">
            <span className="truncate font-mono text-[15px]">{nearest.name}</span>
            <Status kind="warn">typo risk</Status>
          </span>
          <span className="text-sm text-pretty text-muted-foreground">{nearest.reason}</span>
        </>
      ) : (
        <>
          <Status kind="free">clear</Status>
          <span className="text-sm text-muted-foreground">Nothing popular is one typo away.</span>
        </>
      )}
    </Slot>
  );
}

function AlternativesSlot({ state }: { state: PartState<"alternatives"> }) {
  const view: AlternativesView = state.kind === "ok" ? alternativesView(state.data) : { kind: "none" };

  return (
    <Slot label="Free alternatives">
      {state.kind === "loading" ? (
        <>
          <Line className="w-28" />
          <Line className="w-36" />
          <Line className="w-24" />
        </>
      ) : state.kind === "error" ? (
        <span className="text-sm text-muted-foreground">Couldn&apos;t check.</span>
      ) : view.kind === "free" ? (
        <ul className="flex flex-col gap-1">
          {view.names.map((name) => (
            <li key={name} className="flex items-center justify-between gap-3">
              <span className="truncate font-mono text-[15px]">{name}</span>
              <CheckIcon className="size-4 shrink-0 text-ok" aria-label="available" />
            </li>
          ))}
        </ul>
      ) : view.kind === "sign-in" ? (
        <>
          <ul className="flex flex-col gap-1">
            {view.names.map((name) => (
              <li key={name} className="truncate font-mono text-[15px] text-muted-foreground">
                {name}
              </li>
            ))}
          </ul>
          <span className="text-sm text-muted-foreground">Sign in to check these under your own scope.</span>
        </>
      ) : (
        <span className="text-sm text-muted-foreground">No free variations found.</span>
      )}
    </Slot>
  );
}

type NameStates = { exact: PartState<"exact">; lookalike: PartState<"lookalike">; alternatives: PartState<"alternatives"> };

function NameSlots({ q, states }: { q: string; states: NameStates }) {
  return (
    <>
      <ExactSlot q={q} state={states.exact} />
      <ScopeSlot q={q} state={states.alternatives} />
      <LookalikeSlot state={states.lookalike} />
      <AlternativesSlot state={states.alternatives} />
    </>
  );
}

/** Desktop: a sidebar next to the results. */
function NamePanel({ q, states }: { q: string; states: NameStates }) {
  return (
    <section aria-label={`Name check for ${q}`} className="flex flex-col gap-3">
      <h2 className="text-[15px] font-medium">Name check</h2>
      <div className="flex flex-col divide-y overflow-hidden rounded-2xl border">
        <NameSlots q={q} states={states} />
      </div>
    </section>
  );
}

/** Phone: one line above the results that opens into the same four slots. */
function NameDisclosure({ q, states }: { q: string; states: NameStates }) {
  return (
    <details className="group overflow-hidden rounded-2xl border">
      <summary className="flex min-h-12 cursor-pointer list-none items-center justify-between gap-3 px-4 py-2.5 [&::-webkit-details-marker]:hidden">
        <span className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
          <span className="text-sm text-muted-foreground">Name check</span>
          <ExactStatus state={states.exact} />
        </span>
        <ChevronDownIcon className="size-4 shrink-0 text-muted-foreground transition-transform group-open:rotate-180" aria-hidden />
      </summary>
      <div className="flex flex-col divide-y border-t">
        <NameSlots q={q} states={states} />
      </div>
    </details>
  );
}

// ---------- results ----------

function ResultRow({ hit, q, id, active, reserveScore, onHover }: { hit: SearchHit; q: string; id: string; active: boolean; reserveScore: boolean; onHover: () => void }) {
  return (
    <li role="presentation" className="border-b" onMouseMove={onHover}>
      <Link
        id={id}
        role="option"
        aria-selected={active}
        href={packageHref(hit.name)}
        prefetch={false}
        tabIndex={-1}
        className={cn(
          "relative -mx-3 flex min-h-[4.25rem] items-center gap-4 rounded-xl px-3 py-3 transition-colors duration-100",
          active ? "bg-surface" : "hover:bg-surface/60",
        )}
      >
        <span className="flex min-w-0 flex-1 flex-col gap-0.5">
          <span className="flex min-w-0 items-center gap-2">
            <Highlight name={hit.name} q={q} className="text-[15px] sm:text-base" />
            <SourceTag source={hit.source} />
          </span>
          <span className="truncate text-sm text-muted-foreground">{hit.description || "No description"}</span>
        </span>
        <span className="hidden shrink-0 flex-col items-end gap-0.5 text-right font-mono text-[13px] text-muted-foreground tabular-nums sm:flex">
          <span>{hit.version}</span>
          {hit.weeklyDownloads !== null && <span>{compact.format(hit.weeklyDownloads)}/wk</span>}
        </span>
        {hit.score ? <ScoreBadge score={hit.score.score} grade={hit.score.grade} /> : reserveScore ? <span className="hidden w-[3.75rem] shrink-0 sm:block" aria-hidden /> : null}
        <CornerDownLeftIcon className={cn("hidden size-4 shrink-0 text-muted-foreground sm:block", active ? "opacity-100" : "opacity-0")} aria-hidden />
      </Link>
    </li>
  );
}

function Results({
  done,
  q,
  listId,
  active,
  setActive,
  retry,
}: {
  done: SearchDone;
  q: string;
  listId: string;
  active: number;
  setActive: (i: number) => void;
  retry: () => void;
}) {
  const again = (
    <button type="button" onClick={retry} className="font-medium text-foreground underline underline-offset-4 hover:no-underline">
      Try again
    </button>
  );

  if (done.kind === "error") {
    return <p className="border-t py-6 text-muted-foreground">The registry didn&apos;t answer. {again}</p>;
  }

  const { hits, total, upstreamFailed } = done.answer;
  // Keep the score column only when something in this answer has a stored score.
  const reserveScore = hits.some((h) => h.score !== null);

  return (
    <section aria-label="Search results" className="min-w-0">
      <div className="mb-2 flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 text-sm text-muted-foreground">
        <span className="tabular-nums">
          {hits.length === 0 ? "No results" : total > hits.length ? `Top ${hits.length} of ${total.toLocaleString("en")}` : `${hits.length} ${hits.length === 1 ? "result" : "results"}`}
        </span>
        {upstreamFailed && (
          <span className="inline-flex items-center gap-1.5 text-warn">
            <CloudOffIcon className="size-3.5" aria-hidden />
            npm didn&apos;t answer, showing this registry only
          </span>
        )}
      </div>
      {hits.length === 0 ? (
        <p className="border-t py-6 text-pretty text-muted-foreground">
          {upstreamFailed ? (
            <>
              Nothing on this registry matches <span className="font-mono text-foreground">{q}</span>, and npm results are missing because npm didn&apos;t answer. {again}
            </>
          ) : (
            <>
              Nothing on apm or npm matches <span className="font-mono text-foreground">{q}</span>.
            </>
          )}
        </p>
      ) : (
        <ul id={listId} role="listbox" aria-label="Packages" className="border-t">
          {hits.map((hit, i) => (
            <ResultRow key={hit.name} hit={hit} q={q} id={`${listId}-${i}`} active={i === active} reserveScore={reserveScore} onHover={() => setActive(i)} />
          ))}
        </ul>
      )}
    </section>
  );
}

// ---------- page ----------

export function SearchHome({ recent }: { recent: ReactNode }) {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);
  const listId = useId();
  const [value, setValue] = useState("");
  const q = normalize(value);
  const { current, shownQuery, pending, retry } = useLiveSearch(q);
  // Selection belongs to the answer it was made in, so a new answer starts unselected.
  const [selection, setSelection] = useState<{ query: string; index: number }>({ query: "", index: -1 });
  // Only a non-empty query has navigable results; after Esc the old answer must not open.
  const hits = q !== "" && current?.kind === "ok" ? current.answer.hits : [];
  const active = selection.query === shownQuery ? Math.min(selection.index, hits.length - 1) : -1;
  const setActive = (index: number) => setSelection({ query: shownQuery, index });
  const showName = q !== "" && looksLikePackageName(q);
  const nameQuery = showName ? q : null;

  const names: NameStates = {
    exact: useNamePart(nameQuery, "exact"),
    lookalike: useNamePart(nameQuery, "lookalike"),
    alternatives: useNamePart(nameQuery, "alternatives"),
  };

  // Read ?q= once after mount; the server never renders a query, so the shell stays static.
  useEffect(() => {
    const initial = new URLSearchParams(window.location.search).get("q") ?? "";
    delete document.documentElement.dataset.q;

    if (initial) setValue(initial);
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.key !== "/" && e.key !== "Escape") || e.metaKey || e.ctrlKey || e.altKey) return;
      const el = document.activeElement;

      if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || (el instanceof HTMLElement && el.isContentEditable)) return;
      e.preventDefault();

      // Esc clears from anywhere on the page (focus can sit on the body after back navigation).
      if (e.key === "Escape") clearRef.current();
      inputRef.current?.focus();
      inputRef.current?.select();
    };

    window.addEventListener("keydown", onKey);

    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (active < 0) return;
    document.getElementById(`${listId}-${active}`)?.scrollIntoView({ block: "nearest" });
  }, [active, listId]);

  function update(next: string) {
    setValue(next);

    if (normalize(next) === "") setSelection({ query: "", index: -1 });
    const url = urlFor(normalize(next));

    if (url !== `${window.location.pathname}${window.location.search}`) window.history.replaceState(null, "", url);
  }

  const clearRef = useRef(() => update(""));
  useEffect(() => {
    clearRef.current = () => update("");
  });

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      if (hits.length === 0) return;
      e.preventDefault();
      const step = e.key === "ArrowDown" ? 1 : -1;
      const next = active + step;
      setActive(next < -1 ? hits.length - 1 : next >= hits.length ? hits.length - 1 : next);
    } else if (e.key === "Enter") {
      const hit = hits[active >= 0 ? active : 0];

      if (!hit) return;
      e.preventDefault();
      router.push(packageHref(hit.name));
    } else if (e.key === "Escape") {
      e.preventDefault();
      update("");
    }
  }


  return (
    <div className="flex flex-col">
      <h1 className="sr-only">Search packages</h1>
      <div role="search" className="relative">
        <SearchIcon className="pointer-events-none absolute top-1/2 left-5 size-5 -translate-y-1/2 text-muted-foreground" aria-hidden />
        <input
          ref={inputRef}
          type="search"
          value={value}
          autoFocus
          autoComplete="off"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          enterKeyHint="go"
          placeholder="Search apm and npm"
          aria-label="Search packages"
          role="combobox"
          aria-expanded={hits.length > 0}
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={active >= 0 ? `${listId}-${active}` : undefined}
          onChange={(e) => update(e.target.value)}
          onKeyDown={onKeyDown}
          className="h-14 w-full rounded-2xl border border-transparent bg-surface pr-24 pl-13 font-mono text-lg outline-none transition-[background-color,border-color,box-shadow] duration-150 placeholder:font-sans placeholder:text-muted-foreground hover:border-border focus-visible:border-ring/60 focus-visible:bg-background focus-visible:shadow-[0_0_0_4px_color-mix(in_oklab,var(--ring)_18%,transparent)] focus-visible:outline-none sm:h-16 sm:text-xl [&::-webkit-search-cancel-button]:appearance-none"
        />
        <span className="absolute top-1/2 right-4 flex -translate-y-1/2 items-center gap-2">
          {value ? (
            <button
              type="button"
              onClick={() => {
                update("");
                inputRef.current?.focus();
              }}
              className="grid size-8 place-items-center rounded-lg text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground"
              aria-label="Clear search"
            >
              <XIcon className="size-4" />
            </button>
          ) : (
            <kbd className="hidden h-6 min-w-6 place-items-center rounded-md border bg-background px-1.5 font-mono text-xs text-muted-foreground sm:grid">/</kbd>
          )}
        </span>
        {/* Thin progress line; only shows when a request takes longer than a blink. */}
        <span
          aria-hidden
          className={cn(
            "pointer-events-none absolute inset-x-5 bottom-0 h-0.5 overflow-hidden rounded-full transition-opacity",
            pending ? "opacity-100 delay-150 duration-150" : "opacity-0 duration-300",
          )}
        >
          <span className="block h-full w-1/3 animate-[apm-progress_0.9s_ease-in-out_infinite] rounded-full bg-foreground/50" />
        </span>
      </div>
      <p className="sr-only" aria-live="polite">
        {pending ? "Searching" : current?.kind === "ok" ? `${current.answer.hits.length} results for ${shownQuery}` : ""}
      </p>

      {q === "" ? (
        <div data-recent className="mt-10">
          {recent}
        </div>
      ) : (
        <div className="mt-6 grid gap-x-10 gap-y-5 lg:grid-cols-[minmax(0,1fr)_300px]">
          {showName && (
            <div className="lg:hidden">
              <NameDisclosure q={q} states={names} />
            </div>
          )}
          <div className={cn("min-w-0 transition-opacity duration-200", pending && current ? "opacity-70" : "")}>
            {current ? (
              <Results done={current} q={shownQuery} listId={listId} active={active} setActive={setActive} retry={retry} />
            ) : (
              <div aria-hidden className="flex flex-col">
                <Line className="mb-4 w-24" />
                {[0, 1, 2, 3, 4].map((i) => (
                  <span key={i} className="flex h-[4.25rem] flex-col justify-center gap-2 border-t">
                    <Line className="w-48" />
                    <Line className="w-80 max-w-full" />
                  </span>
                ))}
              </div>
            )}
          </div>
          {showName && (
            <aside className="hidden lg:sticky lg:top-24 lg:block lg:self-start">
              <NamePanel q={q} states={names} />
            </aside>
          )}
        </div>
      )}
    </div>
  );
}
