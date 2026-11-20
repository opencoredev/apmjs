"use client";

// Header search for pages other than home, with results as you type.
// - It is a real GET form to /, so Enter before React hydrates (a package page streams for a while) still opens
//   /?q=<query> instead of reloading the current page.
// - After hydration a dropdown shows the top hits from /api/search. Arrows move the highlight, Enter opens the
//   highlighted package or the home page's results, Escape and a click outside close it, "/" focuses the box.

import Link from "next/link";
import { useEffect, useId, useRef, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { CornerDownLeftIcon, LoaderCircleIcon, SearchIcon } from "lucide-react";
import { cn } from "cn";
import { ScoreBadge } from "@/components/score-badge";
import { Highlight, useLiveSearch, useTypedBeforeHydration, type SearchDone } from "@/components/live-search";
import { afterNavigation, type HeaderSearch } from "@/lib/header-search";
import { moveActive, normalizeQuery, packageHref, searchHref, submitHref, topHits } from "@/lib/typeahead";
import type { SearchHit } from "@/lib/search-schema";

// Rows highlight with --accent: in dark mode --surface is the popover's own color.
function Option({ hit, q, id, active, onHover, onPick }: { hit: SearchHit; q: string; id: string; active: boolean; onHover: () => void; onPick: () => void }) {
  return (
    <li role="presentation" onMouseMove={onHover}>
      <Link
        id={id}
        role="option"
        aria-selected={active}
        href={packageHref(hit.name)}
        prefetch={false}
        tabIndex={-1}
        onClick={onPick}
        className={cn("flex min-h-13 items-center gap-3 rounded-lg px-3 py-2 transition-colors duration-100", active ? "bg-accent" : "hover:bg-accent/60")}
      >
        <span className="flex min-w-0 flex-1 flex-col">
          <Highlight name={hit.name} q={q} className="text-[14px] leading-5" />
          <span className="truncate text-[13px] leading-5 text-muted-foreground">{hit.description || "No description"}</span>
        </span>
        <ScoreBadge score={hit.score?.score} grade={hit.score?.grade} className="h-6 min-w-13 gap-1 rounded-md px-1.5 text-[12px]" />
      </Link>
    </li>
  );
}

/** What the dropdown says about the answer: searching, a failure, npm missing from it, or no match. Null: hits only. */
export function noteText({ done, q, hasHits }: { done: SearchDone | null; q: string; hasHits: boolean }): string | null {
  if (done === null) return hasHits ? null : "Searching";

  if (done.kind === "error") return "Search didn't answer.";
  // npm's search failed: an empty list is not proof that nothing matches

  if (done.answer.upstreamFailed) return hasHits ? "npm search didn't answer; showing packages published on apm only." : "npm search didn't answer.";

  return hasHits ? null : `No packages match ${q}.`;
}

/** The line under the hits, or in place of them while there are none to show; failures offer a retry. */
function Note({ done, q, hasHits, onRetry }: { done: SearchDone | null; q: string; hasHits: boolean; onRetry: () => void }) {
  const text = noteText({ done, q, hasHits });

  if (text === null) return null;
  const failed = done !== null && (done.kind === "error" || done.answer.upstreamFailed);

  return (
    <p className="flex min-h-11 items-center gap-2 px-3 text-[13px] text-muted-foreground">
      {done === null && <LoaderCircleIcon className="size-3.5 animate-spin" aria-hidden />}
      {text}
      {failed && (
        <button type="button" onClick={onRetry} className="ml-auto rounded-md px-2 py-1 font-medium text-foreground hover:bg-accent/60 focus-visible:outline-2 focus-visible:outline-ring">
          Try again
        </button>
      )}
    </p>
  );
}

/** What screen readers hear about the dropdown. */
export function announcement({ done, pending, q, count }: { done: SearchDone | null; pending: boolean; q: string; count: number }): string {
  if (pending || done === null) return "Searching";

  if (done.kind === "error") return "Search didn't answer. Try again.";
  const counted = `${count} ${count === 1 ? "package" : "packages"} for ${q}`;

  return done.answer.upstreamFailed ? `npm search didn't answer. ${counted} published on apm.` : counted;
}

export function SearchBar() {
  const router = useRouter();
  const pathname = usePathname();
  const [field, setField] = useState<HeaderSearch>({ path: pathname, value: "" });
  // Selection belongs to the answer it was made in, so a new answer starts with nothing highlighted.
  const [selection, setSelection] = useState({ query: "", index: -1 });
  const next = afterNavigation(field, pathname);

  // a new page starts with an empty field; set during render so the old query never paints on it
  if (next !== field) {
    setField(next);
    // nor does an old highlight come back when the same query is typed again
    setSelection({ query: "", index: -1 });
  }

  const value = next.value;
  const setValue = (v: string) => setField({ path: pathname, value: v });
  const inputRef = useRef<HTMLInputElement>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const listId = useId();
  const onHome = pathname === "/";
  const q = normalizeQuery(value);
  const [open, setOpen] = useState(false);
  const { current, shownQuery, pending, retry } = useLiveSearch(onHome ? "" : q);
  const hits = q !== "" && current?.kind === "ok" ? topHits({ hits: current.answer.hits, q: shownQuery }) : [];
  // Only an answer for exactly what is typed can be highlighted: Enter on an older list searches what is typed.
  const fresh = shownQuery === q;
  const active = fresh && selection.query === q ? Math.min(selection.index, hits.length - 1) : -1;
  const expanded = open && q !== "";
  const showList = expanded && hits.length > 0;
  // Enter opens a highlighted row only while the list that shows it is on screen (review of cd74781, finding 1)
  const submitActive = showList ? active : -1;

  const close = () => {
    setOpen(false);
    setSelection({ query: "", index: -1 });
  };

  // Typed while the page was still streaming: search it now, and open the dropdown if the box still has focus.
  useTypedBeforeHydration(inputRef, (typed, focused) => {
    setField({ path: pathname, value: typed });

    if (focused) setOpen(true);
  });

  useEffect(() => {
    if (onHome) return;

    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey) return;
      const el = document.activeElement;

      if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || (el instanceof HTMLElement && el.isContentEditable)) return;
      e.preventDefault();
      inputRef.current?.focus();
      inputRef.current?.select();
    };

    window.addEventListener("keydown", onKey);

    return () => window.removeEventListener("keydown", onKey);
  }, [onHome]);

  // A press anywhere outside the form closes the dropdown.
  useEffect(() => {
    if (!expanded) return;

    const onDown = (e: PointerEvent) => {
      if (e.target instanceof Node && formRef.current?.contains(e.target)) return;
      setOpen(false);
      setSelection({ query: "", index: -1 });
    };

    document.addEventListener("pointerdown", onDown);

    return () => document.removeEventListener("pointerdown", onDown);
  }, [expanded]);

  useEffect(() => {
    if (active < 0) return;
    document.getElementById(`${listId}-${active}`)?.scrollIntoView({ block: "nearest" });
  }, [active, listId]);

  if (onHome) return null;

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    // an input method is composing: its keys pick characters, not packages (review of cd74781, finding 2)
    if (e.nativeEvent.isComposing || e.keyCode === 229) {
      if (e.key === "Enter") e.preventDefault();

      return;
    }

    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();

      if (!expanded) {
        setOpen(true);

        return;
      }

      if (fresh) setSelection({ query: q, index: moveActive({ active, count: hits.length, key: e.key }) });
    } else if (e.key === "Escape") {
      e.preventDefault();

      if (expanded) close();
      else setValue("");
    }
  }

  return (
    <form
      ref={formRef}
      role="search"
      action="/"
      method="get"
      className="relative order-last w-full sm:order-none sm:w-auto sm:max-w-xl sm:flex-1"
      onSubmit={(e) => {
        e.preventDefault();
        close();
        router.push(submitHref({ q: value, hits, active: submitActive }));
      }}
      onBlur={(e) => {
        if (!(e.relatedTarget instanceof Node && e.currentTarget.contains(e.relatedTarget))) close();
      }}
    >
      <SearchIcon className="pointer-events-none absolute top-1/2 left-3.5 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
      <input
        ref={inputRef}
        type="search"
        name="q"
        value={value}
        onChange={(e) => {
          setValue(e.target.value);
          setOpen(true);
        }}
        onFocus={() => setOpen(true)}
        onKeyDown={onKeyDown}
        role="combobox"
        aria-expanded={showList}
        aria-controls={showList ? listId : undefined}
        aria-autocomplete="list"
        aria-activedescendant={showList && active >= 0 ? `${listId}-${active}` : undefined}
        autoComplete="off"
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
        enterKeyHint="search"
        placeholder="Search packages"
        aria-label="Search packages"
        className="h-10 w-full rounded-xl border border-transparent bg-surface pr-11 pl-10 text-[15px] outline-none transition-[background-color,border-color] duration-150 placeholder:text-muted-foreground hover:border-border focus-visible:border-ring/60 focus-visible:bg-background focus-visible:outline-none [&:not(:placeholder-shown)]:font-mono [&::-webkit-search-cancel-button]:appearance-none"
      />
      <kbd className="pointer-events-none absolute top-1/2 right-3 grid h-5 min-w-5 -translate-y-1/2 place-items-center rounded-md border bg-background px-1 font-mono text-[11px] text-muted-foreground">/</kbd>
      {expanded && (
        // mousedown would move focus off the input and close the list before a click on a row lands
        <div
          className="absolute inset-x-0 top-full z-30 mt-2 flex max-h-[min(70dvh,30rem)] flex-col overflow-hidden rounded-xl border bg-popover text-popover-foreground shadow-lg"
          onMouseDown={(e) => e.preventDefault()}
        >
          {showList && (
            <ul id={listId} role="listbox" aria-label="Packages" aria-busy={pending} className={cn("min-h-0 overflow-y-auto p-1 transition-opacity duration-150", pending && "opacity-80")}>
              {hits.map((hit, i) => (
                <Option
                  key={hit.name}
                  hit={hit}
                  q={shownQuery}
                  id={`${listId}-${i}`}
                  active={i === active}
                  onHover={() => fresh && setSelection({ query: q, index: i })}
                  onPick={close}
                />
              ))}
            </ul>
          )}
          <Note
            done={current}
            q={shownQuery}
            hasHits={showList}
            onRetry={() => {
              // the button goes away while the retry runs: keep the keyboard in the box (re-check of 4cc6a62)
              inputRef.current?.focus();
              retry();
            }}
          />
          <Link
            href={searchHref(q)}
            prefetch={false}
            tabIndex={-1}
            onClick={close}
            className="flex min-h-11 shrink-0 items-center justify-between gap-3 border-t px-4 text-[13px] text-muted-foreground transition-colors hover:bg-accent/60 hover:text-foreground"
          >
            <span className="min-w-0 truncate">
              All results for <span className="font-mono text-foreground">{q}</span>
            </span>
            <CornerDownLeftIcon className={cn("size-3.5 shrink-0", active >= 0 && "opacity-0")} aria-hidden />
          </Link>
        </div>
      )}
      {/* one stable polite region for loading, failures, partial answers and counts (review of cd74781, finding 4) */}
      <p className="sr-only" role="status" aria-live="polite">
        {expanded ? announcement({ done: fresh ? current : null, pending, q, count: hits.length }) : ""}
      </p>
    </form>
  );
}
