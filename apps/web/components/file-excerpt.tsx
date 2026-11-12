"use client";

// The lines around a citation in a file too large to show whole (over 1 MB, often a bundle). The server renders
// the first window; "Show more" fetches further lines from the registry through this site's /-/apm/v1/ proxy.
// Package code is untrusted: lines are text children only, hidden characters become markers, and a line the
// registry cut says so in a marker that is styled apart from the file's own text.
import { useEffect, useState } from "react";
import { ChevronDownIcon, ChevronUpIcon } from "lucide-react";
import { displayLine } from "@/lib/file-lines";
import { ExcerptAnswer, mergeLines, MORE_LINES, moreRequest, type Excerpt, type ExcerptLine } from "@/lib/file-excerpt";
import { formatSize } from "@/lib/format";
import { excerptApiPath } from "@/lib/registry-url";
import { LineFocus } from "./line-focus";

type Direction = "above" | "below";

const NO_ANCHORS: readonly [] = [];

/** An old link that names the line only in its fragment (#L12) reloads with ?line=, so the server can centre on it. */
function useLineFromFragment(cited: number | null) {
  useEffect(() => {
    if (cited !== null) return;
    const m = /^#L(\d{1,9})$/.exec(window.location.hash);
    const line = m ? Number(m[1]) : 0;

    if (line >= 1) window.location.replace(`${window.location.pathname}?line=${line}#L${line}`);
  }, [cited]);
}

function MoreButton({ direction, hidden, busy, onClick }: { direction: Direction; hidden: number; busy: boolean; onClick: () => void }) {
  const Icon = direction === "above" ? ChevronUpIcon : ChevronDownIcon;
  const count = Math.min(hidden, MORE_LINES);

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={busy}
      aria-busy={busy}
      className={`flex min-h-11 w-full items-center justify-center gap-2 px-4 text-[13px] text-inverse-muted transition-colors hover:bg-inverse-raised hover:text-inverse-foreground disabled:cursor-wait disabled:hover:bg-transparent ${direction === "above" ? "border-b" : "border-t"} border-inverse-border`}
    >
      <Icon className="size-4" aria-hidden />
      {busy ? "Loading lines…" : `Show ${count.toLocaleString("en")} more ${count === 1 ? "line" : "lines"} ${direction}`}
      <span className="tabular-nums text-inverse-muted/80">· {hidden.toLocaleString("en")} not shown</span>
    </button>
  );
}

function Lines({ lines }: { lines: readonly ExcerptLine[] }) {
  return lines.map((l) => (
    <span key={l.n}>
      {displayLine(l.text)}
      {l.truncated && (
        <span className="ml-3 rounded bg-inverse-raised px-1.5 font-sans text-[12px] text-inverse-warn select-none">… line truncated, {formatSize(l.truncated.bytes)} in all</span>
      )}
      {"\n"}
    </span>
  ));
}

export function ExcerptView({ excerpt, cited }: { excerpt: Excerpt; cited: number | null }) {
  const [lines, setLines] = useState<ExcerptLine[]>(excerpt.lines);
  const [busy, setBusy] = useState<Direction | null>(null);
  const [failed, setFailed] = useState(false);
  const total = excerpt.totalLines;
  const from = lines[0]?.n ?? excerpt.from;
  const to = lines.at(-1)?.n ?? excerpt.to;
  const digits = String(to).length;

  useLineFromFragment(cited);

  const more = async (direction: Direction) => {
    const req = moreRequest({ from, to, total, direction });

    if (!req || busy) return;
    setBusy(direction);
    setFailed(false);

    try {
      const res = await fetch(`/${excerptApiPath({ name: excerpt.name, version: excerpt.version, path: excerpt.path, ...req })}`, { headers: { accept: "application/json" } });
      const parsed = ExcerptAnswer.safeParse(res.ok ? await res.json() : null);

      if (parsed.success && parsed.data.kind === "excerpt") {
        const got = parsed.data.lines;

        setLines((shown) => mergeLines(shown, got));
      } else {
        setFailed(true);
      }
    } catch {
      setFailed(true);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="overflow-hidden rounded-2xl bg-inverse text-inverse-foreground">
        <div className="flex items-center justify-between gap-4 border-b border-inverse-border px-4 py-2.5 text-[13px] text-inverse-muted sm:px-5">
          <span className="min-w-0 truncate font-mono">{excerpt.path}</span>
          <span className="shrink-0 tabular-nums">
            Lines {from.toLocaleString("en")}–{to.toLocaleString("en")} of {total.toLocaleString("en")}
          </span>
        </div>
        {from > 1 && <MoreButton direction="above" hidden={from - 1} busy={busy === "above"} onClick={() => void more("above")} />}
        {/* A keyboard user can scroll the code sideways once it has focus. */}
        <div role="region" aria-label={`Lines ${from} to ${to} of ${excerpt.path}`} tabIndex={0} className="overflow-x-auto outline-none focus-visible:ring-2 focus-visible:ring-inverse-muted focus-visible:ring-inset">
          <div className="relative w-max min-w-full py-3 font-mono text-[12.5px] leading-5">
            <LineFocus first={from} last={to} anchors={NO_ANCHORS} fallback={cited} />
            <div data-start={from} className="flex">
              <pre data-gutter aria-hidden className="sticky left-0 z-[1] shrink-0 cursor-pointer bg-inverse pr-4 pl-4 text-right text-inverse-muted select-none sm:pl-5" style={{ width: `calc(${digits}ch + 2.25rem)` }}>
                {lines.map((l) => l.n).join("\n")}
              </pre>
              <pre className="pr-6">
                <code>
                  <Lines lines={lines} />
                </code>
              </pre>
            </div>
          </div>
        </div>
        {to < total && <MoreButton direction="below" hidden={total - to} busy={busy === "below"} onClick={() => void more("below")} />}
      </div>
      {failed && (
        <p role="alert" className="text-sm text-bad">
          Couldn&apos;t load more lines: the registry did not answer. Try again.
        </p>
      )}
    </div>
  );
}
