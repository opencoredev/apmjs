"use client";

// The file view's highlighted line. The view renders blocks of plain text, not one element per line, so a
// 1 MB file stays light on a phone; every line is one 20px row, so a line's position is arithmetic. This reads
// #L12 (or a package.json anchor like #scripts.postinstall), places the highlight on that row and scrolls to it.
// Clicking a line number moves the highlight there and puts #L<n> in the address bar. When the line is wider
// than the code box (a phone, a minified file), a bar at the bottom of the screen shows all of it, wrapped.
// An excerpt of a large file shows lines `first` to `last` only; the arithmetic starts at `first`.
import { useEffect, useRef, useState } from "react";
import { XIcon } from "lucide-react";

/** Row height and top padding of the text, in px: leading-5 and py-3 in file-view.tsx. */
const ROW = 20;
const PAD = 12;

/** A named place in the file (a package.json script) and the line it opens at. */
export type LineAnchor = { anchor: string; line: number };

type Cited = { line: number; text: string };

/** The text of one line, read back from the rendered block that holds it. */
function lineText(body: HTMLElement, line: number): { text: string; code: HTMLElement } | null {
  for (const block of body.querySelectorAll<HTMLElement>("[data-start]")) {
    const start = Number(block.dataset.start);
    const code = block.querySelector("code");

    if (!code || line < start) continue;
    const text = (code.textContent ?? "").split("\n")[line - start];

    if (text !== undefined) return { text, code };
  }

  return null;
}

/** Whether `text` would run past the right edge of the code box. */
function overflows(body: HTMLElement, code: HTMLElement, text: string): boolean {
  const box = body.parentElement;
  const ctx = document.createElement("canvas").getContext("2d");

  if (!box || !ctx) return false;
  ctx.font = getComputedStyle(code).font;

  return code.getBoundingClientRect().left - box.getBoundingClientRect().left + ctx.measureText(text).width > box.clientWidth;
}

type Props = {
  /** The first and last line shown. */
  first?: number;
  last: number;
  anchors: readonly LineAnchor[];
  /** The line to mark when the address names none (an excerpt opened with ?line= and no #L). */
  fallback?: number | null;
};

export function LineFocus({ first = 1, last, anchors, fallback = null }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [cited, setCited] = useState<Cited | null>(null);
  // an excerpt that grows ("Show more") re-places the mark without scrolling back to it
  const scrolled = useRef(false);

  useEffect(() => {
    const mark = ref.current;
    const body = mark?.parentElement;

    if (!mark || !body) return;

    const lineOf = (hash: string): number | null => {
      let id: string;

      try {
        id = decodeURIComponent(hash.replace(/^#/, ""));
      } catch {
        return null;
      }

      const m = /^L(\d+)$/.exec(id);
      const n = m ? Number(m[1]) : (anchors.find((a) => a.anchor === id)?.line ?? (id === "" ? fallback : null));

      return n !== null && n >= first && n <= last ? n : null;
    };

    const show = (scroll: boolean) => {
      const line = lineOf(window.location.hash);

      mark.hidden = line === null;

      if (line === null) {
        setCited(null);

        return;
      }

      mark.style.top = `${PAD + (line - first) * ROW}px`;
      mark.dataset.line = String(line);

      if (scroll) mark.scrollIntoView({ block: "center" });
      const found = lineText(body, line);

      setCited(found && overflows(body, found.code, found.text) ? { line, text: found.text } : null);
    };

    const onHash = () => show(true);

    const onClick = (e: MouseEvent) => {
      const gutter = e.target instanceof Element ? e.target.closest("[data-gutter]") : null;
      const start = Number(gutter?.parentElement?.dataset.start);

      if (!gutter || !Number.isInteger(start)) return;
      const line = Math.min(last, start + Math.max(0, Math.floor((e.clientY - gutter.getBoundingClientRect().top) / ROW)));

      window.history.replaceState(window.history.state, "", `#L${line}`);
      show(false);
    };

    show(!scrolled.current);
    scrolled.current = true;
    window.addEventListener("hashchange", onHash);
    body.addEventListener("click", onClick);

    return () => {
      window.removeEventListener("hashchange", onHash);
      body.removeEventListener("click", onClick);
    };
  }, [first, last, anchors, fallback]);

  return (
    <>
      <div ref={ref} hidden aria-hidden className="pointer-events-none absolute inset-x-0 z-[2] h-5 border-l-2 border-inverse-warn bg-inverse-foreground/15" />
      {cited && (
        <div role="region" aria-label={`Line ${cited.line}`} className="fixed inset-x-3 bottom-3 z-30 mx-auto max-w-3xl rounded-xl border border-inverse-border bg-inverse-raised text-inverse-foreground shadow-lg">
          <div className="flex items-center justify-between gap-3 border-b border-inverse-border py-1 pr-1 pl-4">
            <span className="text-[13px] text-inverse-muted tabular-nums">Line {cited.line}, in full</span>
            <button type="button" onClick={() => setCited(null)} aria-label="Close" className="flex size-9 items-center justify-center rounded-lg text-inverse-muted transition-colors hover:bg-inverse hover:text-inverse-foreground">
              <XIcon className="size-4" aria-hidden />
            </button>
          </div>
          <pre className="max-h-36 overflow-y-auto px-4 py-2.5 font-mono text-[12.5px] leading-5 whitespace-pre-wrap [overflow-wrap:anywhere]">{cited.text.trimStart()}</pre>
        </div>
      )}
    </>
  );
}
