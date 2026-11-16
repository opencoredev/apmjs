"use client";

import { Fragment, useRef, useState, type ReactNode } from "react";
import { CheckIcon, CopyIcon } from "lucide-react";
import { cn } from "cn";

/** Clipboard API needs a secure context (HTTPS); fall back to a hidden textarea on plain HTTP. */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard) {
      await navigator.clipboard.writeText(text);

      return true;
    }
  } catch {
    // fall through to the textarea route
  }

  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;

  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }

  ta.remove();

  return ok;
}

export type CopyState = "idle" | "copied" | "manual";

/** What useCopy hands back: the last copy's outcome, and the function that copies. */
export type Copier = { state: CopyState; copy: (text: string, onFail?: () => void) => void };

/** Copies on demand and holds the outcome long enough to show it: a tick for a copy, a hint when it failed. */
export function useCopy(): Copier {
  const [state, setState] = useState<CopyState>("idle");

  return {
    state,
    copy(text, onFail) {
      void copyText(text).then((ok) => {
        setState(ok ? "copied" : "manual");

        if (!ok) onFail?.();
        setTimeout(() => setState("idle"), ok ? 1500 : 3000);
      });
    },
  };
}

/** The copy and check icons, cross-faded in place so the button never changes size. */
export function CopyGlyph({ copied, className }: { copied: boolean; className?: string }) {
  return (
    <span className={cn("relative grid size-4 place-items-center", className)} aria-hidden>
      <CopyIcon className={cn("col-start-1 row-start-1 size-4 transition-[opacity,scale] duration-150", copied ? "scale-50 opacity-0" : "scale-100 opacity-100")} />
      <CheckIcon className={cn("col-start-1 row-start-1 size-4 text-ok transition-[opacity,scale] duration-150", copied ? "scale-100 opacity-100" : "scale-50 opacity-0")} />
    </span>
  );
}

/** A polite live region that says what a copy did; visible only when the copy failed. */
export function CopyStatus({ state, manual, className }: { state: CopyState; manual: ReactNode; className?: string }) {
  return (
    <p role="status" aria-live="polite" className={state === "manual" ? cn("text-[13px] leading-5 text-warn", className) : "sr-only"}>
      {state === "manual" ? manual : state === "copied" ? "Copied" : ""}
    </p>
  );
}

/** The text with a line-break opportunity after each "=", so a setting like registry=<url> wraps before the URL, never inside it. */
function SettingBreaks({ text }: { text: string }) {
  const parts = text.split(/(?<==)/);

  return parts.map((part, i) => (
    <Fragment key={i}>
      {part}
      {i < parts.length - 1 && <wbr />}
    </Fragment>
  ));
}

/**
 * Text in a filled block with a copy button on its right edge. Lines wrap at spaces and after "=" (the copied text
 * has no breaks added); a longer word scrolls sideways. `wrap` breaks long words anywhere, for prose;
 * `oneLine` keeps a single setting on one line (smaller on phones, scrolling if it still does not fit).
 */
export function CopyBlock({ text, label, caption, wrap = false, oneLine = false }: { text: string; label: string; caption?: ReactNode; wrap?: boolean; oneLine?: boolean }) {
  const { state, copy } = useCopy();
  const preRef = useRef<HTMLPreElement>(null);

  return (
    <figure className="flex min-w-0 flex-col gap-1.5">
      {caption && <figcaption className="text-[13px] text-muted-foreground">{caption}</figcaption>}
      <div className={cn("flex gap-1 rounded-xl bg-surface py-1.5 pr-1.5 pl-3 sm:pl-4", oneLine ? "items-center" : "items-start")}>
        <pre
          ref={preRef}
          className={cn(
            "min-w-0 flex-1 py-2 font-mono leading-5 text-foreground",
            oneLine ? "overflow-x-auto text-[11.5px] whitespace-pre sm:text-[13px]" : "text-[12px] sm:text-[13px]",
            !oneLine && (wrap ? "whitespace-pre-wrap [overflow-wrap:anywhere]" : "overflow-x-auto whitespace-pre-wrap"),
          )}
        >
          {wrap ? text : <SettingBreaks text={text} />}
        </pre>
        <button
          type="button"
          aria-label={state === "copied" ? "Copied" : label}
          className={cn(
            "grid size-9 shrink-0 place-items-center rounded-lg text-muted-foreground transition-[background-color,color,scale] duration-150 hover:text-foreground active:scale-[0.96]",
            "hover:bg-background",
          )}
          onClick={() =>
            copy(text, () => {
              if (preRef.current) window.getSelection()?.selectAllChildren(preRef.current);
            })
          }
        >
          <CopyGlyph copied={state === "copied"} />
        </button>
      </div>
      <CopyStatus state={state} manual="Couldn't copy automatically. The text is selected: press Ctrl+C or ⌘C." />
    </figure>
  );
}
