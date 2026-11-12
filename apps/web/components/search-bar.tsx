"use client";

import { useEffect, useRef, useState, useTransition } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { SearchIcon, LoaderCircleIcon } from "lucide-react";

/** One stationary input; the query lives in ?q= so every search is a shareable URL. */
export function SearchBar({ autoFocus = false }: { autoFocus?: boolean }) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const [value, setValue] = useState(params.get("q") ?? "");
  const [pending, startTransition] = useTransition();
  const inputRef = useRef<HTMLInputElement>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "/" && document.activeElement !== inputRef.current) {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  function go(next: string) {
    const q = next.trim();
    const url = q ? `/?q=${encodeURIComponent(q)}` : "/";
    startTransition(() => (pathname === "/" ? router.replace(url, { scroll: false }) : router.push(url)));
  }

  return (
    <form
      role="search"
      className="relative w-full"
      onSubmit={(e) => {
        e.preventDefault();
        if (timer.current) clearTimeout(timer.current);
        go(value);
      }}
    >
      <SearchIcon className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
      <input
        ref={inputRef}
        type="search"
        name="q"
        value={value}
        autoFocus={autoFocus}
        autoComplete="off"
        autoCapitalize="none"
        spellCheck={false}
        placeholder="Search or check a name"
        aria-label="Search packages"
        className="h-11 w-full rounded-lg border border-input bg-background pr-16 pl-9 text-sm outline-none [&:not(:placeholder-shown)]:font-mono transition-[border-color,box-shadow] placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/40"
        onChange={(e) => {
          const next = e.target.value;
          setValue(next);
          if (timer.current) clearTimeout(timer.current);
          if (pathname === "/") timer.current = setTimeout(() => go(next), 180);
        }}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            setValue("");
            go("");
          }
        }}
      />
      <span className="pointer-events-none absolute top-1/2 right-3 flex -translate-y-1/2 items-center gap-2 text-muted-foreground">
        {pending ? <LoaderCircleIcon className="size-4 animate-spin" aria-label="Searching" /> : <kbd className="rounded border px-1.5 font-mono text-[11px]">/</kbd>}
      </span>
    </form>
  );
}
