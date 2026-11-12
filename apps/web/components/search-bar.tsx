"use client";

import { useEffect, useRef, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { SearchIcon } from "lucide-react";

/** Header search for pages other than home. Enter opens the home page with the query; "/" focuses it. */
export function SearchBar() {
  const router = useRouter();
  const pathname = usePathname();
  const [value, setValue] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const onHome = pathname === "/";

  useEffect(() => {
    if (onHome) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey) return;
      const el = document.activeElement;
      if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || (el instanceof HTMLElement && el.isContentEditable)) return;
      e.preventDefault();
      inputRef.current?.focus();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onHome]);

  if (onHome) return null;

  return (
    <form
      role="search"
      className="relative order-last w-full sm:order-none sm:w-auto sm:max-w-xl sm:flex-1"
      onSubmit={(e) => {
        e.preventDefault();
        const q = value.trim().toLowerCase();
        router.push(q ? `/?q=${encodeURIComponent(q)}` : "/");
      }}
    >
      <SearchIcon className="pointer-events-none absolute top-1/2 left-3.5 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
      <input
        ref={inputRef}
        type="search"
        name="q"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Escape") setValue("");
        }}
        autoComplete="off"
        autoCapitalize="none"
        spellCheck={false}
        enterKeyHint="search"
        placeholder="Search packages"
        aria-label="Search packages"
        className="h-10 w-full rounded-xl border border-transparent bg-surface pr-11 pl-10 text-[15px] outline-none transition-[background-color,border-color] duration-150 placeholder:text-muted-foreground hover:border-border focus-visible:border-ring/60 focus-visible:bg-background focus-visible:outline-none [&:not(:placeholder-shown)]:font-mono [&::-webkit-search-cancel-button]:appearance-none"
      />
      <kbd className="pointer-events-none absolute top-1/2 right-3 grid h-5 min-w-5 -translate-y-1/2 place-items-center rounded-md border bg-background px-1 font-mono text-[11px] text-muted-foreground">/</kbd>
    </form>
  );
}
