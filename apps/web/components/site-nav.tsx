"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "cn";

const LINKS = [
  { href: "/publish", label: "Publish" },
  { href: "/compare", label: "Compare" },
  { href: "/docs", label: "Docs" },
] as const;

function Links({ current }: { current: string | null }) {
  return (
    <nav aria-label="Main" className="flex items-center gap-0.5 sm:gap-1">
      {LINKS.map((l) => {
        const active = current === l.href;

        return (
          <Link
            key={l.href}
            href={l.href}
            aria-current={active ? "page" : undefined}
            className={cn(
              "inline-flex h-9 items-center rounded-full px-2.5 text-[15px] font-medium transition-colors sm:px-3.5",
              active ? "bg-secondary text-foreground" : "text-muted-foreground hover:text-foreground",
            )}
          >
            {l.label}
          </Link>
        );
      })}
    </nav>
  );
}

/** Static fallback for the Suspense boundary: same links, no active state. */
export function SiteNavFallback() {
  return <Links current={null} />;
}

export function SiteNav() {
  return <Links current={usePathname()} />;
}
