"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "cn";
import { clickEvent } from "@/lib/databuddy-client";

const LINKS = [
  { href: "/publish", label: "Publish" },
  { href: "/compare", label: "Compare" },
  // the docs site (apps/docs); /docs stays as a short overview that links into it
  { href: "https://docs.apmjs.dev", label: "Docs" },
] as const;

function Links({ current }: { current: string | null }) {
  return (
    <nav aria-label="Main" className="flex items-center gap-0.5 sm:gap-1">
      {LINKS.map((l) => {
        const active = current === l.href;

        const className = cn(
          "inline-flex h-9 items-center rounded-full px-2.5 text-[15px] font-medium transition-colors sm:px-3.5",
          active ? "bg-secondary text-foreground" : "text-muted-foreground hover:text-foreground",
        );

        // /publish is a private route: use a plain anchor so leaving a tracked page is a direct full navigation
        if (l.href === "/publish") {
          return (
            <a key={l.href} href={l.href} aria-current={active ? "page" : undefined} className={className}>
              {l.label}
            </a>
          );
        }

        const event = l.href === "https://docs.apmjs.dev" ? clickEvent({ name: "docs_cta_clicked", props: { location: "nav" } }) : {};

        return (
          <Link key={l.href} href={l.href} aria-current={active ? "page" : undefined} className={className} {...event}>
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
