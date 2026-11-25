// The 404 page for any unmatched URL, and for a package or file the registry doesn't have (proxy.ts rewrites those
// to an unmatched path with a 404). It can't see the URL that was asked for, so it covers both cases.
import type { Metadata } from "next";
import Link from "next/link";
import { buttonVariants } from "@/components/ui/button";
import { clickEvent } from "@/lib/databuddy-client";

export const metadata: Metadata = { title: "Page not found · apm" };

export default function NotFound() {
  return (
    <div className="flex max-w-xl flex-col items-start gap-6 py-6 sm:py-12">
      <div className="flex flex-col gap-3">
        <p className="font-mono text-sm text-muted-foreground">404</p>
        <h1 className="text-3xl font-medium tracking-tight text-balance sm:text-4xl">Page not found</h1>
        <p className="text-[15px] leading-6 text-pretty text-muted-foreground">
          There is no page at this address. If you were looking for a package, it isn&apos;t on npm under that name, or the version or file doesn&apos;t exist. Check the spelling or search for it.
        </p>
      </div>
      <div className="flex flex-wrap gap-3">
        <Link href="/" className={buttonVariants({ size: "lg" })}>
          Search packages
        </Link>
        <a href="https://docs.apmjs.dev" {...clickEvent({ name: "docs_cta_clicked", props: { location: "not_found" } })} className={buttonVariants({ size: "lg", variant: "outline" })}>
          Read the docs
        </a>
      </div>
    </div>
  );
}
