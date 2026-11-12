import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";
import { Host_Grotesk, Geist_Mono } from "next/font/google";
import { SearchBar } from "@/components/search-bar";
import { SiteNav, SiteNavFallback } from "@/components/site-nav";
import "./globals.css";

const sans = Host_Grotesk({ variable: "--font-host-grotesk", subsets: ["latin"] });
const mono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: "apm",
  description: "A package registry for Bun and npm with per-version security scores, yank and revoke, and a cooldown view.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable} h-full antialiased`}>
      <body className="flex min-h-full flex-col bg-background text-foreground">
        <header className="sticky top-0 z-20 bg-background/85 backdrop-blur-md supports-[backdrop-filter]:bg-background/75">
          <div className="mx-auto grid max-w-6xl grid-cols-[auto_1fr] items-center gap-x-4 gap-y-3 px-4 py-3 sm:grid-cols-[auto_1fr_auto] sm:px-6 sm:py-4">
            <Link href="/" className="flex h-9 shrink-0 items-center rounded-md font-mono text-[17px] font-semibold tracking-tight">
              apm
            </Link>
            <div className="col-span-2 row-start-2 sm:col-span-1 sm:row-start-1 sm:col-start-2">
              <Suspense fallback={<div className="h-12 w-full rounded-xl bg-surface" />}>
                <SearchBar />
              </Suspense>
            </div>
            <div className="justify-self-end sm:col-start-3">
              <Suspense fallback={<SiteNavFallback />}>
                <SiteNav />
              </Suspense>
            </div>
          </div>
        </header>
        <main className="mx-auto w-full max-w-6xl flex-1 px-4 pt-6 pb-24 sm:px-6 sm:pt-10">{children}</main>
        <footer className="border-t">
          <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-x-6 gap-y-2 px-4 py-6 text-sm text-muted-foreground sm:px-6">
            <span>
              <span className="font-mono text-foreground">apm</span> registry demo. Your package manager stays the same.
            </span>
            <span className="flex gap-5">
              <Link href="/compare" className="hover:text-foreground">
                npm vs apm
              </Link>
              <Link href="/docs" className="hover:text-foreground">
                How it works
              </Link>
            </span>
          </div>
        </footer>
      </body>
    </html>
  );
}
