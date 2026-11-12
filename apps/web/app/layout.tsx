import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";
import { Host_Grotesk, Geist_Mono } from "next/font/google";
import { SearchBar } from "@/components/search-bar";
import { SiteNav, SiteNavFallback } from "@/components/site-nav";
import { Logo, LogoMark } from "@/components/logo";
import "./globals.css";

const sans = Host_Grotesk({ variable: "--font-host-grotesk", subsets: ["latin"] });
const mono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: "apm",
  description: "A package registry for Bun and npm with per-version security scores, yank and revoke, and a cooldown view.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" suppressHydrationWarning className={`${sans.variable} ${mono.variable} h-full antialiased`}>
      <body className="flex min-h-full flex-col bg-background text-foreground">
        <header className="sticky top-0 z-20 bg-background/85 backdrop-blur-md supports-[backdrop-filter]:bg-background/75">
          <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-3 px-4 py-3 sm:flex-nowrap sm:px-6 sm:py-4">
            <Link href="/" aria-label="apm home" className="-m-1 flex h-9 shrink-0 items-center rounded-lg p-1">
              <Logo className="h-[26px]" />
            </Link>
            <Suspense fallback={<div className="order-last h-10 w-full sm:order-none sm:w-auto sm:max-w-xl sm:flex-1" />}>
              <SearchBar />
            </Suspense>
            <div className="ml-auto">
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
              <LogoMark className="mr-2 inline-block size-4 align-[-3px]" />
              apm registry demo. Your package manager stays the same.
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
