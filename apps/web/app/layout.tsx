import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";
import { Geist, Geist_Mono } from "next/font/google";
import { SearchBar } from "@/components/search-bar";
import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: "apm",
  description: "A package registry for Bun and npm with per-version security scores, yank and revoke, and a cooldown view.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}>
      <body className="flex min-h-full flex-col bg-background text-foreground">
        <header className="sticky top-0 z-20 border-b bg-background/90 backdrop-blur">
          <div className="mx-auto flex h-16 max-w-5xl items-center gap-4 px-4">
            <Link href="/" className="shrink-0 font-mono text-sm font-semibold tracking-tight">
              apm
            </Link>
            <Suspense fallback={<div className="h-11 w-full rounded-lg border" />}>
              <SearchBar />
            </Suspense>
            <Link href="/docs" className="hidden shrink-0 text-sm text-muted-foreground hover:text-foreground sm:block">
              Docs
            </Link>
          </div>
        </header>
        <main className="mx-auto w-full max-w-5xl flex-1 px-4 py-8">{children}</main>
      </body>
    </html>
  );
}
