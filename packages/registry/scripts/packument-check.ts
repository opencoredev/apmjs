// Asks a registry for the packuments of large and popular packages the way npm install does (its Accept header), one
// at a time with a pause between, and reports which it could not serve. Read-only: GETs of public packuments only.
//
//   bun packages/registry/scripts/packument-check.ts [registry URL] [names...]
//
// The registry defaults to https://registry.apmjs.dev/. A body is read to its end and counted, never kept.
import { z } from "zod";

/** Packages whose packuments are among npm's largest, or that most projects install. */
export const CHECKED_PACKAGES = [
  "@mastra/core",
  "@mastra/mcp",
  "mastra",
  "next",
  "react-dom",
  "typescript",
  "@types/node",
  "aws-sdk",
  "@aws-sdk/client-s3",
  "@babel/core",
  "webpack",
  "vite",
  "esbuild",
  "@swc/core",
  "prisma",
  "@prisma/client",
  "electron",
  "@angular/core",
  "firebase",
  "googleapis",
  "@cloudflare/workers-types",
  "wrangler",
  "eslint",
  "lodash",
  "rxjs",
  "three",
  "@tensorflow/tfjs",
  "puppeteer",
  "playwright",
  "sharp",
  "discord.js",
  "@clerk/backend",
  "@clerk/shared",
  "@clerk/nextjs",
  "@clerk/clerk-react",
  "@clerk/types",
] as const;

/** What npm install sends (npm 10, pacote). */
const NPM_INSTALL_ACCEPT = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*";
const PAUSE_MS = 1_500;
const TIMEOUT_MS = 60_000;

const encodeName = (name: string): string => (name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name));

type Outcome = { name: string; status: number | "error"; ms: number; bytes: number; detail: string };

async function check(base: string, name: string): Promise<Outcome> {
  const start = performance.now();

  try {
    const res = await fetch(`${base}${encodeName(name)}`, { headers: { accept: NPM_INSTALL_ACCEPT, "user-agent": "apm-packument-check" }, signal: AbortSignal.timeout(TIMEOUT_MS) });
    let bytes = 0;
    let head = "";

    if (res.body) {
      for await (const chunk of res.body) {
        if (head.length < 300 && res.status !== 200) head += new TextDecoder().decode(chunk).slice(0, 300 - head.length);
        bytes += chunk.length;
      }
    }

    const detail = res.status === 200 ? (res.headers.get("content-type") ?? "") : head.replace(/\s+/g, " ").trim();

    return { name, status: res.status, ms: Math.round(performance.now() - start), bytes, detail };
  } catch (e) {
    return { name, status: "error", ms: Math.round(performance.now() - start), bytes: 0, detail: e instanceof Error ? e.message : String(e) };
  }
}

if (import.meta.main) {
  const args = process.argv.slice(2);
  const base = z.url().parse(args[0] ?? "https://registry.apmjs.dev/").replace(/\/?$/, "/");
  const names = args.length > 1 ? args.slice(1) : CHECKED_PACKAGES;
  const failed: Outcome[] = [];

  for (const [i, name] of names.entries()) {
    if (i > 0) await Bun.sleep(PAUSE_MS);
    const got = await check(base, name);
    process.stdout.write(`${got.status === 200 ? "ok  " : "FAIL"} ${String(got.status).padEnd(5)} ${String(got.ms).padStart(6)} ms ${(got.bytes / 1e6).toFixed(2).padStart(7)} MB  ${name}  ${got.status === 200 ? "" : got.detail}\n`);

    if (got.status !== 200) failed.push(got);
  }

  process.stdout.write(`\n${names.length - failed.length}/${names.length} served; failed: ${failed.map((f) => f.name).join(", ") || "none"}\n`);
  process.exitCode = failed.length > 0 ? 1 : 0;
}
