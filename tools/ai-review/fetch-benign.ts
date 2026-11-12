// Downloads benign releases (latest and the release before it) from registry.npmjs.org into the cache.
// Usage: bun tools/ai-review/fetch-benign.ts
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { installScriptsOf } from "../../packages/core/src/score.ts";
import { fetchNpmTarball } from "./fetch-malicious.ts";
import { loadTgz } from "./samples.ts";
import { CACHE_DIR, mapLimit } from "./util.ts";

const POPULAR = [
  "zod", "react", "react-dom", "hono", "vite", "typescript", "next", "express", "axios", "eslint", "prettier",
  "tailwindcss", "@tanstack/react-query", "drizzle-orm", "openai", "@anthropic-ai/sdk", "undici", "ws", "commander",
  "vitest", "debug", "@ctrl/tinycolor",
];
/** Packages known for legitimate install-time work: binary downloads, native builds, banners. */
const INSTALL_SCRIPTS = [
  "esbuild", "sharp", "prisma", "@prisma/client", "@prisma/engines", "puppeteer", "electron", "@swc/core", "core-js",
  "bcrypt", "cypress", "@sentry/cli", "lefthook", "canvas", "sqlite3", "nx", "unrs-resolver", "@parcel/watcher",
  "node-pty",
];

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const STABLE = /^\d+\.\d+\.\d+$/;

export type BenignEntry = { id: string; name: string; version: string; previous: string | null; publishedAt: string; group: "popular" | "install-script"; tgz: string; prevTgz: string | null; hasInstallScript: boolean };

async function pick(name: string, group: BenignEntry["group"]): Promise<BenignEntry> {
  const res = await fetch(`https://registry.npmjs.org/${name.replace("/", "%2f")}`, { headers: { "user-agent": "apm-research/0.1" } });
  if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
  const doc: unknown = await res.json();
  if (!isRecord(doc) || !isRecord(doc["dist-tags"]) || !isRecord(doc.time)) throw new Error(`${name}: bad packument`);
  const latest = doc["dist-tags"].latest;
  if (typeof latest !== "string") throw new Error(`${name}: no latest`);
  const time = doc.time;
  const at = (v: string): number => (typeof time[v] === "string" ? Date.parse(time[v]) : 0);
  // Previous = the highest stable version below latest that is still on the registry (time keeps
  // entries for unpublished versions, such as debug 4.4.2).
  const live = isRecord(doc.versions) ? doc.versions : {};
  const previous =
    Object.keys(live)
      .filter((v) => STABLE.test(v) && Bun.semver.order(v, latest) < 0)
      .sort((a, b) => Bun.semver.order(b, a))[0] ?? null;
  const tgz = await fetchNpmTarball(name, latest);
  const prevTgz = previous ? await fetchNpmTarball(name, previous) : null;
  const hasInstallScript = Object.keys(installScriptsOf(loadTgz(tgz).manifest)).length > 0;
  return { id: `${name}@${latest}`, name, version: latest, previous, publishedAt: new Date(at(latest)).toISOString(), group, tgz, prevTgz, hasInstallScript };
}

const all = [...POPULAR.map((n) => [n, "popular"] as const), ...INSTALL_SCRIPTS.map((n) => [n, "install-script"] as const)];
const entries = await mapLimit(all, 4, ([n, g]) => pick(n, g));
mkdirSync(join(CACHE_DIR, "benign"), { recursive: true });
writeFileSync(join(CACHE_DIR, "benign", "index.json"), JSON.stringify(entries, null, 2));
for (const e of entries) process.stdout.write(`${e.group.padEnd(14)} ${e.id.padEnd(36)} prev ${e.previous ?? "-"} ${e.publishedAt.slice(0, 10)} install=${e.hasInstallScript}\n`);
process.stdout.write(`${entries.length} benign; with install scripts: ${entries.filter((e) => e.hasInstallScript).length}\n`);
