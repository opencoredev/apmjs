// Cloudflare's _headers files as its asset layer reads them (https://developers.cloudflare.com/workers/static-assets/headers/):
// a path pattern on its own line, then indented `Name: value` lines. Every rule whose pattern matches a path applies,
// and a header set by more than one is joined with ", ". Used by lib/static-headers.test.ts and by
// scripts/canonical-proxy.ts, which serves the docs build with its _headers as Cloudflare would. Test tooling: never
// imported by the site.
import { readFileSync } from "node:fs";

/** One rule: its pattern, and its headers with lowercase names, in file order. */
export type HeaderRule = { readonly pattern: string; readonly headers: readonly (readonly [string, string])[] };

export function headerRules(file: string): HeaderRule[] {
  const out: { pattern: string; headers: [string, string][] }[] = [];

  for (const line of readFileSync(file, "utf8").split("\n")) {
    if (line.trim() === "" || line.trimStart().startsWith("#")) continue;

    if (!/^\s/.test(line)) {
      out.push({ pattern: line.trim(), headers: [] });
      continue;
    }

    const at = line.indexOf(":");

    out.at(-1)?.headers.push([line.slice(0, at).trim().toLowerCase(), line.slice(at + 1).trim()]);
  }

  return out;
}

/** Whether a pattern matches `path`: "*" matches anything, "/" included. */
export function patternMatches(pattern: string, path: string): boolean {
  const parts = pattern.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&"));

  return new RegExp(`^${parts.join(".*")}$`).test(path);
}

/** The headers Cloudflare sends for `path` under `rules`. */
export function headersFor(rules: readonly HeaderRule[], path: string): Map<string, string> {
  const out = new Map<string, string>();

  for (const rule of rules) {
    if (!patternMatches(rule.pattern, path)) continue;

    for (const [name, value] of rule.headers) {
      const before = out.get(name);

      out.set(name, before === undefined ? value : `${before}, ${value}`);
    }
  }

  return out;
}
