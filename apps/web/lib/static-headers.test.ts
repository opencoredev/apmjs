// The files Cloudflare's asset layer serves without the Worker get their headers from _headers files, not from
// next.config.ts: the website's /_next/static/* (public/_headers) and the docs site's /_astro/* (apps/docs). Each must
// carry every security header the Worker sends (review of de5c7b7, finding 3: only nosniff was left, so a built SVG
// could be framed) and the immutable cache policy their content-named files allow.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { securityHeaders } from "./security-headers";

/** The headers a _headers file sets for `path`, as Cloudflare reads the file: a path line, then indented `Name: value` lines. */
function rulesFor(file: string, path: string): Map<string, string> {
  const out = new Map<string, string>();
  let inside = false;

  for (const line of readFileSync(file, "utf8").split("\n")) {
    if (line.trim() === "" || line.trimStart().startsWith("#")) continue;

    if (!/^\s/.test(line)) {
      inside = line.trim() === path;
      continue;
    }

    if (!inside) continue;
    const at = line.indexOf(":");

    out.set(line.slice(0, at).trim().toLowerCase(), line.slice(at + 1).trim());
  }

  return out;
}

const STATIC_RULES = [
  { site: "the website", file: join(import.meta.dir, "..", "public", "_headers"), path: "/_next/static/*" },
  { site: "the docs site", file: join(import.meta.dir, "..", "..", "docs", "public", "_headers"), path: "/_astro/*" },
];

describe("static file headers", () => {
  for (const rule of STATIC_RULES) {
    test(`${rule.site}'s ${rule.path} carries every security header the Worker sends, and is kept for a year`, () => {
      const rules = rulesFor(rule.file, rule.path);

      for (const h of securityHeaders(false)) expect(rules.get(h.key.toLowerCase())).toBe(h.value);
      expect(rules.get("x-frame-options")).toBe("DENY");
      expect(rules.get("content-security-policy")).toContain("frame-ancestors 'none'");
      expect(rules.get("cache-control")).toBe("public, max-age=31536000, immutable");
    });
  }
});
