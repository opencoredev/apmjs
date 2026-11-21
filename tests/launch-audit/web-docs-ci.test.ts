// Launch-audit check (Web legal pages, Bun scanner docs/CI consistency, docs drift, search Enter, CI web build, polish).
import { describe, expect, test } from "bun:test";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { CLI_VERSION } from "../../packages/cli/src/version.ts";
import { SCORER } from "../../packages/core/src/index.ts";

const ROOT = join(import.meta.dir, "..", "..");

function read(rel: string): string {
  return readFileSync(join(ROOT, rel), "utf8");
}

function allMdx(dir: string): string[] {
  const out: string[] = [];

  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);

    if (entry.isDirectory()) out.push(...allMdx(full));
    else if (entry.name.endsWith(".mdx")) out.push(full);
  }

  return out;
}

describe("launch audit: web, docs & CI", () => {
  test("P0: /privacy and /terms pages exist and are linked from both web and docs footers", () => {
    expect(existsSync(join(ROOT, "apps/web/app/privacy/page.tsx"))).toBe(true);
    expect(existsSync(join(ROOT, "apps/web/app/terms/page.tsx"))).toBe(true);

    const layout = read("apps/web/app/layout.tsx");
    const docsConfig = read("apps/docs/blume.config.ts");

    expect(layout).toContain("/privacy");
    expect(layout).toContain("/terms");
    expect(docsConfig).toContain("/privacy");
    expect(docsConfig).toContain("/terms");
  });

  test("P0: Bun scanner docs and CI guide do not prescribe broken commands while @apm/bun-scanner is private", () => {
    const pkg = z.object({ private: z.boolean().optional() }).parse(JSON.parse(read("packages/bun-scanner/package.json")));

    if (pkg.private !== true) return;

    const ciGuide = read("apps/docs/docs/guides/ci.mdx");
    const webDocs = read("apps/web/app/docs/page.tsx");
    const llms = read("apps/web/lib/agent/llms.ts");

    // CI guide must not tell users that APM_SCANNER_STRICT=1 works when the scanner is unpublished
    expect(ciGuide).not.toContain("APM_SCANNER_STRICT=1 bun install --frozen-lockfile");
    // Web docs and llms.txt must not tell users to run `bun add -d @apm/bun-scanner` without noting it isn't published
    expect(webDocs.toLowerCase()).toContain("not on a registry");
    expect(llms).not.toContain('scanner = "@apm/bun-scanner"');
  });

  test("P0: CI workflow builds apps/web so build/prerender breaks cannot pass CI", () => {
    const ci = read(".github/workflows/ci.yml");

    expect(ci).toMatch(/build-web\.ts|next build/);
  });

  test("P1: docs match CLI_VERSION, CLI commands, queue consumer config, scorer version, and lint baseline", () => {
    const mdxFiles = allMdx(join(ROOT, "apps/docs/docs"));

    for (const file of mdxFiles) {
      const text = readFileSync(file, "utf8");
      const stale = text.match(/\b0\.1\.0\b/g) ?? [];

      expect({ file, stale }).toEqual({ file, stale: [] });
    }

    const cliRef = read("apps/docs/docs/reference/cli.mdx");

    expect(cliRef).toContain("apm explain");
    expect(cliRef).toContain("apm search");

    const deployDoc = read("docs/DEPLOY.md");

    expect(deployDoc).not.toContain("batches of 5, 3 retries");

    const agentsDoc = read("docs/AGENTS.md");

    expect(agentsDoc).not.toContain("apm-score-v10)");
    expect(agentsDoc).toContain(SCORER);

    const baseline = z.object({ files: z.record(z.string(), z.record(z.string(), z.number())) }).parse(JSON.parse(read("lint-baseline.json")));
    const total = Object.values(baseline.files).reduce((sum, rules) => sum + Object.values(rules).reduce((s, n) => s + n, 0), 0);
    const lintDoc = read("docs/LINT.md");

    expect(lintDoc).not.toContain("1,335 findings");
    expect(lintDoc).toContain(String(total));

    const accountLib = read("apps/web/lib/account.ts");

    expect(accountLib).not.toContain("apm owner add");
    expect(CLI_VERSION.length).toBeGreaterThan(0);
  });

  test("P1: home search Enter does not blindly jump to an unrelated first hit", () => {
    const src = read("apps/web/components/search-home.tsx");

    // Both the pending-Enter effect and onKeyDown previously jumped straight to hits[0] / actionable[0]
    // even when active === -1 and hits[0].name did not match the query.
    expect(src).not.toContain("const hit = actionable[active >= 0 ? active : 0];");
  });

  test("P2: unused Next.js starter SVGs are removed from apps/web/public and missing-version titles do not claim the latest version", () => {
    for (const svg of ["file.svg", "globe.svg", "next.svg", "vercel.svg", "window.svg"]) {
      expect(existsSync(join(ROOT, "apps/web/public", svg))).toBe(false);
    }

    const pkgPage = read("apps/web/app/package/[...name]/page.tsx");

    // When ?v= asks for a version that does not exist, generateMetadata must not render the latest version's title
    expect(pkgPage).toMatch(/missingVersion|askedVersion/);
    expect(pkgPage).toMatch(/No such version/);
  });
});
