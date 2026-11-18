// The docs' page-view labels as Blume builds them (analytics.ts, components/PageView.astro). Builds a copy of this site
// with two extra pages, a draft and a page whose frontmatter slug moves it, and checks the built HTML:
//
//   - every published page carries exactly one label, and it is the route the page is served at;
//   - the moved page carries its published route, not one from its filename;
//   - the draft is not built and its name is in no page;
//   - the 404 page carries no label.
//
//   bun scripts/check-labels.ts
//
// Test tooling: never imported by the site. Exits 1 on the first failed check.
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { PAGE_VIEW_ATTRIBUTE } from "../analytics";

const SITE = join(import.meta.dir, "..");
const work = mkdtempSync(join(tmpdir(), "docs-labels-"));

let failures = 0;

function check(ok: boolean, what: string): void {
  process.stdout.write(`${ok ? "PASS" : "FAIL"} ${what}\n`);

  if (!ok) failures += 1;
}

/** Every label on a built page, in order. */
function labels(html: string): string[] {
  return [...html.matchAll(new RegExp(`${PAGE_VIEW_ATTRIBUTE}="([^"]*)"`, "g"))].map((m) => m[1] ?? "");
}

/** The route a built HTML file is served at: dist/index.html is /, dist/guides/ci/index.html is /guides/ci. */
function routeOf(file: string): string {
  return `/${file.split(sep).join("/").replace(/(?:^|\/)index\.html$/, "")}`;
}

try {
  cpSync(SITE, work, { recursive: true, filter: (src) => !/[/\\](?:dist|node_modules|\.blume|\.blume-verify)$/.test(src) });
  symlinkSync(join(SITE, "node_modules"), join(work, "node_modules"));
  writeFileSync(join(work, "docs", "draft-check.mdx"), "---\ntitle: Draft check\ndraft: true\n---\n\nnot published\n");
  writeFileSync(join(work, "docs", "guides", "slug-check.mdx"), "---\ntitle: Slug check\nslug: elsewhere/moved\n---\n\nmoved\n");

  const build = Bun.spawnSync(["bun", "run", "build"], { cwd: work, stdout: "pipe", stderr: "pipe", env: { ...process.env, NEXT_PUBLIC_DATABUDDY_CLIENT_ID: "test-client-0000" } });

  check(build.exitCode === 0, `the copy builds${build.exitCode === 0 ? "" : `: ${build.stderr.toString().slice(-2000)}`}`);

  const dist = join(work, "dist");

  const pages = readdirSync(dist, { recursive: true, encoding: "utf8" })
    .filter((f) => f.endsWith(".html"))
    .map((f) => ({ file: f, route: routeOf(f), html: readFileSync(join(dist, f), "utf8") }));

  const published = pages.filter((p) => p.file.endsWith("index.html"));

  check(published.length > 10, `the build has its pages (${published.length})`);

  for (const p of published) check(JSON.stringify(labels(p.html)) === JSON.stringify([p.route]), `${p.file} carries exactly its route ${p.route}: ${JSON.stringify(labels(p.html))}`);

  const moved = published.find((p) => p.route === "/elsewhere/moved");

  check(moved !== undefined && labels(moved.html)[0] === "/elsewhere/moved", "the slug-moved page carries its published route");
  check(!published.some((p) => p.route === "/guides/slug-check"), "nothing is built at the moved page's filename");
  check(!pages.some((p) => p.route.includes("draft-check") || p.html.includes("draft-check")), "the draft is not built and no page names it");

  const notFound = pages.find((p) => p.file === "404.html");

  check(notFound !== undefined && labels(notFound.html).length === 0, "the 404 page carries no label");
  check(pages.every((p) => p.file.endsWith("index.html") || labels(p.html).length === 0), "no other HTML file carries a label");

  const sitemap = readFileSync(join(dist, "sitemap.xml"), "utf8");
  const listed = [...sitemap.matchAll(/<loc>https:\/\/docs\.apmjs\.dev([^<]*)<\/loc>/g)].map((m) => (m[1] ?? "/").replace(/(.)\/$/, "$1"));

  check(listed.length > 0 && listed.every((r) => published.some((p) => p.route === r)), `every sitemap page is a labelled page (${listed.length})`);
} finally {
  rmSync(work, { recursive: true, force: true });
}

process.stdout.write(failures === 0 ? "all checks passed\n" : `${failures} check(s) failed\n`);

process.exit(failures === 0 ? 0 : 1);
