// The readme pipeline inside workerd, through Miniflare, the runtime the website deploys to. Bun's stack is
// deeper than workerd's, so these inputs only prove anything here: a readme that nests thousands of levels deep
// must not throw (the page renders the readme even while it is collapsed).
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Miniflare } from "miniflare";
import { MAX_DEPTH } from "./readme";

let mf: Miniflare | null = null;
const out = mkdtempSync(join(tmpdir(), "apm-readme-workerd-"));

async function render(markdown: string): Promise<{ status: number; body: string }> {
  if (!mf) throw new Error("Miniflare did not start");
  const res = await mf.dispatchFetch("http://readme.test/", { method: "POST", body: markdown });

  return { status: res.status, body: await res.text() };
}

beforeAll(async () => {
  const built = await Bun.build({
    entrypoints: [join(import.meta.dir, "readme.workerd-entry.ts")],
    outdir: out,
    target: "browser",
    format: "esm",
    conditions: ["workerd", "worker", "edge-light"],
    define: { "process.env.NODE_ENV": '"production"' },
  });

  if (!built.success) throw new AggregateError(built.logs, "bundling the readme Worker failed");
  const script = built.outputs[0]?.path;

  if (!script) throw new Error("bundling the readme Worker produced no file");
  // The registry's runtime contract (packages/registry/scripts/compat.ts); OpenNext deploys the website with nodejs_compat too.
  mf = new Miniflare({
    modules: [{ type: "ESModule", path: script }],
    modulesRoot: out,
    compatibilityDate: "2026-07-30",
    compatibilityFlags: ["nodejs_compat"],
  });
  await mf.ready;
}, 60_000);

afterAll(async () => {
  await mf?.dispose();
  rmSync(out, { recursive: true, force: true });
});

describe("in workerd", () => {
  test("an ordinary readme renders", async () => {
    const { status, body } = await render("# Title\n\n> quoted\n\n- a\n  - b\n\n<div><p>raw</p></div>");

    expect(status).toBe(200);
    expect(body).toContain('<h3 id="user-content-title" class="readme-h1">Title</h3>');
    expect(body).toContain("<blockquote>");
    expect(body).toContain("<p>raw</p>");
  });

  test("2,500 nested divs show the escaped source instead of overflowing the stack", async () => {
    const { status, body } = await render(`${"<div>".repeat(2500)}x`);

    expect(status).toBe(200);
    expect(body).toContain("readme-fallback");
    expect(body).toContain("&lt;div&gt;&lt;div&gt;");
    expect(body).not.toContain("<div><div>");
  });

  test("5,000 nested blockquotes show the escaped source instead of overflowing the stack", async () => {
    const { status, body } = await render(`${"> ".repeat(5000)}x`);

    expect(status).toBe(200);
    expect(body).toContain("readme-fallback");
    expect(body).not.toContain("<blockquote>");
  });

  test("nesting the source check can't see still ends in the fallback, not a thrown error", async () => {
    // Alternating emphasis 1,600 deep has no tags or line markers; in workerd the parser overflows on it,
    // and the catch around the pipeline shows the source.
    const { status, body } = await render(`${"*a _b ".repeat(1600)}x${" b_ a*".repeat(1600)}`);

    expect(status).toBe(200);
    expect(body).toContain("readme-fallback");
  });

  test("nesting just under the limit still renders", async () => {
    const depth = MAX_DEPTH - 2;
    const divs = await render(`${"<div>".repeat(depth)}deep`);
    const quotes = await render(`${"> ".repeat(depth)}deep`);

    expect(divs.status).toBe(200);
    expect(divs.body).not.toContain("readme-fallback");
    expect(divs.body).toContain(`${"<div>".repeat(depth)}deep`);
    expect(quotes.status).toBe(200);
    expect(quotes.body).not.toContain("readme-fallback");
    expect(quotes.body.split("<blockquote>").length - 1).toBe(depth);
  });
});
