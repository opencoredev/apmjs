// Round 7 review of dce1655, P1: binaries read through the plain view (@apm/core score.ts) waited for the end of the
// walks with their whole import lists kept and no bound, so 500 Mach-O files of 2,800 relative requires each (39.3 MiB)
// ended workerd under a 96 MiB heap where production (274d284) finished. A view now keeps only its findings and facts,
// within MAX_KEPT_VIEW_BYTES. Run inside workerd under the cap, as the review ran it: it finishes, complete or partial.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { join } from "node:path";
import { z } from "zod";
import { startWorkerdHeap, type WorkerdHeap } from "./workerd-heap.ts";

const CORE = join(import.meta.dir, "..", "..", "core");
const HEAP_CAP_MB = 96;
const GC_LINE = /Mark-Compact.*->\s*([\d.]+)/;

const ENTRY = `
import { analyze } from ${JSON.stringify(join(CORE, "src", "score.ts"))};
import { machO } from ${JSON.stringify(join(CORE, "test", "executables.ts"))};
const enc = new TextEncoder();
const ent = (path, data) => ({ path, data, size: data.length, mode: 0o755 });
export default {
  async fetch(req) {
    const u = new URL(req.url);
    const n = Number(u.searchParams.get("n"));
    const imports = Number(u.searchParams.get("imports") || 0);
    const joined = Number(u.searchParams.get("joined") || 0);
    // a packument's weight of live objects held beside the run, as the queue holds one
    const ballast = [];
    for (let i = 0; i < Number(u.searchParams.get("ballastMiB") || 0) * 1024; i++) ballast.push(Array.from({ length: 256 }, (_, k) => k + i));
    const manifest = { name: "review-probe", version: "1.0.0", license: "MIT" };
    const files = [ent("package.json", enc.encode(JSON.stringify(manifest)))];
    for (let i = 0; i < n; i++) {
      let text = "";
      for (let j = 0; j < imports; j++) text += "\\nrequire('./missing" + i + "_" + j + "');";
      for (let j = 0; j < joined; j++) text += "\\n'child_'+'process';";
      const d = machO({ size: 256, tail: enc.encode("*/\\n" + text + "\\n") });
      d[40] = 47;
      d[41] = 42;
      files.push(ent("lib/n" + String(i).padStart(5, "0"), d));
    }
    const a = analyze({ name: manifest.name, manifest, files, publisher: "alice", previousPublishers: [] });
    return Response.json({ coverage: a.coverage.kind, files: files.length, ballast: ballast.length });
  },
};`;

const Result = z.object({ coverage: z.enum(["complete", "partial"]), files: z.number(), ballast: z.number() });

describe("binaries' plain views under a Worker's heap", () => {
  let heap: WorkerdHeap;
  let peakLiveMb = 0;

  beforeAll(async () => {
    heap = await startWorkerdHeap(ENTRY, {
      v8Flags: [`--max-old-space-size=${HEAP_CAP_MB}`, "--max-semi-space-size=4", "--trace-gc"],
      onStdout: (line) => {
        const m = GC_LINE.exec(line);

        if (m) peakLiveMb = Math.max(peakLiveMb, Number(m[1]));
      },
    });
  }, 120_000);

  afterAll(async () => {
    await heap?.dispose();
  });

  test("500 Mach-O files of 2,800 requires each finish under the cap (on dce1655 workerd was killed, no report)", async () => {
    const res = await heap.dispatch("/?n=500&imports=2800");

    expect(res.status).toBe(200);
    const r = Result.parse(await res.json());

    console.log(`[binary-views] 500 x 2800 imports: ${r.coverage}, V8 live at most ${peakLiveMb} MB after a full collection`);
    expect(r.files).toBe(501);
    expect(peakLiveMb).toBeLessThan(HEAP_CAP_MB);
  }, 300_000);

  // memory review of 49b35f9, P1: views counted past the budget were still kept, so 500 Mach-O files of 200 joined
  // strings each (about 131 KiB of results each) ended workerd beside 27 MiB of live objects, where production (274d284)
  // finished. What views add is bounded as a whole now: past it, files are unread
  test("500 Mach-O files of 200 joined strings each, beside 27 MiB of live objects, finish under the cap", async () => {
    const res = await heap.dispatch("/?n=500&joined=200&ballastMiB=27");

    expect(res.status).toBe(200);
    const r = Result.parse(await res.json());

    console.log(`[binary-views] 500 x 200 joined strings, 27 MiB held: ${r.coverage}, V8 live at most ${peakLiveMb} MB after a full collection`);
    expect(r.files).toBe(501);
    expect(r.ballast).toBe(27 * 1024);
  }, 300_000);
});
