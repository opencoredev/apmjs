// gunzipCapped inside workerd, the runtime the registry's queue consumer runs in. Its node:zlib refuses an inflate
// whose maxOutputLength is the stream's exact size for many streams Bun inflates without complaint, so the staging
// queue recorded react 19.3.1, picomatch 4.0.7 and tinyglobby 0.2.17 as "not valid gzip: it inflates to more than the
// N bytes its trailer says". This bundles tarball.ts from source and runs it in workerd through Miniflare.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { Miniflare } from "miniflare";
import { z } from "zod";
import { COMPATIBILITY_DATE, COMPATIBILITY_FLAGS } from "../../registry/scripts/compat.ts";

const ENTRY = `
import { gunzipCapped } from ${JSON.stringify(join(import.meta.dir, "..", "src", "tarball.ts"))};
export default {
  async fetch(req) {
    const bytes = new Uint8Array(await req.arrayBuffer());
    const limit = Number(new URL(req.url).searchParams.get("max"));
    try {
      return Response.json({ kind: "ok", length: gunzipCapped(bytes, limit).length });
    } catch (e) {
      return Response.json({ kind: "error", message: e instanceof Error ? e.message : String(e) });
    }
  },
};
`;

const Answer = z.discriminatedUnion("kind", [z.object({ kind: z.literal("ok"), length: z.number() }), z.object({ kind: z.literal("error"), message: z.string() })]);

/** Text of `size` bytes from a fixed seed: word-like, so it compresses about as well as source code does. */
function text(size: number, seed: number): Uint8Array {
  const words = ["function", "return", "const", "module", "exports", "require", "value", "index", "length", "(", ")", "{", "}", ";", "\n", "=", "if", "else", "this", "null"];
  const out = new Uint8Array(size);
  let s = seed;
  let at = 0;

  while (at < size) {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    const w = new TextEncoder().encode(`${words[s % words.length] ?? "x"}${s % 7 === 0 ? String(s % 1000) : ""} `);

    out.set(w.subarray(0, size - at), at);
    at += w.length;
  }

  return out;
}

let dir: string;
let mf: Miniflare;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "apm-workerd-gunzip-"));
  const entry = join(dir, "entry.js");

  await Bun.write(entry, ENTRY);
  const built = await Bun.build({ entrypoints: [entry], outdir: dir, target: "browser", format: "esm", external: ["node:*"], naming: "worker.js" });

  if (!built.success) throw new Error(built.logs.map(String).join("\n"));
  mf = new Miniflare({ modules: true, script: await Bun.file(join(dir, "worker.js")).text(), compatibilityDate: COMPATIBILITY_DATE, compatibilityFlags: [...COMPATIBILITY_FLAGS] });
}, 60_000);

afterAll(async () => {
  await mf.dispose();
  rmSync(dir, { recursive: true, force: true });
});

async function inflate(bytes: Uint8Array, max = 48 * 1024 * 1024): Promise<z.infer<typeof Answer>> {
  const res = await mf.dispatchFetch(`http://gunzip.invalid/?max=${max}`, { method: "POST", body: bytes });

  return Answer.parse(await res.json());
}

describe("gunzipCapped in workerd", () => {
  // the sizes of the packages staging refused, and others around them: each stream is a different shape for zlib
  const sizes = [10_752, 46_080, 48_640, 54_784, 101_888, 139_776, 200_192, 707_072];

  test("inflates every well-formed stream to the size its trailer says", async () => {
    const results: { size: number; answer: z.infer<typeof Answer> }[] = [];

    for (const [i, size] of sizes.entries()) results.push({ size, answer: await inflate(new Uint8Array(gzipSync(text(size, i + 1)))) });

    expect(results).toEqual(sizes.map((size) => ({ size, answer: { kind: "ok", length: size } })));
  }, 60_000);

  test("a stream that inflates past its trailer is still refused", async () => {
    const gz = new Uint8Array(gzipSync(text(300_000, 9)));
    const view = new DataView(gz.buffer, gz.byteOffset, gz.byteLength);

    // the trailer now says 1000 bytes; the stream holds 300000
    view.setUint32(gz.length - 4, 1000, true);
    const answer = await inflate(gz);

    expect(answer.kind).toBe("error");
    expect(answer.kind === "error" ? answer.message : "").toContain("its trailer says");
  }, 60_000);
});
