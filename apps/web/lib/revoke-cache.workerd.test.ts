// The version permission through workerd's own Cache API, the edge cache's second layer, which bun's tests can't reach:
// lib/revoke-cache.workerd-entry.ts reads files the way the website does, inside Miniflare. Dropping the isolate's
// memory between requests stands in for a request that lands on another isolate in the same data center, so what is
// checked is what the Cache API alone holds.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Miniflare } from "miniflare";
import { z } from "zod";

let mf: Miniflare | null = null;
let registry: ReturnType<typeof Bun.serve>;
const out = mkdtempSync(join(tmpdir(), "apm-revoke-workerd-"));


/** The registry's status per path, for GET and HEAD; 200 with a small file when unset. */
const statuses = new Map<string, number>();

/** Paths whose next GET waits until the test releases it. */
const toHold = new Set<string>();
const held = new Map<string, () => void>();
const seen: { method: string; path: string }[] = [];

/** What the Worker answers: the shown file, or why it is not shown. */
const Answer = z.union([
  z.object({ kind: z.literal("ok"), value: z.object({ kind: z.literal("text"), text: z.string() }).nullable() }),
  z.object({ kind: z.literal("missing") }),
  z.object({ kind: z.literal("unavailable"), reason: z.object({ kind: z.string(), status: z.number().optional() }) }),
  z.object({ ok: z.literal(true) }),
]);

async function send(action: Record<string, string>): Promise<z.infer<typeof Answer>> {
  if (!mf) throw new Error("Miniflare did not start");
  const res = await mf.dispatchFetch("http://site.test/", { method: "POST", body: JSON.stringify(action) });

  return Answer.parse(await res.json());
}

function fileOf(name: string) {
  const path = `/-/apm/v1/file/${name}/1.0.0?path=index.js`;
  const target = { url: `${registry.url.origin}${path}`, servable: `${registry.url.origin}/-/apm/v1/servable/${name}/1.0.0` };

  return {
    path,
    view: () => send({ do: "view", ...target }),
    ask: () => send({ do: "ask", ...target }),
    answer: (status: number) => statuses.set(path, status),
    asked: () => seen.filter((s) => s.path === path).length,
  };
}

const forget = () => send({ do: "forget" });
const GONE = { kind: "unavailable", reason: { kind: "status", status: 410 } } as const;
const SHOWN = { kind: "ok", value: { kind: "text", text: "hello" } } as const;

beforeAll(async () => {
  registry = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const u = new URL(req.url);
      const path = `${u.pathname}${u.search}`;
      seen.push({ method: req.method, path });

      // the answer is the one the registry had when the request arrived, however long it is held
      const status = statuses.get(path) ?? 200;

      if (req.method === "GET" && toHold.delete(path)) await new Promise<void>((resolve) => held.set(path, resolve));

      return status === 200 ? Response.json({ kind: "text", text: "hello" }) : Response.json({ error: `answered ${status}` }, { status });
    },
  });

  const built = await Bun.build({
    entrypoints: [join(import.meta.dir, "revoke-cache.workerd-entry.ts")],
    outdir: out,
    target: "browser",
    format: "esm",
    conditions: ["workerd", "worker", "edge-light"],
    define: { "process.env.NODE_ENV": '"production"' },
  });

  if (!built.success) throw new AggregateError(built.logs, "bundling the revoke-cache Worker failed");
  const script = built.outputs[0]?.path;

  if (!script) throw new Error("bundling the revoke-cache Worker produced no file");
  mf = new Miniflare({ modules: [{ type: "ESModule", path: script }], modulesRoot: out, compatibilityDate: "2026-07-30", compatibilityFlags: ["nodejs_compat"] });
  await mf.ready;
}, 60_000);

afterAll(async () => {
  await mf?.dispose();
  await registry.stop(true);
  rmSync(out, { recursive: true, force: true });
});

describe("the Cache API layer", () => {
  test("another isolate serves a cached file only while the permission in the Cache API is fresh", async () => {
    const f = fileOf("workerd-gate");
    expect(await f.view()).toEqual(SHOWN);
    await Bun.sleep(100);
    await forget();
    expect(await f.view()).toEqual(SHOWN);
    // bytes and permission both came from the Cache API
    expect(f.asked()).toBe(1);

    f.answer(410);
    await Bun.sleep(5_200);
    await forget();
    expect(await f.view()).toEqual(GONE);
    expect(seen.filter((s) => s.path === f.path && s.method === "HEAD").length).toBe(1);
  }, 20_000);

  test("a no in the Cache API stops a yes from an older GET, wherever that GET finishes", async () => {
    const f = fileOf("workerd-race");
    toHold.add(f.path);
    const old = f.view();

    for (let i = 0; i < 200 && !held.has(f.path); i++) await Bun.sleep(5);
    expect(held.has(f.path)).toBe(true);

    // the revoke, heard by a HEAD; then only the Cache API holds the no
    f.answer(410);
    expect(await f.ask()).toEqual(GONE);
    await Bun.sleep(100);
    await forget();

    // the GET sent before the revoke comes back with the bytes
    held.get(f.path)?.();
    expect(await old).toEqual(SHOWN);
    await Bun.sleep(100);
    await forget();

    const before = f.asked();
    expect(await f.view()).toEqual(GONE);
    expect(f.asked()).toBe(before + 1);
  }, 20_000);
});
