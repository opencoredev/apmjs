// A load createSharedCache shares between requests, run inside workerd: the request that starts it may end first (a
// HEAD of / answers before its score badges finish), and a request after it must still get the answer. Without the
// owner keeping the load (inBackground, its waitUntil) the second request waited forever (review of 0c82348).
// OpenNext's request context is stood in for with AsyncLocalStorage, as @opennextjs/cloudflare keeps it.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Miniflare } from "miniflare";

const dir = mkdtempSync(join(tmpdir(), "shared-cache-workerd-"));
let mf: Miniflare;

beforeAll(async () => {
  writeFileSync(
    join(dir, "opennext.ts"),
    `import { AsyncLocalStorage } from "node:async_hooks";
export const als = new AsyncLocalStorage();
export function getCloudflareContext() {
  const ctx = als.getStore();
  if (!ctx) throw new Error("no request context");
  return ctx;
}`,
  );
  writeFileSync(
    join(dir, "entry.ts"),
    `import { als } from "./opennext";
import { popularScores } from ${JSON.stringify(join(import.meta.dir, "agent/popular-scores"))};
let registry;
const popular = popularScores({
  load: async () => {
    const res = await registry.fetch("https://registry.test/scores", { signal: AbortSignal.timeout(4000) });
    return { kind: "ok", value: await res.json() };
  },
  ttlMs: 60000,
  missTtlMs: 1000,
});
export default {
  fetch(request, env, ctx) {
    registry = env.REGISTRY;
    return als.run({ env, ctx }, async () => {
      if (new URL(request.url).pathname === "/start") {
        void popular.score("react");
        return new Response("started");
      }
      return Response.json(await popular.score("react"));
    });
  },
};`,
  );

  const built = await Bun.build({
    entrypoints: [join(dir, "entry.ts")],
    target: "browser",
    format: "esm",
    external: ["node:*"],
    plugins: [{ name: "opennext", setup: (b) => void b.onResolve({ filter: /^@opennextjs\/cloudflare$/ }, () => ({ path: join(dir, "opennext.ts") })) }],
  });

  const bundle = built.outputs[0];

  if (!built.success || bundle === undefined) throw new AggregateError(built.logs, "bundle failed");
  const script = await bundle.text();

  mf = new Miniflare({
    workers: [
      { name: "site", modules: true, script, compatibilityDate: "2026-07-30", compatibilityFlags: ["nodejs_compat"], serviceBindings: { REGISTRY: "registry" } },
      {
        name: "registry",
        modules: true,
        compatibilityDate: "2026-07-30",
        script: `export default { async fetch() { await new Promise((r) => setTimeout(r, 250)); return Response.json({ packages: [{ name: "react", version: "1.0.0", score: 80, grade: "B" }] }); } };`,
      },
    ],
  });
  await mf.ready;
}, 60_000);

afterAll(async () => {
  await mf?.dispose();
  rmSync(dir, { recursive: true, force: true });
});

describe("a shared load whose request ended first", () => {
  test("still answers the request that waits on it", async () => {
    const start = await mf.dispatchFetch("http://site.test/start");

    expect(await start.text()).toBe("started");
    const second = await Promise.race([mf.dispatchFetch("http://site.test/get").then((r) => r.text()), Bun.sleep(6_000).then(() => "unresolved after 6 s")]);

    expect(second).toBe(JSON.stringify({ version: "1.0.0", score: 80, grade: "B" }));
  }, 30_000);
});
