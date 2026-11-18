// The built website Worker in workerd, through Miniflare: what only the real OpenNext bundle shows. It builds the site
// the way the deploy does (packages/infra/build-web.ts), so it is slow, and lives here rather than in lib/ (CI runs it
// as its own step). The registry is a stand-in Worker on the REGISTRY binding that knows a few packages.
//
//   cd apps/web && bun test test
//
// Launch QA finding: Open Graph images failed with a 500 after 8 s on every request but an isolate's first. next/og
// imports its renderer inside each render, Cache Components tracks that import() with a timer kept from an earlier
// request, and workerd refuses I/O across requests. app/og/[[...name]]/route.tsx now imports the renderer once.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { Miniflare } from "miniflare";
import { pkg } from "../lib/agent/testing";

const ROOT = join(import.meta.dir, "../../..");
const WEB = join(ROOT, "apps/web");
const WORKER_DIR = join(WEB, "dist");
const PACKAGES = ["react", "next", "lodash", "@types/node"];

// The registry's package answer for each known package, and 404 for anything else (HEAD and GET alike).
const REGISTRY = `
const known = ${JSON.stringify(Object.fromEntries(PACKAGES.map((name) => [name, pkg({ name })])))};
export default {
  async fetch(request) {
    const path = decodeURIComponent(new URL(request.url).pathname);
    const name = path.startsWith("/-/apm/v1/packages/") ? path.slice("/-/apm/v1/packages/".length) : null;
    const answer = name === null ? undefined : known[name];
    if (answer === undefined) return new Response("not found", { status: 404 });
    return new Response(request.method === "HEAD" ? null : JSON.stringify(answer), { headers: { "content-type": "application/json" } });
  },
};`;

let mf: Miniflare | null = null;

function site(): Miniflare {
  if (!mf) throw new Error("Miniflare did not start");

  return mf;
}

function listFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);

    return statSync(p).isDirectory() ? listFiles(p) : [p];
  });
}

const moduleType = (file: string): "ESModule" | "CompiledWasm" | "Data" => (file.endsWith(".js") ? "ESModule" : file.endsWith(".wasm") ? "CompiledWasm" : "Data");

/** A PNG's width and height from its IHDR chunk, or null when the bytes are not a PNG. */
function pngSize(bytes: Uint8Array): { width: number; height: number } | null {
  const signature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

  if (bytes.length < 24 || signature.some((b, i) => bytes[i] !== b)) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  return { width: view.getUint32(16), height: view.getUint32(20) };
}

/** Asks for one image and reads it to the end, as an unfurler does. */
async function image(path: string): Promise<{ path: string; status: number; type: string | null; size: { width: number; height: number } | null }> {
  const res = await site().dispatchFetch(`http://apm.test${path}`);
  const bytes = new Uint8Array(await res.arrayBuffer());

  return { path, status: res.status, type: res.headers.get("content-type"), size: pngSize(bytes) };
}

const CARD = { status: 200, type: "image/png", size: { width: 1200, height: 630 } };

beforeAll(async () => {
  const build = Bun.spawn(["bun", "packages/infra/build-web.ts"], { cwd: ROOT, stdout: "pipe", stderr: "pipe" });
  const [code, out, err] = await Promise.all([build.exited, new Response(build.stdout).text(), new Response(build.stderr).text()]);

  if (code !== 0) throw new Error(`building the website failed (${code}):\n${out.slice(-4000)}\n${err.slice(-4000)}`);
  const files = listFiles(join(WORKER_DIR, "worker"));
  const entry = join(WORKER_DIR, "worker", "worker.js");

  mf = new Miniflare({
    host: "127.0.0.1",
    port: 0,
    workers: [
      {
        name: "web",
        modules: [entry, ...files.filter((f) => f !== entry)].map((path) => ({ type: moduleType(path), path })),
        modulesRoot: WORKER_DIR,
        compatibilityDate: "2026-08-06",
        compatibilityFlags: ["nodejs_compat"],
        assets: {
          directory: join(WEB, ".open-next/assets"),
          binding: "ASSETS",
          routerConfig: { invoke_user_worker_ahead_of_assets: false, has_user_worker: true, static_routing: { user_worker: ["/*"], asset_worker: ["/_next/static/*"] } },
        },
        bindings: { APM_REGISTRY: "http://registry.test/", APM_CLIENT_IP_HEADER: "cf-connecting-ip" },
        serviceBindings: { REGISTRY: "registry", WORKER_SELF_REFERENCE: "web" },
        ratelimits: { AGENT_RATE_LIMIT: { namespace_id: "4801", simple: { limit: 1000, period: 60 } } },
      },
      { name: "registry", modules: true, script: REGISTRY, compatibilityDate: "2026-07-30" },
    ],
  });
  await mf.ready;
}, 900_000);

afterAll(async () => {
  await mf?.dispose();
});

describe("Open Graph images from one isolate", () => {
  test("concurrent first requests each end in a whole 1200x630 PNG", async () => {
    const results = await Promise.all(["/og?c=1", "/og/react?c=2", "/og/next?c=3", "/og/@types/node?c=4"].map(image));

    for (const r of results) expect(r).toEqual({ path: r.path, ...CARD });
  }, 60_000);

  test("later requests, one after another, keep working: the site card and package cards", async () => {
    const paths = ["/og?s=1", "/og?s=2", "/og/react?s=3", "/og/lodash?s=4", "/og/react?s=5", "/og/@types/node?s=6", "/og?s=7"];

    for (const path of paths) expect(await image(path)).toEqual({ path, ...CARD });
  }, 60_000);

  test("a package the registry doesn't have is a 404, not an image", async () => {
    const res = await site().dispatchFetch("http://apm.test/og/no-such-package-qa");

    await res.arrayBuffer();
    expect(res.status).toBe(404);
  });
});

describe("routes", () => {
  test("/status redirects to the status page, temporarily", async () => {
    const res = await site().dispatchFetch("http://apm.test/status", { redirect: "manual" });

    await res.arrayBuffer();
    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toBe("https://status.apmjs.dev/");
  });

  test("an unknown page and an unknown package get the branded 404", async () => {
    for (const path of ["/does-not-exist-qa", "/package/no-such-package-qa"]) {
      const res = await site().dispatchFetch(`http://apm.test${path}`);
      const html = await res.text();

      expect(res.status).toBe(404);
      expect(html).toContain("<title>Page not found · apm</title>");
      expect(html).toContain("Page not found");
      expect(html).toContain("Search packages");
      expect(html).not.toContain("This page could not be found");
    }
  });
});
