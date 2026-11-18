// The built website Worker in workerd, through Miniflare: what only the real OpenNext bundle shows. It builds the site
// the way the deploy does (packages/infra/build-web.ts), so it lives here rather than in lib/. It is a local check, not
// a CI step: the build fetches the site's fonts from Google Fonts (next/font/google), so a cold build needs the
// network. The registry is a stand-in Worker on the REGISTRY binding that knows a few packages.
//
//   cd apps/web && bun test ./test/     (not `bun test test`, which matches every test file by name)
//
// Launch QA finding: Open Graph images failed with a 500 after 8 s on every request but an isolate's first. next/og
// imports its renderer inside each render, Cache Components tracks that import() with a timer kept from an earlier
// request, and workerd refuses I/O across requests. app/og/[[...name]]/route.tsx now imports the renderer once.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { inflateSync } from "node:zlib";
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

const SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

/** Bytes per pixel for an 8-bit PNG colour type (greyscale, RGB, greyscale+alpha, RGBA); null for palette or unknown. */
function channelsOf(colour: number): number | null {
  switch (colour) {
    case 0:
      return 1;
    case 2:
      return 3;
    case 4:
      return 2;
    case 6:
      return 4;
    default:
      return null;
  }
}

/**
 * A PNG's width and height, or null unless it decodes: the signature, then chunks whose lengths and CRCs check out,
 * IHDR first, IDAT data that inflates to exactly one filtered row per line, and IEND as the last bytes. A truncated
 * or padded response fails, however its header looks (review of 020c9e8: a 24-byte header alone used to pass).
 */
function pngSize(bytes: Uint8Array): { width: number; height: number } | null {
  if (bytes.length < SIGNATURE.length || SIGNATURE.some((b, i) => bytes[i] !== b)) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const idat: Uint8Array[] = [];
  let header: { width: number; height: number; depth: number; colour: number; interlace: number } | null = null;
  let at = SIGNATURE.length;

  while (at + 12 <= bytes.length) {
    const length = view.getUint32(at);
    const end = at + 12 + length;

    if (end > bytes.length) return null;
    const type = new TextDecoder().decode(bytes.subarray(at + 4, at + 8));
    const data = bytes.subarray(at + 8, at + 8 + length);

    if (crc32(bytes.subarray(at + 4, at + 8 + length)) !== view.getUint32(at + 8 + length)) return null;

    if (type === "IHDR") header = { width: view.getUint32(at + 8), height: view.getUint32(at + 12), depth: data[8] ?? 0, colour: data[9] ?? -1, interlace: data[12] ?? -1 };
    else if (type === "IDAT") idat.push(data);
    else if (type === "IEND") {
      if (end !== bytes.length || header === null || idat.length === 0) return null;
      const channels = channelsOf(header.colour);

      if (header.depth !== 8 || header.interlace !== 0 || channels === null) return null;
      const pixels = inflateSync(Buffer.concat(idat));

      return pixels.length === header.height * (1 + header.width * channels) ? { width: header.width, height: header.height } : null;
    }

    at = end;
  }

  return null;
}

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;

  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;

  return c >>> 0;
});

function crc32(bytes: Uint8Array): number {
  let c = 0xffffffff;

  for (const b of bytes) c = (CRC_TABLE[(c ^ b) & 0xff] ?? 0) ^ (c >>> 8);

  return (c ^ 0xffffffff) >>> 0;
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

describe("the PNG check itself", () => {
  test("a whole card decodes; its first 24 bytes, a truncated copy and one with bytes after IEND do not", async () => {
    const bytes = new Uint8Array(await (await site().dispatchFetch("http://apm.test/og?check=1")).arrayBuffer());

    expect(pngSize(bytes)).toEqual({ width: 1200, height: 630 });
    expect(pngSize(bytes.slice(0, 24))).toBeNull();
    expect(pngSize(bytes.slice(0, bytes.length - 100))).toBeNull();
    expect(pngSize(bytes.slice(0, bytes.length - 12))).toBeNull();
    expect(pngSize(new Uint8Array([...bytes, 0]))).toBeNull();
  }, 60_000);
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
