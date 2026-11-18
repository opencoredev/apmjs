// The CLI's download routes inside workerd, through Miniflare, with a real R2 bucket: what proxy.ts answers on the
// website for /install and /cli/*. A binary streams through whole, byte for byte.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Miniflare } from "miniflare";
import { cliDownload, cliPath } from "./cli-download";

let mf: Miniflare | null = null;
const out = mkdtempSync(join(tmpdir(), "apm-cli-download-"));
const binary = randomBytes(12 * 1024 * 1024);
const SCRIPT = "#!/bin/sh\necho apm\n";

function worker(): Miniflare {
  if (!mf) throw new Error("Miniflare did not start");

  return mf;
}

beforeAll(async () => {
  const built = await Bun.build({ entrypoints: [join(import.meta.dir, "cli-download.workerd-entry.ts")], outdir: out, target: "browser", format: "esm" });

  if (!built.success) throw new AggregateError(built.logs, "bundling the CLI download Worker failed");
  const script = built.outputs[0]?.path;

  if (!script) throw new Error("bundling the CLI download Worker produced no file");
  mf = new Miniflare({ modules: [{ type: "ESModule", path: script }], modulesRoot: out, compatibilityDate: "2026-07-30", compatibilityFlags: ["nodejs_compat"], r2Buckets: ["CLI"] });
  await mf.ready;
  const bucket = await mf.getR2Bucket("CLI");
  await bucket.put("install.sh", SCRIPT);
  await bucket.put("cli/0.1.0/apm-linux-x64", binary);
  await bucket.put("cli/0.1.0/SHA256SUMS", "abc  apm-linux-x64\n");
  await bucket.put("cli/releases.txt", "0.1.0 linux-x64 abc\n");
}, 60_000);

afterAll(async () => {
  await mf?.dispose();
  rmSync(out, { recursive: true, force: true });
});

describe("in workerd", () => {
  test("/install is the script as text, cached for five minutes", async () => {
    const res = await worker().dispatchFetch("http://apm.test/install");

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    expect(res.headers.get("cache-control")).toBe("public, max-age=300");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(await res.text()).toBe(SCRIPT);
  });

  test("a binary streams whole, with a year's immutable cache", async () => {
    const res = await worker().dispatchFetch("http://apm.test/cli/0.1.0/apm-linux-x64");
    const body = new Uint8Array(await res.arrayBuffer());

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/octet-stream");
    expect(res.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
    expect(res.headers.get("content-length")).toBe(String(binary.length));
    expect(createHash("sha256").update(body).digest("hex")).toBe(createHash("sha256").update(binary).digest("hex"));
  });

  test("HEAD answers the size without a body; SHA256SUMS and releases.txt are text", async () => {
    const head = await worker().dispatchFetch("http://apm.test/cli/0.1.0/apm-linux-x64", { method: "HEAD" });

    expect(head.status).toBe(200);
    expect(head.headers.get("content-length")).toBe(String(binary.length));
    expect(await head.text()).toBe("");
    const sums = await worker().dispatchFetch("http://apm.test/cli/0.1.0/SHA256SUMS");
    expect(sums.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
    expect(await sums.text()).toBe("abc  apm-linux-x64\n");
    const index = await worker().dispatchFetch("http://apm.test/cli/releases.txt");
    expect(index.headers.get("cache-control")).toBe("public, max-age=300");
  });

  // review of 1919be8, finding 4: a release cut short before SHA256SUMS left binaries served as immutable
  test("a binary whose version has no SHA256SUMS yet is an uncached 404, and is served once it has", async () => {
    const bucket = await worker().getR2Bucket("CLI");
    await bucket.put("cli/0.2.0/apm-linux-x64", "uploaded by a release that has not finished");

    for (const method of ["GET", "HEAD"]) {
      const res = await worker().dispatchFetch("http://apm.test/cli/0.2.0/apm-linux-x64", { method });

      expect(res.status).toBe(404);
      expect(res.headers.get("cache-control")).toBe("no-store");
      expect(await res.text()).toBe(method === "GET" ? "this apm version is not released\n" : "");
    }

    await bucket.put("cli/0.2.0/SHA256SUMS", "abc  apm-linux-x64\n");
    const released = await worker().dispatchFetch("http://apm.test/cli/0.2.0/apm-linux-x64");

    expect(released.status).toBe(200);
    expect(released.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
    expect(await released.text()).toBe("uploaded by a release that has not finished");
  });

  test("missing files, other paths and other methods", async () => {
    const missing = await worker().dispatchFetch("http://apm.test/cli/0.9.0/apm-linux-x64");
    expect(missing.status).toBe(404);
    expect(missing.headers.get("cache-control")).toBe("no-store");

    for (const path of ["/cli/0.1.0/../../install.sh", "/cli/latest/apm-linux-x64", "/cli/0.1.0/install.sh", "/cli/", "/cli/0.1.0/apm-linux-x64/x"]) {
      expect((await worker().dispatchFetch(`http://apm.test${path}`)).status).toBe(404);
    }

    const post = await worker().dispatchFetch("http://apm.test/install", { method: "POST", body: "x" });
    expect(post.status).toBe(405);
    expect(post.headers.get("allow")).toBe("GET, HEAD");
  });
});

describe("without the bucket", () => {
  test("no binding is a 503, never a missing release", async () => {
    const res = await cliDownload({ pathname: "/install", method: "GET", bucket: null });

    expect(res.status).toBe(503);
  });

  test("an empty bucket says no release is published yet", async () => {
    const res = await cliDownload({ pathname: "/install", method: "GET", bucket: { get: async () => null, head: async () => null } });

    expect(res.status).toBe(404);
    expect(await res.text()).toBe("no apm CLI release is published on this site yet\n");
  });

  test("only these paths are CLI files", () => {
    expect(cliPath("/install")).toEqual({ key: "install.sh", kind: "script" });
    expect(cliPath("/cli/1.2.3-rc.1/apm-darwin-arm64")).toEqual({ key: "cli/1.2.3-rc.1/apm-darwin-arm64", kind: "binary", released: "cli/1.2.3-rc.1/SHA256SUMS" });
    expect(cliPath("/install.sh")).toBeNull();
    expect(cliPath("/cli/1.2.3/APM")).toBeNull();
  });
});
