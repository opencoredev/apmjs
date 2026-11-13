// Review of a76b9fc, finding 2: the scanner asks 200 packages per request, in parallel, and threw every answer away
// when one request failed. With 201 packages, batch 1 named a fatal advisory and batch 2 got a 503: the scan returned
// [] with only "not checked" warnings, so `bun install` went ahead with a version the registry had said to block.
// Now the batches that answered count, and only the failed batch's packages are unchecked. The registry is a stub.
import { afterEach, describe, expect, test } from "bun:test";
import { z } from "zod";
import { scanPackages } from "../src/index.ts";

const ScanBody = z.object({ packages: z.array(z.object({ name: z.string(), version: z.string() })) });

let server: ReturnType<typeof Bun.serve> | null = null;

afterEach(() => {
  server?.stop(true);
  server = null;
});

/** A scan API that blocks `evil` wherever it is asked, and answers 503 to any request that names `down`. */
function stub(): string {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req): Promise<Response> {
      const body = ScanBody.parse(await req.json());
      const names = body.packages.map((p) => p.name);

      if (names.includes("down")) return new Response("unavailable", { status: 503 });

      return Response.json({
        advisories: names.includes("evil") ? [{ package: "evil", version: "1.0.0", level: "fatal", description: "evil@1.0.0: apm reviewers confirmed this version is malicious.", url: null }] : [],
        unchecked: [],
        pending: [],
      });
    },
  });

  return server.url.href;
}

const pkg = (name: string, registry: string): Bun.Security.Package => ({ name, version: "1.0.0", tarball: `${registry}${name}/-/${name}-1.0.0.tgz`, requestedRange: "^1.0.0" });

describe("one failed scan batch", () => {
  // batch 1: evil and 199 fine packages; batch 2: the one package whose request fails
  const names = ["evil", ...Array.from({ length: 199 }, (_, i) => `fine-${i}`), "down"];

  test("keeps the fatal advisory the other batch named, and reports only the failed batch's package unchecked", async () => {
    const registry = stub();
    const warnings: string[] = [];
    const out = await scanPackages({ packages: names.map((n) => pkg(n, registry)), env: { APM_REGISTRY: registry }, cwd: "/nonexistent", warn: (l) => warnings.push(l), waitMs: 0, interactive: false });

    expect(out.map((a) => [a.package, a.level])).toEqual([["evil", "fatal"]]);
    const notChecked = warnings.filter((w) => w.startsWith("apm scanner: not checked:"));

    expect(notChecked).toHaveLength(1);
    expect(notChecked[0]).toContain("down@1.0.0");
    expect(notChecked[0]).toContain("HTTP 503");
  });

  test("strict mode cancels on the unchecked package, after the advisory is known", async () => {
    const registry = stub();
    const run = scanPackages({ packages: names.map((n) => pkg(n, registry)), env: { APM_REGISTRY: registry, APM_SCANNER_STRICT: "1" }, cwd: "/nonexistent", warn: () => {}, waitMs: 0, interactive: false });

    await expect(run).rejects.toThrow("1 package(s) not checked");
  });

  test("when no batch can be asked, every package is unchecked, as before", async () => {
    const registry = stub();
    const warnings: string[] = [];
    const out = await scanPackages({ packages: ["down", "other"].map((n) => pkg(n, registry)), env: { APM_REGISTRY: registry }, cwd: "/nonexistent", warn: (l) => warnings.push(l), waitMs: 0, interactive: false });

    expect(out).toEqual([]);
    expect(warnings.filter((w) => w.startsWith("apm scanner: not checked:"))).toHaveLength(2);
  });
});
