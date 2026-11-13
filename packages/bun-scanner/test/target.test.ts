// Review of 2fbf383, finding 5: bun hands the scanner every platform's optional binaries (all 26 of @esbuild/* for
// esbuild) and installs only this machine's, so a scan of the others could cancel an install that never fetches them.
// The scanner now sends the install's platform, and the registry skips the binaries a scanned package lists as
// optional for another. The registry is a stub that records what it is asked.
import { afterEach, expect, test } from "bun:test";
import { z } from "zod";
import { scanPackages } from "../src/index.ts";

const ScanBody = z.object({ packages: z.array(z.object({ name: z.string(), version: z.string() })), os: z.string().optional(), cpu: z.string().optional() });

let server: ReturnType<typeof Bun.serve> | null = null;

afterEach(() => {
  server?.stop(true);
  server = null;
});

test("every scan request names the platform the install is for", async () => {
  const asked: z.infer<typeof ScanBody>[] = [];

  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req): Promise<Response> {
      asked.push(ScanBody.parse(await req.json()));

      return Response.json({ advisories: [], unchecked: [], pending: [], skippedForPlatform: [] });
    },
  });
  const registry = server.url.href;
  const packages = ["esbuild", "@esbuild/linux-x64", "@esbuild/win32-x64"].map((name): Bun.Security.Package => ({ name, version: "0.25.0", tarball: `${registry}${name}/-/x-0.25.0.tgz`, requestedRange: "0.25.0" }));

  await scanPackages({ packages, env: { APM_REGISTRY: registry }, cwd: "/nonexistent", warn: () => {}, waitMs: 0, interactive: false });

  // on 2fbf383: { packages, strict } only, so the registry judged the win32 binary for a linux install
  expect(asked.map((a) => [a.os, a.cpu])).toEqual([[process.platform, process.arch]]);
});
