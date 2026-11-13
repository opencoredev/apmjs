// Review of 93274c8, finding 1: the registry decided from package names which scanned packages were optional for
// another platform, so a parent asking optionally for scan-bin@1.0.0 hid a revoked scan-bin@2.0.0 that bun was about
// to install. Bun hands the scanner exactly what it installs, so the scanner sends no platform and the registry checks
// every package. The registry is a stub that records what it is asked.
import { afterEach, expect, test } from "bun:test";
import { z } from "zod";
import { scanPackages } from "../src/index.ts";

const ScanBody = z.object({ packages: z.array(z.object({ name: z.string(), version: z.string() })), os: z.string().optional(), cpu: z.string().optional() });

let server: ReturnType<typeof Bun.serve> | null = null;

afterEach(() => {
  server?.stop(true);
  server = null;
});

test("every scan request asks about every package it was handed, and names no platform to skip by", async () => {
  const asked: z.infer<typeof ScanBody>[] = [];

  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req): Promise<Response> {
      asked.push(ScanBody.parse(await req.json()));

      return Response.json({ advisories: [], unchecked: [], pending: [] });
    },
  });
  const registry = server.url.href;
  const packages = ["esbuild", "@esbuild/linux-x64", "@esbuild/win32-x64"].map((name): Bun.Security.Package => ({ name, version: "0.25.0", tarball: `${registry}${name}/-/x-0.25.0.tgz`, requestedRange: "0.25.0" }));

  await scanPackages({ packages, env: { APM_REGISTRY: registry }, cwd: "/nonexistent", warn: () => {}, waitMs: 0, interactive: false });

  // on 93274c8: os and cpu were sent, and the registry skipped @esbuild/win32-x64 by name
  expect(asked.map((a) => [a.os, a.cpu])).toEqual([[undefined, undefined]]);
  expect(asked.flatMap((a) => a.packages.map((p) => p.name))).toEqual(["esbuild", "@esbuild/linux-x64", "@esbuild/win32-x64"]);
});
