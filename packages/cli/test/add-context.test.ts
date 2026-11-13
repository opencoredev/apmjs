// What `apm add` asks the registry about a project, against a stand-in registry and a stand-in package manager.
//
// Review of 1924692:
// 1. A peer the project provides was checked at the newest in range, not the version the project's lockfile pins, and
//    the JSON output left projectPeers out. apm add now sends each direct dependency with its pin.
// 2, 3. A config line (a bare `force` in .npmrc) or a pnpm hook made the package manager install a binary for another
//    platform than the one apm asked about. apm add now asks about every platform: it sends no os or cpu.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";

/** What one resolve asked for. */
type Asked = { os: string | null; cpu: string | null; installed: string | null };

describe("apm add's question to the registry", () => {
  let server: ReturnType<typeof Bun.serve>;
  let root: string;
  let bin: string;
  const asked = new Map<string, Asked>();

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), "apm-add-context-"));
    bin = join(root, "bin");
    mkdirSync(bin);

    // the package managers apm runs: each fails at once, so nothing is installed and apm reports what it resolved
    for (const pm of ["npm", "pnpm", "bun", "yarn"]) {
      writeFileSync(join(bin, pm), "#!/bin/sh\nexit 7\n");
      chmodSync(join(bin, pm), 0o755);
    }

    server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        const url = new URL(req.url);

        if (url.pathname !== "/-/apm/v1/resolve") return Response.json({ error: "not found" }, { status: 404 });
        const name = url.searchParams.get("name") ?? "";
        const installed = url.searchParams.get("installed");

        asked.set(name, { os: url.searchParams.get("os"), cpu: url.searchParams.get("cpu"), installed });
        // the registry's answer for the peer host: the version the project pins, or the newest in range
        const pin = (installed ?? "").split(",").find((e) => e.startsWith("host"));
        const version = pin?.split("@")[1] ?? "1.1.0";
        const projectPeers = pin === undefined ? [] : [{ dependency: "host@^1.0.0", via: [`${name}@1.0.0`], kind: version === "?" ? "unknown" : pin.includes("@") ? "lockfile" : "newest", version: version === "?" ? null : version }];

        const swc = ["darwin-arm64", "darwin-x64", "linux-x64-gnu", "linux-x64-musl", "linux-arm64-gnu", "linux-arm64-musl", "win32-x64-msvc", "win32-arm64-msvc"].map((p) => ({ name: `@next/swc-${p}`, version: "16.4.6", platform: { os: [p.split("-")[0] ?? ""], cpu: [p.split("-")[1] ?? ""] } }));
        const tooLarge = (n: string) => ({ name: n, version: "16.4.6", kind: "unscorable", score: null, grade: null, text: "apm cannot score this version: it is too large for apm to analyze", reasons: [], url: `https://web.test/package/${n}`, via: [`${name}@1.0.0`] });
        const warnings = name === "next-like" ? [tooLarge("@next/swc-linux-x64-gnu"), tooLarge("@next/swc-win32-x64-msvc"), { ...tooLarge("plain-dep"), name: "plain-dep", version: "1.0.0" }] : [];

        return Response.json(
          {
            name,
            range: "latest",
            source: "local",
            version: "1.0.0",
            report: { score: 95, grade: "A", signals: [] },
            skipped: [],
            tree: { unchecked: 0, uncheckedDeps: [], packages: name === "next-like" ? [...swc, { name: "plain-dep", version: "1.0.0" }] : [], projectPeers },
            warnings,
          },
          { headers: { "cache-control": "no-store" } },
        );
      },
    });
  });

  afterAll(() => {
    server.stop(true);
    rmSync(root, { recursive: true, force: true });
  });

  /** A project listing host, with these files beside its package.json. */
  function project(name: string, files: Record<string, string>): string {
    const dir = join(root, name);
    mkdirSync(dir);
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name, version: "1.0.0", private: true, dependencies: { host: "^1.0.0" } }));

    for (const [file, text] of Object.entries(files)) writeFileSync(join(dir, file), text);

    return dir;
  }

  /** `out` is stdout; `text` is everything a person in a terminal sees. */
  async function add(input: { cwd: string; pm: string; pkg: string; json: boolean }): Promise<{ code: number; out: string; text: string }> {
    const proc = Bun.spawn([process.execPath, join(import.meta.dir, "..", "src", "main.ts"), "add", input.pkg, "--pm", input.pm, ...(input.json ? ["--json"] : [])], {
      cwd: input.cwd,
      env: { PATH: `${bin}:/usr/bin:/bin`, HOME: root, APM_REGISTRY: server.url.toString(), NO_COLOR: "1" },
      stdout: "pipe",
      stderr: "pipe",
    });

    const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);

    return { code, out, text: out + err };
  }

  const npmLock = JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { host: "^1.0.0" } }, "node_modules/host": { version: "1.0.0", resolved: "https://registry.npmjs.org/host/-/host-1.0.0.tgz", integrity: "sha512-host" } } });

  const Json = z.object({ packages: z.array(z.object({ name: z.string(), projectPeers: z.array(z.object({ dependency: z.string(), kind: z.string(), version: z.string().nullable() })) })) });

  test("it sends the version the project's lockfile pins, and the JSON output names the peer and the version checked", async () => {
    const cwd = project("pinned", { "package-lock.json": npmLock });
    const r = await add({ cwd, pm: "npm", pkg: "plugin", json: true });

    // on 1924692: installed=host, so the registry checked the newest in range
    expect(asked.get("plugin")?.installed).toBe("host@1.0.0");
    // on 1924692: no projectPeers in the JSON
    expect(Json.parse(JSON.parse(r.out)).packages[0]?.projectPeers).toEqual([{ dependency: "host@^1.0.0", kind: "lockfile", version: "1.0.0" }]);
  });

  test("with no lockfile it sends the name alone, so the newest in range is checked, and says so", async () => {
    const cwd = project("unlocked", {});
    const r = await add({ cwd, pm: "npm", pkg: "plugin-b", json: false });

    expect(asked.get("plugin-b")?.installed).toBe("host");
    // review of 16fc8b5, finding 2: the newest in range is a guess, not what the package manager installs
    expect(r.text).toContain("peer host@^1.0.0: your package.json lists it with no lockfile entry; apm checked the newest in range, 1.1.0, and checks the version your package manager picks once it is installed");
  });

  test("with a lockfile apm cannot read (yarn's) it sends the name as unknown", async () => {
    const cwd = project("yarned", { "yarn.lock": 'host@^1.0.0:\n  version "1.0.0"\n' });
    await add({ cwd, pm: "yarn", pkg: "plugin-c", json: true });

    // on 1924692: installed=host, so the registry checked the newest in range
    expect(asked.get("plugin-c")?.installed).toBe("host@?");
  });

  test("it never asks about one platform, whatever the config or hooks say", async () => {
    // the reviewer's bypasses: a bare force line, a mixed-case userconfig with force=true, a pnpm hook adding win32
    const userconfig = join(root, "mixed.npmrc");
    writeFileSync(userconfig, "force=true\n");
    const cwd = project("platform", { ".npmrc": "force\n", ".pnpmfile.cjs": "module.exports = { hooks: { updateConfig: (c) => ({ ...c, supportedArchitectures: { os: ['current', 'win32'] } }) } };\n" });

    for (const pm of ["npm", "pnpm", "bun"]) {
      asked.delete("plain");
      await add({ cwd, pm, pkg: "plain", json: true });

      // on 1924692: os=linux and cpu=x64 for pnpm with the hook, and for npm with a bare force line
      expect([pm, asked.get("plain")?.os, asked.get("plain")?.cpu]).toEqual([pm, null, null]);
    }
  });

  test("platform binaries are summed up a family a line, and the other warnings are printed one by one", async () => {
    const cwd = project("binaries", {});
    const r = await add({ cwd, pm: "npm", pkg: "next-like", json: false });

    expect(r.text).toContain("WARNING 8 platform binaries (@next/swc-*): 2 too large to analyze");
    expect(r.text).toContain("WARNING plain-dep@1.0.0 apm cannot score this version");
    expect(r.text).not.toContain("WARNING @next/swc-linux-x64-gnu");
  });
});
