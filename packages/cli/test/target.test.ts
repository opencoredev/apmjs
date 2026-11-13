// Review of 93274c8, finding 2: the CLI always sent this machine's platform, so the registry skipped optional packages
// built for another, while npm_config_force=true (which the child env keeps) or an os/cpu override made the package
// manager install them unchecked. Now the CLI sends the real platform only when nothing in effect for the package
// manager it runs says otherwise, and "any" when something does. Finding 6: apm explain --strict asked in the default
// mode. Finding 3, the CLI's half: apm add tells the registry which names the project's package.json lists.
// Every case runs in a fresh directory with its own HOME, so no real config file is read; the registry is a local
// stub that records what it is asked and knows no package.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { z } from "zod";
import { installTarget } from "../src/target.ts";
import type { Pm } from "../src/pm.ts";

const HOST = { os: "linux", cpu: "x64" };
const made: string[] = [];

/** A fresh project directory and the HOME beside it. */
type Dirs = { cwd: string; home: string };

/** A fresh project directory and HOME, with `files` written into the project (or into HOME, for a `~/` path). */
function dirs(files: Record<string, string> = {}): Dirs {
  const home = mkdtempSync(join(tmpdir(), "apm-target-home-"));
  const cwd = mkdtempSync(join(tmpdir(), "apm-target-app-"));

  made.push(home, cwd);

  for (const [path, text] of Object.entries(files)) {
    const full = path.startsWith("~/") ? join(home, path.slice(2)) : join(cwd, path);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, text);
  }

  return { cwd, home };
}

/** What the CLI would send for `pm`, with `env` (and HOME) and `files` in effect. */
function sent(pm: Pm, env: Record<string, string> = {}, files: Record<string, string> = {}): { os: string; cpu: string } {
  const { cwd, home } = dirs(files);

  return installTarget({ pm, cwd, env: { HOME: home, ...env }, host: HOST }).target;
}

const ANY = { os: "any", cpu: "any" };

/** A scan request as the registry reads it, with any platform fields an older CLI sent kept for the check. */
const ScanRequest = z.object({ packages: z.array(z.object({ name: z.string(), version: z.string() })), os: z.string().optional(), cpu: z.string().optional() });

afterAll(() => {
  for (const d of made) rmSync(d, { recursive: true, force: true });
});

describe("the platform the CLI asks about", () => {
  test("with nothing in effect, this machine's, for npm, pnpm and bun", () => {
    for (const pm of ["npm", "pnpm", "bun"] as const) expect([pm, sent(pm)]).toEqual([pm, HOST]);
  });

  // on 93274c8 every case below sent { os: "linux", cpu: "x64" }
  test("npm: npm_config_force, npm_config_os and npm_config_cpu in the environment, in any case", () => {
    expect(sent("npm", { npm_config_force: "true" })).toEqual(ANY);
    expect(sent("npm", { NPM_CONFIG_FORCE: "true" })).toEqual(ANY);
    expect(sent("npm", { npm_config_os: "win32" })).toEqual(ANY);
    expect(sent("npm", { npm_config_cpu: "arm64" })).toEqual(ANY);
    // an explicit false is no override
    expect(sent("npm", { npm_config_force: "false" })).toEqual(HOST);
  });

  test("npm: force, os or cpu in the project's .npmrc, the user's, or the named global one", () => {
    expect(sent("npm", {}, { ".npmrc": "force=true\n" })).toEqual(ANY);
    expect(sent("npm", {}, { ".npmrc": "os=darwin\n" })).toEqual(ANY);
    expect(sent("npm", {}, { "~/.npmrc": "cpu=arm64\n" })).toEqual(ANY);
    expect(sent("npm", {}, { ".npmrc": "force=false\nregistry=https://example.test/\n" })).toEqual(HOST);
    const { cwd, home } = dirs({ "global-npmrc": "force=true\n" });

    expect(installTarget({ pm: "npm", cwd, env: { HOME: home, npm_config_globalconfig: join(cwd, "global-npmrc") }, host: HOST }).target).toEqual(ANY);
  });

  test("pnpm: the npm settings, pnpm_config_*, supported-architectures, package.json and pnpm-workspace.yaml", () => {
    expect(sent("pnpm", { npm_config_force: "true" })).toEqual(ANY);
    expect(sent("pnpm", { pnpm_config_cpu: "arm64" })).toEqual(ANY);
    expect(sent("pnpm", {}, { ".npmrc": "supported-architectures[]=x\n" })).toEqual(ANY);
    expect(sent("pnpm", {}, { "package.json": JSON.stringify({ name: "app", pnpm: { supportedArchitectures: { os: ["current", "win32"] } } }) })).toEqual(ANY);
    expect(sent("pnpm", {}, { "pnpm-workspace.yaml": "supportedArchitectures:\n  cpu: [x64, arm64]\n" })).toEqual(ANY);
    expect(sent("pnpm", {}, { "pnpm-workspace.yaml": "packages: [a]\n" })).toEqual(HOST);
  });

  test("bun: [install] os, cpu or force in bunfig.toml, and the npm_config_* settings", () => {
    expect(sent("bun", {}, { "bunfig.toml": '[install]\ncpu = "*"\n' })).toEqual(ANY);
    expect(sent("bun", {}, { "bunfig.toml": '[install]\nos = "*"\n' })).toEqual(ANY);
    expect(sent("bun", {}, { "~/.bunfig.toml": "[install]\nforce = true\n" })).toEqual(ANY);
    expect(sent("bun", { npm_config_cpu: "arm64" })).toEqual(ANY);
    expect(sent("bun", {}, { "bunfig.toml": '[install]\nregistry = "https://example.test/"\n' })).toEqual(HOST);
  });

  test("yarn: always any, since apm does not read yarn's supportedArchitectures", () => {
    expect(sent("yarn")).toEqual(ANY);
  });
});

describe("what apm add and apm explain send", () => {
  let server: ReturnType<typeof Bun.serve>;
  const asked: URLSearchParams[] = [];
  /** Each scan request's body, as apm audit sent it. */
  const scans: z.infer<typeof ScanRequest>[] = [];

  beforeAll(() => {
    server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(req) {
        const url = new URL(req.url);

        if (url.pathname === "/-/apm/v1/resolve") asked.push(url.searchParams);

        if (url.pathname === "/-/apm/v1/audit") return Response.json({ advisories: {}, unavailable: [] });

        if (url.pathname === "/-/apm/v1/scan") {
          return req.json().then((body) => {
            scans.push(ScanRequest.parse(body));

            return Response.json({ advisories: [], unchecked: [] });
          });
        }

        return Response.json({ error: "No package named that." }, { status: 404 });
      },
    });
  });

  afterAll(() => {
    server.stop(true);
  });

  /** Runs apm with `args` in a fresh project with `files` and `env`. */
  async function run(args: string[], env: Record<string, string> = {}, files: Record<string, string> = {}): Promise<void> {
    const { cwd, home } = dirs(files);

    const proc = Bun.spawn(["bun", join(import.meta.dir, "..", "src", "main.ts"), ...args], {
      cwd,
      env: { PATH: process.env.PATH ?? "", HOME: home, APM_REGISTRY: server.url.toString(), NO_COLOR: "1", ...env },
      stdout: "pipe",
      stderr: "pipe",
    });

    await proc.exited;
  }

  /** The resolve query `args` makes, run in a fresh project with `files` and `env`. */
  async function query(args: string[], env: Record<string, string> = {}, files: Record<string, string> = {}): Promise<URLSearchParams> {
    asked.length = 0;
    await run(args, env, files);
    const q = asked[0];

    if (!q) throw new Error(`apm ${args.join(" ")} asked the registry nothing`);

    return q;
  }

  test("apm add sends any when npm_config_force is set for npm, and this machine's platform otherwise", async () => {
    const forced = await query(["add", "thing", "--pm", "npm"], { npm_config_force: "true" });

    // on 93274c8: os=linux, and npm then installed every platform's optional packages
    expect([forced.get("os"), forced.get("cpu")]).toEqual(["any", "any"]);
    const plain = await query(["add", "thing", "--pm", "npm"]);

    expect([plain.get("os"), plain.get("cpu")]).toEqual([process.platform, process.arch]);
  });

  test("apm add sends the names the project's package.json lists", async () => {
    const pj = JSON.stringify({ name: "app", dependencies: { react: "^19.0.0" }, devDependencies: { "@types/node": "^24.0.0" }, peerDependencies: { react: "*" } });
    const q = await query(["add", "thing", "--pm", "npm"], {}, { "package.json": pj });

    // on 93274c8: no installed parameter
    expect(q.get("installed")).toBe("react,@types/node");
  });

  test("apm explain --strict and APM_STRICT=1 ask in strict mode, for the platform apm add would ask about", async () => {
    // on 93274c8: no strict parameter
    expect((await query(["explain", "thing", "--strict"])).get("strict")).toBe("1");
    expect((await query(["explain", "thing"], { APM_STRICT: "1" })).get("strict")).toBe("1");
    expect((await query(["explain", "thing"])).get("strict")).toBeNull();
    expect((await query(["explain", "thing", "--pm", "npm"], { npm_config_os: "win32" })).get("os")).toBe("any");
  });

  // review of 93274c8, finding 1: installed packages are never skipped for their platform either
  test("apm audit asks about every installed package, with no platform to skip by", async () => {
    scans.length = 0;
    const manifest = (name: string, version: string, extra: Partial<Record<"dependencies" | "optionalDependencies", Record<string, string>> & { os: string[] }> = {}) => JSON.stringify({ name, version, ...extra });

    await run(["audit"], {}, {
      "package.json": manifest("app", "1.0.0", { dependencies: { "scan-parent": "1.0.0", "scan-bin": "2.0.0" } }),
      "node_modules/scan-parent/package.json": manifest("scan-parent", "1.0.0", { optionalDependencies: { "scan-bin": "1.0.0" } }),
      "node_modules/scan-bin/package.json": manifest("scan-bin", "2.0.0", { os: ["win32"] }),
    });

    // on 93274c8: os and cpu were sent, and the registry skipped scan-bin@2.0.0 for its platform
    expect(scans).toEqual([{ packages: expect.arrayContaining([{ name: "scan-parent", version: "1.0.0" }, { name: "scan-bin", version: "2.0.0" }]) }]);
  });
});
